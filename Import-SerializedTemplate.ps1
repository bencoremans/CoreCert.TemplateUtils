<#
.SYNOPSIS
    Imports a serialized certificate template (from ConvertTo-SerializedTemplate) into Active Directory.

.DESCRIPTION
    Imports a certificate template from XML into Active Directory.

    Import behaviour:

    - Template does NOT exist (by name and OID): create new via CX509CertificateTemplateADWritable.
    - Template DOES exist with the same OID:
        * Compare revision + minor revision + content attributes.
        * If changed: apply in-place LDAP attribute update (increment revision).
        * If identical: skip (no-op).
    - OID exists but template object NOT found: orphan OID detected -- abort with a clear error.

    Optionally override Name, DisplayName, and Version (major.minor) on import.
    When overriding Name or DisplayName, a new OID is minted to avoid conflicts.

.PARAMETER XmlString
    The serialized template XML, as produced by ConvertTo-SerializedTemplate.

.PARAMETER Name
    Optional. Override the template CN. Forces a new OID.

.PARAMETER DisplayName
    Optional. Override the display name shown in the CA MMC.

.PARAMETER Version
    Optional. Override the version as "major.minor" (e.g. "100.1").

.PARAMETER Server
    Optional. LDAP server (DC) to connect to. Defaults to local domain.

.PARAMETER Domain
    Optional. Domain DN. Auto-discovered if not specified.

.EXAMPLE
    $xml = ConvertTo-SerializedTemplate -Template (Get-CertificateTemplate "CC-WebServer")
    Import-SerializedTemplate -XmlString $xml

.EXAMPLE
    Import-SerializedTemplate -XmlString $xml -Name "ACME-WebServer" -DisplayName "ACME Web Server" -Version "100.1"

.EXAMPLE
    # Re-import an updated source template -- will detect change and apply update
    Import-SerializedTemplate -XmlString $xml -Name "CC-WebServer"

.NOTES
    Requires Enterprise Administrator rights.
    LDAP attribute mapping is based on msPKI-* schema attributes defined in MS-ADSC.
#>
function Import-SerializedTemplate {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$XmlString,

        [string]$Name        = "",
        [string]$DisplayName = "",
        [string]$Version     = "",
        [string]$Server      = "",
        [string]$Domain      = ""
    )

    process {
        # -------------------------------------------------------------------------
        # Parse XML
        # -------------------------------------------------------------------------
        [xml]$doc = $XmlString
        $root = $doc.CertificateTemplate

        $srcName    = $root.Name
        $srcDisplay = $root.DisplayName
        $srcOid     = $root.OID
        $srcMajor   = [int]$root.Version.Major
        $srcMinor   = [int]$root.Version.Minor

        # -------------------------------------------------------------------------
        # Apply overrides
        # -------------------------------------------------------------------------
        $forceNewOid = $false

        if ($Name -and $Name -ne $srcName) {
            Write-Verbose "Name override: '$srcName' -> '$Name'"
            $srcName    = $Name
            $forceNewOid = $true
        }

        if ($DisplayName -and $DisplayName -ne $srcDisplay) {
            Write-Verbose "DisplayName override: '$srcDisplay' -> '$DisplayName'"
            $srcDisplay = $DisplayName
            $forceNewOid = $true   # display name is used as OID displayName too
        }

        if ($Version) {
            $parts = $Version -split '\.'
            if ($parts.Count -ne 2) { throw "Version must be 'major.minor', got: $Version" }
            $srcMajor = [int]$parts[0]
            $srcMinor = [int]$parts[1]
            Write-Verbose "Version override: $($root.Version.Major).$($root.Version.Minor) -> $srcMajor.$srcMinor"
        }

        # -------------------------------------------------------------------------
        # Auto-discover domain
        # -------------------------------------------------------------------------
        if (-not $Domain) {
            $rootDse = if ($Server) { [ADSI]"LDAP://$Server/RootDSE" } else { [ADSI]"LDAP://RootDSE" }
            $Domain  = $rootDse.defaultNamingContext
            Write-Verbose "Domain: $Domain"
        }

        $ldapPrefix  = if ($Server) { "LDAP://$Server/" } else { "LDAP://" }
        $pkiBase     = "CN=Public Key Services,CN=Services,CN=Configuration,$Domain"
        $tplBase     = "CN=Certificate Templates,$pkiBase"
        $oidBase     = "CN=OID,$pkiBase"

        # -------------------------------------------------------------------------
        # Check if template object exists (by name)
        # -------------------------------------------------------------------------
        $tplSearcher = New-Object System.DirectoryServices.DirectorySearcher
        $tplSearcher.SearchRoot  = [ADSI]"${ldapPrefix}${tplBase}"
        $tplSearcher.Filter      = "(cn=$srcName)"
        $tplSearcher.SearchScope = "OneLevel"
        $existingTemplate = $tplSearcher.FindOne()

        # -------------------------------------------------------------------------
        # Check if OID entry exists
        # -------------------------------------------------------------------------
        # OID entry displayName matches the template displayName (srcDisplay after override),
        # not the CN (srcName). Try displayName first, then fall back to srcName.
        $oidSearcher = New-Object System.DirectoryServices.DirectorySearcher
        $oidSearcher.SearchRoot  = [ADSI]"${ldapPrefix}${oidBase}"
        $oidSearcher.SearchScope = "OneLevel"
        $oidSearcher.Filter      = "(displayName=$srcDisplay)"
        $existingOid = $oidSearcher.FindOne()
        if (-not $existingOid) {
            $oidSearcher.Filter = "(displayName=$srcName)"
            $existingOid = $oidSearcher.FindOne()
        }

        # -------------------------------------------------------------------------
        # Decision tree
        # -------------------------------------------------------------------------

        if ($existingTemplate -and $existingOid) {
            # --- UPDATE PATH: both exist ---
            Write-Verbose "Template '$srcName' exists in AD. Checking for updates..."
            $tplEntry = $existingTemplate.GetDirectoryEntry()

            $adRevision = [int]$tplEntry.Properties["revision"].Value
            $adMinor    = [int]$tplEntry.Properties["msPKI-Template-Minor-Revision"].Value

            # Build a fingerprint of all content attributes from XML for comparison
            $srcAttrs = @{}
            foreach ($attr in $root.Attributes.Attribute) {
                $srcAttrs[$attr.Name] = $attr.Value
            }

            # Build fingerprint from AD
            $adAttrs = @{}
            $contentAttrNames = @(
                "flags","msPKI-Certificate-Application-Policy","msPKI-Certificate-Name-Flag",
                "msPKI-Enrollment-Flag","msPKI-Minimal-Key-Size","msPKI-Private-Key-Flag",
                "msPKI-RA-Application-Policies","msPKI-RA-Signature","msPKI-Template-Schema-Version",
                "pKICriticalExtensions","pKIDefaultKeySpec","pKIExpirationPeriod",
                "pKIExtendedKeyUsage","pKIKeyUsage","pKIMaxIssuingDepth","pKIOverlapPeriod"
            )
            foreach ($attrName in $contentAttrNames) {
                $vals = $tplEntry.Properties[$attrName]
                if ($vals -and $vals.Count -gt 0) {
                    # Convert byte arrays to Base64 for comparison
                    $v = $vals[0]
                    if ($v -is [byte[]]) {
                        $adAttrs[$attrName] = [Convert]::ToBase64String($v)
                    } else {
                        $adAttrs[$attrName] = "$v"
                    }
                }
            }

            # Compare version and content
            $versionChanged = ($srcMajor -ne $adRevision) -or ($srcMinor -ne $adMinor)
            $contentChanged = $false
            foreach ($k in $srcAttrs.Keys) {
                $adVal  = if ($adAttrs.ContainsKey($k)) { $adAttrs[$k] } else { "" }
                $srcVal = $srcAttrs[$k]
                # Normalise: LDAP returns null/empty for int attributes with value 0;
                # treat "" and "0" as equivalent for int-type attributes.
                $xmlAttr = $root.Attributes.Attribute | Where-Object { $_.Name -eq $k }
                if ($xmlAttr -and $xmlAttr.Type -eq "int" -and $srcVal -eq "0" -and $adVal -eq "") {
                    continue
                }
                if ($adVal -ne $srcVal) {
                    Write-Verbose "  Attribute changed: $k"
                    Write-Verbose "    AD:  $adVal"
                    Write-Verbose "    Src: $srcVal"
                    $contentChanged = $true
                }
            }

            if (-not $versionChanged -and -not $contentChanged) {
                Write-Verbose "Template '$srcName' is up to date (revision $adRevision.$adMinor). No update needed."
                Write-Output "Template '$srcName' is already up to date. No changes applied."
                return
            }

            # Apply update
            $changeDesc = if ($versionChanged) { "version $adRevision.$adMinor -> $srcMajor.$srcMinor" } else { "content changed" }
            if ($PSCmdlet.ShouldProcess("Template '$srcName'", "Update in AD ($changeDesc)")) {
                Write-Verbose "Applying update to '$srcName'..."

                # Write all content attributes from XML
                foreach ($attr in $root.Attributes.Attribute) {
                    $attrName  = $attr.Name
                    $attrValue = $attr.Value
                    $attrType  = $attr.Type

                    if ($attrType -eq "bytes") {
                        $bytes = [Convert]::FromBase64String($attrValue)
                        $tplEntry.Properties[$attrName].Clear()
                        $tplEntry.Properties[$attrName].Add($bytes) | Out-Null
                    } elseif ($attrType -eq "strings") {
                        $tplEntry.Properties[$attrName].Clear()
                        foreach ($line in ($attrValue -split "`n")) {
                            if ($line.Trim()) { $tplEntry.Properties[$attrName].Add($line.Trim()) | Out-Null }
                        }
                    } elseif ($attrType -eq "int") {
                        $tplEntry.Properties[$attrName].Clear()
                        $tplEntry.Properties[$attrName].Add([int]$attrValue) | Out-Null
                    } else {
                        $tplEntry.Properties[$attrName].Clear()
                        $tplEntry.Properties[$attrName].Add($attrValue) | Out-Null
                    }
                }

                # Update version
                $tplEntry.Properties["revision"].Clear()
                $tplEntry.Properties["revision"].Add($srcMajor) | Out-Null
                $tplEntry.Properties["msPKI-Template-Minor-Revision"].Clear()
                $tplEntry.Properties["msPKI-Template-Minor-Revision"].Add($srcMinor) | Out-Null

                $tplEntry.CommitChanges()
                Write-Verbose "Template '$srcName' updated: $changeDesc"
                Write-Output "Template '$srcName' updated successfully ($changeDesc)."
            }
            return
        }

        if (-not $existingTemplate -and $existingOid) {
            # --- ORPHAN OID: template gone but OID remains ---
            $oidEntry = $existingOid.GetDirectoryEntry()
            throw "Orphan OID detected for '$srcName'. The OID entry exists (DN: $($oidEntry.distinguishedName)) but the template object does not. Run Remove-CertTemplateFromAD -Name '$srcName' to clean up, then retry."
        }

        # -------------------------------------------------------------------------
        # CREATE PATH: template does not exist
        # -------------------------------------------------------------------------
        Write-Verbose "Template '$srcName' not found in AD. Creating new..."

        # When name or displayName is overridden we mint a fresh OID so the new
        # template does not collide with the source template's OID.
        # NOTE: forceNewOid is only honoured on the CREATE path; the UPDATE path
        # above always keeps the existing AD OID.
        if ($forceNewOid -or $srcOid -eq "") {
            # Use Windows PKI OID arc with two random arcs (same as Windows MMC)
            $a = Get-Random -Min 1000000 -Max 9999999
            $b = Get-Random -Min 1000000 -Max 9999999
            $srcOid = "1.3.6.1.4.1.311.21.8.$a.$b"
            Write-Verbose "New OID minted: $srcOid"
        }

        # Serialize to XML for CX509CertificateTemplateADWritable
        $sb = New-Object System.Text.StringBuilder
        $sb.AppendLine('<?xml version="1.0" encoding="utf-8"?>') | Out-Null
        $sb.AppendLine('<CertificateTemplateProperty>') | Out-Null
        foreach ($attr in $root.Attributes.Attribute) {
            $sb.AppendLine("  <Property Name=`"$($attr.Name)`" Value=`"$($attr.Value)`" Type=`"$($attr.Type)`" />") | Out-Null
        }
        $sb.AppendLine('</CertificateTemplateProperty>') | Out-Null

        $comTemplate = New-Object -ComObject X509Enrollment.CX509CertificateTemplateADWritable

        # Build raw LDAP attributes directly -- more reliable than COM serialization
        $tplContainer = [ADSI]"${ldapPrefix}${tplBase}"
        $newEntry = $tplContainer.Children.Add("CN=$srcName", "pKICertificateTemplate")

        $newEntry.Properties["displayName"].Add($srcDisplay) | Out-Null
        $newEntry.Properties["msPKI-Cert-Template-OID"].Add($srcOid) | Out-Null
        $newEntry.Properties["revision"].Add($srcMajor) | Out-Null
        $newEntry.Properties["msPKI-Template-Minor-Revision"].Add($srcMinor) | Out-Null
        $newEntry.Properties["flags"].Add(66257) | Out-Null   # standard template flags

        # Write all content attributes from XML
        foreach ($attr in $root.Attributes.Attribute) {
            $attrName  = $attr.Name
            $attrValue = $attr.Value
            $attrType  = $attr.Type

            # Skip version/OID attributes -- handled separately
            if ($attrName -in @("revision","msPKI-Template-Minor-Revision","msPKI-Cert-Template-OID","displayName","flags")) {
                continue
            }

            if ($attrType -eq "bytes") {
                $bytes = [Convert]::FromBase64String($attrValue)
                $newEntry.Properties[$attrName].Add($bytes) | Out-Null
            } elseif ($attrType -eq "strings") {
                foreach ($line in ($attrValue -split "`n")) {
                    if ($line.Trim()) { $newEntry.Properties[$attrName].Add($line.Trim()) | Out-Null }
                }
            } elseif ($attrType -eq "int") {
                $newEntry.Properties[$attrName].Add([int]$attrValue) | Out-Null
            } else {
                $newEntry.Properties[$attrName].Add($attrValue) | Out-Null
            }
        }

        if ($PSCmdlet.ShouldProcess("Template '$srcName'", "Import template to AD on '$Server'")) {
            $newEntry.CommitChanges()
            Write-Verbose "Template object created."

            # Register OID entry
            $oidContainer = [ADSI]"${ldapPrefix}${oidBase}"
            $oidCn        = "CN=$([guid]::NewGuid().ToString()),$oidBase"
            $newOidEntry  = $oidContainer.Children.Add("CN=$([guid]::NewGuid().ToString())", "msPKI-Enterprise-Oid")
            $newOidEntry.Properties["msPKI-Cert-Template-OID"].Add($srcOid) | Out-Null
            $newOidEntry.Properties["displayName"].Add($srcDisplay) | Out-Null
            $newOidEntry.Properties["flags"].Add(2) | Out-Null
            $newOidEntry.CommitChanges()
            Write-Verbose "OID entry registered."

            Write-Verbose "Template '$srcName' imported successfully."
            Write-Output "Template '$srcName' imported successfully."
        }
    }
}
