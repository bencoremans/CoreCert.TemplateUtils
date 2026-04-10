<#
.SYNOPSIS
    Imports certificate templates into Active Directory from an MS-XCEP XML string.

.DESCRIPTION
    Imports certificate templates from the MS-XCEP GetPoliciesResponse XML produced by
    Export-ADCSTemplate.

    Import behaviour:
    - Template does NOT exist (by name): create via CX509EnrollmentPolicyWebService /
      CX509CertificateTemplateADWritable COM interfaces. A new OID is always minted to
      avoid conflicts with the source template OID already registered in AD.
    - Template DOES exist (same commonName in AD): compare all key LDAP attributes against
      the serialized source. If changed: apply in-place LDAP attribute update and
      increment revision. If identical: skip (no-op).

    Optionally override Name and DisplayName on import to deploy the same base template
    under a different name per customer or forest.

.PARAMETER XmlString
    MS-XCEP XML string produced by Export-ADCSTemplate.

.PARAMETER Name
    Optional. Override the template CN on import. Only applies when XML contains a single policy.

.PARAMETER DisplayName
    Optional. Override the display name. Defaults to Name if not specified.

.PARAMETER Version
    Optional. Version as "major.minor" (e.g. "100.1"). Overrides source version.

.PARAMETER Server
    Optional. Target DC FQDN. Defaults to nearest writable DC.

.PARAMETER Domain
    Optional. Domain DN. Auto-discovered if not specified.

.EXAMPLE
    $xml = Export-ADCSTemplate -Template $t
    Import-ADCSTemplate -XmlString $xml

.EXAMPLE
    # Multi-tenant: same XML, different name per customer
    Import-ADCSTemplate -XmlString $xml -Name "ACME-WebServer" -DisplayName "ACME Web Server"

.EXAMPLE
    Import-ADCSTemplate -XmlString $xml -Name "TEST-WebServer" -WhatIf

.NOTES
    Requires Enterprise Administrator permissions.
    COM interfaces require Windows Server 2008 R2 / Windows 7 or newer.
    Update path uses System.DirectoryServices -- no ActiveDirectory module required.
#>
function Import-ADCSTemplate {
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

    begin {
        if (
            [Environment]::OSVersion.Version.Major -lt 6 -or
            ([Environment]::OSVersion.Version.Major -eq 6 -and [Environment]::OSVersion.Version.Minor -lt 1)
        ) { throw [System.PlatformNotSupportedException]"Requires Windows Server 2008 R2 / Windows 7 or newer." }

        #region Helper: convert seconds to AD binary period (FILETIME intervals)
        function ConvertTo-ADPeriod {
            param([int64]$Seconds)
            # AD stores validity/overlap as negative FILETIME intervals (100-nanosecond units)
            $intervals = -($Seconds * 10000000)
            [BitConverter]::GetBytes($intervals)
        }
        #endregion

        #region Helper: convert AD binary period to seconds
        function ConvertFrom-ADPeriod {
            param([byte[]]$Bytes)
            if ($null -eq $Bytes -or $Bytes.Length -ne 8) { return 0 }
            $intervals = [BitConverter]::ToInt64($Bytes, 0)
            [Math]::Abs($intervals) / 10000000
        }
        #endregion
    }

    process {
        # -----------------------------------------------------------------------
        # Resolve target DC and domain
        # -----------------------------------------------------------------------
        if (-not $Server) {
            try {
                $dc = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().FindDomainController()
                $Server = $dc.Name
                Write-Verbose "Auto-discovered DC: $Server"
            } catch {
                Write-Verbose "DC discovery failed: $($_.Exception.Message)"
            }
        }

        if (-not $Domain) {
            $rootDse = if ($Server) { [ADSI]"LDAP://$Server/RootDSE" } else { [ADSI]"LDAP://RootDSE" }
            $Domain = $rootDse.defaultNamingContext
        }

        $ldapPrefix = if ($Server) { "LDAP://$Server/" } else { "LDAP://" }
        $tplBase    = "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$Domain"

        # -----------------------------------------------------------------------
        # Parse XML
        # -----------------------------------------------------------------------
        [xml]$doc = $XmlString

        # Support single and multi-policy XML
        $policies = @($doc.GetPoliciesResponse.response.policies.policy)
        if ($policies.Count -eq 0) {
            throw "No <policy> elements found in XML. Verify the XML is valid MS-XCEP output from Export-ADCSTemplate."
        }

        if ($Name -and $policies.Count -gt 1) {
            throw "The -Name parameter cannot be used when the XML contains multiple templates. Import each template separately or omit -Name."
        }

        # -----------------------------------------------------------------------
        # Process each policy
        # -----------------------------------------------------------------------
        foreach ($policy in $policies) {
            $attrs        = $policy.attributes
            $originalName = $attrs.commonName
            $effectiveName = if ($Name) { $Name } else { $originalName }
            $effectiveDisplay = if ($DisplayName) { $DisplayName } elseif ($Name) { $Name } else {
                $oidRef = [int]$policy.policyOIDReference
                $oidNode = $doc.GetPoliciesResponse.oIDs.oID | Where-Object { $_.oIDReferenceID -eq "$oidRef" } | Select-Object -First 1
                if ($oidNode) { $oidNode.defaultName } else { $originalName }
            }

            # Apply name override in the XML document (for COM create path)
            if ($Name -and $Name -ne $originalName) {
                Write-Verbose "Name override: '$originalName' -> '$Name'"
                $attrs.commonName = $Name
            }

            # Update OID group=9 displayName and mint a new OID for COM create
            $oidRef = [int]$policy.policyOIDReference
            $doc.GetPoliciesResponse.oIDs.oID | ForEach-Object {
                if ($_.oIDReferenceID -eq "$oidRef" -and $_.group -eq "9") {
                    $_.defaultName = $effectiveDisplay
                    $a = Get-Random -Min 1000000 -Max 9999999
                    $b = Get-Random -Min 1000000 -Max 9999999
                    $_.value = "1.3.6.1.4.1.311.21.8.$a.$b"
                    Write-Verbose "DisplayName set to '$effectiveDisplay', new OID minted: $($_.value)"
                }
            }

            # Version override
            if ($Version) {
                if ($Version -match "^(\d+)\.(\d+)$") {
                    $attrs.revision.majorRevision = $matches[1]
                    $attrs.revision.minorRevision = $matches[2]
                    Write-Verbose "Version override: $Version"
                } else {
                    throw "Invalid -Version format. Expected 'major.minor' (e.g. '100.1')."
                }
            }

            # -------------------------------------------------------------------
            # Check if template already exists in AD
            # -------------------------------------------------------------------
            $searcher             = New-Object System.DirectoryServices.DirectorySearcher
            $searcher.SearchRoot  = [ADSI]"${ldapPrefix}${tplBase}"
            $searcher.Filter      = "(cn=$effectiveName)"
            $searcher.SearchScope = "OneLevel"
            $existingTemplate     = $searcher.FindOne()

            # -------------------------------------------------------------------
            # UPDATE PATH
            # -------------------------------------------------------------------
            if ($existingTemplate) {
                Write-Verbose "Template '$effectiveName' already exists in AD. Comparing attributes..."

                $tplEntry   = $existingTemplate.GetDirectoryEntry()
                $adRevision = [int]$tplEntry.Properties["revision"].Value
                $adMinor    = [int]$tplEntry.Properties["msPKI-Template-Minor-Revision"].Value

                # --- Build comprehensive attribute comparison map ---
                $changedAttrs = [System.Collections.Generic.List[string]]::new()

                # Integer attributes (direct comparison)
                $intAttrMap = @{
                    privateKeyFlags  = @{ ldap = "msPKI-Private-Key-Flag";        xcep = [int]$attrs.privateKeyFlags  }
                    subjectNameFlags = @{ ldap = "msPKI-Certificate-Name-Flag";   xcep = [int]$attrs.subjectNameFlags }
                    enrollmentFlags  = @{ ldap = "msPKI-Enrollment-Flag";         xcep = [int]$attrs.enrollmentFlags  }
                    generalFlags     = @{ ldap = "flags";                         xcep = [int]$attrs.generalFlags     }
                    policySchema     = @{ ldap = "msPKI-Template-Schema-Version"; xcep = [int]$attrs.policySchema     }
                    keySpec          = @{ ldap = "pKIDefaultKeySpec";             xcep = [int]$attrs.privateKeyAttributes.keySpec }
                    minimalKeyLength = @{ ldap = "msPKI-Minimal-Key-Size";       xcep = [int]$attrs.privateKeyAttributes.minimalKeyLength }
                    raSignatures     = @{ ldap = "msPKI-RA-Signature";           xcep = if ($attrs.rARequirements -and
                                            $attrs.rARequirements.rASignatures) { [int]$attrs.rARequirements.rASignatures } else { 0 } }
                }

                foreach ($key in $intAttrMap.Keys) {
                    $adVal  = [int]$tplEntry.Properties[$intAttrMap[$key].ldap].Value
                    $srcVal = $intAttrMap[$key].xcep
                    if ($adVal -ne $srcVal) {
                        Write-Verbose "  Differs: $($intAttrMap[$key].ldap)  AD=$adVal  Src=$srcVal"
                        $changedAttrs.Add($key)
                    }
                }

                # Binary period attributes (validity / renewal)
                $srcValiditySec = [int64]$attrs.certificateValidity.validityPeriodSeconds
                $srcRenewalSec  = [int64]$attrs.certificateValidity.renewalPeriodSeconds
                $adValiditySec  = ConvertFrom-ADPeriod ([byte[]]$tplEntry.Properties["pKIExpirationPeriod"].Value)
                $adRenewalSec   = ConvertFrom-ADPeriod ([byte[]]$tplEntry.Properties["pKIOverlapPeriod"].Value)

                if ([Math]::Abs($adValiditySec - $srcValiditySec) -gt 1) {
                    Write-Verbose "  Differs: pKIExpirationPeriod  AD=${adValiditySec}s  Src=${srcValiditySec}s"
                    $changedAttrs.Add("validity")
                }
                if ([Math]::Abs($adRenewalSec - $srcRenewalSec) -gt 1) {
                    Write-Verbose "  Differs: pKIOverlapPeriod  AD=${adRenewalSec}s  Src=${srcRenewalSec}s"
                    $changedAttrs.Add("renewal")
                }

                # Note: pKIExtendedKeyUsage, msPKI-Certificate-Application-Policy, and
                # pKICriticalExtensions are NOT compared in the update path. These attributes
                # are set by the COM layer during CREATE and are not represented as separate
                # elements in the MS-XCEP XML — they are embedded in the extension blobs which
                # the COM interfaces parse internally. For full template replacement, use
                # Remove-ADCSTemplate + Import-ADCSTemplate (delete/recreate via COM).

                # Version comparison
                $srcMajor = [int]$attrs.revision.majorRevision
                $srcMinor = [int]$attrs.revision.minorRevision
                $versionChanged = ($srcMajor -ne $adRevision) -or ($srcMinor -ne $adMinor)
                $contentChanged = $changedAttrs.Count -gt 0

                if (-not $versionChanged -and -not $contentChanged) {
                    Write-Output "Template '$effectiveName' is already up to date (v$adRevision.$adMinor). No changes applied."
                    continue
                }

                $changeDesc = @()
                if ($versionChanged)  { $changeDesc += "version v$adRevision.$adMinor -> v$srcMajor.$srcMinor" }
                if ($contentChanged)  { $changeDesc += "$($changedAttrs.Count) attribute(s): $($changedAttrs -join ', ')" }

                if ($PSCmdlet.ShouldProcess("Template '$effectiveName'", "Update in AD ($($changeDesc -join '; '))")) {
                    # Write integer attributes
                    foreach ($key in ($changedAttrs | Where-Object { $intAttrMap.ContainsKey($_) })) {
                        $ldapAttr = $intAttrMap[$key].ldap
                        $tplEntry.Properties[$ldapAttr].Clear()
                        $tplEntry.Properties[$ldapAttr].Add($intAttrMap[$key].xcep) | Out-Null
                    }

                    # Write binary period attributes
                    if ($changedAttrs -contains "validity") {
                        [byte[]]$newVal = ConvertTo-ADPeriod $srcValiditySec
                        $tplEntry.Properties["pKIExpirationPeriod"].Clear()
                        [void]$tplEntry.Properties["pKIExpirationPeriod"].Add($newVal)
                    }
                    if ($changedAttrs -contains "renewal") {
                        [byte[]]$newVal = ConvertTo-ADPeriod $srcRenewalSec
                        $tplEntry.Properties["pKIOverlapPeriod"].Clear()
                        [void]$tplEntry.Properties["pKIOverlapPeriod"].Add($newVal)
                    }

                    # Update version
                    $tplEntry.Properties["revision"].Clear()
                    $tplEntry.Properties["revision"].Add($srcMajor) | Out-Null
                    $tplEntry.Properties["msPKI-Template-Minor-Revision"].Clear()
                    $tplEntry.Properties["msPKI-Template-Minor-Revision"].Add($srcMinor) | Out-Null

                    $tplEntry.CommitChanges()
                    Write-Output "Template '$effectiveName' updated successfully ($($changeDesc -join '; '))."
                }
                continue
            }

            # -------------------------------------------------------------------
            # CREATE PATH: use COM
            # -------------------------------------------------------------------
            Write-Verbose "Template '$effectiveName' not found in AD. Creating via COM..."

            if ($PSCmdlet.ShouldProcess("Template '$effectiveName'", "Import to AD")) {
                $encoder = New-Object System.Text.ASCIIEncoding
                $bytes   = $encoder.GetBytes($doc.OuterXml)

                $pol = New-Object -ComObject X509Enrollment.CX509EnrollmentPolicyWebService
                $pol.InitializeImport($bytes)
                $templates = @($pol.GetTemplates())

                if ($templates.Count -eq 0) {
                    throw "COM returned 0 templates from the provided XML. Verify the XML is valid MS-XCEP output from Export-ADCSTemplate."
                }

                foreach ($template in $templates) {
                    $adwt = New-Object -ComObject X509Enrollment.CX509CertificateTemplateADWritable
                    $adwt.Initialize($template)
                    if ($Server) { $adwt.Commit(1, $Server) } else { $adwt.Commit(1, $null) }
                    Write-Verbose "Template '$effectiveName' committed to AD via COM."
                }

                Write-Output "Template '$effectiveName' imported successfully."
            }
        }
    }
}
