
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
    - Template DOES exist (same commonName in AD): compare key LDAP attributes against
      the serialized source. If changed: apply in-place LDAP attribute update and
      increment revision. If identical: skip (no-op).

    Optionally override Name and DisplayName on import to deploy the same base template
    under a different name per customer or forest.

.PARAMETER XmlString
    MS-XCEP XML string produced by Export-ADCSTemplate.

.PARAMETER Name
    Optional. Override the template CN on import.

.PARAMETER DisplayName
    Optional. Override the display name. Defaults to Name if not specified.

.PARAMETER Server
    Optional. Target DC FQDN. Defaults to nearest writable DC.

.EXAMPLE
    $t = @{
        templatePSPKI = Get-CertificateTemplate -Name "CC-WebServer"
        templateADO   = Get-ADCSTemplate        -Name "CC-WebServer"
    }
    $xml = Export-ADCSTemplate -Template $t
    Import-ADCSTemplate -XmlString $xml

.EXAMPLE
    # Multi-tenant: same XML, different name per customer
    Import-ADCSTemplate -XmlString $xml -Name "ACME-WebServer" -DisplayName "ACME Web Server" -Server "dc01.acme.com"

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
        [string]$Server      = ""
    )

    begin {
        if (
            [Environment]::OSVersion.Version.Major -lt 6 -or
            ([Environment]::OSVersion.Version.Major -eq 6 -and [Environment]::OSVersion.Version.Minor -lt 1)
        ) { throw [System.PlatformNotSupportedException]"Requires Windows Server 2008 R2 / Windows 7 or newer." }
    }

    process {
        # -----------------------------------------------------------------------
        # Resolve target DC
        # -----------------------------------------------------------------------
        if (-not $Server) {
            if (Get-Command Get-ADDomainController -ErrorAction SilentlyContinue) {
                try {
                    $Server = (Get-ADDomainController -Discover -Writable -ErrorAction Stop).HostName[0]
                } catch {
                    Write-Verbose "DC discovery failed: $($_.Exception.Message)"
                }
            }
        }

        # -----------------------------------------------------------------------
        # Parse XML and apply Name / DisplayName overrides
        # -----------------------------------------------------------------------
        [xml]$doc = $XmlString

        $originalName = $doc.GetPoliciesResponse.response.policies.policy.attributes.commonName
        $effectiveName = if ($Name) { $Name } else { $originalName }
        $effectiveDisplay = if ($DisplayName) { $DisplayName } elseif ($Name) { $Name } else {
            ($doc.GetPoliciesResponse.oIDs.oID | Where-Object { $_.group -eq "9" } | Select-Object -First 1).defaultName
        }

        if ($Name -and $Name -ne $originalName) {
            Write-Verbose "Name override: '$originalName' -> '$Name'"
            $doc.GetPoliciesResponse.response.policies.policy.attributes.commonName = $Name
        }

        # Always update the OID group=9 displayName and mint a new OID
        # to prevent CRYPT_E_EXISTS when source OID is already registered in AD
        $doc.GetPoliciesResponse.oIDs.oID | ForEach-Object {
            if ($_.group -eq "9") {
                $_.defaultName = $effectiveDisplay
                $a = Get-Random -Min 1000000 -Max 9999999
                $b = Get-Random -Min 1000000 -Max 9999999
                $_.value = "1.3.6.1.4.1.311.21.8.$a.$b"
                Write-Verbose "DisplayName set to '$effectiveDisplay', new OID minted: $($_.value)"
            }
        }

        # -----------------------------------------------------------------------
        # Check if template already exists in AD
        # -----------------------------------------------------------------------
        $ldapPrefix = if ($Server) { "LDAP://$Server/" } else { "LDAP://" }
        $rootDse    = if ($Server) { [ADSI]"LDAP://$Server/RootDSE" } else { [ADSI]"LDAP://RootDSE" }
        $domain     = $rootDse.defaultNamingContext
        $tplBase    = "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$domain"

        $searcher             = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.SearchRoot  = [ADSI]"${ldapPrefix}${tplBase}"
        $searcher.Filter      = "(cn=$effectiveName)"
        $searcher.SearchScope = "OneLevel"
        $existingTemplate     = $searcher.FindOne()

        # -----------------------------------------------------------------------
        # UPDATE PATH
        # -----------------------------------------------------------------------
        if ($existingTemplate) {
            Write-Verbose "Template '$effectiveName' already exists in AD. Comparing attributes..."

            $tplEntry   = $existingTemplate.GetDirectoryEntry()
            $adRevision = [int]$tplEntry.Properties["revision"].Value
            $adMinor    = [int]$tplEntry.Properties["msPKI-Template-Minor-Revision"].Value

            $attrs = $doc.GetPoliciesResponse.response.policies.policy.attributes

            $attrMap = @{
                privateKeyFlags  = @{ ldap = "msPKI-Private-Key-Flag";        xcep = [int]$attrs.privateKeyFlags  }
                subjectNameFlags = @{ ldap = "msPKI-Certificate-Name-Flag";   xcep = [int]$attrs.subjectNameFlags }
                enrollmentFlags  = @{ ldap = "msPKI-Enrollment-Flag";         xcep = [int]$attrs.enrollmentFlags  }
                generalFlags     = @{ ldap = "flags";                         xcep = [int]$attrs.generalFlags     }
                policySchema     = @{ ldap = "msPKI-Template-Schema-Version"; xcep = [int]$attrs.policySchema     }
            }

            $changedAttrs = [System.Collections.Generic.List[string]]::new()
            foreach ($key in $attrMap.Keys) {
                $adVal  = [int]$tplEntry.Properties[$attrMap[$key].ldap].Value
                $srcVal = $attrMap[$key].xcep
                if ($adVal -ne $srcVal) {
                    Write-Verbose "  Differs: $($attrMap[$key].ldap)  AD=$adVal  Src=$srcVal"
                    $changedAttrs.Add($key)
                }
            }

            $srcMajor = [int]$attrs.revision.majorRevision
            $srcMinor = [int]$attrs.revision.minorRevision

            $versionChanged = ($srcMajor -ne $adRevision) -or ($srcMinor -ne $adMinor)
            $contentChanged = $changedAttrs.Count -gt 0

            if (-not $versionChanged -and -not $contentChanged) {
                Write-Output "Template '$effectiveName' is already up to date (v$adRevision.$adMinor). No changes applied."
                return
            }

            $changeDesc = @()
            if ($versionChanged) { $changeDesc += "version v$adRevision.$adMinor -> v$srcMajor.$srcMinor" }
            if ($contentChanged) { $changeDesc += "$($changedAttrs.Count) attribute(s): $($changedAttrs -join ', ')" }

            if ($PSCmdlet.ShouldProcess("Template '$effectiveName'", "Update in AD ($($changeDesc -join '; '))")) {
                foreach ($key in $changedAttrs) {
                    $ldapAttr = $attrMap[$key].ldap
                    $tplEntry.Properties[$ldapAttr].Clear()
                    $tplEntry.Properties[$ldapAttr].Add($attrMap[$key].xcep) | Out-Null
                }
                $tplEntry.Properties["revision"].Clear()
                $tplEntry.Properties["revision"].Add($srcMajor) | Out-Null
                $tplEntry.Properties["msPKI-Template-Minor-Revision"].Clear()
                $tplEntry.Properties["msPKI-Template-Minor-Revision"].Add($srcMinor) | Out-Null
                $tplEntry.CommitChanges()
                Write-Output "Template '$effectiveName' updated successfully ($($changeDesc -join '; '))."
            }
            return
        }

        # -----------------------------------------------------------------------
        # CREATE PATH: use COM
        # -----------------------------------------------------------------------
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

            $imported = 0
            foreach ($template in $templates) {
                $adwt = New-Object -ComObject X509Enrollment.CX509CertificateTemplateADWritable
                $adwt.Initialize($template)
                if ($Server) { $adwt.Commit(1, $Server) } else { $adwt.Commit(1, $null) }
                Write-Verbose "Template committed to AD via COM."
                $imported++
            }

            Write-Output "$imported template(s) imported successfully."
        }
    }
}
