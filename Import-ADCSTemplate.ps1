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
    - Template DOES exist (same commonName in AD): compare the supported LDAP update attributes against
      the serialized source. If changed: apply in-place LDAP attribute update and
      advance the revision without downgrading. After create, update and no-op, independently verify
      the supported XML settings against fresh LDAP data. Differences terminate the import.

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

.PARAMETER PolicyRegistrations
    Optional companion objects from Export-ADCSTemplatePolicyRegistration / ConvertFrom-Json.
    Missing policy registrations are created via PSPKI before importing templates.
    Existing registrations must match. The executing context must remain unchanged throughout
    the PowerShell session, including before the first pkix.net use.

.PARAMETER PolicyRegistrationTimeoutSeconds
    Maximum wait per newly registered OID for visibility on Server. Default: 120 seconds.

.PARAMETER Domain
    Retained for compatibility. The configuration naming context is read from Server.

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
    Verification of Application Policies or Certificate Policies loads PSPKI on demand.
#>
. (Join-Path $PSScriptRoot 'TemplateVerification.ps1')
. (Join-Path $PSScriptRoot 'TemplateDirectory.ps1')
. (Join-Path $PSScriptRoot 'TemplatePolicyRegistration.ps1')

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
        [string]$Domain      = "",
        [object[]]$PolicyRegistrations = @(),
        [ValidateRange(1,3600)]
        [int]$PolicyRegistrationTimeoutSeconds = 120
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
            if ($null -eq $Bytes -or $Bytes.Length -ne 8) { throw 'Invalid stored AD interval.' }
            $intervals = [BitConverter]::ToInt64($Bytes, 0)
            if ($intervals -gt 0) { throw 'Invalid positive stored AD interval.' }
            -[decimal]$intervals / 10000000
        }
        #endregion
    }

    process {
        # -----------------------------------------------------------------------
        # Resolve target DC and domain
        # -----------------------------------------------------------------------
        $context = Get-TemplateDirectoryContext $Server
        $Server = $context.Server
        $ldapPrefix = "LDAP://$Server/"
        $tplBase = $context.TemplateBase

        # -----------------------------------------------------------------------
        # Parse XML
        # -----------------------------------------------------------------------
        [xml]$doc = Read-TemplatePolicyDocument $XmlString

        # Support single and multi-policy XML
        $policies = @($doc.GetPoliciesResponse.response.policies.policy | Where-Object { $null -ne $_ })
        if ($policies.Count -eq 0) {
            throw "No <policy> elements found in XML. Verify the XML is valid MS-XCEP output from Export-ADCSTemplate."
        }

        if ($Name -and $policies.Count -gt 1) {
            throw "The -Name parameter cannot be used when the XML contains multiple templates. Import each template separately or omit -Name."
        }

        if ($Version) {
            if ($Version -notmatch '^(\d+)\.(\d+)$') { throw 'Invalid -Version format; expected major.minor.' }
            foreach ($part in $Version.Split('.')) {
                [int]$parsed=0
                if (-not [int]::TryParse($part,[ref]$parsed) -or $parsed -lt 0) { throw 'Invalid -Version range.' }
            }
        }
        if ($Name -and ([string]::IsNullOrWhiteSpace($Name) -or $Name -match '["+,;<=>]')) { throw 'Invalid -Name.' }
        # Validate every policy before any writes (including extensions we cannot verify).
        $names = @{}
        foreach ($sourcePolicy in $policies) {
            $sourceName = [string]$sourcePolicy.attributes.commonName
            if (-not $sourceName -or $names.ContainsKey($sourceName)) { throw "Missing or duplicate template name '$sourceName'." }
            $names[$sourceName] = $true
            Assert-TemplatePolicyInput $doc $sourcePolicy
            $null = Get-TemplateXmlExpectation $doc $sourcePolicy ''
        }

        if ($PolicyRegistrations.Count) {
            $missingRegistrations = @(Get-TemplatePolicyRegistrationPlan $doc $PolicyRegistrations $context)
            foreach ($registration in $missingRegistrations) {
                if ($PSCmdlet.ShouldProcess("$($registration.OidGroup) '$($registration.Oid)' in $($context.ConfigurationNamingContext)", 'Register policy OID via PSPKI')) {
                    Register-TemplatePolicyRegistration $registration $context $PolicyRegistrationTimeoutSeconds
                } elseif (-not $WhatIfPreference) {
                    throw 'Policy registration was declined; template import stopped.'
                }
            }
        }

        # -----------------------------------------------------------------------
        # Process each policy
        # -----------------------------------------------------------------------
        foreach ($policy in $policies) {
            $searcher=$null; $tplEntry=$null; $pol=$null; $adwt=$null; $templates=@()
            try {
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
            $expected = Get-TemplateXmlExpectation $doc $policy $effectiveDisplay
            $searcher             = New-Object System.DirectoryServices.DirectorySearcher
            $searcher.SearchRoot  = [ADSI]"${ldapPrefix}${tplBase}"
            $escapedName = ConvertTo-TemplateLdapFilterValue $effectiveName
            $searcher.Filter      = "(&(objectClass=pKICertificateTemplate)(cn=$escapedName))"
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
                    privateKeyFlags  = @{ ldap = "msPKI-Private-Key-Flag";        xcep = (ConvertTo-TemplateInt32 $attrs.privateKeyFlags)  }
                    subjectNameFlags = @{ ldap = "msPKI-Certificate-Name-Flag";   xcep = (ConvertTo-TemplateInt32 $attrs.subjectNameFlags) }
                    enrollmentFlags  = @{ ldap = "msPKI-Enrollment-Flag";         xcep = (ConvertTo-TemplateInt32 $attrs.enrollmentFlags)  }
                    generalFlags     = @{ ldap = "flags";                         xcep = (ConvertTo-TemplateInt32 $attrs.generalFlags)     }
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

                if ($adValiditySec -ne $srcValiditySec) {
                    Write-Verbose "  Differs: pKIExpirationPeriod  AD=${adValiditySec}s  Src=${srcValiditySec}s"
                    $changedAttrs.Add("validity")
                }
                if ($adRenewalSec -ne $srcRenewalSec) {
                    Write-Verbose "  Differs: pKIOverlapPeriod  AD=${adRenewalSec}s  Src=${srcRenewalSec}s"
                    $changedAttrs.Add("renewal")
                }

                # Note: pKIExtendedKeyUsage, msPKI-Certificate-Application-Policy, and
                # pKICriticalExtensions are NOT written in the update path. Independent readback verification
                # below does compare them. These attributes
                # are set by the COM layer during CREATE and are not represented as separate
                # elements in the MS-XCEP XML — they are embedded in the extension blobs which
                # the COM interfaces parse internally. Differences cause verification failure and require a separate correction.

                if ([string]$tplEntry.Properties['displayName'].Value -cne $effectiveDisplay) { $changedAttrs.Add('displayName') }

                # Fail before mutating this template if a difference is outside the updater's scope.
                $current = Read-TemplateVerificationState $Server $tplBase $effectiveName
                $writable = @($intAttrMap.Values | ForEach-Object { $_.ldap }) + @('displayName','pKIExpirationPeriod','pKIOverlapPeriod','revision','msPKI-Template-Minor-Revision')
                $unsupported = @(Compare-TemplateVerificationState $expected $current | Where-Object { $_.Property -notin $writable })
                if ($unsupported.Count) {
                    $error = [InvalidOperationException]::new("Unsupported update differences for '$effectiveName'; nothing written to this template: " + (($unsupported | ForEach-Object { $_.Property }) -join ', '))
                    $error.Data['Differences'] = $unsupported
                    throw $error
                }

                # Version comparison
                $srcMajor = [int]$attrs.revision.majorRevision
                $srcMinor = [int]$attrs.revision.minorRevision
                $contentChanged = $changedAttrs.Count -gt 0
                $nextRevision = Get-TemplateUpdateRevision $adRevision $adMinor $srcMajor $srcMinor $contentChanged ([bool]$Version)
                $srcMajor = $nextRevision[0]; $srcMinor = $nextRevision[1]
                $expected['revision']=$srcMajor; $expected['msPKI-Template-Minor-Revision']=$srcMinor
                $versionChanged = ($srcMajor -ne $adRevision) -or ($srcMinor -ne $adMinor)

                if (-not $versionChanged -and -not $contentChanged) {
                    Assert-TemplateVerification $expected $Server $tplBase
                    Write-Output "Template '$effectiveName' is verified and already up to date (v$adRevision.$adMinor). No changes applied."
                    continue
                }

                $changeDesc = @()
                if ($versionChanged)  { $changeDesc += "version v$adRevision.$adMinor -> v$srcMajor.$srcMinor" }
                if ($contentChanged)  { $changeDesc += "$($changedAttrs.Count) attribute(s): $($changedAttrs -join ', ')" }

                if ($PSCmdlet.ShouldProcess("Template '$effectiveName'", "Update in AD ($($changeDesc -join '; '))")) {
                    if ($changedAttrs -contains 'displayName') {
                        $tplEntry.Properties['displayName'].Value = $effectiveDisplay
                    }
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
                    Assert-TemplateVerification $expected $Server $tplBase
                    Write-Output "Template '$effectiveName' updated and verified successfully ($($changeDesc -join '; '))."
                }
                continue
            }

            # -------------------------------------------------------------------
            # CREATE PATH: use COM
            # -------------------------------------------------------------------
            Write-Verbose "Template '$effectiveName' not found in AD. Creating via COM..."

            if ($PSCmdlet.ShouldProcess("Template '$effectiveName'", "Import to AD")) {
                # Import only this policy, not the entire multi-policy document again.
                [xml]$importDoc = $doc.OuterXml
                foreach ($other in @($importDoc.GetPoliciesResponse.response.policies.policy)) {
                    if ([string]$other.attributes.commonName -cne $effectiveName) { [void]$other.ParentNode.RemoveChild($other) }
                }
                # OuterXml may retain an input declaration. Match it to the actual byte encoding.
                if ($importDoc.FirstChild -is [System.Xml.XmlDeclaration]) {
                    $importDoc.FirstChild.Encoding = 'utf-8'
                }
                $encoder = New-Object System.Text.UTF8Encoding($false, $true)
                $bytes   = $encoder.GetBytes($importDoc.OuterXml)

                $pol = New-Object -ComObject X509Enrollment.CX509EnrollmentPolicyWebService
                $pol.InitializeImport($bytes)
                $templates = @($pol.GetTemplates())

                if ($templates.Count -ne 1) {
                    throw "COM did not return exactly one template from the isolated policy XML. Verify the XML is valid MS-XCEP output from Export-ADCSTemplate."
                }

                foreach ($template in $templates) {
                    $adwt = New-Object -ComObject X509Enrollment.CX509CertificateTemplateADWritable
                    $adwt.Initialize($template)
                    if ($Server) { $adwt.Commit(1, $Server) } else { $adwt.Commit(1, $null) }
                    Write-Verbose "Template '$effectiveName' committed to AD via COM."
                }

                Assert-TemplateVerification $expected $Server $tplBase
                Write-Output "Template '$effectiveName' imported and verified successfully."
            }
            } finally {
                if ($null -ne $tplEntry) { $tplEntry.Dispose() }
                if ($null -ne $searcher) { $searcher.SearchRoot.Dispose(); $searcher.Dispose() }
                foreach ($com in @($adwt) + @($templates) + @($pol)) {
                    if ($null -ne $com -and [Runtime.InteropServices.Marshal]::IsComObject($com)) { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($com) }
                }
            }
        }
    }
}

