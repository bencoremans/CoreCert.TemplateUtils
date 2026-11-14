function Invoke-TestBundleImport {
 [CmdletBinding(SupportsShouldProcess)]
 param([string]$XmlString,[string]$Server,[string]$Version,[string]$DisplayName,[object[]]$PolicyRegistrations=@())
 $args=@{}+$PSBoundParameters;$args.Remove('XmlString');$args.Remove('PolicyRegistrations')
 $args.JsonString=([ordered]@{FormatVersion=1;TemplateXml=$XmlString;PolicyRegistrations=@($PolicyRegistrations)}|ConvertTo-Json -Depth 8)
 Import-ADCSTemplate @args
}
# Executes the importer's control flow with explicit AD/COM test doubles.
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Export-Serialization.Tests.ps1')
. (Join-Path $PSScriptRoot '../TemplateVerification.ps1')
. (Join-Path $PSScriptRoot '../TemplateDirectory.ps1')
. (Join-Path $PSScriptRoot 'Import-Verification.Tests.ps1')
. (Join-Path $PSScriptRoot '../TemplateBundle.ps1')
$stub=New-Module -Name PSPKI -ScriptBlock {}; Import-Module $stub
try {
    $source=Get-Content (Join-Path $PSScriptRoot '../Import-ADCSTemplate.ps1') -Raw
    $source=$source.Replace(". (Join-Path `$PSScriptRoot 'TemplateVerification.ps1')",'').Replace(". (Join-Path `$PSScriptRoot 'TemplateDirectory.ps1')",'')
    $source=$source.Replace(". (Join-Path `$PSScriptRoot 'TemplatePolicyRegistration.ps1')",'')
    $start=$source.IndexOf('        if ('); $end=$source.IndexOf('        #region Helper:', $start)
    $source=$source.Remove($start,$end-$start).Replace('[ADSI]','[object]')
    $source=$source.Replace('$searcher.SearchRoot.Dispose();', '')
    $source=$source.Replace('$rootDse = [object]"LDAP://$Server/RootDSE"','$rootDse = New-TestRoot')
    . ([scriptblock]::Create($source))
    function Get-TemplateDirectoryContext { param($Server); [pscustomobject]@{Server=$Server; TemplateBase='CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=forest,DC=test'} }
    function New-TestRoot {
        $o=[pscustomobject]@{configurationNamingContext='CN=Configuration,DC=forest,DC=test'}
        $o | Add-Member ScriptMethod Dispose {}; return $o
    }
    $script:writes=0; $script:verifications=0; $script:existing=$null; $script:fail=$false
    $script:policyCounts=@()
    function Assert-TemplateVerification {
        param($Expected,$Server,$TemplateBase)
        $script:verifications++
        $script:lastExpected=$Expected
        Assert-Equal $Server 'dc.child.test' 'Verify on commit DC'
        Assert-Equal $TemplateBase 'CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=forest,DC=test' 'Forest configuration context'
        if ($script:fail) { throw 'Verification failed (test double)' }
    }
    # Dedicated reconciliation suite tests the real create verification path.
    function Complete-TemplateCreateVerification { param($Expected,$Server,$TemplateBase); Assert-TemplateVerification $Expected $Server $TemplateBase }
    function New-Object {
        param([Parameter(Position=0)][string]$TypeName, [Parameter(Position=1)][object[]]$ArgumentList, [string]$ComObject)
        if ($TypeName -eq 'System.DirectoryServices.DirectorySearcher') {
            $o=[pscustomobject]@{SearchRoot=$null;Filter=$null;SearchScope=$null}
            $o | Add-Member ScriptMethod FindOne { return $script:existing }; $o | Add-Member ScriptMethod Dispose {}; return $o
        }
        if ($ComObject -eq 'X509Enrollment.CX509EnrollmentPolicyWebService') {
            $o=[pscustomobject]@{Document=$null}
            $o | Add-Member ScriptMethod InitializeImport {
                param($bytes)
                $this.Document=[xml][Text.Encoding]::UTF8.GetString($bytes)
                $script:policyCounts+=@($this.Document.GetPoliciesResponse.response.policies.policy).Count
            }
            $o | Add-Member ScriptMethod GetTemplates { [pscustomobject]@{Name=$this.Document.GetPoliciesResponse.response.policies.policy.attributes.commonName} }
            return $o
        }
        if ($ComObject -eq 'X509Enrollment.CX509CertificateTemplateADWritable') {
            $o=[pscustomobject]@{}
            $o | Add-Member ScriptMethod Initialize { param($template) }
            $o | Add-Member ScriptMethod Commit { param($flag,$server); Assert-Equal $server 'dc.child.test' 'Commit DC'; $script:writes++ }
            return $o
        }
        Microsoft.PowerShell.Utility\New-Object -TypeName $TypeName -ArgumentList $ArgumentList
    }
    $first=New-Fixture; $second=New-Fixture
    $second.templatePSPKI.Name='Second'; $second.templateADO.Name='Second'
    $second.templatePSPKI.OID=[Security.Cryptography.Oid]::new('1.2.3.4.6','Second')
    $xml=ConvertTo-TemplateXml @($first,$second)
    $result=@(Invoke-TestBundleImport $xml -Server dc.child.test)
    Assert-Equal $script:writes 2 'Two isolated commits'
    Assert-Equal $script:verifications 2 'Each created template verified'
    Assert-Equal ($script:policyCounts -join ',') '1,1' 'One policy per COM import'
    Assert-Equal $result.Count 2 'Only verified successes'
    $script:writes=0; $script:verifications=0
    Invoke-TestBundleImport $xml -Server dc.child.test -WhatIf | Out-Null
    Assert-Equal $script:writes 0 'WhatIf never writes'
    Assert-Equal $script:verifications 0 'WhatIf does not assert a creation'
    $script:fail=$true; $success=[Collections.Generic.List[object]]::new()
    Assert-Throws { Invoke-TestBundleImport (ConvertTo-TemplateXml $first) -Server dc.child.test | ForEach-Object { $success.Add($_) } } '*Verification failed*'
    Assert-Equal $success.Count 0 'No false success after failed readback'
    $script:fail=$false
    # Existing template entry contains exactly the fields supported by the updater.
    [xml]$doc=ConvertTo-TemplateXml $first
    $expected=Get-TemplateXmlExpectation $doc $doc.GetPoliciesResponse.response.policies.policy.attributes.ParentNode 'Test & <TLS> café'
    $properties=@{}
    foreach ($key in $expected.Keys) {
        $value=$expected[$key]
        if ($key -in @('pKIExpirationPeriod','pKIOverlapPeriod')) { $value=[Convert]::FromBase64String($value) }
        $item=[pscustomobject]@{Value=$value}
        $item | Add-Member ScriptMethod Clear { $this.Value=$null }
        $item | Add-Member ScriptMethod Add { param($v); $this.Value=$v }
        $properties[$key]=$item
    }
    $entry=[pscustomobject]@{Properties=$properties}
    $entry | Add-Member ScriptMethod Dispose {}
    $entry | Add-Member ScriptMethod CommitChanges { $script:writes++ }
    $script:testEntry=$entry
    $script:existing=[pscustomobject]@{}
    $script:existing | Add-Member ScriptMethod GetDirectoryEntry { return $script:testEntry }
    function Read-TemplateVerificationState { New-ActualFixture }
    $script:writes=0; $script:verifications=0
    Invoke-TestBundleImport (ConvertTo-TemplateXml $first) -Server dc.child.test | Out-Null
    Assert-Equal $script:writes 0 'No-op does not write'
    Assert-Equal $script:verifications 1 'No-op verifies untouched fields too'
    $script:fail=$true
    Assert-Throws { Invoke-TestBundleImport (ConvertTo-TemplateXml $first) -Server dc.child.test } '*Verification failed*'
    $script:fail=$false; $script:verifications=0
    $entry.Properties['msPKI-Minimal-Key-Size'].Value=2048
    Invoke-TestBundleImport (ConvertTo-TemplateXml $first) -Server dc.child.test | Out-Null
    Assert-Equal $script:writes 1 'Changed key size writes'
    Assert-Equal $script:verifications 1 'Update verifies after commit'
    Assert-Equal $entry.Properties['msPKI-Minimal-Key-Size'].Value 4096 'Update applied'
    Assert-Equal $script:lastExpected['msPKI-Template-Minor-Revision'] 3 'Verify bumped revision'
    $script:writes=0
    Invoke-TestBundleImport (ConvertTo-TemplateXml $first) -Server dc.child.test | Out-Null
    Assert-Equal $script:writes 0 'Repeat import does not downgrade or increment again'
    Invoke-TestBundleImport (ConvertTo-TemplateXml $first) -Server dc.child.test -DisplayName 'Renamed' | Out-Null
    Assert-Equal $entry.Properties['displayName'].Value 'Renamed' 'Display override saved'
    Assert-Equal $script:lastExpected['msPKI-Template-Minor-Revision'] 4 'Display change advances revision'
    $script:writes=0
    function Read-TemplateVerificationState { $a=New-ActualFixture; $a['pKIExtendedKeyUsage']=@('1.2.3'); return $a }
    Assert-Throws { Invoke-TestBundleImport (ConvertTo-TemplateXml $first) -Server dc.child.test } '*Unsupported update differences*'
    Assert-Equal $script:writes 0 'Unsupported differences do not partially write'
    $script:existing=$null; $script:writes=0
    [xml]$bad=ConvertTo-TemplateXml @($first,$second)
    $bad.GetPoliciesResponse.response.policies.policy[1].attributes.revision.minorRevision='bad'
    Assert-Throws { Invoke-TestBundleImport $bad.OuterXml -Server dc.child.test } '*Invalid nonnegative*'
    Assert-Equal $script:writes 0 'Invalid second policy stops first write'
    Assert-Throws { Invoke-TestBundleImport $xml -Server dc.child.test -Version '999999999999.0' } '*Invalid -Version range*'
    Assert-Equal $script:writes 0 'Invalid version stops all writes'
    # Registration must complete before any COM commit, and WhatIf must not register.
    $script:registrationCalls=0; $script:registrationFailure=$false
    function Get-TemplatePolicyRegistrationPlan { param($Document,$Registrations,$Context); $Registrations }
    function Register-TemplatePolicyRegistration {
        param($Registration,$Context,$TimeoutSeconds)
        Assert-Equal $script:writes 0 'Registration before template writes'
        $script:registrationCalls++
        if ($script:registrationFailure) { throw 'Policy replication timeout (test double)' }
    }
    $metadata=[pscustomobject]@{Oid='1.2.3.4';OidGroup='ApplicationPolicy';FriendlyName='Custom'}
    $policyOids=[Security.Cryptography.OidCollection]::new()
    [void]$policyOids.Add([Security.Cryptography.Oid]::new('1.2.3.4'))
    $first.templatePSPKI.Settings.Extensions+=[Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($policyOids,$false)
    $xml=ConvertTo-TemplateXml @($first,$second)
    Invoke-TestBundleImport $xml -Server dc.child.test -PolicyRegistrations @($metadata) -WhatIf | Out-Null
    Assert-Equal $script:registrationCalls 0 'WhatIf does not register policies'
    Assert-Equal $script:writes 0 'WhatIf with metadata does not commit templates'
    $script:registrationFailure=$true
    Assert-Throws { Invoke-TestBundleImport $xml -Server dc.child.test -PolicyRegistrations @($metadata) } '*Policy replication timeout*'
    Assert-Equal $script:writes 0 'Failed registration prevents all template commits'
    $script:registrationFailure=$false
    Invoke-TestBundleImport $xml -Server dc.child.test -PolicyRegistrations @($metadata) | Out-Null
    Assert-Equal $script:writes 2 'Templates committed after registration succeeds'
    'PASS: import control flow tests'  
} finally { Remove-Module $stub; Remove-Item Function:New-Object -ErrorAction SilentlyContinue }
