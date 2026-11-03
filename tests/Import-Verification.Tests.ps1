# Offline behavioral tests; run with PowerShell 5.1+ (no AD or CertEnroll needed).
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Export-Serialization.Tests.ps1')
. (Join-Path $PSScriptRoot '../TemplateVerification.ps1')
$stub = New-Module -Name PSPKI -ScriptBlock {}
Import-Module $stub
function New-ActualFixture {
    @{
        cn='TestTemplate'; displayName='Test & <TLS> café'; revision=100
        'msPKI-Template-Minor-Revision'=2; 'msPKI-Template-Schema-Version'=4
        'msPKI-Private-Key-Flag'=101056768; 'msPKI-Certificate-Name-Flag'=1
        'msPKI-Enrollment-Flag'=0; flags=0; pKIDefaultKeySpec=1; 'msPKI-Minimal-Key-Size'=4096
        pKIExpirationPeriod=[BitConverter]::GetBytes([long]-26784010000000)
        pKIOverlapPeriod=[BitConverter]::GetBytes([long]-123450000000)
        'msPKI-Supersede-Templates'=@('Old & <template>')
        pKIDefaultCSPs=@('2,Utimaco test provider','1,Provider & <test>')
        'msPKI-RA-Application-Policies'='msPKI-Asymmetric-Algorithm`PZPWSTR`RSA`msPKI-Hash-Algorithm`PZPWSTR`SHA256`msPKI-Key-Usage`DWORD`3`msPKI-Key-Security-Descriptor`PZPWSTR`D:(A;;GA;;;SY)`'
        pKIKeyUsage=[byte[]]@(160,0); pKICriticalExtensions=@('2.5.29.15')
    }
}
try {
    [xml]$doc = Export-ADCSTemplate (New-Fixture)
    $policy = $doc.GetPoliciesResponse.response.policies.policy
    $expected = Get-TemplateXmlExpectation $doc $policy 'Test & <TLS> café'
    $actual = New-ActualFixture
    $diff = @(Compare-TemplateVerificationState $expected $actual)
    if ($diff.Count) { throw ($diff | ConvertTo-Json -Depth 5) }
    # Reproduces a save that silently resets a 4096-bit template to 2048 bits.
    $actual['msPKI-Minimal-Key-Size'] = 2048
    $diff = @(Compare-TemplateVerificationState $expected $actual)
    Assert-Equal $diff.Count 1 'Detect reset'
    Assert-Equal $diff[0].Property 'msPKI-Minimal-Key-Size' 'Reset field'
    Assert-Equal $diff[0].Expected 4096 'Expected value'
    Assert-Equal $diff[0].Actual 2048 'Actual value'
    $actual = New-ActualFixture
    $actual.pKIOverlapPeriod=[BitConverter]::GetBytes([long]-123460000000)
    Assert-Equal @(Compare-TemplateVerificationState $expected $actual).Count 1 'One second drift'
    $actual = New-ActualFixture; $actual.Remove('msPKI-Minimal-Key-Size')
    Assert-Equal @(Compare-TemplateVerificationState $expected $actual).Count 1 'Missing required value'
    $actual = New-ActualFixture; $actual.pKICriticalExtensions=@()
    Assert-Equal @(Compare-TemplateVerificationState $expected $actual).Count 1 'Criticality drift'
    $actual = New-ActualFixture; $actual.pKIDefaultCSPs=@('1,Utimaco test provider','2,Provider & <test>')
    Assert-Equal @(Compare-TemplateVerificationState $expected $actual).Count 1 'Provider priority drift'
    $actual = New-ActualFixture; $actual['msPKI-RA-Application-Policies']=$actual['msPKI-RA-Application-Policies'].Replace('SHA256','SHA1')
    Assert-Equal @(Compare-TemplateVerificationState $expected $actual).Count 1 'Hash drift'
    $actual = New-ActualFixture; $actual['msPKI-Certificate-Application-Policy']=@('1.2.3')
    Assert-Equal @(Compare-TemplateVerificationState $expected $actual).Count 1 'Unexpected application policy'
    $actual = New-ActualFixture; $actual['msPKI-RA-Application-Policies']='bad`metadata'
    Assert-Throws { Compare-TemplateVerificationState $expected $actual } '*Malformed*'
    Assert-Equal (ConvertTo-TemplateInt32 '2147483648') ([int]::MinValue) 'High-bit subject flag'
    Assert-Equal (ConvertTo-TemplateLdapFilterValue 'A*(B)\C') 'A\2a\28B\29\5cC' 'LDAP escaping'
    # Sequence of policy information containing OID 1.2.3.4.
    Assert-Throws { Read-TemplatePolicyOids ([byte[]]@(48,9,48,7,6,3,42,3,4,48,0)) } '*qualifiers cannot be verified*'
    Assert-Throws { Read-TemplatePolicyOids ([byte[]]@(48,10,48,5,6,3,42,3,4)) } '*Truncated*'
    $attrs=$policy.attributes; $attrs.RemoveChild($attrs.SelectSingleNode('*[local-name()="privateKeyFlags"]')) | Out-Null
    Assert-Throws { Get-TemplateXmlExpectation $doc $policy '' } '*Missing required*'
    [xml]$doc = Export-ADCSTemplate (New-Fixture)
    $doc.GetPoliciesResponse.oIDs.oID[-1].value='1.2.3.999'
    Assert-Throws { Get-TemplateXmlExpectation $doc $doc.GetPoliciesResponse.response.policies.policy '' } '*cannot be verified*'
    # Verify the error carries a machine-readable diff and the reader uses the pinned DC.
    function Read-TemplateVerificationState {
        param($Server,$TemplateBase,$Name)
        Assert-Equal $Server 'dc.example.test' 'Pinned DC'
        Assert-Equal $Name 'TestTemplate' 'Read name'
        $a=New-ActualFixture; $a['msPKI-Minimal-Key-Size']=2048; return $a
    }
    try { Assert-TemplateVerification $expected 'dc.example.test' 'CN=Templates'; throw 'No verification error' }
    catch {
        if ($_.Exception.Message -notlike '*Verification failed*') { throw }
        Assert-Equal $_.Exception.Data['Differences'][0].Property 'msPKI-Minimal-Key-Size' 'Structured diff'
    }
    'PASS: import verification comparison tests'
} finally { Remove-Module $stub }
