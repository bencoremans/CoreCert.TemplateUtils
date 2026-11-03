# Uses the actual pkix.net extension classes. LibraryPath allows offline DLL testing.
param([string]$LibraryPath)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Export-Serialization.Tests.ps1')
. (Join-Path $PSScriptRoot '../TemplateVerification.ps1')
if ($LibraryPath) {
    Add-Type -Path (Join-Path $LibraryPath 'SysadminsLV.Asn1Parser.dll')
    Add-Type -Path (Join-Path $LibraryPath 'SysadminsLV.PKI.dll')
    Import-Module (New-Module -Name PSPKI -ScriptBlock {})
} elseif (Get-Module -ListAvailable -Name PSPKI) {
    Import-Module PSPKI
} else {
    'SKIP: policy round trip requires PSPKI or -LibraryPath'
    return
}

$fixture = New-Fixture
$applicationOid = '1.3.6.1.4.1.311.21.10'
$eku = [Security.Cryptography.OidCollection]::new()
[void]$eku.Add([Security.Cryptography.Oid]::new('1.2.3.4'))
$fixture.templatePSPKI.Settings.Extensions += [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($eku, $false)
# Simulate the application policy synthesized from the EKU list by PSPKI.
$fixture.templatePSPKI.Settings.Extensions += [SysadminsLV.PKI.Cryptography.X509Certificates.X509ApplicationPoliciesExtension]::new($eku, $false)
$fixture.templateADO | Add-Member NoteProperty 'msPKI-Certificate-Application-Policy' @('1.2.3.5', '1.2.3.6')
$fixture.templateADO | Add-Member NoteProperty pKICriticalExtensions @('2.5.29.15', $applicationOid)

function Get-PolicyExpectation($Template) {
    [xml]$doc = Export-ADCSTemplate $Template
    Get-TemplateXmlExpectation $doc $doc.GetPoliciesResponse.response.policies.policy $Template.templatePSPKI.DisplayName
}
$expected = Get-PolicyExpectation $fixture
Assert-Equal ($expected['pKIExtendedKeyUsage'] -join ',') '1.2.3.4' 'EKU retained'
Assert-Equal ($expected['msPKI-Certificate-Application-Policy'] -join ',') '1.2.3.5,1.2.3.6' 'Independent application policies retained'
Assert-Equal ($applicationOid -in $expected['pKICriticalExtensions']) $true 'Criticality from LDAP'
$policyExpectation = @{
    pKIExtendedKeyUsage = $expected['pKIExtendedKeyUsage']
    'msPKI-Certificate-Application-Policy' = $expected['msPKI-Certificate-Application-Policy']
}
$actual = @{
    pKIExtendedKeyUsage = @('1.2.3.4')
    'msPKI-Certificate-Application-Policy' = @('1.2.3.6', '1.2.3.5')
}
Assert-Equal @(Compare-TemplateVerificationState $policyExpectation $actual).Count 0 'Independent LDAP lists match'
$actual['msPKI-Certificate-Application-Policy'] = @('1.2.3.4')
$differences = @(Compare-TemplateVerificationState $policyExpectation $actual)
Assert-Equal $differences.Count 1 'EKU copied into Application Policies is detected'
Assert-Equal $differences[0].Property 'msPKI-Certificate-Application-Policy' 'Only the changed policy list differs'
$fixture.templateADO.PSObject.Properties.Remove('msPKI-Certificate-Application-Policy')
$expected = Get-PolicyExpectation $fixture
Assert-Equal $expected['msPKI-Certificate-Application-Policy'].Count 0 'Missing AD policy does not copy EKUs'
Assert-Equal (Read-TemplatePolicyOids ([byte[]]@(48,7,48,5,6,3,42,3,4)) '2.5.29.32') '1.2.3.4' 'Certificate policy decoded'
'PASS: policy extension round trip with pkix.net'
