# Offline regression tests. No AD, CertEnroll or installed PSPKI required.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '../Export-ADCSTemplate.ps1')
$stub = New-Module -Name PSPKI -ScriptBlock {}
Import-Module $stub
function Assert-Equal($Actual, $Expected, $Message) {
    if ($Actual -cne $Expected) { throw "$Message; actual=[$Actual], expected=[$Expected]" }
}
function Assert-Throws([scriptblock]$Action, [string]$Pattern) {
    try { & $Action | Out-Null } catch {
        if ($_.Exception.Message -notlike $Pattern) { throw }
        return
    }
    throw "Expected error: $Pattern"
}
function New-Fixture {
    $crypto = [pscustomobject]@{
        MinimalKeyLength = 4096; KeySpec = 1; CNGKeyUsage = 3
        PrivateKeySecuritySDDL = 'D:(A;;GA;;;SY)'
        KeyAlgorithm = [Security.Cryptography.Oid]::new('1.2.840.113549.1.1.1', 'RSA')
        HashAlgorithm = [Security.Cryptography.Oid]::new('2.16.840.1.101.3.4.2.1', 'SHA256')
        CSPList = @('Provider & <test>', 'Utimaco test provider')
    }
    @{
        templatePSPKI = [pscustomobject]@{
            Name = 'TestTemplate'; DisplayName = 'Test & <TLS> café'
            OID = [Security.Cryptography.Oid]::new('1.2.3.4.5', 'Test')
            SchemaVersion = 4; Version = '100.2'
            Settings = [pscustomobject]@{
                Cryptography = $crypto
                # Deliberately unusable display strings: export must use AD intervals.
                ValidityPeriod = 'localized display'; RenewalPeriod = 'localized display'
                SupersededTemplates = @('Old & <template>')
                RegistrationAuthority = [pscustomobject]@{ SignatureCount = 0 }
                KeyArchivalSettings = [pscustomobject]@{ KeyArchival = $false }
                SubjectName = 1; EnrollmentOptions = 0; GeneralFlags = 0
                Extensions = @([pscustomobject]@{
                    Oid = [Security.Cryptography.Oid]::new('2.5.29.15', 'Key & Usage')
                    Critical = $true; RawData = [byte[]]@(3,2,5,160)
                })
            }
        }
        templateADO = [pscustomobject]@{
            Name = 'TestTemplate'; 'msPKI-Private-Key-Flag' = 101056768
            pKIExpirationPeriod = [BitConverter]::GetBytes([long]-26784010000000)
            pKIOverlapPeriod = [BitConverter]::GetBytes([long]-123450000000)
        }
    }
}
try {
    $f = New-Fixture
    $output = @(Export-ADCSTemplate $f)
    Assert-Equal $output.Count 1 'Export must return one string'
    [xml]$doc = $output[0]
    $a = $doc.GetPoliciesResponse.response.policies.policy.attributes
    Assert-Equal $a.certificateValidity.validityPeriodSeconds '2678401' 'Exact validity'
    Assert-Equal $a.certificateValidity.renewalPeriodSeconds '12345' 'Exact renewal'
    Assert-Equal $a.privateKeyFlags '101056768' 'Raw flags'
    Assert-Equal $a.privateKeyAttributes.minimalKeyLength '4096' 'Key size'
    Assert-Equal $a.privateKeyAttributes.cryptoProviders.provider[0] 'Provider & <test>' 'Escaped provider'
    Assert-Equal $a.supersededPolicies.commonName 'Old & <template>' 'Escaped supersedence'
    Assert-Equal $doc.GetPoliciesResponse.oIDs.oID[0].defaultName 'Test & <TLS> café' 'Unicode display name'
    Assert-Equal $a.extensions.extension.value 'AwIFoA==' 'Extension bytes'
    Assert-Equal $a.extensions.extension.critical 'true' 'Extension criticality'
    $encoded = [Text.UTF8Encoding]::new($false, $true).GetBytes($doc.OuterXml)
    [xml]$decoded = [Text.Encoding]::UTF8.GetString($encoded)
    Assert-Equal $decoded.GetPoliciesResponse.oIDs.oID[0].defaultName 'Test & <TLS> café' 'UTF-8 round trip'
    [xml]$multi = Export-ADCSTemplate @($f, (New-Fixture))
    Assert-Equal @($multi.GetPoliciesResponse.response.policies.policy).Count 2 'Multiple policies'
    $f.templatePSPKI.Settings.Cryptography | Add-Member ProviderList @('Preferred provider')
    [xml]$doc = Export-ADCSTemplate $f
    Assert-Equal $doc.GetPoliciesResponse.response.policies.policy.attributes.privateKeyAttributes.cryptoProviders.provider 'Preferred provider' 'ProviderList preference'
    $f = New-Fixture
    $f.templatePSPKI.Settings.Cryptography.CSPList = @()
    [xml]$doc = Export-ADCSTemplate $f
    Assert-Equal $doc.GetPoliciesResponse.response.policies.policy.attributes.privateKeyAttributes.cryptoProviders.GetAttribute('nil', 'http://www.w3.org/2001/XMLSchema-instance') 'true' 'Explicit empty providers'
    $f.templatePSPKI.Settings.Cryptography.PSObject.Properties.Remove('CSPList')
    Assert-Throws { Export-ADCSTemplate $f } '*neither ProviderList nor CSPList*'
    $f = New-Fixture
    $f.templateADO.pKIExpirationPeriod = [BitConverter]::GetBytes([long]-10000001)
    Assert-Throws { Export-ADCSTemplate $f } '*refusing to round*'
    $f = New-Fixture
    $f.templateADO.PSObject.Properties.Remove('pKIOverlapPeriod')
    Assert-Throws { Export-ADCSTemplate $f } '*Missing AD attribute*'
    $f = New-Fixture
    $f.templateADO.Name = 'WrongTemplate'
    Assert-Throws { Export-ADCSTemplate $f } '*names differ*'
    $f = New-Fixture
    $f.templateADO.PSObject.Properties.Remove('msPKI-Private-Key-Flag')
    Assert-Throws { Export-ADCSTemplate $f } '*Missing AD msPKI-Private-Key-Flag*'
    $f = New-Fixture
    $f.templatePSPKI.Settings.Cryptography.PSObject.Properties.Remove('HashAlgorithm')
    Assert-Throws { Export-ADCSTemplate $f } '*Missing PSPKI cryptography property*'
    $f = New-Fixture
    $f.templatePSPKI.DisplayName = "Invalid$([char]1)name"
    Assert-Throws { Export-ADCSTemplate $f } '*'
    'PASS: export serialization regression tests'
} finally {
    Remove-Module $stub
}
