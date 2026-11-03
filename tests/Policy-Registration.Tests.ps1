$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Export-Serialization.Tests.ps1')
. (Join-Path $PSScriptRoot '../TemplatePolicyRegistration.ps1')
$script:context = [pscustomobject]@{ Server='dc.target'; ConfigurationNamingContext='CN=Configuration,DC=target'; OidBase='CN=OID,test' }
$script:implicit = $context.ConfigurationNamingContext
$script:entries = @()
$script:reads = 0
function Get-TemplateImplicitConfiguration { $script:implicit }
function Get-TemplateDirectoryContext { $script:context }
function Read-TemplatePolicyRegistration { param($Context,$Oid); $script:reads++; $script:entries }
Import-Module (New-Module -Name PSPKI -ScriptBlock {})
$fixture = New-Fixture
$oids = [Security.Cryptography.OidCollection]::new()
[void]$oids.Add([Security.Cryptography.Oid]::new('1.2.3.4'))
$fixture.templatePSPKI.Settings.Extensions += [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($oids,$false)
[xml]$doc = Export-ADCSTemplate $fixture
$registration = [pscustomobject]@{ Oid='1.2.3.4'; OidGroup='ApplicationPolicy'; FriendlyName='Custom policy' }
function New-Entry($Flags=3,$Name='Custom policy') {
    [pscustomobject]@{ Values=@{ 'msPKI-Cert-Template-OID'='1.2.3.4'; flags=$Flags; displayName=$Name } }
}
Assert-Equal @(Get-TemplatePolicyRegistrationPlan $doc @($registration) $context).Count 1 'Missing registration planned'
$script:implicit = 'CN=Configuration,DC=other'
Assert-Throws { Get-TemplatePolicyRegistrationPlan $doc @($registration) $context } '*differs from target*'
$script:implicit = $context.ConfigurationNamingContext
$script:entries = @(New-Entry)
Assert-Equal @(Get-TemplatePolicyRegistrationPlan $doc @($registration) $context).Count 0 'Existing identical registration reused'
$exported = @(Export-ADCSTemplatePolicyRegistration -XmlString $doc.OuterXml -Server dc.source)
Assert-Equal $exported.Count 1 'Referenced registration exported'
Assert-Equal $exported[0].FriendlyName 'Custom policy' 'Name preserved'
Assert-Equal $exported[0].Oid '1.2.3.4' 'Numeric OID preserved'
$script:entries = @(New-Entry 2)
Assert-Throws { Get-TemplatePolicyRegistrationPlan $doc @($registration) $context } '*conflict*'
$script:entries = @(New-Entry 3 'Different name')
Assert-Throws { Get-TemplatePolicyRegistrationPlan $doc @($registration) $context } '*conflict*'
$script:entries = @((New-Entry),(New-Entry))
Assert-Throws { Get-TemplatePolicyRegistrationPlan $doc @($registration) $context } '*Ambiguous*'
$script:entries = @(New-Entry)
$script:entries[0].Values['msDS-OIDToGroupLink']='CN=privileged group'
Assert-Throws { Export-ADCSTemplatePolicyRegistration $doc.OuterXml } '*unsupported registration metadata*'
Assert-Throws { Get-TemplatePolicyRegistrationPlan $doc @($registration,$registration) $context } '*Duplicate policy OID*'
$unrelated = [pscustomobject]@{ Oid='1.2.3.99'; OidGroup='ApplicationPolicy'; FriendlyName='Unrelated' }
Assert-Throws { Get-TemplatePolicyRegistrationPlan $doc @($unrelated) $context } '*not referenced*'
$extra = [pscustomobject]@{ Oid='1.2.3.4'; OidGroup='ApplicationPolicy'; FriendlyName='Custom'; CPS='https://example.test' }
Assert-Throws { Get-TemplatePolicyRegistrationPlan $doc @($extra) $context } '*Unsupported policy registration field*'
$script:entries = @()
Assert-Equal @(Export-ADCSTemplatePolicyRegistration $doc.OuterXml).Count 0 'No registration does not synthesize one'
Assert-Throws { Wait-TemplatePolicyRegistration $registration $context 0 } '*not visible*'
# Replication: absent on first read, present on the next. No real delay or AD writes.
function Start-Sleep { param($Milliseconds) }
$script:reads = 0
function Read-TemplatePolicyRegistration { param($Context,$Oid); $script:reads++; if ($script:reads -gt 1) { New-Entry } }
Wait-TemplatePolicyRegistration $registration $context 1
Assert-Equal $script:reads 2 'Read back until visible on target DC'
# Exercise the module-qualified PSPKI invocation using a fake module.
Remove-Module PSPKI
Import-Module (New-Module -Name PSPKI -ScriptBlock {
    function Register-ObjectIdentifier {
        [CmdletBinding(SupportsShouldProcess)]
        param($Value,$FriendlyName,$OidGroup,[switch]$UseActiveDirectory)
        $global:PolicyRegistrationCall = @($Value,$FriendlyName,$OidGroup,[bool]$UseActiveDirectory)
    }
})
Register-TemplatePolicyRegistration $registration $context 1
Assert-Equal ($global:PolicyRegistrationCall -join '|') '1.2.3.4|Custom policy|ApplicationPolicy|True' 'PSPKI receives source OID and group'
$issuance = [pscustomobject]@{ Oid='1.2.3.4'; OidGroup='IssuancePolicy'; FriendlyName='Custom policy' }
Assert-Equal (Test-TemplatePolicyRegistrationMatch $issuance @((New-Entry 2))) $true 'Issuance policy flag mapping'
Remove-Variable PolicyRegistrationCall -Scope Global
$script:implicit = 'CN=Configuration,DC=wrong'
Assert-Throws { Register-TemplatePolicyRegistration $registration $context 1 } '*differs from target*'
Assert-Equal ([bool](Get-Variable PolicyRegistrationCall -Scope Global -ErrorAction SilentlyContinue)) $false 'Context mismatch never calls PSPKI'
$script:implicit = $context.ConfigurationNamingContext
# An object with incomplete replicated attributes must not be accepted as complete.
$script:reads = 0
function Read-TemplatePolicyRegistration {
    param($Context,$Oid)
    $script:reads++
    if ($script:reads -eq 1) { New-Entry 0 '' } else { New-Entry }
}
Wait-TemplatePolicyRegistration $registration $context 1
Assert-Equal $script:reads 2 'Wait for complete registration attributes' 
'PASS: policy registration planning, context, conflicts, export and readback'
