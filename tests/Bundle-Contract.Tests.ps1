# Public bundle boundary and automatic registration export; no directory writes.
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Export-Serialization.Tests.ps1')
. (Join-Path $PSScriptRoot '../TemplateBundle.ps1')
$stub=New-Module -Name PSPKI -ScriptBlock {};Import-Module $stub
$fixture=New-Fixture
$eku=[Security.Cryptography.OidCollection]::new()
[void]$eku.Add([Security.Cryptography.Oid]::new('1.2.3.4'))
$fixture.templatePSPKI.Settings.Extensions+=[Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($eku,$false)
$script:found=$true;$script:exportReads=0;$script:imports=0
function Get-TemplateDirectoryContext {param($Server);[pscustomobject]@{Server=$Server;OidBase='CN=OID,DC=example,DC=test'}}
function Read-TemplatePolicyRegistration {
 param($Context,$Oid)
 $script:exportReads++
 if($Context.Server -cne 'dc.example.test'){throw 'Export changed source DC'}
 if($script:found){[pscustomobject]@{Values=@{'flags'=3;'msPKI-Cert-Template-OID'=$Oid;displayName='Example policy'}}}
}
function Import-TemplateXml {
 [CmdletBinding(SupportsShouldProcess)]param($XmlString,$PolicyRegistrations,$Server)
 if($PSCmdlet.ShouldProcess('fixture','Import')){$script:imports++}
 $script:forwarded=@($PolicyRegistrations)
}
$json=Export-ADCSTemplate -Template $fixture -Server dc.example.test
$bundle=Read-TemplateBundle $json
Assert-Equal $bundle.PolicyRegistrations.Count 1 'Export discovers registration without sidecar'
Assert-Equal $bundle.PolicyRegistrations[0].FriendlyName 'Example policy' 'Actual AD name exported'
Import-ADCSTemplate -JsonString $json -Server dc.example.test -WhatIf | Out-Null
Assert-Equal $script:imports 0 'WhatIf forwarded'
Import-ADCSTemplate -JsonString $json -Server dc.example.test -Confirm:$false | Out-Null
Assert-Equal $script:imports 1 'Valid bundle invokes importer once'
Assert-Equal $script:forwarded.Count 1 'Registration metadata forwarded'
$script:found=$false
$absent=Read-TemplateBundle (Export-ADCSTemplate $fixture -Server dc.example.test)
Assert-Equal $absent.PolicyRegistrations.Count 0 'No registration is invented'
Assert-Equal $absent.TemplateXml $bundle.TemplateXml 'Unregistered numeric XML OIDs preserved'
$script:found=$true
[void]$eku.Add([Security.Cryptography.Oid]::new('1.2.3.5'))
$fixture.templatePSPKI.Settings.Extensions=@([Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($eku,$false))
function Read-TemplatePolicyRegistration {
 param($Context,$Oid)
 if($Oid -eq '1.2.3.5'){throw 'Late registration conflict'}
 [pscustomobject]@{Values=@{'flags'=3;'msPKI-Cert-Template-OID'=$Oid;displayName='Example policy'}}
}
$partial=[Collections.Generic.List[string]]::new()
Assert-Throws {Export-ADCSTemplate $fixture -Server dc.example.test | ForEach-Object {$partial.Add($_)}} '*Late registration conflict*'
Assert-Equal $partial.Count 0 'Late export error emits no partial bundle'
Assert-Throws {Import-ADCSTemplate -JsonString $bundle.TemplateXml} '*'
Assert-Throws {Import-ADCSTemplate -XmlString $bundle.TemplateXml} '*parameter*XmlString*'
foreach($mutate in @(
 {param($b)$b.FormatVersion=2},
 {param($b)$b.FormatVersion='1'},
 {param($b)$b.PSObject.Properties.Remove('PolicyRegistrations')},
 {param($b)$b.PolicyRegistrations=$null},
 {param($b)$b.PolicyRegistrations=$b.PolicyRegistrations[0]},
 {param($b)$b.PolicyRegistrations[0].FriendlyName=''},
 {param($b)$b.PolicyRegistrations=@($b.PolicyRegistrations[0],$b.PolicyRegistrations[0])},
 {param($b)$b|Add-Member NoteProperty Unexpected 'data'},
 {param($b)$b.TemplateXml='<broken>'}
)){
 $bad=$json|ConvertFrom-Json;& $mutate $bad
 Assert-Throws {Import-ADCSTemplate -JsonString ($bad|ConvertTo-Json -Depth 8)} '*'
 Assert-Equal $script:imports 1 'Invalid bundle never invokes importer'
}
'PASS: public JSON contract, automatic registration export, absent registration preservation, WhatIf/Confirm and pre-import refusals.'
