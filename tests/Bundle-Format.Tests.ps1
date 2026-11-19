# PowerShell5.1 JSON arrays must be assigned before binding object[] parameters.
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Export-Serialization.Tests.ps1')
. (Join-Path $PSScriptRoot '../TemplateVerification.ps1')
. (Join-Path $PSScriptRoot '../TemplateBundle.ps1')
$stub=New-Module -Name PSPKI -ScriptBlock {};Import-Module $stub
try{
 $fixture=New-Fixture;$eku=[Security.Cryptography.OidCollection]::new()
 [void]$eku.Add([Security.Cryptography.Oid]::new('1.2.3.4'));[void]$eku.Add([Security.Cryptography.Oid]::new('1.2.3.5'))
 $fixture.templatePSPKI.Settings.Extensions+=[Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($eku,$false)
 $doc=Read-TemplatePolicyDocument (ConvertTo-TemplateXml $fixture)
 $context=[pscustomobject]@{Server='dc.example.test';ConfigurationNamingContext='CN=Configuration,DC=example,DC=test';OidBase='CN=OID,DC=example,DC=test'}
 function Get-TemplateImplicitConfiguration {'CN=Configuration,DC=example,DC=test'}
 function Find-TemplateDirectoryObject {@()}
 foreach($count in @(1,2)){
  $items=@([pscustomobject]@{Oid='1.2.3.4';OidGroup='ApplicationPolicy';FriendlyName='Example A'})
  if($count -eq 2){$items+=[pscustomobject]@{Oid='1.2.3.5';OidGroup='ApplicationPolicy';FriendlyName='Example B'}}
  $json=ConvertTo-TemplateBundle -TemplateXml $doc.OuterXml -PolicyRegistrations $items
  $bundle=Read-TemplateBundle $json; $registrations=$bundle.PolicyRegistrations
  Assert-Equal $registrations.Count $count 'JSON array item count'
  Assert-Equal ($registrations[0] -is [array]) $false 'Registration objects are not nested'
  $plan=@(Get-TemplatePolicyRegistrationPlan $doc $registrations $context)
  Assert-Equal $plan.Count $count 'Actual registration planner accepts each decoded object'
  Assert-Equal $plan[0].FriendlyName 'Example A' 'Registration meaning preserved'
 }
 'PASS: one-item and multi-item JSON bundles bind flat objects to the actual offline planner.'
}finally{Remove-Module $stub -Force}