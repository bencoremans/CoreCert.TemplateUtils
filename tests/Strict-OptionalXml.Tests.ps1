# Optional SourceXml/LibraryPath permit private real-source verification without publishing it.
param([string]$SourceRoot=(Split-Path $PSScriptRoot),[string]$SourceXml,[string]$LibraryPath)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Export-Serialization.Tests.ps1')
. (Join-Path $SourceRoot 'TemplateVerification.ps1')
$stub=New-Module -Name PSPKI -ScriptBlock {};Import-Module $stub
if($LibraryPath){Add-Type -Path (Join-Path $LibraryPath 'SysadminsLV.Asn1Parser.dll');Add-Type -Path (Join-Path $LibraryPath 'SysadminsLV.PKI.dll')}
$fixture=New-Fixture
[xml]$doc=Export-ADCSTemplate $fixture
if($SourceXml){$doc=Read-TemplatePolicyDocument ([IO.File]::ReadAllText((Resolve-Path $SourceXml)))}
Set-StrictMode -Version Latest
try{
 $policy=$doc.GetPoliciesResponse.response.policies.policy;$a=$policy.attributes
 foreach($path in @('rARequirements','supersededPolicies','privateKeyAttributes/cryptoProviders','keyArchivalAttributes')){
  $xpath=($path.Split('/')|ForEach-Object{'*[local-name()="'+$_+'"]'}) -join '/'
  $node=$a.SelectSingleNode($xpath);$node.RemoveAll();$node.SetAttribute('nil','http://www.w3.org/2001/XMLSchema-instance','true')|Out-Null
 }
 Assert-TemplatePolicyInput $doc $policy
 $expected=Get-TemplateXmlExpectation $doc $policy 'Strict nil test'
 Assert-Equal $expected['msPKI-RA-Signature'] 0 'Nil RA count'
 Assert-Equal $expected.Providers.Count 0 'Nil providers'
 Assert-Equal $expected['msPKI-Supersede-Templates'].Count 0 'Nil superseded'
 Assert-Equal $expected.RAApplicationPolicies.Count 0 'Nil RA application policies'
 Assert-Equal $expected['msPKI-RA-Policies'].Count 0 'Nil RA policies'
 Assert-Equal $expected.HashAlgorithm '2.16.840.1.101.3.4.2.1' 'SHA256 retained'
 foreach($path in @('supersededPolicies','privateKeyAttributes/cryptoProviders','extensions')){
  $xpath=($path.Split('/')|ForEach-Object{'*[local-name()="'+$_+'"]'}) -join '/'
  $a.SelectSingleNode($xpath).RemoveAll()
 }
 Assert-TemplatePolicyInput $doc $policy
 $empty=Get-TemplateXmlExpectation $doc $policy 'Empty containers'
 Assert-Equal $empty.Providers.Count 0 'Empty provider container'
 Assert-Equal $empty['pKICriticalExtensions'].Count 0 'Empty extensions'
 Write-Output 'PASS: nil and empty optional XML containers under StrictMode Latest; defaults retained.'
}finally{Remove-Module $stub -Force}