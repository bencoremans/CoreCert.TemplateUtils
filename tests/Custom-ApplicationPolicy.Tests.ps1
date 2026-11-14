param([string]$LibraryPath)
$ErrorActionPreference='Stop'
if(-not $LibraryPath -and -not (Get-Module -ListAvailable PSPKI)){'SKIP: custom application policy roundtrip needs PSPKI or -LibraryPath';return}
if($LibraryPath){Add-Type -Path (Join-Path $LibraryPath 'SysadminsLV.Asn1Parser.dll');Add-Type -Path (Join-Path $LibraryPath 'SysadminsLV.PKI.dll');$stub=New-Module -Name PSPKI -ScriptBlock {};Import-Module $stub}else{Import-Module PSPKI}
. (Join-Path $PSScriptRoot '../TemplateVerification.ps1')
. (Join-Path $PSScriptRoot '../TemplatePolicyRegistration.ps1')
$doc=Read-TemplatePolicyDocument ((Get-Content (Join-Path $PSScriptRoot 'fixtures/CustomApplicationPolicy.json') -Raw|ConvertFrom-Json).TemplateXml)
$policy=$doc.GetPoliciesResponse.response.policies.policy;Assert-TemplatePolicyInput $doc $policy
$expect=Get-TemplateXmlExpectation $doc $policy 'Example custom application policy'
if(($expect.pKIExtendedKeyUsage -join ',') -cne '1.3.6.1.5.5.7.3.1' -or ($expect['msPKI-Certificate-Application-Policy'] -join ',') -cne '1.2.3.4'){throw 'Custom application policy was conflated with EKU'}
$registration=(Get-Content (Join-Path $PSScriptRoot 'fixtures/CustomApplicationPolicy.json') -Raw|ConvertFrom-Json).PolicyRegistrations
if($registration[0] -is [array]){throw 'Registration JSON must yield flat objects, not a nested array'}
$context=[pscustomobject]@{Server='dc.example.test';ConfigurationNamingContext='CN=Configuration,DC=example,DC=test';OidBase='CN=OID,DC=example,DC=test'}
function Get-TemplateImplicitConfiguration { 'CN=Configuration,DC=example,DC=test' }
function Find-TemplateDirectoryObject {@()}
$plan=@(Get-TemplatePolicyRegistrationPlan $doc $registration $context)
if($plan.Count -ne 1 -or $plan[0].Oid -cne '1.2.3.4'){throw 'Complete companion metadata not planned'}
$bad=[pscustomobject]@{Oid='1.2.3.4';OidGroup='ApplicationPolicy'}
$rejected=$false;try{Get-TemplatePolicyRegistrationPlan $doc @($bad) $context|Out-Null}catch{$rejected=$true}
if(-not $rejected){throw 'Missing custom friendly name was accepted'}
'PASS: actual pkix custom ApplicationPolicy decoding distinct from EKU and complete companion metadata.'
