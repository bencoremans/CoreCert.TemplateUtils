# Offline source-contract tests: no PSPKI, AD, COM or keys.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '../TemplateVerification.ps1')
function Assert-True($Value,$Message){if(-not $Value){throw $Message}}
$directory=Join-Path $PSScriptRoot '../examples/templates'
$combined=Read-TemplatePolicyDocument ((Get-Content (Join-Path $directory 'CC-Templates.json') -Raw|ConvertFrom-Json).TemplateXml)
$contracts=@{
 'CC-CepEncryption'=@('1.3.6.1.4.1.311.20.2.1',365,42,84214016,1207959552,32,131649,'nil')
 'CC-ClientAuth'=@('1.3.6.1.5.5.7.3.2',365,42,101056512,9,0,131680,'SHA256')
 'CC-CodeSigning'=@('1.3.6.1.5.5.7.3.3',365,42,101056512,1,0,131616,'SHA256')
 'CC-DomainController'=@('1.3.6.1.5.2.3.5,1.3.6.1.4.1.311.20.2.2,1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2',365,42,101056512,138412032,32,131168,'SHA256')
 'CC-EnrollmentAgentComputer'=@('1.3.6.1.4.1.311.20.2.1',365,42,84214016,1207959552,32,131680,'nil')
 'CC-NDESDevice'=@('1.3.6.1.5.5.7.3.2',365,42,101056512,9,0,131649,'SHA256')
 'CC-OCSPSigning'=@('1.3.6.1.5.5.7.3.9',14,2,101056512,402653184,20512,131648,'SHA256')
 'CC-UserAuth'=@('1.3.6.1.4.1.311.20.2.2,1.3.6.1.5.5.7.3.2',365,42,101056528,1,0,131584,'SHA256')
 'CC-WebServer'=@('1.3.6.1.5.5.7.3.1',365,42,101056512,9,0,131649,'SHA256')
 'CC-WinRM'=@('1.3.6.1.5.5.7.3.1',365,42,101056512,9,0,131649,'SHA256')
}
$policies=@($combined.GetPoliciesResponse.response.policies.policy)
Assert-True ($policies.Count -eq 10) 'Expected ten combined policies'
Assert-True (@(Get-ChildItem $directory -Filter '*.json').Count -eq 11) 'Expected combined export plus ten singles'
foreach($policy in $policies){
 $name=[string]$policy.attributes.commonName;Assert-True ($contracts.ContainsKey($name)) "Unexpected example $name"
 Assert-TemplatePolicyInput $combined $policy
 $single=Read-TemplatePolicyDocument ((Get-Content (Join-Path $directory ($name+'.json')) -Raw|ConvertFrom-Json).TemplateXml)
 $one=@($single.GetPoliciesResponse.response.policies.policy)
 Assert-True ($one.Count -eq 1) "Not a single policy: $name"
 Assert-True ($one[0].OuterXml -ceq $policy.OuterXml) "Single policy drift: $name"
 Assert-True ($single.GetPoliciesResponse.oIDs.OuterXml -ceq $combined.GetPoliciesResponse.oIDs.OuterXml) "OID table drift: $name"
 Assert-TemplatePolicyInput $single $one[0]
 $a=$policy.attributes;$c=$contracts[$name]
 Assert-True ([int]$a.policySchema -eq 4 -and [int]$a.privateKeyAttributes.minimalKeyLength -eq 2048) "Schema/key size drift: $name"
 $actual=@(([long]$a.certificateValidity.validityPeriodSeconds/86400),([long]$a.certificateValidity.renewalPeriodSeconds/86400),[long]$a.privateKeyFlags,[long]$a.subjectNameFlags,[long]$a.enrollmentFlags,[long]$a.generalFlags)
 for($i=0;$i -lt 6;$i++){Assert-True ($actual[$i] -eq $c[$i+1]) "Period/flag drift $name index$i"}
 $oids=@{};foreach($oid in $combined.GetPoliciesResponse.oIDs.oID){$oids[[string]$oid.oIDReferenceID]=[string]$oid.value}
 $eku=@();foreach($extension in $a.extensions.extension){if($oids[[string]$extension.oIDReference] -eq '2.5.29.37'){
  $raw=[Security.Cryptography.X509Certificates.X509Extension]::new('2.5.29.37',[Convert]::FromBase64String([string]$extension.value),$false)
  $decoded=[Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new();$decoded.CopyFrom($raw);$eku=@($decoded.EnhancedKeyUsages|ForEach-Object{$_.Value})
 }}
 Assert-True (($eku|Sort-Object) -join ',' -ceq (($c[0].Split(',')|Sort-Object) -join ',')) "EKU contract drift: $name"
 $hashNode=$a.SelectSingleNode('*[local-name()="hashAlgorithmOIDReference"]')
 if($c[7] -eq 'nil'){Assert-True ($hashNode.GetAttribute('nil','http://www.w3.org/2001/XMLSchema-instance') -eq 'true') "Legacy hash changed: $name"}
 else{Assert-True ($oids[$hashNode.InnerText] -ceq '2.16.840.1.101.3.4.2.1') "SHA256 changed: $name"}
}
'PASS: all ten example policies, independent EKU/flag/period contracts, exact singles and OID references.'
# A complete custom-policy companion is structural coverage even without pkix.net.
$custom=Read-TemplatePolicyDocument ((Get-Content (Join-Path $PSScriptRoot 'fixtures/CustomApplicationPolicy.json') -Raw|ConvertFrom-Json).TemplateXml)
Assert-TemplatePolicyInput $custom $custom.GetPoliciesResponse.response.policies.policy
$registration=(Get-Content (Join-Path $PSScriptRoot 'fixtures/CustomApplicationPolicy.json') -Raw|ConvertFrom-Json).PolicyRegistrations
if($registration[0] -is [array]){throw 'Registration JSON must yield flat objects, not a nested array'}
Assert-True ($registration.Count -eq 1 -and $registration[0].Oid -ceq '1.2.3.4' -and $registration[0].OidGroup -ceq 'ApplicationPolicy' -and -not [string]::IsNullOrWhiteSpace($registration[0].FriendlyName)) 'Custom fixture companion incomplete'
$oidMap=@{};foreach($oid in $custom.GetPoliciesResponse.oIDs.oID){$oidMap[[string]$oid.oIDReferenceID]=[string]$oid.value}
$app=@($custom.GetPoliciesResponse.response.policies.policy.attributes.extensions.extension|Where-Object{$oidMap[[string]$_.oIDReference] -ceq '1.3.6.1.4.1.311.21.10'})
Assert-True ($app.Count -eq 1 -and [Convert]::ToBase64String([byte[]]@(48,7,48,5,6,3,42,3,4)) -ceq [string]$app[0].value) 'Custom application-policy DER vector no longer matches companion OID1.2.3.4'
'PASS: custom fixture structure, OID references and complete registration sidecar (no pkix dependency).'