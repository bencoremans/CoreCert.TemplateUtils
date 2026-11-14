# One explicitly selected live phase. No automatic cleanup or CA publication.
param([switch]$RunLive,[ValidateSet('Create','Update','Export','Remove','PolicyExport')][string]$Phase='Export',[string]$Server,[string]$Name,[string]$BundlePath,[string]$ReportPath,[guid]$ExpectedObjectGuid=[guid]::Empty,[string]$ExpectedTemplateOid,[string]$DisplayName)
$ErrorActionPreference='Stop'
if(-not $RunLive){'SKIP: live template lifecycle requires -RunLive and explicit phase/DC/test identity';return}
if(-not $Server -or $Name -notmatch '^TU-Test-[A-Za-z0-9-]+$' -or -not $ReportPath){throw 'Specify Server, TU-Test-* Name and a new ReportPath'}
if((Test-Path $ReportPath) -or (Test-Path ($ReportPath+'.before.clixml'))){throw 'Report/baseline already exists'}
[IO.File]::Open($ReportPath,[IO.FileMode]::CreateNew).Dispose()
$modulePath=Join-Path $PSScriptRoot '../../CoreCert.TemplateUtils.psd1';Import-Module $modulePath -ErrorAction Stop
Import-Module PSPKI -ErrorAction Stop
. (Join-Path $PSScriptRoot '../../TemplateVerification.ps1')
. (Join-Path $PSScriptRoot '../../TemplateDirectory.ps1')
. (Join-Path $PSScriptRoot '../../TemplateBundle.ps1')
$r=[ordered]@{Phase=$Phase;Status='Started';Name=$Name;Server=$Server;Calls=0;Before=$null;After=$null}
try{
 $xml=$null
 if($Phase -ne 'Remove'){
  if(-not $BundlePath){throw 'Explicit single-template BundlePath is required'}
  $json=[IO.File]::ReadAllText((Resolve-Path $BundlePath));$bundle=Read-TemplateBundle $json
  $xml=$bundle.TemplateXml;$registrations=@($bundle.PolicyRegistrations);$inputDoc=Read-TemplatePolicyDocument $xml
  $inputPolicies=@($inputDoc.GetPoliciesResponse.response.policies.policy)
  if($inputPolicies.Count -ne 1){throw 'Select exactly one template policy'}
  Assert-TemplatePolicyInput $inputDoc $inputPolicies[0]
 }
 if($Phase -ne 'Remove'){
  if($Phase -in @('Create','Update') -and @($registrations|Where-Object {$_.Oid -eq '1.2.3.4'}).Count){throw 'Replace offline placeholder OID with your own authorized test OID/metadata before live registration'}
 }
 $before=@(Get-ADCSTemplate -Name $Name -Server $Server -WarningAction SilentlyContinue)
 if($Phase -eq 'Create'){if($before.Count){throw 'Test name already exists'}}
 else{
  if($before.Count -ne 1 -or $ExpectedObjectGuid -eq [guid]::Empty -or -not $ExpectedTemplateOid){throw 'Existing-object phases require explicit expected GUID and OID'}
  if([guid]::new([byte[]]$before[0].objectGUID) -ne $ExpectedObjectGuid -or $before[0].'msPKI-Cert-Template-OID' -cne $ExpectedTemplateOid){throw 'Object ownership binding mismatch'}
 }
 $r.Before=$before|Select-Object Name,revision,'msPKI-Template-Minor-Revision','msPKI-Cert-Template-OID',objectGUID
 $before|Export-Clixml ($ReportPath+'.before.clixml')
 if($Phase -eq 'PolicyExport'){
  $r.Calls=1
  $pt=@(Get-CertificateTemplate -Name $Name)
  if($pt.Count -ne 1){throw 'Expected one PSPKI template'}
  $export=CoreCert.TemplateUtils\Export-ADCSTemplate @{templatePSPKI=$pt[0];templateADO=$before[0]} -Server $Server
  $r.ExportBundle=$export;$r.PolicyRegistrations=@((Read-TemplateBundle $export).PolicyRegistrations)
  $wanted=@($registrations|Sort-Object Oid);$got=@($r.PolicyRegistrations|Sort-Object Oid)
  if($wanted.Count -ne $got.Count){throw 'Registration export count differs from bundle'}
  for($i=0;$i -lt $wanted.Count;$i++){foreach($field in @('Oid','OidGroup','FriendlyName')){if($wanted[$i].$field -cne $got[$i].$field){throw "Registration export differs: $field"}}}
 }elseif($Phase -eq 'Remove'){
  $r.Calls=1;Remove-ADCSTemplate -Name $Name -Server $Server -Confirm:$false
  if(@(Get-ADCSTemplate -Name $Name -Server $Server -WarningAction SilentlyContinue).Count){throw 'Template remains after removal'}
  $context=Get-TemplateDirectoryContext $Server
  if(@(Find-TemplateDirectoryObject $Server $context.OidBase "(msPKI-Cert-Template-OID=$ExpectedTemplateOid)").Count){throw 'Owned template OID remains'}
 }else{
  if(-not $DisplayName){$DisplayName=$Name}
  if($Phase -eq 'Update' -and $before[0].displayName -ceq $DisplayName){throw 'Choose a different display name to exercise an update'}
  $arguments=@{JsonString=$json;Name=$Name;DisplayName=$DisplayName;Server=$Server}
  if($Phase -in @('Create','Update')){$r.Calls++;CoreCert.TemplateUtils\Import-ADCSTemplate @arguments|Out-Null}
  $actual=Read-TemplateVerificationState $Server (Get-TemplateDirectoryContext $Server).TemplateBase $Name
  if($Phase -ne 'Create' -and ([guid]::new([byte[]]$actual.objectGUID) -ne $ExpectedObjectGuid -or $actual['msPKI-Cert-Template-OID'] -cne $ExpectedTemplateOid)){throw 'Template GUID/OID changed during operation'}
  if($Phase -eq 'Update'){
   if($actual.revision -ne $before[0].revision -or $actual['msPKI-Template-Minor-Revision'] -ne ($before[0].'msPKI-Template-Minor-Revision'+1)){throw 'Expected one minor revision increment'}
   $r.Calls++;CoreCert.TemplateUtils\Import-ADCSTemplate @arguments|Out-Null
   $repeat=Read-TemplateVerificationState $Server (Get-TemplateDirectoryContext $Server).TemplateBase $Name
   if($repeat.revision -ne $actual.revision -or $repeat['msPKI-Template-Minor-Revision'] -ne $actual['msPKI-Template-Minor-Revision'] -or $repeat.uSNChanged -ne $actual.uSNChanged){throw 'Repeated update is not a no-op'}
  }
  $pt=@(Get-CertificateTemplate -Name $Name);$ad=@(Get-ADCSTemplate -Name $Name -Server $Server)
  if($pt.Count -ne 1 -or $ad.Count -ne 1){throw 'Expected one export object'}
  $export=CoreCert.TemplateUtils\Export-ADCSTemplate @{templatePSPKI=$pt[0];templateADO=$ad[0]} -Server $Server;$r.ExportBundle=$export
  $doc=Read-TemplatePolicyDocument $xml;$want=Get-TemplateXmlExpectation $doc $doc.GetPoliciesResponse.response.policies.policy $DisplayName;$want.cn=$Name
  if($Phase -eq 'Update'){$want.revision=$actual.revision;$want['msPKI-Template-Minor-Revision']=$actual['msPKI-Template-Minor-Revision']}
  if(@(Compare-TemplateVerificationState $want $actual).Count){throw 'Stored state differs from expected profile'}
  $outBundle=Read-TemplateBundle $export
  $wanted=@($registrations|Sort-Object Oid);$got=@($outBundle.PolicyRegistrations|Sort-Object Oid)
  if($wanted.Count -ne $got.Count){throw 'Registration export count differs from bundle'}
  for($i=0;$i -lt $wanted.Count;$i++){foreach($field in @('Oid','OidGroup','FriendlyName')){if($wanted[$i].$field -cne $got[$i].$field){throw "Registration export differs: $field"}}}
  $out=Read-TemplatePolicyDocument $outBundle.TemplateXml;$outWant=Get-TemplateXmlExpectation $out $out.GetPoliciesResponse.response.policies.policy $DisplayName
  if(@(Compare-TemplateVerificationState $outWant $actual).Count){throw 'Real export does not match stored state'}
  $r.After=$actual
 }
 $r.Status='Pass'
}catch{$r.Status='Fail';$r.Error=$_.Exception.Message;throw}
finally{$r|ConvertTo-Json -Depth 10|Set-Content $ReportPath -Encoding UTF8}
