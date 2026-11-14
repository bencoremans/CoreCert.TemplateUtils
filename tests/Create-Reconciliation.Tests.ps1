param([string]$SourceRoot=(Split-Path $PSScriptRoot))
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Import-Verification.Tests.ps1')
. (Join-Path $SourceRoot 'TemplateVerification.ps1')
. (Join-Path $SourceRoot 'TemplateDirectory.ps1')
$stub=New-Module -Name PSPKI -ScriptBlock {};Import-Module $stub
$source=Get-Content (Join-Path $SourceRoot 'Import-ADCSTemplate.ps1') -Raw
$source=$source.Replace(". (Join-Path `$PSScriptRoot 'TemplateVerification.ps1')",'').Replace(". (Join-Path `$PSScriptRoot 'TemplateDirectory.ps1')",'').Replace(". (Join-Path `$PSScriptRoot 'TemplatePolicyRegistration.ps1')",'')
$start=$source.IndexOf('        if (');$end=$source.IndexOf('        #region Helper:',$start)
$source=$source.Remove($start,$end-$start).Replace('[ADSI]','[object]').Replace('$searcher.SearchRoot.Dispose();','')
. ([scriptblock]::Create($source))
function Get-TemplateDirectoryContext { param($Server);[pscustomobject]@{Server=$Server;TemplateBase='CN=Templates,DC=test'} }
function Read-TemplateVerificationState { param($Server,$TemplateBase,$Name);return $script:stored.Clone() }
function Write-TemplateCreateReconciliation {
 param($Server,$Baseline,$Changes)
 $script:repairs++
 if($script:writeFailure){throw 'Simulated LDAP refusal'}
 if(-not $script:ignoreWrite){foreach($key in $Changes.Keys){$script:stored[$key]=$Changes[$key]}}
}
function New-Object {
 param([Parameter(Position=0)][string]$TypeName,[Parameter(Position=1)][object[]]$ArgumentList,[string]$ComObject)
 if($TypeName -eq 'System.DirectoryServices.DirectorySearcher'){
  $o=[pscustomobject]@{SearchRoot=$null;Filter=$null;SearchScope=$null};$o|Add-Member ScriptMethod FindOne {$null};$o|Add-Member ScriptMethod Dispose {};return $o
 }
 if($ComObject -eq 'X509Enrollment.CX509EnrollmentPolicyWebService'){
  $o=[pscustomobject]@{};$o|Add-Member ScriptMethod InitializeImport {param($bytes)};$o|Add-Member ScriptMethod GetTemplates {[pscustomobject]@{Name='TestTemplate'}};return $o
 }
 if($ComObject -eq 'X509Enrollment.CX509CertificateTemplateADWritable'){
  $o=[pscustomobject]@{};$o|Add-Member ScriptMethod Initialize {param($template)}
  $o|Add-Member ScriptMethod Commit {param($flag,$server);$script:creates++;$script:stored=New-StoredFixture;& $script:fault $script:stored};return $o
 }
 Microsoft.PowerShell.Utility\New-Object -TypeName $TypeName -ArgumentList $ArgumentList
}
function New-StoredFixture {
 $a=New-ActualFixture;$a['msPKI-Template-Minor-Revision']=5
 $a['msPKI-Private-Key-Flag']=101056512
 $a.objectGUID=([guid]'11111111-2222-3333-4444-555555555555').ToByteArray();$a.uSNChanged=17473;$a.unrelatedAttribute='keep exact'
 $a['msPKI-Cert-Template-OID']='1.2.3.4.12345'
 return $a
}
$fixture=New-Fixture;$fixture.templatePSPKI.Version='100.5'
$fixture.templateADO.'msPKI-Private-Key-Flag'=101056512
[xml]$doc=ConvertTo-TemplateXml $fixture
$expected=Get-TemplateXmlExpectation $doc $doc.GetPoliciesResponse.response.policies.policy $fixture.templatePSPKI.DisplayName
$script:writeFailure=$false;$script:ignoreWrite=$false
# Each fault passes through the actual importer create branch, actual planner,
# and strict final verifier. Only COM storage and LDAP transport are doubles.
$faults=@(
 {param($a);$a['msPKI-RA-Application-Policies']=$a['msPKI-RA-Application-Policies'].Replace('SHA256','SHA1')},
 {param($a);$a['msPKI-Minimal-Key-Size']=2048},
 {param($a);$a.pKIDefaultCSPs=@('1,Wrong provider')},
 {param($a);$a.pKIKeyUsage=[byte[]]@(128,0)},
 {param($a);$a['msPKI-Private-Key-Flag']=0;$a['msPKI-Certificate-Name-Flag']=0;$a['msPKI-Enrollment-Flag']=1},
 {param($a);$a.pKIExpirationPeriod=[BitConverter]::GetBytes([long]-1);$a.pKIOverlapPeriod=[BitConverter]::GetBytes([long]-1)},
 {param($a);$a.pKIExtendedKeyUsage=@('1.2.3');$a['msPKI-Certificate-Application-Policy']=@('1.2.3');$a.pKICriticalExtensions=@()},
 {param($a);$a['msPKI-RA-Application-Policies']=$a['msPKI-RA-Application-Policies'].Replace('RSA','ECDSA_P256').Replace('SHA256','SHA1').Replace('DWORD`3','DWORD`0');$a['msPKI-Minimal-Key-Size']=2048;$a.pKIDefaultCSPs=@();$a.pKIKeyUsage=[byte[]]@(0,0)}
)
try{
 foreach($fault in $faults){
  $script:fault=$fault;$script:creates=0;$script:repairs=0
  Import-TemplateXml $doc.OuterXml -Server dc.test | Out-Null
  Assert-Equal $script:creates 1 'One COM create'
  Assert-Equal $script:repairs 1 'One LDAP reconciliation'
  Assert-Equal $script:stored.revision 100 'Major preserved'
  Assert-Equal $script:stored['msPKI-Template-Minor-Revision'] 5 'Minor preserved'
  Assert-Equal $script:stored.unrelatedAttribute 'keep exact' 'Unknown ordinary field preserved'
  Assert-Equal $script:stored['msPKI-Cert-Template-OID'] '1.2.3.4.12345' 'Actual allocated OID preserved'
  Complete-TemplateCreateVerification $expected dc.test 'CN=Templates,DC=test'
  Assert-Equal $script:repairs 1 'Second reconciliation is no-op'
 }
 foreach($fault in @(
  {param($a);$a.revision=99},
  {param($a);$a['msPKI-Template-Minor-Revision']=4},
  {param($a);$a['msPKI-Template-Schema-Version']=3},
  {param($a);$a['msPKI-RA-Application-Policies']+='Unknown`PZPWSTR`preserve`'},
  {param($a);$a['msPKI-RA-Application-Policies']+='broken'}
 )){
  $script:fault=$fault;$script:repairs=0
  Assert-Throws {Import-TemplateXml $doc.OuterXml -Server dc.test} '*'
  Assert-Equal $script:repairs 0 'Unsupported state stops before LDAP repair'
 }
 # Empty XML metadata removes only that tuple, retaining other valid crypto tokens.
 $emptyExpected=[ordered]@{};foreach($k in $expected.Keys){$emptyExpected[$k]=$expected[$k]}
 $emptyExpected.PrivateKeySDDL='';$emptyExpected.RAApplicationPolicies=@()
 $a=New-StoredFixture;$a['msPKI-RA-Application-Policies']+='msPKI-RA-Application-Policies`PZPWSTR`1.2.3`msPKI-Symmetric-Algorithm`PZPWSTR`3DES`'
 $plan=Get-TemplateCreateReconciliationPlan $emptyExpected $a
 foreach($k in $plan.Keys){$a[$k]=$plan[$k]}
 Assert-Equal @(Compare-TemplateVerificationState $emptyExpected $a).Count 0 'Empty metadata reconciles'
 Assert-Equal $a['msPKI-RA-Application-Policies'].Contains('msPKI-Symmetric-Algorithm`PZPWSTR`3DES`') $true 'Unspecified symmetric token preserved'
 Assert-Equal $a['msPKI-RA-Application-Policies'].Contains('msPKI-Key-Security-Descriptor') $false 'Empty SDDL removes tuple'
 foreach($schema in @(2,4)){
  $legacy=[ordered]@{};foreach($k in $expected.Keys){$legacy[$k]=$expected[$k]}
  $legacy['msPKI-Template-Schema-Version']=$schema;$legacy['msPKI-Private-Key-Flag']=101056768
  $a=New-StoredFixture;$a['msPKI-Template-Schema-Version']=$schema;$a['msPKI-Private-Key-Flag']=101056768
  $a['msPKI-RA-Application-Policies']=$a['msPKI-RA-Application-Policies'].Replace('SHA256','SHA1')
  Assert-Throws {Get-TemplateCreateReconciliationPlan $legacy $a} '*Legacy cryptographic*'
 }
 $legacy['msPKI-Template-Schema-Version']=3;$a['msPKI-Template-Schema-Version']=3
 Assert-Equal (Get-TemplateCreateReconciliationPlan $legacy $a).Count 1 'Schema3 supports packed syntax'
 $script:fault=$faults[0];$script:repairs=0;$script:ignoreWrite=$true
 Assert-Throws {Import-TemplateXml $doc.OuterXml -Server dc.test} '*Verification failed*'
 Assert-Equal $script:repairs 1 'Ignored storage write detected without retry'
 $script:ignoreWrite=$false;$script:writeFailure=$true;$script:repairs=0
 Assert-Throws {Import-TemplateXml $doc.OuterXml -Server dc.test} '*Simulated LDAP refusal*'
 Assert-Equal $script:repairs 1 'LDAP failure not retried'
 Write-Output 'PASS: real importer create flow, eight reset cases, strict verification, revision/unknown-field preservation, no-op and fail-closed behavior.'
}finally{Remove-Module $stub -Force}
