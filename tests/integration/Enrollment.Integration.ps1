# Separate opt-in enrollment: existing published test template and current pilot identity only.
# Does not publish templates, change ACLs, create users or accept/install the issued certificate.
param([switch]$RunLive,[switch]$AllowEnrollment,[string]$CaConfig,[string]$Template,[string]$ExpectedTemplateOid,[string]$ExpectedIdentity,[string]$DnsName,[string]$Provider,[string]$OutputDirectory)
$ErrorActionPreference='Stop'
if(-not $RunLive -or -not $AllowEnrollment){'SKIP: enrollment requires both -RunLive and -AllowEnrollment';return}
if($Template -notmatch '^TU-Test-[A-Za-z0-9-]+$' -or $CaConfig -notmatch '^[^\r\n"]+\\[^\r\n"]+$' -or $DnsName -notmatch '^[A-Za-z0-9][A-Za-z0-9.-]+[A-Za-z0-9]$' -or $Provider -ne 'Microsoft Software Key Storage Provider' -or -not $OutputDirectory){throw 'Explicit test template, CA, DNS name, Software KSP and new output directory are required'}
if([Security.Principal.WindowsIdentity]::GetCurrent().Name -ine $ExpectedIdentity){throw 'Current pilot identity differs from ExpectedIdentity'}
if($ExpectedTemplateOid -notmatch '^\d+(\.\d+)+$'){throw 'ExpectedTemplateOid from the dedicated test template is required'}
if(Test-Path $OutputDirectory){throw 'Output directory already exists'}
[void](New-Item -ItemType Directory $OutputDirectory)
$inf=Join-Path $OutputDirectory 'request.inf';$req=Join-Path $OutputDirectory 'request.req';$cert=Join-Path $OutputDirectory 'issued.cer'
$lines=@('[Version]','Signature="$Windows NT$"','[NewRequest]',('Subject="CN='+$DnsName+'"'),'RequestType=PKCS10','KeyAlgorithm=RSA','KeyLength=2048','HashAlgorithm=SHA256','Exportable=FALSE','MachineKeySet=FALSE',('ProviderName="'+$Provider+'"'),'[Extensions]','2.5.29.17="{text}"',('_continue_="dns='+$DnsName+'"'),'[RequestAttributes]',('CertificateTemplate='+$Template))
[IO.File]::WriteAllLines($inf,$lines,[Text.Encoding]::ASCII)
$r=[ordered]@{Status='Started';Identity=$ExpectedIdentity;Template=$Template;Ca=$CaConfig;Calls=@()}
function Invoke-Native([string]$Tool,[string[]]$Arguments,[string]$Label){
 $output=@(&$Tool @Arguments 2>&1|ForEach-Object{[string]$_});$code=$LASTEXITCODE
 $r.Calls+=@{Operation=$Label;ExitCode=$code;Output=$output};if($code -ne 0){throw "$Label failed with exit $code; no retry or cleanup"}
}
try{
 Invoke-Native certreq.exe @('-new',$inf,$req) 'Create pilot request'
 Invoke-Native certreq.exe @('-submit','-config',$CaConfig,$req,$cert) 'Submit to existing published template'
 if(-not (Test-Path $cert)){throw 'No issued certificate; pending approval is not an enrollment PASS'}
 $issued=[Security.Cryptography.X509Certificates.X509Certificate2]::new($cert)
 if($issued.Subject -ine ('CN='+$DnsName)){throw 'Issued subject differs from requested pilot name'}
 # Standard CertEnroll decoders bind the response to this request and profile.
 $csr=New-Object -ComObject X509Enrollment.CX509CertificateRequestPkcs10
 $san=New-Object -ComObject X509Enrollment.CX509ExtensionAlternativeNames
 $templateInfo=New-Object -ComObject X509Enrollment.CX509ExtensionTemplate
 try{
  $csr.InitializeDecode([IO.File]::ReadAllText($req),6)
  $key=$csr.PublicKey
  $encoded=$key.GetType().InvokeMember('EncodedKey',[Reflection.BindingFlags]::GetProperty,$null,$key,@([int]1))
  if([Convert]::ToBase64String([Convert]::FromBase64String($encoded)) -cne [Convert]::ToBase64String($issued.GetPublicKey())){throw 'Issued certificate key differs from this CSR'}
  $sanRaw=@($issued.Extensions|Where-Object{$_.Oid.Value -eq '2.5.29.17'})
  $templateRaw=@($issued.Extensions|Where-Object{$_.Oid.Value -eq '1.3.6.1.4.1.311.21.7'})
  $ekuRaw=@($issued.Extensions|Where-Object{$_.Oid.Value -eq '2.5.29.37'})
  if($sanRaw.Count -ne 1 -or $templateRaw.Count -ne 1 -or $ekuRaw.Count -ne 1){throw 'Required SAN/template/EKU extension missing or duplicated'}
  $san.InitializeDecode(1,[Convert]::ToBase64String($sanRaw[0].RawData));$names=@($san.AlternativeNames)
  if($names.Count -ne 1 -or [int]$names[0].Type -ne 3 -or $names[0].strValue -ine $DnsName){throw 'Issued DNS SAN differs from the single requested name'}
  $templateInfo.InitializeDecode(1,[Convert]::ToBase64String($templateRaw[0].RawData))
  if($templateInfo.TemplateOid.Value -cne $ExpectedTemplateOid){throw 'Certificate template identity mismatch'}
  $eku=[Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new();$eku.CopyFrom($ekuRaw[0])
  if($eku.EnhancedKeyUsages.Count -ne 1 -or $eku.EnhancedKeyUsages[0].Value -cne '1.3.6.1.5.5.7.3.1'){throw 'Expected Server Authentication EKU only'}
 }finally{foreach($object in @($key,$csr,$san,$templateInfo)){if($null -ne $object -and [Runtime.InteropServices.Marshal]::IsComObject($object)){[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($object)}}}
 Invoke-Native certutil.exe @('-verify','-urlfetch',$cert) 'Verify chain and revocation'
 $r.Thumbprint=$issued.Thumbprint;$r.Status='Pass';$r.Limit='RSA2048 Software KSP ServerTLS issuance/key/SAN/template/chain; no installation or application TLS test'
}catch{$r.Status='Fail';$r.Error=$_.Exception.Message;throw}
finally{$r|ConvertTo-Json -Depth 7|Set-Content (Join-Path $OutputDirectory 'result.json') -Encoding UTF8}
