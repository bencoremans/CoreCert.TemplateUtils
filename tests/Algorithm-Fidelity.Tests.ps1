# Public-format regression: a known asymmetric algorithm must survive XML export.
# No AD, CertEnroll, certificate/key generation or installed PSPKI is required.
param([string]$SourceRoot = (Split-Path $PSScriptRoot))
$ErrorActionPreference='Stop'
. (Join-Path $SourceRoot 'Export-ADCSTemplate.ps1')
. (Join-Path $SourceRoot 'TemplateVerification.ps1')
$stub=New-Module -Name PSPKI -ScriptBlock {};Import-Module $stub
function Assert-Equal($Actual,$Expected,[string]$Message){if($Actual -cne $Expected){throw "$Message; expected=[$Expected]; actual=[$Actual]"}}
try{
 foreach($case in @(
  @{Schema=4;Oid='1.2.840.113549.1.1.1';Label='RSA';Providers=@()},
  @{Schema=3;Oid='1.2.840.113549.1.1.1';Label='RSA';Providers=@('Microsoft Software Key Storage Provider')},
  @{Schema=4;Oid='1.2.840.10045.3.1.7';Label='ECDSA_P256';Providers=@()},
  @{Schema=3;Oid='1.3.132.0.34';Label='ECDSA_P384';Bits=384;Providers=@('Microsoft Software Key Storage Provider')},
  @{Schema=4;Oid='1.3.132.0.35';Label='ECDSA_P521';Bits=521;Providers=@('Provider first','Provider second')},
  @{Schema=4;Oid='1.2.840.113549.1.1.1';Label='RSA';Bits=3072;Providers=@('Provider second','Provider first')},
  @{Schema=3;Oid='1.2.840.113549.1.1.1';Label='RSA';Bits=4096;Providers=@('Provider first','Provider second')},
  @{Schema=2;Oid='1.2.840.113549.1.1.1';Label='RSA';Providers=@('Microsoft RSA SChannel Cryptographic Provider')},
  @{Schema=1;Oid='1.2.840.113549.1.1.1';Label='RSA';Providers=@('Microsoft RSA SChannel Cryptographic Provider')}
 )){
  $crypto=[pscustomobject]@{MinimalKeyLength=2048;KeySpec=1;CNGKeyUsage=3;PrivateKeySecuritySDDL='';KeyAlgorithm=[Security.Cryptography.Oid]::new($case.Oid,$case.Label);HashAlgorithm=[Security.Cryptography.Oid]::new('2.16.840.1.101.3.4.2.1','SHA256');ProviderList=$case.Providers}
  if($case.ContainsKey('Bits')){$crypto.MinimalKeyLength=$case.Bits}
  elseif($case.Label -eq 'ECDSA_P256'){$crypto.MinimalKeyLength=256}
  if($case.Label -like 'ECDSA*'){$crypto.KeySpec=0}
  $source=@{
   templatePSPKI=[pscustomobject]@{Name='AlgorithmFidelity';DisplayName='Algorithm fidelity';OID=[Security.Cryptography.Oid]::new('1.2.3.4.5','Algorithm fidelity');SchemaVersion=$case.Schema;Version='100.5';Settings=[pscustomobject]@{Cryptography=$crypto;SupersededTemplates=@();RegistrationAuthority=[pscustomobject]@{SignatureCount=0};KeyArchivalSettings=[pscustomobject]@{KeyArchival=$false};SubjectName=9;EnrollmentOptions=0;GeneralFlags=131649;Extensions=@([pscustomobject]@{Oid=[Security.Cryptography.Oid]::new('2.5.29.15','Key Usage');Critical=$true;RawData=[byte[]]@(3,2,5,160)})}}
   templateADO=[pscustomobject]@{Name='AlgorithmFidelity';'msPKI-Private-Key-Flag'=101056512;pKIExpirationPeriod=[BitConverter]::GetBytes([long]-315360000000000);pKIOverlapPeriod=[BitConverter]::GetBytes([long]-36288000000000)}
  }
  [xml]$doc=Export-ADCSTemplate $source
  $ns=[Xml.XmlNamespaceManager]::new($doc.NameTable);$ns.AddNamespace('p','http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy')
  $a=$doc.SelectSingleNode('/p:GetPoliciesResponse/p:response/p:policies/p:policy/p:attributes',$ns)
  $ref=$a.SelectSingleNode('p:privateKeyAttributes/p:algorithmOIDReference',$ns)
  if($case.Schema -ge 3){
   Assert-Equal $ref.GetAttribute('nil','http://www.w3.org/2001/XMLSchema-instance') '' 'Known asymmetric algorithm was discarded'
   $oid=$doc.SelectSingleNode('/p:GetPoliciesResponse/p:oIDs/p:oID[p:oIDReferenceID="'+$ref.InnerText+'"]',$ns)
   Assert-Equal $oid.value $case.Oid 'Asymmetric OID must round trip'
   Assert-Equal $oid.group '3' 'Asymmetric OID must use public-key group'
  }else{
   Assert-Equal $ref.GetAttribute('nil','http://www.w3.org/2001/XMLSchema-instance') 'true' 'Legacy RSA representation remains unchanged'
  }
  $hash=$doc.SelectSingleNode('/p:GetPoliciesResponse/p:oIDs/p:oID[p:oIDReferenceID="'+$a.hashAlgorithmOIDReference+'"]',$ns)
  Assert-Equal $hash.value '2.16.840.1.101.3.4.2.1' 'Hash remains SHA256'
  Assert-Equal $hash.group '1' 'Hash OID group remains distinct'
  Assert-Equal (@($a.privateKeyAttributes.cryptoProviders.provider|Where-Object {$_}) -join '|') ($case.Providers -join '|') 'Provider restriction remains unchanged'
  Assert-Equal $a.extensions.extension.value 'AwIFoA==' 'Key-usage bytes remain unchanged'
  Assert-Equal $a.privateKeyFlags '101056512' 'Private flags remain unchanged'
  Assert-Equal $crypto.KeyAlgorithm.Value $case.Oid 'Source object remains unchanged'
  $expect=Get-TemplateXmlExpectation $doc $a.ParentNode 'Algorithm fidelity'
  Assert-Equal $expect.AsymmetricAlgorithm $case.Oid 'Importer consumes exported asymmetric OID'
  Assert-Equal $expect['msPKI-Minimal-Key-Size'] $crypto.MinimalKeyLength 'RSA/ECC key size survives export/import expectation'
  Assert-Equal $expect.pKIDefaultKeySpec $crypto.KeySpec 'CNG key spec retained'
  Assert-Equal ($expect.Providers -join '|') ($case.Providers -join '|') 'Provider preference consumed in order'
 }
 'PASS: explicit RSA/ECC algorithm fidelity with unchanged hash/providers/flags'
}finally{Remove-Module $stub -Force}
