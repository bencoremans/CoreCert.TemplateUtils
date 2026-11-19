# Read-only acceptance across two genuinely different writable DCs. No forced replication.
param([switch]$RunLive,[string]$PrimaryServer,[string]$SecondaryServer,[string]$Name,[guid]$ExpectedObjectGuid=[guid]::Empty)
$ErrorActionPreference='Stop'
if(-not $RunLive){'SKIP: replication acceptance requires -RunLive and two DCs';return}
if(-not $PrimaryServer -or -not $SecondaryServer -or $PrimaryServer -ieq $SecondaryServer -or -not $Name -or $ExpectedObjectGuid -eq [guid]::Empty){throw 'Two distinct DCs, template name and GUID from the new Create result are required'}
foreach($server in @($PrimaryServer,$SecondaryServer)){
 $root=[DirectoryServices.DirectoryEntry]::new("LDAP://$server/RootDSE")
 try{$hostName=[string]$root.Properties['dnsHostName'].Value;$configuration=[string]$root.Properties['configurationNamingContext'].Value
  if(-not $hostName -or -not $configuration){throw 'DC identity/context missing'}
  if($server -eq $PrimaryServer){$firstHost=$hostName;$firstConfiguration=$configuration}else{if($hostName -ieq $firstHost -or $configuration -ine $firstConfiguration){throw 'DCs must differ and share the same forest configuration context'}}
 }finally{$root.Dispose()}
}
Import-Module (Join-Path $PSScriptRoot '../../CoreCert.TemplateUtils.psd1')
$a=@(Get-ADCSTemplate -Name $Name -Server $PrimaryServer);$b=@(Get-ADCSTemplate -Name $Name -Server $SecondaryServer)
if($a.Count -ne 1 -or $b.Count -ne 1){throw 'Template must be visible exactly once on both DCs'}
if([guid]::new([byte[]]$a[0].objectGUID) -ne $ExpectedObjectGuid -or [guid]::new([byte[]]$b[0].objectGUID) -ne $ExpectedObjectGuid){throw 'Expected newly created object is not visible on both DCs'}
foreach($field in @('objectGUID','msPKI-Cert-Template-OID','revision','msPKI-Template-Minor-Revision','msPKI-Template-Schema-Version','msPKI-Private-Key-Flag','msPKI-Certificate-Name-Flag','msPKI-Enrollment-Flag','flags','pKIDefaultCSPs','pKIDefaultKeySpec','msPKI-Minimal-Key-Size','msPKI-RA-Application-Policies','pKIExtendedKeyUsage','msPKI-Certificate-Application-Policy','pKIExpirationPeriod','pKIOverlapPeriod','pKIKeyUsage')){
 $left=$a[0].PSObject.Properties[$field];$right=$b[0].PSObject.Properties[$field]
 $lv=if($left){$left.Value}else{$null};$rv=if($right){$right.Value}else{$null}
 if($lv -is [byte[]]){$lv=[Convert]::ToBase64String($lv)}else{$lv=@($lv|Sort-Object)-join '|'}
 if($rv -is [byte[]]){$rv=[Convert]::ToBase64String($rv)}else{$rv=@($rv|Sort-Object)-join '|'}
 if($lv -cne $rv){throw "Replication differs: $field"}
}
'PASS: same GUID/OID and selected template fields on two distinct DCs; USNs intentionally not compared.'
