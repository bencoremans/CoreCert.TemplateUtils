$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'helpers/PolicyUsage.ps1')
$oid='1.2.3.4'
function New-Snapshot($name,$fields){$v=@{cn=$name;'msPKI-Template-Schema-Version'=4;'msPKI-Private-Key-Flag'=0};foreach($k in $fields.Keys){$v[$k]=$fields[$k]};[pscustomobject]@{Values=$v}}
foreach($field in @('pKIExtendedKeyUsage','msPKI-Certificate-Application-Policy','msPKI-Certificate-Policy','msPKI-RA-Policies')){
 $a=New-Snapshot A @{$field=$oid};$b=New-Snapshot B @{$field=$oid}
 $r=Get-TestPolicyUsage $oid @($a,$b) @();if($r.Status -ne 'Referenced' -or $r.References.Count -ne 2 -or $r.DeleteAuthorized){throw "Shared $field not retained"}
 $r=Get-TestPolicyUsage $oid @($b) @();if($r.References.Count -ne 1){throw 'Surviving reference lost'}
}
foreach($raw in @('1.2.3.4','msPKI-RA-Application-Policies`PZPWSTR`1.2.3.4`')){
 $r=Get-TestPolicyUsage $oid @((New-Snapshot RA @{'msPKI-RA-Application-Policies'=$raw;'msPKI-Private-Key-Flag'=$(if($raw.Contains('`')){0}else{256})})) @();if($r.Status -ne 'Referenced'){throw 'RA reference not found'}
}
foreach($case in @(@{Raw='1.2.3.4';Flags=0},@{Raw='msPKI-RA-Application-Policies`PZPWSTR`1.2.3.4`';Flags=256})){
 $r=Get-TestPolicyUsage $oid @((New-Snapshot WrongSyntax @{'msPKI-RA-Application-Policies'=$case.Raw;'msPKI-Private-Key-Flag'=$case.Flags})) @()
 if($r.Status -ne 'Unknown'){throw 'Mismatched RA syntax/schema accepted'}
}
$r=Get-TestPolicyUsage $oid @((New-Snapshot Near @{'pKIExtendedKeyUsage'='1.2.3.40'})) @();if($r.Status -ne 'NoTemplateReferences'){throw 'Substring match'}
$r=Get-TestPolicyUsage $oid @((New-Snapshot Bad @{'msPKI-RA-Application-Policies'='unknown`PZPWSTR`1.2.3.4`'})) @();if($r.Status -ne 'Unknown'){throw 'Malformed metadata treated as unused'}
$r=Get-TestPolicyUsage $oid @() @((New-Snapshot Policy @{'msPKI-Cert-Template-OID'=$oid;'msDS-OIDToGroupLink'='CN=ExampleGroup'}));if($r.GroupLinks.Count -ne 1 -or $r.DeleteAuthorized){throw 'Group link or conservative boundary lost'}
'PASS: policy usage reporting preserves shared references, exact OIDs, unknown metadata and group links; no deletion API'
