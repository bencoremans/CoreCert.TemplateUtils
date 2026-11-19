# Read-only policy reference analysis. This is test/report support, not a deletion API.
param([string]$VerificationPath=(Join-Path $PSScriptRoot '../../TemplateVerification.ps1'))
. $VerificationPath
function Get-TestPolicyUsage {
 param([Parameter(Mandatory)][ValidatePattern('^\d+(\.\d+)+$')][string]$Oid,[object[]]$Templates,[object[]]$Registrations)
 $references=@();$unknown=@()
 foreach($template in $Templates){
  try{
   [hashtable]$values=$template.Values;$fields=@()
   foreach($attribute in @('pKIExtendedKeyUsage','msPKI-Certificate-Application-Policy','msPKI-Certificate-Policy','msPKI-RA-Policies','msPKI-Cert-Template-OID')){
    foreach($raw in @($values[$attribute])){
     if($null -eq $raw){continue}
     foreach($token in ([string]$raw).Split(',')){
      if($token -notmatch '^\d+(\.\d+)+$'){throw "Invalid OID metadata in $attribute"}
      if($token -ceq $Oid){$fields+=$attribute}
     }
    }
   }
   $rawRa=$values['msPKI-RA-Application-Policies']
   if($null -ne $rawRa -and $rawRa -isnot [string]){throw 'Unsupported RA metadata type'}
   $schema=[int]$values['msPKI-Template-Schema-Version'];$flags=[int]$values['msPKI-Private-Key-Flag']
   if($schema -notin @(1,2,3,4)){throw 'Unknown template schema'}
   $packed=($schema -eq 3 -or ($schema -eq 4 -and -not ($flags -band 256)))
   if($rawRa -and $packed -ne ([string]$rawRa).Contains('`')){throw 'RA metadata syntax conflicts with schema/provider mode'}
   # Reuse the module verifier's strict packed/legacy parser. An empty expected set
   # returns the actual parsed list as a difference, or no difference for no policies.
   $difference=@(Compare-TemplateVerificationState @{RAApplicationPolicies=@()} $values)
   foreach($d in $difference){foreach($token in @($d.Actual)){
    if($token -notmatch '^\d+(\.\d+)+$'){throw 'Invalid RA policy OID'}
    if($token -ceq $Oid){$fields+='msPKI-RA-Application-Policies'}
   }}
   if($fields.Count){$references+=[pscustomobject]@{Name=[string]$values['cn'];Fields=@($fields|Sort-Object -Unique)}}
  }catch{$unknown+=[pscustomobject]@{Name=[string]$template.Values['cn'];Reason=$_.Exception.Message}}
 }
 $matching=@($Registrations|Where-Object{[string]$_.Values['msPKI-Cert-Template-OID'] -ceq $Oid})
 $links=@($matching|ForEach-Object{$_.Values['msDS-OIDToGroupLink']}|Where-Object{$_})
 [pscustomobject]@{Oid=$Oid;Status=if($unknown.Count){'Unknown'}elseif($references.Count){'Referenced'}else{'NoTemplateReferences'};References=$references;Unknown=$unknown;RegistrationCount=$matching.Count;GroupLinks=$links;DeleteAuthorized=$false;Scope='Same-DC template metadata only; no external certificate/application usage claim'}
}
