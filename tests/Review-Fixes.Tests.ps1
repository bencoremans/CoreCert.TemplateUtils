$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Export-Serialization.Tests.ps1')
. (Join-Path $PSScriptRoot '../TemplateVerification.ps1')
. (Join-Path $PSScriptRoot '../Remove-ADCSTemplate.ps1')
. (Join-Path $PSScriptRoot '../Get-ADCSTemplate.ps1')
$stub=New-Module -Name PSPKI -ScriptBlock {}; Import-Module $stub
try {
    $fixture=New-Fixture
    [xml]$doc=Read-TemplatePolicyDocument (Export-ADCSTemplate $fixture)
    Assert-TemplatePolicyInput $doc $doc.GetPoliciesResponse.response.policies.policy
    Assert-Throws { Read-TemplatePolicyDocument '<GetPoliciesResponse/>' } '*MS-XCEP*'
    Assert-Throws { Read-TemplatePolicyDocument '<!DOCTYPE x [<!ENTITY t "bad">]><x>&t;</x>' } '*'
    $policy=$doc.GetPoliciesResponse.response.policies.policy
    $policy.attributes.policySchema='5'
    Assert-Throws { Assert-TemplatePolicyInput $doc $policy } '*Invalid schema*'
    $policy.attributes.policySchema='4'
    $policy.attributes.revision.majorRevision='2147483648'
    Assert-Throws { Assert-TemplatePolicyInput $doc $policy } '*Invalid nonnegative*'
    $policy.attributes.revision.majorRevision='100'
    $policy.policyOIDReference='999'
    Assert-Throws { Assert-TemplatePolicyInput $doc $policy } '*group-9*'
    $policy.policyOIDReference='1'
    $doc.GetPoliciesResponse.oIDs.oID[-1].group='7'
    Assert-Throws { Assert-TemplatePolicyInput $doc $policy } '*incorrect group*'
    $fixture.templatePSPKI.Version='broken'
    Assert-Throws { Export-ADCSTemplate $fixture } '*Invalid source template version*'
    $fixture=New-Fixture
    # Identical OID strings used in two groups must get distinct references.
    $fixture.templatePSPKI.Settings.Extensions[0].Oid=$fixture.templatePSPKI.OID
    [xml]$groups=Export-ADCSTemplate $fixture
    Assert-Equal @($groups.GetPoliciesResponse.oIDs.oID | Where-Object value -eq '1.2.3.4.5').Count 2 'OID groups remain distinct'
    Assert-Equal ((Get-TemplateUpdateRevision 100 5 100 2 $false $false) -join '.') '100.5' 'No downgrade on no-op'
    Assert-Equal ((Get-TemplateUpdateRevision 100 5 100 2 $true $false) -join '.') '100.6' 'Content advances current minor'
    Assert-Equal ((Get-TemplateUpdateRevision 100 5 101 0 $true $false) -join '.') '101.0' 'Newer source revision'
    Assert-Throws { Get-TemplateUpdateRevision 100 5 100 2 $false $true } '*downgrade*'
    Assert-Throws { Get-TemplateUpdateRevision 100 ([int]::MaxValue) 100 0 $true $false } '*overflow*'
    # Execute removal with directory boundaries replaced; confirm/no-op never reaches deletion.
    $script:template=[pscustomobject]@{Path='LDAP://dc/template'; Values=@{'msPKI-Cert-Template-OID'='1.2.3.4';cn='A*(B)'}}
    $script:registration=[pscustomobject]@{Path='LDAP://dc/oid'; Values=@{'msPKI-Cert-Template-OID'='1.2.3.4';flags=1;displayName='Different display name'}}
    $script:registrations=@($script:registration); $script:references=@($script:template)
    $script:deleted=[Collections.Generic.List[string]]::new(); $script:filters=[Collections.Generic.List[string]]::new()
    $script:missing=$false; $script:deleteFailure=$false
    function Get-TemplateDirectoryContext { [pscustomobject]@{Server='dc';TemplateBase='templates';OidBase='oids'} }
    function Find-TemplateDirectoryObject {
        param($Server,$Base,$Filter)
        $script:filters.Add($Filter)
        if ($Base -eq 'oids') { return $script:registrations }
        if ($Filter -like '*msPKI-Cert-Template-OID*') { return $script:references }
        if (-not $script:missing) { return $script:template }
    }
    function Remove-TemplateDirectoryObject {
        param($Path)
        if ($script:deleteFailure -and $Path -eq 'LDAP://dc/oid') { throw 'denied' }
        $script:deleted.Add($Path)
    }
    Remove-ADCSTemplate 'A*(B)' -WhatIf | Out-Null
    Assert-Equal $script:deleted.Count 0 'WhatIf deletes nothing'
    Assert-Equal $script:filters[0] '(&(objectClass=pKICertificateTemplate)(cn=A\2a\28B\29))' 'Literal remove filter'
    Remove-ADCSTemplate 'A*(B)' -Confirm:$false | Out-Null
    Assert-Equal ($script:deleted -join ',') 'LDAP://dc/template,LDAP://dc/oid' 'Exact OID despite different display name'
    $script:deleted.Clear(); $script:registration.Values.flags=2
    Assert-Throws { Remove-ADCSTemplate 'A*(B)' -Confirm:$false } '*not a template registration*'
    Assert-Equal $script:deleted.Count 0 'Never delete EKU/policy registration'
    $script:registration.Values.flags=1; $script:registrations=@($script:registration,$script:registration)
    Assert-Throws { Remove-ADCSTemplate 'A*(B)' -Confirm:$false } '*Ambiguous*'
    Assert-Equal $script:deleted.Count 0 'Ambiguity stops both deletes'
    $script:registrations=@($script:registration)
    $script:references+= [pscustomobject]@{Path='LDAP://dc/other-template'}
    Assert-Throws { Remove-ADCSTemplate 'A*(B)' -Confirm:$false } '*shared*'
    Assert-Equal $script:deleted.Count 0 'Shared OID stops both deletes'
    $script:references=@($script:template); $script:deleteFailure=$true
    $outputs=[Collections.Generic.List[object]]::new()
    Assert-Throws { Remove-ADCSTemplate 'A*(B)' -Confirm:$false | ForEach-Object { $outputs.Add($_) } } '*was deleted, but OID*'
    Assert-Equal $outputs.Count 0 'No false full-removal success'
    Assert-Equal $script:deleted.Count 1 'Partial failure recorded'
    $script:deleted.Clear(); $script:deleteFailure=$false; $script:registrations=@()
    Remove-ADCSTemplate 'A*(B)' -Confirm:$false | Out-Null
    Assert-Equal $script:deleted.Count 1 'Missing OID permits template-only removal'
    $script:deleted.Clear(); $script:missing=$true
    Remove-ADCSTemplate 'A*(B)' -Confirm:$false -WarningAction SilentlyContinue | Out-Null
    Assert-Equal $script:deleted.Count 0 'Missing template deletes nothing'
    $script:missing=$false; $script:filters.Clear()
    $result=Get-ADCSTemplate 'A*(B)'
    Assert-Equal $result.Name 'A*(B)' 'Get aliases'
    Assert-Equal $script:filters[0] '(&(objectClass=pKICertificateTemplate)(cn=A\2a\28B\29))' 'Literal Get filter'
    function Find-TemplateDirectoryObject { throw 'LDAP unavailable' }
    Assert-Throws { Get-ADCSTemplate Test } '*LDAP unavailable*'
    'PASS: review fixes regression tests'
} finally { Remove-Module $stub }
