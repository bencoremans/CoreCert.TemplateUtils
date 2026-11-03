<#
.SYNOPSIS
    Removes a template and its uniquely identified template OID registration.
.DESCRIPTION
    Resolves both objects before deletion using the exact OID and flags=1.
    Shared, ambiguous or non-template registrations stop the operation before writes.
    The two LDAP deletes are sequential, not atomic. Partial failure is a terminating error.
.PARAMETER Domain
    Compatibility parameter; the configuration context is discovered from Server.
.EXAMPLE
    Remove-ADCSTemplate -Name 'ACME-WebServer' -Server 'dc01.contoso.com' -WhatIf
#>
. (Join-Path $PSScriptRoot 'TemplateVerification.ps1')
. (Join-Path $PSScriptRoot 'TemplateDirectory.ps1')
function Remove-ADCSTemplate {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact='High')]
    param([Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Name, [string]$Server='', [string]$Domain='')
    $context=Get-TemplateDirectoryContext $Server
    $escaped=ConvertTo-TemplateLdapFilterValue $Name
    $templates=@(Find-TemplateDirectoryObject $context.Server $context.TemplateBase "(&(objectClass=pKICertificateTemplate)(cn=$escaped))")
    if ($templates.Count -eq 0) { Write-Warning "Template '$Name' not found."; return }
    if ($templates.Count -ne 1) { throw "Ambiguous template name '$Name'." }
    $template=$templates[0]; $oid=[string]$template.Values['msPKI-Cert-Template-OID']
    if ($oid -notmatch '^\d+(\.\d+)+$') { throw 'Template has no valid OID; refusing deletion.' }
    $escapedOid=ConvertTo-TemplateLdapFilterValue $oid
    $registrations=@(Find-TemplateDirectoryObject $context.Server $context.OidBase "(&(objectClass=msPKI-Enterprise-Oid)(msPKI-Cert-Template-OID=$escapedOid))")
    $references=@(Find-TemplateDirectoryObject $context.Server $context.TemplateBase "(&(objectClass=pKICertificateTemplate)(msPKI-Cert-Template-OID=$escapedOid))")
    $registration=Get-TemplateOidRemovalCandidate $oid $registrations $references $template.Path
    if (-not $PSCmdlet.ShouldProcess("Template '$Name' and its OID '$oid' on '$($context.Server)'", 'Delete template and owned OID registration')) { return }
    Remove-TemplateDirectoryObject $template.Path
    if ($registration) {
        try { Remove-TemplateDirectoryObject $registration.Path }
        catch { throw "Template '$Name' was deleted, but OID '$oid' remains at '$($registration.Path)': $($_.Exception.Message)" }
    }
    Write-Output "Template '$Name' removed; no matching template OID registration remains."
}
