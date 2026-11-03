<#
.SYNOPSIS
    Returns the properties of either a single or all Active Directory Certificate Template(s).

.DESCRIPTION
    Returns the properties of either a single or list of Active Directory Certificate Template(s)
    depending on whether a Name parameter was passed.

    Uses System.DirectoryServices directly — no ActiveDirectory PowerShell module required.

.PARAMETER Name
    Name of an AD CS template to retrieve.

.PARAMETER Server
    FQDN of Active Directory Domain Controller to target for the operation.
    When not specified it will search for the nearest Domain Controller.

.EXAMPLE
    PS C:\> Get-ADCSTemplate

.EXAMPLE
    PS C:\> Get-ADCSTemplate -Name "CC-WebServer"

.EXAMPLE
    PS C:\> Get-ADCSTemplate | Sort-Object Name | Format-Table Name, Created, Modified

.EXAMPLE
    # Inspect ACLs
    $t = Get-ADCSTemplate -Name "CC-WebServer"
    $t.nTSecurityDescriptor

.NOTES
    Requires read access to the Certificate Templates container in the AD Configuration partition.
    No ActiveDirectory module dependency — uses System.DirectoryServices only.
#>
 . (Join-Path $PSScriptRoot 'TemplateVerification.ps1')
. (Join-Path $PSScriptRoot 'TemplateDirectory.ps1')
function Get-ADCSTemplate {
    [CmdletBinding()]
    param([Parameter(Position=0)][ValidateNotNullOrEmpty()][string]$Name, [string]$Server='')
    $context=Get-TemplateDirectoryContext $Server
    $filter='(objectClass=pKICertificateTemplate)'
    if ($PSBoundParameters.ContainsKey('Name')) {
        $escaped=ConvertTo-TemplateLdapFilterValue $Name
        $filter="(&(objectClass=pKICertificateTemplate)(cn=$escaped))"
    }
    $results=@(Find-TemplateDirectoryObject $context.Server $context.TemplateBase $filter)
    if (-not $results.Count) { Write-Warning 'No matching certificate templates found.'; return }
    foreach ($result in $results) {
        $values=$result.Values.Clone()
        $values['Name']=$values['cn']; $values['Created']=$values['whenCreated']; $values['Modified']=$values['whenChanged']
        [pscustomobject]$values
    }
}
