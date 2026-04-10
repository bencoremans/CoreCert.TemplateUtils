<#
.SYNOPSIS
Returns the properties of either a single or all Active Directory Certificate Template(s).
.DESCRIPTION
Returns the properties of either a single or list of Active Directory Certificate Template(s)
depending on whether a Name parameter was passed.
.PARAMETER Name
Name of an AD CS template to retrieve.
.PARAMETER Server
FQDN of Active Directory Domain Controller to target for the operation.
When not specified it will search for the nearest Domain Controller.
.EXAMPLE
PS C:\> Get-ADCSTemplate
.EXAMPLE
PS C:\> Get-ADCSTemplate -Name PowerShellCMS
.EXAMPLE
PS C:\> Get-ADCSTemplate | Sort-Object Name | ft Name, Created, Modified
.EXAMPLE
PS C:\> ###View template permissions
(Get-ADCSTemplate pscms).nTSecurityDescriptor
(Get-ADCSTemplate pscms).nTSecurityDescriptor.Sddl
(Get-ADCSTemplate pscms).nTSecurityDescriptor.Access
ConvertFrom-SddlString -Sddl (Get-ADCSTemplate pscms).nTSecurityDescriptor.sddl -Type ActiveDirectoryRights
.NOTES
Requires Enterprise Administrator permissions, since this touches the AD Configuration partition.

The original function is made by Ashley McGlone (GoateePFE):
https://github.com/GoateePFE/ADCSTemplate
#>
function Get-ADCSTemplate {
    [CmdletBinding()]
    param(
        [parameter(Position=0)]
        [string]$Name,
        [string]$Server = ""
    )

    begin {
        try {
            $rootDseParams = if ($Server) { @{ Server = $Server } } else { @{} }
            $ConfigNC = $((Get-ADRootDSE @rootDseParams).configurationNamingContext)
            if (-not $ConfigNC) {
                Write-Error "Unable to retrieve Configuration Naming Context."
                return
            }
            $TemplatePath = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigNC"
        } catch {
            Write-Error "Failed to initialize function: $_"
            return
        }
    }

    process {
        try {
            if ($PSBoundParameters.ContainsKey('Name')) {
                $LDAPFilter = "(&(objectClass=pKICertificateTemplate)(Name=$Name))"
            } else {
                $LDAPFilter = '(objectClass=pKICertificateTemplate)'
            }

            $adParams = if ($Server) { @{ Server = $Server } } else { @{} }
            $templates = Get-ADObject -SearchScope Subtree -SearchBase $TemplatePath -LDAPFilter $LDAPFilter -Properties * @adParams
            if (-not $templates) {
                if ($Name) {
                    Write-Warning "No templates found with Name '$Name'."
                } else {
                    Write-Warning "No certificate templates found."
                }
            }
            return $templates
        } catch {
            Write-Error "An error occurred while retrieving certificate templates: $_"
        }
    }
}
