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
    Requires Enterprise Administrator permissions, since this touches the AD Configuration partition.
    No ActiveDirectory module dependency — uses System.DirectoryServices only.
#>
function Get-ADCSTemplate {
    [CmdletBinding()]
    param(
        [parameter(Position = 0)]
        [string]$Name,
        [string]$Server = ""
    )

    begin {
        try {
            $rootDse = if ($Server) { [ADSI]"LDAP://$Server/RootDSE" } else { [ADSI]"LDAP://RootDSE" }
            $ConfigNC = $rootDse.configurationNamingContext.Value
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
            $ldapPrefix = if ($Server) { "LDAP://$Server/" } else { "LDAP://" }

            $searcher = New-Object System.DirectoryServices.DirectorySearcher
            $searcher.SearchRoot = [ADSI]"${ldapPrefix}${TemplatePath}"

            if ($PSBoundParameters.ContainsKey('Name')) {
                $searcher.Filter = "(&(objectClass=pKICertificateTemplate)(cn=$Name))"
            } else {
                $searcher.Filter = "(objectClass=pKICertificateTemplate)"
            }

            $searcher.SearchScope = "OneLevel"

            # Load all properties
            $searcher.PropertiesToLoad.Clear()

            $results = $searcher.FindAll()

            if ($results.Count -eq 0) {
                if ($Name) {
                    Write-Warning "No templates found with Name '$Name'."
                } else {
                    Write-Warning "No certificate templates found."
                }
                return
            }

            foreach ($result in $results) {
                $entry = $result.GetDirectoryEntry()

                # Build a PSCustomObject with all properties for easy consumption
                $props = [ordered]@{}
                foreach ($propName in $entry.Properties.PropertyNames) {
                    $val = $entry.Properties[$propName]
                    if ($val.Count -eq 1) {
                        $props[$propName] = $val[0]
                    } elseif ($val.Count -gt 1) {
                        $props[$propName] = @($val | ForEach-Object { $_ })
                    } else {
                        $props[$propName] = $null
                    }
                }

                # Add friendly aliases
                $obj = [PSCustomObject]$props
                $obj | Add-Member -NotePropertyName "Name"     -NotePropertyValue $entry.Properties["cn"][0]          -Force
                $obj | Add-Member -NotePropertyName "Created"  -NotePropertyValue $entry.Properties["whenCreated"][0] -Force
                $obj | Add-Member -NotePropertyName "Modified" -NotePropertyValue $entry.Properties["whenChanged"][0] -Force

                $obj
            }
        } catch {
            Write-Error "An error occurred while retrieving certificate templates: $_"
        }
    }
}
