<#
.SYNOPSIS
Updates an existing certificate template in AD to match a desired state.

.DESCRIPTION
Retrieves the current template from AD via Get-ADCSTemplate, compares it with
the desired state using Compare-TemplateAttributes, and applies only the
attributes that differ via Set-ADObject / Clear.

This is the write-back engine used by Import-SerializedTemplate for the UPDATE
path. It can also be called directly when you already have the desired state
as a PSObject or JSON string.

.PARAMETER Name
CN of the certificate template to update.

.PARAMETER DesiredTemplateJson
JSON string of the desired state. Keys are LDAP attribute names; values are
the desired values in their native types (int / byte[] / string[]).
Produced by: $desiredPSObject | ConvertTo-Json -Depth 5

.PARAMETER Server
Optional. FQDN of the domain controller to use. Defaults to the nearest
writable DC discovered automatically.

.EXAMPLE
# Update from a JSON blob
Update-CertificateTemplate -Name "CC-WebServer" -DesiredTemplateJson $json

.EXAMPLE
# Typically called by Import-SerializedTemplate -- not manually
Import-SerializedTemplate -XmlString $xml -Name "CC-WebServer"
#>
function Update-CertificateTemplate {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$DesiredTemplateJson,

        [string]$Server = ""
    )

    # Resolve DC -- use local DC if no server specified (avoids blocking discovery on the DC itself)
    if (-not $Server) {
        if (Get-Command Get-ADDomainController -ErrorAction SilentlyContinue) {
            try {
                # -Discover without -ForceDiscover uses cached result; avoids blocking network scan
                $Server = (Get-ADDomainController -Discover -Writable -ErrorAction Stop).HostName[0]
            } catch {
                Write-Verbose "DC discovery failed ($($_.Exception.Message)); will use default LDAP connection."
            }
        }
    }

    $adParams = @{}
    if ($Server) { $adParams['Server'] = $Server }

    # Load current state
    $currentTemplate = Get-ADCSTemplate -Name $Name @adParams
    if (-not $currentTemplate) {
        Write-Error "Template '$Name' not found in AD."
        return
    }

    # Deserialize desired state
    $desired = $DesiredTemplateJson | ConvertFrom-Json -ErrorAction Stop

    # Run diff
    $differences = Compare-TemplateAttributes -Obj1 $currentTemplate -Obj2 $desired -Verbose:($VerbosePreference -eq 'Continue')

    if ($differences.Count -eq 0) {
        Write-Verbose "Template '$Name' is identical to desired state. No changes."
        Write-Output "Template '$Name' is already up to date. No changes applied."
        return
    }

    # Split into replace (non-null) and clear (null/empty)
    $replaceAttrs = @{}
    $clearAttrs   = [System.Collections.Generic.List[string]]::new()

    foreach ($key in $differences.Keys) {
        $val = $differences[$key]
        if ($null -eq $val -or ($val -is [string] -and $val -eq "") -or ($val -is [array] -and $val.Count -eq 0)) {
            $clearAttrs.Add($key)
        } else {
            $replaceAttrs[$key] = $val
        }
    }

    $changedList = @($replaceAttrs.Keys) + @($clearAttrs)
    $changeDesc  = "$($differences.Count) attribute(s): $($changedList -join ', ')"

    if ($PSCmdlet.ShouldProcess("Template '$Name'", "Update in AD ($changeDesc)")) {
        Write-Verbose "Applying update to '$Name': $changeDesc"

        if ($replaceAttrs.Count -gt 0) {
            Set-ADObject -Identity $currentTemplate.DistinguishedName -Replace $replaceAttrs @adParams -ErrorAction Stop
        }
        if ($clearAttrs.Count -gt 0) {
            Set-ADObject -Identity $currentTemplate.DistinguishedName -Clear $clearAttrs @adParams -ErrorAction Stop
        }

        Write-Verbose "Template '$Name' updated."
        Write-Output "Template '$Name' updated successfully ($changeDesc)."
    }
}
