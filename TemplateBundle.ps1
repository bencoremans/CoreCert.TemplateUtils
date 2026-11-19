. (Join-Path $PSScriptRoot 'TemplatePolicyRegistration.ps1')

function Read-TemplateBundle {
    param([Parameter(Mandatory)][string]$JsonString)
    $bundle = ConvertFrom-Json -InputObject $JsonString -ErrorAction Stop
    if ($null -eq $bundle -or $bundle -is [array] -or $bundle -isnot [pscustomobject]) { throw 'A template bundle must be a JSON object.' }
    $fields = @($bundle.PSObject.Properties.Name)
    foreach ($field in @('FormatVersion','TemplateXml','PolicyRegistrations')) {
        if ($field -cnotin $fields) { throw "Missing bundle field '$field'." }
    }
    if ($fields.Count -ne 3) { throw 'Unsupported template bundle fields.' }
    if (($bundle.FormatVersion -isnot [int] -and $bundle.FormatVersion -isnot [long]) -or $bundle.FormatVersion -ne 1) { throw 'Unsupported template bundle FormatVersion; expected integer 1.' }
    if ($bundle.TemplateXml -isnot [string] -or [string]::IsNullOrWhiteSpace($bundle.TemplateXml)) { throw 'TemplateXml must be a nonempty string.' }
    if ($bundle.PolicyRegistrations -isnot [array]) { throw 'PolicyRegistrations must be a JSON array, including when empty or containing one item.' }
    $document = Read-TemplatePolicyDocument $bundle.TemplateXml
    $references = @(Get-TemplatePolicyReferences $document)
    $seen = @{}
    foreach ($registration in $bundle.PolicyRegistrations) {
        if ($null -eq $registration -or $registration -isnot [pscustomobject]) { throw 'Invalid policy registration object.' }
        $keys = @($registration.PSObject.Properties.Name)
        if ($keys.Count -ne 3 -or 'Oid' -cnotin $keys -or 'OidGroup' -cnotin $keys -or 'FriendlyName' -cnotin $keys) { throw 'Policy registration requires exactly Oid, OidGroup and FriendlyName.' }
        if ($registration.Oid -isnot [string] -or $registration.Oid -notmatch '^\d+(\.\d+)+$' -or
            $registration.OidGroup -isnot [string] -or $registration.OidGroup -cnotin @('ApplicationPolicy','IssuancePolicy') -or
            $registration.FriendlyName -isnot [string] -or [string]::IsNullOrWhiteSpace($registration.FriendlyName)) { throw 'Invalid policy registration values.' }
        if ($seen.ContainsKey($registration.Oid)) { throw "Duplicate or conflicting policy OID '$($registration.Oid)'." }
        $seen[$registration.Oid] = $true
        if (-not @($references | Where-Object { $_.Oid -ceq $registration.Oid -and $_.OidGroup -ceq $registration.OidGroup }).Count) { throw "Unreferenced policy registration '$($registration.Oid)'." }
    }
    $bundle
}

function ConvertTo-TemplateBundle {
    param([Parameter(Mandatory)][string]$TemplateXml, [object[]]$PolicyRegistrations = @())
    $json = [ordered]@{ FormatVersion=1; TemplateXml=$TemplateXml; PolicyRegistrations=@($PolicyRegistrations) } | ConvertTo-Json -Depth 8
    $null = Read-TemplateBundle $json
    $json
}

function Export-ADCSTemplate {
    <#
    .SYNOPSIS
    Exports templates and their policy registrations as one versioned JSON bundle.
    .PARAMETER Template
    One or more objects containing templatePSPKI and templateADO.
    .PARAMETER Server
    Source domain controller used to read policy registrations.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Template, [string]$Server)
    $xml = ConvertTo-TemplateXml -Template $Template
    $registrations = @(Get-TemplateBundleRegistrations -XmlString $xml -Server $Server)
    ConvertTo-TemplateBundle -TemplateXml $xml -PolicyRegistrations $registrations
}

function Import-ADCSTemplate {
    <#
    .SYNOPSIS
    Imports a versioned JSON bundle, registering missing policy OIDs before templates.
    .PARAMETER JsonString
    Complete FormatVersion 1 JSON bundle produced by Export-ADCSTemplate.
    .NOTES
    This command does not accept standalone XML or separate registration metadata.
    No automatic rollback is performed. A failed operation can leave created objects.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$JsonString,
        [string]$Name='', [string]$DisplayName='', [string]$Version='',
        [string]$Server='', [string]$Domain='',
        [ValidateRange(1,3600)][int]$PolicyRegistrationTimeoutSeconds=120
    )
    $bundle = Read-TemplateBundle $JsonString
    $arguments = @{} + $PSBoundParameters
    $arguments.Remove('JsonString')
    $arguments.XmlString = $bundle.TemplateXml
    $arguments.PolicyRegistrations = @($bundle.PolicyRegistrations)
    Import-TemplateXml @arguments
}
