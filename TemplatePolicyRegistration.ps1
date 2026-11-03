. (Join-Path $PSScriptRoot 'TemplateDirectory.ps1')
. (Join-Path $PSScriptRoot 'TemplateVerification.ps1')

function Get-TemplatePolicyReferences {
    param([xml]$Document)
    $seen = @{}
    foreach ($policy in $Document.GetPoliciesResponse.response.policies.policy) {
        Assert-TemplatePolicyInput $Document $policy
        $expected = Get-TemplateXmlExpectation $Document $policy ''
        foreach ($group in @('ApplicationPolicy', 'IssuancePolicy')) {
            $keys = if ($group -eq 'ApplicationPolicy') {
                @('pKIExtendedKeyUsage', 'msPKI-Certificate-Application-Policy', 'RAApplicationPolicies')
            } else { @('msPKI-Certificate-Policy', 'msPKI-RA-Policies') }
            foreach ($key in $keys) {
                foreach ($oid in $expected[$key]) {
                    $id = "$group|$oid"
                    if (-not $seen.ContainsKey($id)) {
                        $seen[$id] = $true
                        [pscustomobject]@{ Oid=[string]$oid; OidGroup=$group }
                    }
                }
            }
        }
    }
}

function Read-TemplatePolicyRegistration {
    param($Context, [string]$Oid)
    $escaped = ConvertTo-TemplateLdapFilterValue $Oid
    Find-TemplateDirectoryObject $Context.Server $Context.OidBase "(&(objectClass=msPKI-Enterprise-Oid)(msPKI-Cert-Template-OID=$escaped))"
}

function ConvertFrom-TemplatePolicyRegistration {
    param($Entry)
    $v = $Entry.Values
    $group = switch ([string]$v['flags']) { '2' { 'IssuancePolicy' }; '3' { 'ApplicationPolicy' }; default { throw 'OID registration is not a policy.' } }
    # These require an explicit migration decision, rather than silently dropping data.
    foreach ($attribute in @('msPKI-OID-CPS', 'msPKI-OID-User-Notice', 'msPKI-OIDLocalizedName', 'msDS-OIDToGroupLink')) {
        if (@($v[$attribute] | Where-Object { $null -ne $_ -and [string]$_ -ne '' }).Count) {
            throw "Policy OID '$($v['msPKI-Cert-Template-OID']) has unsupported registration metadata '$attribute'."
        }
    }
    if ([string]::IsNullOrWhiteSpace([string]$v['displayName'])) { throw 'Policy registration has no displayName.' }
    [pscustomobject]@{ Oid=[string]$v['msPKI-Cert-Template-OID']; OidGroup=$group; FriendlyName=[string]$v['displayName'] }
}

function Export-ADCSTemplatePolicyRegistration {
    <#
    .SYNOPSIS
        Exports AD policy registrations referenced by template XML as companion metadata.
    .DESCRIPTION
        Reads the selected source DC. OIDs without AD registrations (including built-in
        policies) are omitted. CPS, notices, localized names and group links are rejected.
        Pipe the returned objects to ConvertTo-Json and supply them as PolicyRegistrations
        to Import-ADCSTemplate. Original numeric policy OIDs are preserved.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$XmlString, [string]$Server)
    $doc = Read-TemplatePolicyDocument $XmlString
    $references = @(Get-TemplatePolicyReferences $doc)
    $context = Get-TemplateDirectoryContext $Server
    # Buffer everything so a later conflict cannot leave a partial export on the pipeline.
    $output = foreach ($reference in $references) {
        $entries = @(Read-TemplatePolicyRegistration $context $reference.Oid)
        if ($entries.Count -gt 1) { throw "Ambiguous registration for OID '$($reference.Oid)'." }
        if ($entries.Count -eq 1) {
            $registration = ConvertFrom-TemplatePolicyRegistration $entries[0]
            if ($registration.OidGroup -ne $reference.OidGroup) { throw "Policy type conflict for OID '$($reference.Oid)'." }
            $registration
        }
    }
    $output
}

function Get-TemplateImplicitConfiguration {
    $root = [DirectoryServices.DirectoryEntry]::new('LDAP://RootDSE')
    try {
        $configuration = [string]$root.Properties['configurationNamingContext'].Value
        if (-not $configuration) { throw 'Cannot resolve the implicit LDAP configuration context.' }
        $configuration
    } finally { $root.Dispose() }
}

function Assert-TemplatePolicyRegistrationContext {
    param($Context)
    $implicit = Get-TemplateImplicitConfiguration
    if ($implicit -ine $Context.ConfigurationNamingContext) {
        throw "PSPKI LDAP context '$implicit' differs from target '$($Context.ConfigurationNamingContext)'. Run registration in the target forest context; no policy OIDs were registered."
    }
}

function Test-TemplatePolicyRegistrationMatch {
    param($Registration, [object[]]$Entries)
    if ($Entries.Count -gt 1) { throw "Ambiguous registration for OID '$($Registration.Oid)'." }
    if (-not $Entries.Count) { return $false }
    $actual = ConvertFrom-TemplatePolicyRegistration $Entries[0]
    if ($actual.Oid -cne $Registration.Oid -or $actual.OidGroup -ne $Registration.OidGroup -or $actual.FriendlyName -cne $Registration.FriendlyName) {
        throw "Policy registration conflict for OID '$($Registration.Oid)' (type or displayName differs)."
    }
    return $true
}

function Get-TemplatePolicyRegistrationPlan {
    param([xml]$Document, [object[]]$Registrations, $Context)
    $references = @{}
    foreach ($reference in @(Get-TemplatePolicyReferences $Document)) { $references["$($reference.OidGroup)|$($reference.Oid)"] = $true }
    $seen = @{}
    foreach ($registration in $Registrations) {
        if ($null -eq $registration) { throw 'Null policy registration metadata.' }
        if ([string]$registration.Oid -notmatch '^\d+(\.\d+)+$' -or
            $registration.OidGroup -notin @('ApplicationPolicy', 'IssuancePolicy') -or
            [string]::IsNullOrWhiteSpace([string]$registration.FriendlyName)) { throw 'Invalid policy registration metadata.' }
        foreach ($property in $registration.PSObject.Properties.Name) {
            if ($property -notin @('Oid','OidGroup','FriendlyName')) { throw "Unsupported policy registration field '$property'." }
        }
        $id = "$($registration.OidGroup)|$($registration.Oid)"
        if (-not $references.ContainsKey($id)) { throw "Policy OID '$id' is not referenced by the template XML." }
        # PSPKI derives the same CN from a numeric OID irrespective of policy type.
        if ($seen.ContainsKey([string]$registration.Oid)) { throw "Duplicate policy OID '$($registration.Oid)'." }
        $seen[[string]$registration.Oid] = $true
    }
    # Complete all conflict checks before returning any missing registrations.
    $missing = foreach ($registration in $Registrations) {
        $entries = @(Read-TemplatePolicyRegistration $Context $registration.Oid)
        if (-not (Test-TemplatePolicyRegistrationMatch $registration $entries)) { $registration }
    }
    if (@($missing).Count) { Assert-TemplatePolicyRegistrationContext $Context }
    $missing
}

function Wait-TemplatePolicyRegistration {
    param($Registration, $Context, [int]$TimeoutSeconds)
    $timer = [Diagnostics.Stopwatch]::StartNew()
    do {
        $entries = @(Read-TemplatePolicyRegistration $Context $Registration.Oid)
        # A DC can briefly expose the object before all separately written attributes arrive.
        $mismatch = ''
        try {
            if (Test-TemplatePolicyRegistrationMatch $Registration $entries) { return }
        } catch { $mismatch = $_.Exception.Message }
        if ($timer.Elapsed.TotalSeconds -ge $TimeoutSeconds) {
            throw "Policy OID '$($Registration.Oid)' was registered but is not visible on '$($Context.Server)' or does not match after $TimeoutSeconds seconds. $mismatch Template import stopped; registration may remain. Retry after replication."
        }
        Start-Sleep -Milliseconds 500
    } while ($true)
}

function Register-TemplatePolicyRegistration {
    param($Registration, $Context, [int]$TimeoutSeconds)
    Assert-TemplatePolicyRegistrationContext $Context
    Import-TemplatePolicyLibrary 'Policy OID registration'
    # The caller owns ShouldProcess; suppress the nested confirmation only here.
    $null = PSPKI\Register-ObjectIdentifier -Value $Registration.Oid -FriendlyName $Registration.FriendlyName -OidGroup $Registration.OidGroup -UseActiveDirectory -Confirm:$false -ErrorAction Stop
    Wait-TemplatePolicyRegistration $Registration $Context $TimeoutSeconds
}
