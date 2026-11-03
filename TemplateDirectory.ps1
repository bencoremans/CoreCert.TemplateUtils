# Shared directory boundaries; public commands use literal names on a pinned DC.
function Get-TemplateDirectoryContext {
    param([string]$Server)
    if (-not $Server) {
        $domain = [DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        try {
            $dc = $domain.FindDomainController([DirectoryServices.ActiveDirectory.LocatorOptions]::WriteableRequired)
            try { $Server = $dc.Name } finally { $dc.Dispose() }
        } finally { $domain.Dispose() }
    }
    $root = [DirectoryServices.DirectoryEntry]::new("LDAP://$Server/RootDSE")
    try { $configuration = [string]$root.Properties['configurationNamingContext'].Value } finally { $root.Dispose() }
    if (-not $configuration) { throw "Cannot read configurationNamingContext from '$Server'." }
    $base = "CN=Public Key Services,CN=Services,$configuration"
    [pscustomobject]@{ Server=$Server; ConfigurationNamingContext=$configuration; TemplateBase="CN=Certificate Templates,$base"; OidBase="CN=OID,$base" }
}
function Find-TemplateDirectoryObject {
    param([string]$Server, [string]$Base, [string]$Filter)
    $root = [DirectoryServices.DirectoryEntry]::new("LDAP://$Server/$Base")
    $searcher = [DirectoryServices.DirectorySearcher]::new($root)
    $results = $null
    try {
        $searcher.Filter=$Filter; $searcher.SearchScope='OneLevel'; $searcher.PageSize=1000
        $results=$searcher.FindAll()
        foreach ($result in $results) {
            $entry=$result.GetDirectoryEntry()
            try {
                $entry.RefreshCache()
                $values=@{}
                foreach ($key in $entry.Properties.PropertyNames) { $values[$key]=$entry.Properties[$key].Value }
                [pscustomobject]@{ Path=$entry.Path; Values=$values }
            } finally { $entry.Dispose() }
        }
    } finally {
        if ($null -ne $results) { $results.Dispose() }; $searcher.Dispose(); $root.Dispose()
    }
}
function Remove-TemplateDirectoryObject {
    param([string]$Path)
    $entry=[DirectoryServices.DirectoryEntry]::new($Path)
    try {
        $parent=$entry.Parent
        try { $parent.Children.Remove($entry) } finally { $parent.Dispose() }
    } finally { $entry.Dispose() }
}
function Get-TemplateOidRemovalCandidate {
    param([string]$Oid, [object[]]$Registrations, [object[]]$References, [string]$TemplatePath)
    if ($Oid -notmatch '^\d+(\.\d+)+$') { throw 'Template has no valid OID; refusing deletion.' }
    if (@($References | Where-Object { $_.Path -ine $TemplatePath }).Count) { throw 'Template OID is shared; refusing deletion.' }
    if ($Registrations.Count -gt 1) { throw 'Ambiguous OID registrations; refusing deletion.' }
    if ($Registrations.Count -eq 1) {
        $item=$Registrations[0]
        if ([string]$item.Values['msPKI-Cert-Template-OID'] -cne $Oid -or
            [string]$item.Values['flags'] -ne '1') { throw 'OID is not a template registration; refusing deletion.' }
        return $item
    }
}
