function Import-TemplatePolicyLibrary {
    param([string]$Operation)
    if (-not (Get-Module -Name PSPKI -ErrorAction SilentlyContinue)) {
        try {
            Import-Module -Name PSPKI -ErrorAction Stop
        } catch {
            throw [InvalidOperationException]::new(
                "$Operation requires PSPKI and could not load it. Install it with 'Install-Module PSPKI', then retry. Loader error: $($_.Exception.Message)",
                $_.Exception)
        }
    }
}
