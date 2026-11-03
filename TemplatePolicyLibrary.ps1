function Import-TemplatePolicyLibrary {
    param([string]$Operation, [string]$RequiredType)
    if (-not (Get-Module -Name PSPKI -ErrorAction SilentlyContinue)) {
        try {
            Import-Module -Name PSPKI -ErrorAction Stop
        } catch {
            throw [InvalidOperationException]::new(
                "$Operation requires PSPKI and could not load it. Install it with 'Install-Module PSPKI', then retry. Loader error: $($_.Exception.Message)",
                $_.Exception)
        }
    }

    if ($RequiredType -and -not ($RequiredType -as [type])) {
        throw "$Operation requires pkix.net type '$RequiredType', but the loaded PSPKI libraries do not provide it. Check the installed PSPKI version and loaded assemblies."
    }
}
