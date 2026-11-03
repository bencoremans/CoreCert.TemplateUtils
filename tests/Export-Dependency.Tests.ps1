# Dependency loading boundaries, without installing or loading real PSPKI.
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Export-Serialization.Tests.ps1')
$fixture=New-Fixture
$script:loaded=$false; $script:loadCount=0; $script:loaderFailure=$false
function Get-Module {
    param($Name,$ErrorAction)
    if ($Name -ne 'PSPKI') { throw 'Unexpected dependency lookup' }
    if ($script:loaded) { [pscustomobject]@{Name='PSPKI'} }
}
function Import-Module {
    param($Name,$ErrorAction,[switch]$Force)
    Assert-Equal $Name 'PSPKI' 'Only PSPKI requested'
    Assert-Equal $ErrorAction 'Stop' 'Loader errors terminate'
    Assert-Equal $Force.IsPresent $false 'Never force a reload'
    $script:loadCount++
    if ($script:loaderFailure) { throw 'simulated DLL version conflict' }
    $script:loaded=$true
}
try {
    $result=@(Export-ADCSTemplate $fixture)
    Assert-Equal $script:loadCount 1 'Load on first use'
    Assert-Equal $result.Count 1 'Export returns only XML'
    Export-ADCSTemplate $fixture | Out-Null
    Assert-Equal $script:loadCount 1 'Already loaded dependency reused'
    Assert-Throws { Import-TemplatePolicyLibrary 'Policy verification' 'Missing.Pkix.Type' } '*loaded PSPKI libraries do not provide*'
    $script:loaded=$false; $script:loaderFailure=$true
    $output=[Collections.Generic.List[object]]::new()
    Assert-Throws { Export-ADCSTemplate $fixture | ForEach-Object { $output.Add($_) } } '*could not load*simulated DLL version conflict*'
    Assert-Equal $output.Count 0 'No XML after loading failure'
} finally {
    Remove-Item Function:Get-Module,Function:Import-Module
}
# Manifest imports independently and keeps all four public functions available.
$before=@(Get-Module PSPKI).Count
Import-Module (Join-Path $PSScriptRoot '../CoreCert.TemplateUtils.psd1') -Force
Assert-Equal @(Get-Module PSPKI).Count $before 'Module import does not load PSPKI'
Assert-Equal @(Get-Command -Module CoreCert.TemplateUtils).Count 4 'Public commands available'
'PASS: export dependency loading tests'
