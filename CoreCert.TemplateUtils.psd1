@{
    RootModule        = 'CoreCert.TemplateUtils.psm1'
    ModuleVersion     = '2.0.0'
    GUID              = 'c8e82f8d-13d2-4a1d-91b3-24ff8b01827d'
    Author            = 'Ben Coremans'
    Description       = 'PowerShell module for managing AD CS certificate templates: export to portable XML, idempotent import/update, multi-tenant name override, and cleanup — no AD module required for import/update operations.'
    FunctionsToExport = @(
        'ConvertTo-SerializedTemplate',
        'Get-ADCSTemplate',
        'Import-SerializedTemplate',
        'Remove-CertTemplateFromAD'
    )
    PowerShellVersion = '5.1'
    FileList          = @(
        'CoreCert.TemplateUtils.psd1',
        'CoreCert.TemplateUtils.psm1',
        'ConvertTo-SerializedTemplate.ps1',
        'Get-ADCSTemplate.ps1',
        'Import-SerializedTemplate.ps1',
        'Remove-CertTemplateFromAD.ps1',
        'README.md'
    )
    RequiredModules   = @('PSPKI')
    AliasesToExport   = @()
    VariablesToExport = @()
    FormatsToProcess  = @()
    PrivateData       = @{
        PSData = @{
            Tags         = @('PKI', 'ADCS', 'CertificateTemplates', 'ActiveDirectory', 'CoreCert')
            ProjectUri   = ''
            ReleaseNotes = @'
## 2.0.0
- Import-SerializedTemplate is now the single entry point for both create and update operations.
  Import detects whether the template already exists in AD and applies an in-place attribute
  update if anything changed, or skips if already up to date. No separate Update-CertificateTemplate
  call needed.
- Removed Update-CertificateTemplate (superseded by Import-SerializedTemplate update path).
- Removed Compare-TemplateAttributes (logic inlined into Import-SerializedTemplate; the standalone
  function required the ActiveDirectory module which Import-SerializedTemplate no longer needs).
- Get-ADCSTemplate retained as a read-only utility (list / inspect templates in AD).
- Minimum PowerShell version raised to 5.1.
'@
        }
    }
}
