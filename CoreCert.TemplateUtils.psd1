@{
    RootModule        = 'CoreCert.TemplateUtils.psm1'
    ModuleVersion     = '2.1.0'
    GUID              = 'c8e82f8d-13d2-4a1d-91b3-24ff8b01827d'
    Author            = 'Ben Coremans'
    Description       = 'PowerShell module for managing AD CS certificate templates: export to portable XML, idempotent import/update, multi-tenant name override, and cleanup — no AD module dependency required for import/update operations.'
    FunctionsToExport = @(
        'Export-ADCSTemplate',
        'Get-ADCSTemplate',
        'Import-ADCSTemplate',
        'Remove-ADCSTemplate'
    )
    PowerShellVersion = '5.1'
    FileList          = @(
        'CoreCert.TemplateUtils.psd1',
        'CoreCert.TemplateUtils.psm1',
        'Export-ADCSTemplate.ps1',
        'Get-ADCSTemplate.ps1',
        'Import-ADCSTemplate.ps1',
        'Remove-ADCSTemplate.ps1',
        'README.md'
    )
    RequiredModules   = @()
    AliasesToExport   = @()
    VariablesToExport = @()
    FormatsToProcess  = @()
    PrivateData       = @{
        PSData = @{
            Tags         = @('PKI', 'ADCS', 'CertificateTemplates', 'ActiveDirectory', 'CoreCert')
            ProjectUri   = ''
            ReleaseNotes = @'
## 2.1.0
- Renamed all functions to consistent *-ADCSTemplate pattern:
    ConvertTo-SerializedTemplate -> Export-ADCSTemplate
    Import-SerializedTemplate    -> Import-ADCSTemplate
    Remove-CertTemplateFromAD    -> Remove-ADCSTemplate
  Get-ADCSTemplate unchanged.
- Renamed PS1 files to match function names.

## 2.0.0
- Import-ADCSTemplate (formerly Import-SerializedTemplate) now handles both create
  and update in one idempotent call. No separate Update-CertificateTemplate needed.
- Removed Update-CertificateTemplate (superseded).
- Removed Compare-TemplateAttributes (logic inlined; AD module no longer required).
'@
        }
    }
}
