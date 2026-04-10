@{
    RootModule        = 'CoreCert.TemplateUtils.psm1'
    ModuleVersion     = '2.2.0'
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
## 2.2.0
- Import-ADCSTemplate update path now compares all XCEP-representable attributes:
  8 integer flags + binary period fields (validity/renewal) + version.
- Import-ADCSTemplate supports multi-policy XML (multiple templates in one XML).
- Get-ADCSTemplate rewritten: uses System.DirectoryServices only, no ActiveDirectory
  module dependency.
- Export-ADCSTemplate: improved multi-template input validation.
- Remove-ADCSTemplate: early return when template not found (no misleading output).
- PSPKI removed from RequiredModules (only needed at runtime by Export-ADCSTemplate).
- README updated to reflect current implementation.

## 2.1.0
- Renamed all functions to consistent *-ADCSTemplate pattern.

## 2.0.0
- Import-ADCSTemplate now handles both create and update in one idempotent call.
- Removed Update-CertificateTemplate and Compare-TemplateAttributes.
'@
        }
    }
}
