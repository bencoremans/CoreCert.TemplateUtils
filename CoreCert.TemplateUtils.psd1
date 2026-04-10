@{
    RootModule = 'CoreCert.TemplateUtils.psm1'
    ModuleVersion = '1.0.3'
    GUID = 'c8e82f8d-13d2-4a1d-91b3-24ff8b01827d'
    Author = 'Ben Coremans'
    Description = 'A PowerShell module containing functions for managing Active Directory certificate templates.'
    FunctionsToExport = 'Compare-TemplateAttributes', 'ConvertTo-SerializedTemplate', 'Get-ADCSTemplate', 'Import-SerializedTemplate', 'Update-CertificateTemplate'
    PowerShellVersion = '3.0'
    DotNetFrameworkVersion = '4.0'
    PowerShellHostVersion = '1.0'
    FormatsToProcess = @()
    AliasesToExport = @()
    VariablesToExport = @()
    RequiredModules = @('PSPKI')
    FileList = @(
        'CoreCert.TemplateUtils.psd1',
        'CoreCert.TemplateUtils.psm1',
        'Compare-TemplateAttributes.ps1',
        'ConvertTo-SerializedTemplate.ps1',
        'Get-ADCSTemplate.ps1',
        'Import-SerializedTemplate.ps1',
        'README.md',
        'Update-CertificateTemplate.ps1'
    )
    PrivateData = @{
        PSData = @{
            Tags = @()
            ProjectUri = ''
            ReleaseNotes = 'Initial release.'
        }
    }
}
