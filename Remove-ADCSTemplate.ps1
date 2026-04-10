<#
.SYNOPSIS
    Removes a certificate template from Active Directory, including its OID registration.

.DESCRIPTION
    Fully removes a certificate template from Active Directory. A complete removal requires
    two operations:

    1. Delete the template object from CN=Certificate Templates,...
    2. Delete the corresponding OID entry from CN=OID,CN=Public Key Services,...

    Using only PSPKI's Remove-CertificateTemplate or direct LDAP deletion of the template
    object leaves the OID entry behind as an orphan. This orphan OID causes
    CRYPT_E_EXISTS (0x80092005) on subsequent imports using CX509CertificateTemplateADWritable,
    because Commit() checks OID uniqueness in the OID container before registering a new template.

    This function performs both deletions atomically via LDAP.

.PARAMETER Name
    The CN (commonName) of the certificate template to remove.
    Example: "ACME-WebServer"

.PARAMETER Server
    Optional. The LDAP server (DC) to connect to. Defaults to the local domain.

.PARAMETER Domain
    Optional. The domain DN. Example: "DC=contoso,DC=com"
    If not specified, auto-discovered from the current machine's domain.

.EXAMPLE
    # Remove a template completely (template object + OID entry)
    Remove-ADCSTemplate -Name "ACME-WebServer"

.EXAMPLE
    # Remove from a specific DC and domain
    Remove-ADCSTemplate -Name "ACME-WebServer" -Server "dc01.contoso.com" -Domain "DC=contoso,DC=com"

.EXAMPLE
    # Dry-run
    Remove-ADCSTemplate -Name "ACME-WebServer" -WhatIf

.NOTES
    Must be run as Enterprise Administrator.
    If the OID entry is not found (already cleaned up), the function continues without error.

.LINK
    https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xcep/
#>
function Remove-ADCSTemplate {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [string]$Server = "",

        [string]$Domain = ""
    )

    process {
        # --- Auto-discover domain DN if not specified ---
        if (-not $Domain) {
            $rootDse = if ($Server) {
                [ADSI]"LDAP://$Server/RootDSE"
            } else {
                [ADSI]"LDAP://RootDSE"
            }
            $Domain = $rootDse.defaultNamingContext
            Write-Verbose "Auto-discovered domain: $Domain"
        }

        $ldapPrefix = if ($Server) { "LDAP://$Server/" } else { "LDAP://" }
        $pkiBase    = "CN=Public Key Services,CN=Services,CN=Configuration,$Domain"

        # --- Step 1: Remove template object ---
        $templateBase = "CN=Certificate Templates,$pkiBase"
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = [ADSI]"${ldapPrefix}${templateBase}"
        $searcher.Filter = "(cn=$Name)"
        $searcher.SearchScope = "OneLevel"
        $templateResult = $searcher.FindOne()

        if ($templateResult) {
            if ($PSCmdlet.ShouldProcess("Template '$Name'", "Delete from Certificate Templates container")) {
                $templateEntry = $templateResult.GetDirectoryEntry()
                $templateOid   = $templateEntry.Properties["msPKI-Cert-Template-OID"].Value
                Write-Verbose "Removing template object: CN=$Name,$templateBase"
                Write-Verbose "  Template OID: $templateOid"
                $templateEntry.DeleteTree()
                Write-Verbose "Template object removed."
            }
        } else {
            Write-Warning "Template '$Name' not found in Certificate Templates container."
            return
        }

        # --- Step 2: Remove OID entry ---
        # Find by displayName matching the template name (most reliable match)
        $oidBase = "CN=OID,$pkiBase"
        $oidSearcher = New-Object System.DirectoryServices.DirectorySearcher
        $oidSearcher.SearchRoot = [ADSI]"${ldapPrefix}${oidBase}"
        $oidSearcher.Filter = "(displayName=$Name)"
        $oidSearcher.SearchScope = "OneLevel"
        $oidResult = $oidSearcher.FindOne()

        if (-not $oidResult -and $templateOid) {
            # Fallback: search by OID value
            $oidSearcher.Filter = "(msPKI-Cert-Template-OID=$templateOid)"
            $oidResult = $oidSearcher.FindOne()
        }

        if ($oidResult) {
            if ($PSCmdlet.ShouldProcess("OID entry for '$Name'", "Delete from OID container")) {
                $oidEntry = $oidResult.GetDirectoryEntry()
                Write-Verbose "Removing OID entry: $($oidEntry.distinguishedName)"
                $oidEntry.DeleteTree()
                Write-Verbose "OID entry removed."
            }
        } else {
            Write-Verbose "No OID entry found for '$Name' -- nothing to remove from OID container."
        }

        Write-Output "Template '$Name' fully removed from Active Directory."
    }
}
