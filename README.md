# CoreCert.TemplateUtils

PowerShell module for managing AD CS certificate templates: export to portable XML, idempotent import/update, multi-tenant name override, and cleanup — no AD module dependency required.

## Background

Vadims Podans ([@Crypt32](https://github.com/Crypt32)) discovered that the COM interfaces used by MS-XCEP can be reused to export certificate templates to a portable XML format and import them into any AD forest without requiring a forest trust. His approach is documented in [Export and import certificate templates with PowerShell](https://www.sysadmins.lv/blog-en/export-and-import-certificate-templates-with-powershell.aspx).

This module builds on that foundation with:

- **Idempotent import**: `Import-ADCSTemplate` automatically detects whether a template is new (create via COM) or already exists (diff → write only changed attributes via LDAP → increment version). No separate update step needed.
- **Multi-tenant name override**: import the same XML under a different name per customer/forest.
- **No AD module required**: all functions use `System.DirectoryServices` directly. Only `Export-ADCSTemplate` requires PSPKI.

---

## Prerequisites

- PowerShell 5.1 or newer
- Windows Server 2008 R2 / Windows 7 or newer (CertEnroll COM for import)
- [PSPKI module](https://github.com/Crypt32/PSPKI) (`Install-Module PSPKI -AllowClobber`) — required **only** for `Export-ADCSTemplate`
- Enterprise Administrator permissions (templates are stored in the AD Configuration partition)

---

## Installation

```powershell
# From PowerShell Gallery
Install-Module CoreCert.TemplateUtils

# Or clone and import manually
Import-Module .\CoreCert.TemplateUtils.psd1
```

---

## How it works

### Export (`Export-ADCSTemplate`)

Reads template objects via PSPKI's `Get-CertificateTemplate` (for settings/extensions) and `Get-ADCSTemplate` (for AD-specific attributes like `msPKI-Private-Key-Flag`), then serializes them to an **MS-XCEP-compatible XML string**.

### Import / Update (`Import-ADCSTemplate`)

A single function that handles the full lifecycle:

| Situation | Behaviour |
|-----------|-----------|
| Template does **not** exist | Create via `CX509CertificateTemplateADWritable` COM (new OID minted automatically) |
| Template **exists** (same name) | Diff XCEP attributes against AD; write only changed attributes via LDAP; increment version |
| No changes detected | No-op (nothing written) |

**Attributes compared in the update path:**

| Category | Attributes |
|----------|-----------|
| Integer flags | `msPKI-Private-Key-Flag`, `msPKI-Certificate-Name-Flag`, `msPKI-Enrollment-Flag`, `flags`, `msPKI-Template-Schema-Version`, `pKIDefaultKeySpec`, `msPKI-Minimal-Key-Size`, `msPKI-RA-Signature` |
| Binary periods | `pKIExpirationPeriod` (validity), `pKIOverlapPeriod` (renewal) |
| Version | `revision`, `msPKI-Template-Minor-Revision` |

> **Note:** `pKIExtendedKeyUsage`, `msPKI-Certificate-Application-Policy`, and `pKICriticalExtensions` are set by the COM layer during create and are embedded in extension blobs — not separately represented in MS-XCEP XML. To update these, use `Remove-ADCSTemplate` followed by `Import-ADCSTemplate` (delete/recreate via COM).

### Multi-tenant / multi-forest name override

Use `-Name` and `-DisplayName` to override the template identity in memory before import. The source XML on disk is never modified. A new OID is always minted by the COM layer on create.

```powershell
# Same XML, different name per customer
Import-ADCSTemplate -XmlString $xml -Name "ACME-WebServer"    -DisplayName "ACME Web Server"
Import-ADCSTemplate -XmlString $xml -Name "CONTOSO-WebServer" -DisplayName "Contoso Web Server"
```

---

## Functions

### `Export-ADCSTemplate`

Exports one or more certificate template objects to an MS-XCEP XML string.

```powershell
# Export a single template
$t = @{
    templatePSPKI = Get-CertificateTemplate -Name "CC-WebServer"
    templateADO   = Get-ADCSTemplate        -Name "CC-WebServer"
}
$xml = Export-ADCSTemplate -Template $t

# Export multiple templates
$templates = "CC-WebServer","CC-ClientAuth" | ForEach-Object {
    @{
        templatePSPKI = Get-CertificateTemplate -Name $_
        templateADO   = Get-ADCSTemplate        -Name $_
    }
}
$xml = Export-ADCSTemplate -Template $templates

# Save to file (version control friendly)
$xml | Set-Content -Path ".\templates\CC-Templates.xml" -Encoding ASCII
```

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-Template` | `hashtable[]` | Yes | One or more hashtables with `templatePSPKI` (from PSPKI) and `templateADO` (from `Get-ADCSTemplate`) keys |

**Requires:** PSPKI module (`Install-Module PSPKI -AllowClobber`)

---

### `Import-ADCSTemplate`

Imports certificate templates from MS-XCEP XML into Active Directory — creates if new, updates if already present.

```powershell
# Basic import — original name preserved
Import-ADCSTemplate -XmlString $xml

# Import to a specific DC
Import-ADCSTemplate -XmlString $xml -Server "dc01.contoso.com"

# Import with a new name (multi-tenant)
Import-ADCSTemplate -XmlString $xml -Name "ACME-WebServer" -DisplayName "ACME Web Server"

# Version control: start at a clean baseline version
Import-ADCSTemplate -XmlString $xml -Name "CC-WebServer" -Version "100.1"

# Dry-run (no writes)
Import-ADCSTemplate -XmlString $xml -Name "TEST-WebServer" -WhatIf
```

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-XmlString` | `string` | Yes | MS-XCEP XML from `Export-ADCSTemplate` |
| `-Name` | `string` | No | New template CN in AD. Overrides original name. Only valid for single-template XML. |
| `-DisplayName` | `string` | No | New display name in AD. Defaults to `-Name` if not specified. |
| `-Version` | `string` | No | Version as `"major.minor"` (e.g. `"100.1"`). Overrides source version. |
| `-Server` | `string` | No | Target DC FQDN. Defaults to nearest writable DC. |
| `-Domain` | `string` | No | Domain DN. Auto-discovered if not specified. |

---

### `Get-ADCSTemplate`

Reads template properties directly from the AD Configuration partition using `System.DirectoryServices`. No ActiveDirectory module required.

```powershell
# List all templates
Get-ADCSTemplate

# Retrieve a specific template
Get-ADCSTemplate -Name "CC-WebServer"

# From a specific DC
Get-ADCSTemplate -Server "dc01.contoso.com"

# Sorted overview
Get-ADCSTemplate | Sort-Object Name | Format-Table Name, Created, Modified

# Inspect ACLs
$t = Get-ADCSTemplate -Name "CC-WebServer"
$t.nTSecurityDescriptor
```

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-Name` | `string` | No | Template CN to retrieve. Returns all templates if omitted. |
| `-Server` | `string` | No | Target DC FQDN. Defaults to nearest DC. |

---

### `Remove-ADCSTemplate`

Removes a certificate template **and** its OID registration from AD. Both must be removed to allow clean re-import via COM (`CX509CertificateTemplateADWritable.Commit()` checks OID uniqueness).

```powershell
# Remove (prompts for confirmation)
Remove-ADCSTemplate -Name "CC-WebServer"

# Remove without confirmation
Remove-ADCSTemplate -Name "CC-WebServer" -Confirm:$false

# Dry-run
Remove-ADCSTemplate -Name "CC-WebServer" -WhatIf
```

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-Name` | `string` | Yes | CN of the template to remove |
| `-Server` | `string` | No | Target DC FQDN |
| `-Domain` | `string` | No | Domain DN (auto-discovered if not specified) |

---

## Full workflow example

```powershell
Import-Module PSPKI
Import-Module CoreCert.TemplateUtils

# 1. Export templates from source forest
$templates = "CC-WebServer","CC-ClientAuth" | ForEach-Object {
    @{
        templatePSPKI = Get-CertificateTemplate -Name $_
        templateADO   = Get-ADCSTemplate        -Name $_
    }
}
$xml = Export-ADCSTemplate -Template $templates

# Save for version control
$xml | Set-Content -Path ".\templates\CC-Templates.xml" -Encoding ASCII

# 2. Import into target forest — same names
Import-ADCSTemplate -XmlString $xml -Server "dc01.target.com"

# 3. Or import with a customer-specific name (single template XML only)
$singleXml = Export-ADCSTemplate -Template @{
    templatePSPKI = Get-CertificateTemplate -Name "CC-WebServer"
    templateADO   = Get-ADCSTemplate        -Name "CC-WebServer"
}
Import-ADCSTemplate -XmlString $singleXml `
    -Name "ACME-WebServer" `
    -DisplayName "ACME Web Server" `
    -Server "dc01.acme.com"

# 4. Re-import after updating the source template — automatically updates or no-ops
Import-ADCSTemplate -XmlString $updatedXml -Server "dc01.acme.com"

# 5. Inspect result
Get-ADCSTemplate -Name "ACME-WebServer" -Server "dc01.acme.com"

# 6. Clean up
Remove-ADCSTemplate -Name "ACME-WebServer" -Server "dc01.acme.com"
```

---

## Tested on

- Windows Server 2019 / 2022
- PowerShell 5.1
- PSPKI 4.4.0
- AD CS Enterprise CA

---

## References

- [Export and import certificate templates with PowerShell](https://www.sysadmins.lv/blog-en/export-and-import-certificate-templates-with-powershell.aspx) — Vadims Podans
- [MS-XCEP: X.509 Certificate Enrollment Policy Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xcep/)
- [MS-CRTD: Certificate Template Structure](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/)
- [PSPKI PowerShell module](https://github.com/Crypt32/PSPKI)

## Credits

Original export/import technique by [Vadims Podans](https://www.sysadmins.lv/). This module extends his approach with idempotent import/update, multi-tenant name override, comprehensive attribute diffing, and template cleanup support.
