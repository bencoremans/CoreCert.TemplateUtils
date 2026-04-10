# CoreCert.TemplateUtils

PowerShell module for managing AD CS certificate templates: export to portable XML, idempotent import/update, multi-tenant name override, and cleanup — no AD module dependency required for import/update operations.

## Background

Vadims Podans ([@Crypt32](https://github.com/Crypt32)) discovered that the COM interfaces used by MS-XCEP can be reused to export certificate templates to a portable XML format and import them into any AD forest without requiring a forest trust. His approach is documented in [Export and import certificate templates with PowerShell](https://www.sysadmins.lv/blog-en/export-and-import-certificate-templates-with-powershell.aspx).

This module builds on that foundation with:

- **Idempotent import**: `Import-SerializedTemplate` automatically detects whether a template is new (create) or already exists (diff → write only changed attributes → increment version). No separate update step needed.
- **Multi-tenant name override**: import the same XML under a different name per customer/forest.
- **No AD module required** for import and update operations — only PSPKI (for export via `ConvertTo-SerializedTemplate`) and `Get-ADCSTemplate` (for inspection via `Get-ADObject`).

---

## Prerequisites

- PowerShell 5.1 or newer
- Windows Server 2008 R2 / Windows 7 or newer (CertEnroll COM for import)
- [PSPKI module](https://github.com/Crypt32/PSPKI) (`Install-Module PSPKI`) — required for `ConvertTo-SerializedTemplate` and `Get-ADCSTemplate`
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

### Export (`ConvertTo-SerializedTemplate`)

Reads a template object via PSPKI's `Get-CertificateTemplate` and serializes it to an **MS-XCEP-compatible XML string**. The XML contains all template settings: cryptography, validity, EKU, subject flags, extensions, key archival options, and RA requirements.

### Import / Update (`Import-SerializedTemplate`)

A single function that handles the full lifecycle:

| Situation | Behaviour |
|-----------|-----------|
| Template does **not** exist | Create via direct LDAP write + OID registration |
| Template **exists** (same name/OID) | Diff XCEP attributes against AD; write only changed attributes; increment version |
| Template **not found**, OID **exists** | Orphan OID error with cleanup instruction |
| No changes detected | No-op (nothing written) |

The update path uses `System.DirectoryServices` LDAP operations directly — no AD module required.

### Multi-tenant / multi-forest name override

Use `-Name` and `-DisplayName` to override the template identity in memory before import. The source XML on disk is never modified. When name or display name is overridden, a new OID is minted to avoid collisions.

```powershell
# Same XML, different name per customer
Import-SerializedTemplate -XmlString $xml -Name "ACME-WebServer"    -DisplayName "ACME Web Server"
Import-SerializedTemplate -XmlString $xml -Name "CONTOSO-WebServer" -DisplayName "Contoso Web Server"
```

---

## Functions

### `ConvertTo-SerializedTemplate`

Exports one or more certificate template objects to an MS-XCEP XML string.

```powershell
# Export a single template
$xml = Get-CertificateTemplate -Name "CC-WebServer" | ConvertTo-SerializedTemplate

# Export multiple templates (all CC-* templates)
$xml = Get-CertificateTemplate | Where-Object { $_.Name -like "CC-*" } | ConvertTo-SerializedTemplate

# Save to file (version control friendly)
$xml | Set-Content -Path ".\templates\CC-Templates.xml" -Encoding ASCII
```

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-Template` | `CertificateTemplate[]` | Yes | Template object(s) from `Get-CertificateTemplate` (PSPKI) |

---

### `Import-SerializedTemplate`

Imports certificate templates from MS-XCEP XML into Active Directory — creates if new, updates if already present.

```powershell
# Basic import — original name preserved
Import-SerializedTemplate -XmlString $xml

# Import to a specific DC
Import-SerializedTemplate -XmlString $xml -Server "dc01.contoso.com"

# Import with a new name (multi-tenant)
Import-SerializedTemplate -XmlString $xml -Name "ACME-WebServer" -DisplayName "ACME Web Server"

# Version control: start at a clean baseline version
Import-SerializedTemplate -XmlString $xml -Name "CC-WebServer" -Version "100.1"

# Dry-run (no writes)
Import-SerializedTemplate -XmlString $xml -Name "TEST-WebServer" -WhatIf
```

**Update behaviour on re-import:**

When a template with the same name already exists in AD, the function compares all XCEP attributes against AD values. Only changed attributes are written; the version number (revision) is incremented. If nothing has changed, the operation is a no-op.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-XmlString` | `string` | Yes | MS-XCEP XML from `ConvertTo-SerializedTemplate` |
| `-Name` | `string` | No | New template CN in AD. Overrides original name; mints a new OID. |
| `-DisplayName` | `string` | No | New display name in AD. Overrides original; mints a new OID. |
| `-Version` | `string` | No | Version as `"major.minor"` (e.g. `"100.1"`). Overrides source version. |
| `-Server` | `string` | No | Target DC FQDN. Defaults to nearest writable DC. |
| `-Domain` | `string` | No | Domain DN. Auto-discovered if not specified. |

---

### `Get-ADCSTemplate`

Reads template properties directly from the AD Configuration partition. Useful for inspection, ACL review, and listing all templates in AD.

> **Note:** This function requires the ActiveDirectory module (`RSAT` or `ActiveDirectory` PowerShell module), unlike `Import-SerializedTemplate`.

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
$t.nTSecurityDescriptor.Access
ConvertFrom-SddlString -Sddl $t.nTSecurityDescriptor.Sddl -Type ActiveDirectoryRights
```

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-Name` | `string` | No | Template CN to retrieve. Returns all templates if omitted. |
| `-Server` | `string` | No | Target DC FQDN. Defaults to nearest DC. |

---

### `Remove-CertTemplateFromAD`

Removes a certificate template and its OID registration from AD.

```powershell
# Remove (prompts for confirmation)
Remove-CertTemplateFromAD -Name "CC-WebServer"

# Remove without confirmation
Remove-CertTemplateFromAD -Name "CC-WebServer" -Confirm:$false

# Dry-run
Remove-CertTemplateFromAD -Name "CC-WebServer" -WhatIf
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

# 1. Export templates from source forest (or from manually created templates in AD)
$xml = Get-CertificateTemplate | Where-Object { $_.Name -like "CC-*" } |
       ConvertTo-SerializedTemplate

# Save for version control
$xml | Set-Content -Path ".\templates\CC-Templates.xml" -Encoding ASCII

# 2. Import into target forest — same name
Import-SerializedTemplate -XmlString $xml -Server "dc01.target.com"

# 3. Or import with a customer-specific name
Import-SerializedTemplate -XmlString $xml `
    -Name "ACME-WebServer" `
    -DisplayName "ACME Web Server" `
    -Server "dc01.acme.com"

# 4. Re-import after updating the source template — automatically updates or no-ops
Import-SerializedTemplate -XmlString $updatedXml -Name "ACME-WebServer" -Server "dc01.acme.com"

# 5. Inspect result
Get-ADCSTemplate -Name "ACME-WebServer" -Server "dc01.acme.com" |
    Select-Object Name, DisplayName, Created, Modified

# 6. Clean up (e.g. after a test or replacement)
Remove-CertTemplateFromAD -Name "ACME-WebServer" -Server "dc01.acme.com"
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

Original export/import technique by [Vadims Podans](https://www.sysadmins.lv/). This module implements his approach in modular PowerShell form and extends it with idempotent import/update, multi-tenant name override, and template cleanup support.
