# CoreCert.TemplateUtils

PowerShell module for managing AD CS certificate templates: export to portable XML, idempotent import/update, multi-tenant name override, and cleanup — no AD module dependency required.

## Background

Vadims Podans ([@Crypt32](https://github.com/Crypt32)) discovered that the COM interfaces used by MS-XCEP can be reused to export certificate templates to a portable XML format and import them into any AD forest without requiring a forest trust. His approach is documented in [Export and import certificate templates with PowerShell](https://www.sysadmins.lv/blog-en/export-and-import-certificate-templates-with-powershell.aspx).

This module builds on that foundation with:

- **Idempotent import**: `Import-ADCSTemplate` automatically detects whether a template is new (create via COM) or already exists (diff → write supported changed attributes via LDAP → advance revision without downgrading → verify). No separate update step needed.
- **Multi-tenant name override**: import the same XML under a different name per customer/forest.
- **No AD module required**: all functions use `System.DirectoryServices` directly. PSPKI is needed for export and for import verification of Application Policies or Certificate Policies.

---

## Prerequisites

- PowerShell 5.1 or newer
- Windows Server 2008 R2 / Windows 7 or newer (CertEnroll COM for import)
- [PSPKI module](https://github.com/Crypt32/PSPKI) (`Install-Module PSPKI -AllowClobber`) — required for export and for imports containing Application Policies or Certificate Policies; loaded automatically when needed
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
| Template **exists** (same name) | Diff supported XCEP attributes; update via LDAP; advance revision without downgrading; verify |
| No changes detected | Read back and verify; nothing written |

**Attributes written by the update path:**

| Category | Attributes |
|----------|-----------|
| Integer flags | `msPKI-Private-Key-Flag`, `msPKI-Certificate-Name-Flag`, `msPKI-Enrollment-Flag`, `flags`, `msPKI-Template-Schema-Version`, `pKIDefaultKeySpec`, `msPKI-Minimal-Key-Size`, `msPKI-RA-Signature` |
| Binary periods | `pKIExpirationPeriod` (validity), `pKIOverlapPeriod` (renewal) |
| Display name | `displayName` |
| Version | `revision`, `msPKI-Template-Minor-Revision` |

> **Note:** `pKIExtendedKeyUsage`, `msPKI-Certificate-Application-Policy`, and `pKICriticalExtensions` are set by the COM layer during create and are embedded in extension blobs — not separately represented in MS-XCEP XML. Verification checks these values after creation and on existing templates. The updater does not repair them: unsupported differences terminate before changing that template. Correct them separately before retrying.

### Multi-tenant / multi-forest name override

Use `-Name` and `-DisplayName` to override the template identity in memory before import. The source XML on disk is never modified. On create, the importer supplies a temporary unique OID to MS-XCEP; CertEnroll performs the final registration.

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
$xml | Set-Content -Path ".\templates\CC-Templates.xml" -Encoding UTF8
```

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-Template` | `hashtable[]` | Yes | One or more hashtables with `templatePSPKI` (from PSPKI) and `templateADO` (from `Get-ADCSTemplate`) keys |

**Requires:** an installed PSPKI module (`Install-Module PSPKI`). The export function loads
PSPKI on demand if it is not already loaded. It does not install PSPKI or force a reload.
Import verification loads PSPKI on demand when decoding Application Policies or Certificate Policies. Module import, Get and Remove do not load PSPKI. Loading failures retain
the underlying error message. The input still requires the existing PSPKI and AD objects;
this change does not add template lookup by name to the export function.

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
| `-Domain` | `string` | No | Compatibility parameter; the forest configuration context is discovered from `-Server`. |

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

Resolves the template's exact `msPKI-Cert-Template-OID` and looks for a unique registration
with `flags=1`. Display names are never used to select an OID. Shared OIDs, ambiguous
registrations and non-template OID types stop the operation before deletion.

One `ShouldProcess` decision covers both deletes. `-WhatIf` and declined confirmation
perform no deletes. A missing template returns without deleting anything; a missing OID
allows template-only removal. The LDAP deletes are sequential, **not atomic**. If the
second delete fails, the error identifies the remaining OID and no full-success message
is emitted. Avoid concurrent administrative changes during removal. This is not an
orphan-scanning tool and does not remove unrelated OID registrations.

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
| `-Domain` | `string` | No | Compatibility parameter; configuration context is read from the selected DC. |

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
$xml | Set-Content -Path ".\templates\CC-Templates.xml" -Encoding UTF8

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

## Prior module testing

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


## Export fidelity and validation

Export requires both the PSPKI template object and the full `Get-ADCSTemplate` object. EKUs use the PSPKI extension. Application Policies are encoded separately with pkix.net from LDAP `msPKI-Certificate-Application-Policy`, with criticality from `pKICriticalExtensions`. An absent application-policy attribute does not copy the EKU list.
The AD object supplies the original private-key flags and the exact binary validity/renewal
intervals. Intervals that cannot be represented as whole MS-XCEP seconds are rejected;
they are never rounded or reconstructed from display text.

Text is XML-escaped and the completed document is parsed before it is returned. Provider
names use `ProviderList`, with `CSPList` as a compatibility fallback. A missing property
is an error; an existing empty list still means no explicit provider restriction.

Save and read XML explicitly as UTF-8:

```powershell
$xml | Set-Content -LiteralPath '.\template.xml' -Encoding UTF8
$xml = Get-Content -LiteralPath '.\template.xml' -Raw -Encoding UTF8
Import-ADCSTemplate -XmlString $xml
```

Template permissions are deliberately configured separately with PSPKI in the destination.
The exported private-key security descriptor is not the template DACL.
### Mandatory verification after import/update

Before returning success, `Import-ADCSTemplate` reads fresh LDAP data from the same DC
used for the write. This also runs when the update comparison finds nothing to change.
Expectations come from the input XML, including `-Name` and `-DisplayName` overrides.
For an existing template, a newer source revision is adopted. Changed content with an
equal/older source advances the current minor revision; unchanged content preserves the
current revision. Repeated import therefore does not keep increasing or lowering it.
An explicit `-Version` downgrade is rejected. The effective revision is verified. Verification compares the XML with fresh LDAP data. Application Policies and Certificate Policies are decoded using the pkix.net classes shipped with PSPKI.

| Checked settings | Comparison |
|---|---|
| Name, display name, revisions, schema, flags, key spec and size, RA signature count | Exact values; signed/unsigned 32-bit flags normalized |
| Validity and renewal | Exact binary intervals; a one-second difference fails |
| Provider list | Provider names in their numeric preference order |
| Algorithm, request hash, CNG key usage, private-key SDDL | Decoded `msPKI-RA-Application-Policies`; Windows OID registry resolves algorithm names |
| Supersedence, RA policies, EKUs, application policies, issuance policy OIDs, critical extensions | Order-independent lists |
| Key usage, basic constraints, OCSP no-check | Supported extension data compared with LDAP attributes/flags |
| Key archival algorithm and length | Checked when specified by the XML |

A mismatch is a **terminating error** listing `Property`, `Expected` and `Actual`.
The same objects are available in `$_.Exception.Data['Differences']`:

```powershell
try {
    Import-ADCSTemplate -XmlString $xml -Server 'dc01.contoso.com'
} catch {
    $_.Exception.Data['Differences'] | Format-Table Property, Expected, Actual -Wrap
    throw
}
```

Verification detects differences; it does not expand the LDAP updater's write scope.
Already committed changes remain in AD on failure. There is no automatic rollback,
delete/recreate or post-create repair. Multi-template imports can therefore be partly
completed when a later template fails. Correct the reported differences before retrying.

All policies are preflighted before the first write. Unknown extension OIDs and policy
qualifiers are rejected because this verifier cannot establish their complete LDAP
representation. Existing XML files using those features require further verifier support;
they are not silently accepted. SDDL is compared literally, so equivalent reordered SDDL
can produce a conservative mismatch. Windows must resolve the stored algorithm names;
unresolved names also fail verification.

Excluded: template DACL (managed separately), source template identity OIDs and identity
extension payloads (which change across forests/renames), directory-generated metadata,
CA publication, forest policy-registration contents and actual certificate enrollment.
Only settings represented by the supported XML are verified; this is not a byte-for-byte
copy of every source directory attribute. Enrollment remains a separate lab check.

`-WhatIf` performs no writes or verification of a proposed create/update. A genuine no-op
can still read and verify the existing template. A display-name difference on an existing
template is updated and verified.

Run the offline regression checks (no AD writes or installed PSPKI required):

```powershell
powershell.exe -NoProfile -File .\tests\Export-Serialization.Tests.ps1
powershell.exe -NoProfile -File .\tests\Export-Dependency.Tests.ps1
powershell.exe -NoProfile -File .\tests\Import-Verification.Tests.ps1
powershell.exe -NoProfile -File .\tests\Import-ControlFlow.Tests.ps1
powershell.exe -NoProfile -File .\tests\Review-Fixes.Tests.ps1
```

The fixtures check XML escaping, Unicode, both provider property names, exact AD intervals,
raw flags and extension bytes, plus rejection of missing/inconsistent source data. They do
not replace Windows PowerShell 5.1 tests with real PSPKI objects and CertEnroll in a lab.

The verification tests cover silent key-size resets, hash/provider drift, one-second
interval differences, missing values, criticality and application-policy differences,
malformed crypto metadata, unsigned flags, unsupported extensions and structured errors.
Control-flow tests replace AD/COM boundaries with test doubles and exercise create,
update, no-op, multi-policy isolation, pinned DC selection and WhatIf.

The new verification has been tested offline on PowerShell 7.4/Linux only. The
"Prior module testing" list above describes the prior module, not validation of this change. Before
merging, test on Windows PowerShell 5.1 with RSA/CSP, RSA/KSP and ECC schema 3/4 templates,
including actual readback and enrollment. Include a deliberate non-updatable difference
(e.g. EKU) and confirm that re-import terminates instead of reporting success.

## Review tracking (2.3.0 draft)

| Issue | Implemented changes | Regression coverage |
|---|---|---|
| [#3](https://github.com/bencoremans/CoreCert.TemplateUtils/issues/3) | Exact OID ownership, ambiguity/shared-use rejection, one confirmation, partial failure reporting | Wrong type, duplicate registration, shared reference, missing objects, WhatIf, failed second delete |
| [#4](https://github.com/bencoremans/CoreCert.TemplateUtils/issues/4) | Literal LDAP filters, forest context on a pinned DC, paging, resource disposal and terminating read errors | Get/Remove special-character names, import DC/context selection and read failure |
| [#5](https://github.com/bencoremans/CoreCert.TemplateUtils/issues/5) | Preflight every policy, required values, namespaces, OID groups, ranges, unsigned flags and one COM policy per create | Invalid second policy causes zero writes; invalid version, namespace/DTD, group and high-bit flags |
| [#6](https://github.com/bencoremans/CoreCert.TemplateUtils/issues/6) | Display name, non-decreasing revisions, idempotence and unsupported-difference detection before updates | Content/display changes, repeat import, downgrade/overflow and no partial unsupported update |
| [#7](https://github.com/bencoremans/CoreCert.TemplateUtils/issues/7) | Export fidelity, local OID table keyed by value+group, independent LDAP readback and explicit verification limits | Serialization, OID-group collision, crypto/extension drift and missing values |
| [#8](https://github.com/bencoremans/CoreCert.TemplateUtils/issues/8) | Packaging, documentation and five offline suites | Manifest import/export checks and PowerShell parsing |

All six issues are implemented in PR #2 and remain open until merge. This is a draft,
not a release tested in AD. Lab validation must cover Windows PowerShell 5.1, RSA/CSP,
RSA/KSP, ECC and schema 3/4 on the intended Windows versions, actual enrollment and
OID deletion in an isolated forest. No automatic merge or deployment is performed.

Dependency tests cover loading PSPKI on demand, reusing a loaded module, preserving loader errors, and importing CoreCert.TemplateUtils without loading PSPKI.

Run `powershell.exe -NoProfile -File .\tests\Policy-RoundTrip.Tests.ps1` with PSPKI installed to exercise the real extension classes without AD writes. The test also accepts `-LibraryPath` pointing to the PSPKI DLL directory for isolated offline testing.
