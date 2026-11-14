# CoreCert.TemplateUtils

PowerShell tools for AD CS certificate-template export, import/update and removal.
Version **3.0.0** is a breaking change: public import and export use one JSON bundle.
Standalone XML and separate registration sidecars are no longer accepted public formats.

## Requirements

Use Windows PowerShell 5.1 on a domain member with CertEnroll and the required AD
template/OID permissions. Install PSPKI separately (`Install-Module PSPKI`) or use your
approved existing installation. The module does not upgrade dependencies, change template
ACLs, publish templates to a CA or issue certificates. Directory writes target the selected
writable DC; PSPKI registration also requires the same forest in the executing context.

```powershell
Import-Module .\CoreCert.TemplateUtils.psd1
$server = 'dc01.example.test'
$template = @{
    templatePSPKI = Get-CertificateTemplate -Name 'Example-ServerTLS'
    templateADO = Get-ADCSTemplate -Name 'Example-ServerTLS' -Server $server
}
$json = Export-ADCSTemplate -Template $template -Server $server
$json | Set-Content .\Example-ServerTLS.json -Encoding UTF8

# Review a single-template import before creating a new target identity.
$json = Get-Content .\Example-ServerTLS.json -Raw
Import-ADCSTemplate -JsonString $json -Server $server `
    -Name 'Example-ServerTLS-Copy' -DisplayName 'Example Server TLS Copy' -WhatIf
Import-ADCSTemplate -JsonString $json -Server $server `
    -Name 'Example-ServerTLS-Copy' -DisplayName 'Example Server TLS Copy'
```

Export multiple templates by passing an array of `templatePSPKI`/`templateADO` pairs.
The resulting bundle contains all templates in one internal XML document, with deduplicated
policy registration metadata. `-Name` is allowed only for a single-template bundle.
Use [the example bundles](examples/templates/README.md) individually before considering a
larger import. A name that already exists follows the update path.

## Bundle contract

```json
{
  "FormatVersion": 1,
  "TemplateXml": "<GetPoliciesResponse>...</GetPoliciesResponse>",
  "PolicyRegistrations": [
    {"Oid":"1.2.3.4","OidGroup":"ApplicationPolicy","FriendlyName":"Example policy"}
  ]
}
```

The shortened XML above is illustrative, not an importable profile. `1.2.3.4` is an offline
placeholder, not an assigned enterprise namespace. Use authorized OIDs for actual policies.

`FormatVersion` must be integer 1. `TemplateXml` is the internal MS-XCEP representation;
`PolicyRegistrations` must always be an array, including `[]` or one entry. Each registration
contains exactly `Oid`, `OidGroup` (`ApplicationPolicy` or `IssuancePolicy`) and `FriendlyName`.
Unknown fields, malformed XML, invalid metadata and unsupported versions are rejected.

Export reads referenced policy registrations automatically from the selected source DC.
It preserves their numeric OID, type and actual display name. Missing source registrations
produce no invented metadata: the numeric policy reference remains in XML. Absence does
not classify an OID as built-in and does not guarantee complete environment portability.
CPS, user notices, localized names and group links require explicit migration decisions;
currently these registration attributes are rejected rather than silently omitted.

Import validates the whole bundle before writes. Referenced registrations already present
must match; missing registrations represented in the bundle are created before any template.
The same numeric OID cannot be supplied twice, including in different policy groups, because
the registration backend cannot safely represent that conflict. XML OIDs without bundle
registration metadata remain unchanged; no friendly name is guessed. Registration visibility
is bounded by `-PolicyRegistrationTimeoutSeconds` (default 120 seconds).

## Create, update and verification

Creation allocates a new template identity/OID. Template names can be overridden without
changing application/issuance policy OIDs. COM creation is followed by fresh AD readback and
bounded reconciliation from the XML for supported attributes that COM did not preserve.
This corrects the observed schema4 SHA256-to-SHA1 storage reset in the tested profile.
Reconciliation belongs to that same create and does **not** increment its source revision.

Supported repair includes flags, intervals, key size/specification, provider lists, key usage,
policy lists and understood packed cryptographic metadata. Identity, template OID, schema and
revision are not blindly repaired. Unsupported or ambiguous differences stop the operation.
Unknown registration metadata is not discarded. Optional XML containers retain their defaults.
A numeric `uSNChanged` comparison detects observed changes before repair; it is an optimistic
check, not an atomic protection against every concurrent modification.

For an existing template, supported changes use the existing update path and advance the
revision without downgrading; identical imports are no-ops. Unsupported updates fail before
that template is modified. Fresh verification is required after create, update and no-op.
`-WhatIf` does not write; `-Confirm` is honored. Structural validation is not a transaction:
errors during an actual multi-object operation can leave earlier registrations/templates.
There is no automatic rollback, retry, deletion or revision compensation.

## Removal

```powershell
Remove-ADCSTemplate -Name 'Example-ServerTLS-Copy' -Server $server -WhatIf
```

Removal checks the exact template and its own template-identity OID registration, including
ownership, ambiguity and sharing. It does not delete application/issuance policy registrations.
A partial failure is reported; inspect remaining objects before deciding how to continue.
The read-only [policy usage test](tests/integration/Policy-Usage.Integration.ps1) reports exact
references in the supported template attributes and group links. Unknown data stays
unknown; `DeleteAuthorized` is always false. Zero template references does not prove zero
external certificate/application use.

## Tests and evidence

See [tests/README.md](tests/README.md) for isolated offline suites and explicit opt-in live
cases. Tests do not automatically publish templates, grant enrollment rights or issue keys.

The preceding XML implementation passed live create/export/removal for all ten example
profiles, WebServer update/no-op, shared application/issuance registration reuse, real PSPKI
round trips, and sixteen isolated offline suites with actual PSPKI4.4. A separate live group-link
probe proved detection and explicit cleanup of its isolated empty test group/issuance policy.
These remain implementation baselines. The 3.0 JSON API separately passed all seventeen
isolated suites with actual PSPKI4.4, plus a live two-template bundle import, automatic
creation of two application and two issuance policy registrations, real multi-template
export and no-op reimport. Numeric OIDs/types/names and revisions were preserved.

Both bundle templates and their exact owned template OIDs were subsequently removed in
separate accepted steps. A private caller output-array error interrupted the first cleanup
step after successful removal; its corrected continuation removed only the remaining
template. All four policy registrations were deliberately retained.

Six additional JSON profiles passed actual import, PSPKI/AD export comparison and separate
removal: schema3 RSA3072/SHA384, schema4 RSA4096/SHA512, ECDSA P256/P384/P521,
and schema2 RSA2048 with a legacy CSP. The modern profiles used an explicit Software KSP.
The RSA3072 profile also exercised RA requirements, a supported flags/interval update with
one minor revision increment, and repeat-import no-op. Expected downgrade, unsupported
hash update, malformed second-template and registration-conflict refusals preserved AD
state; WhatIf with an absent registration created nothing.

Template import/export alone does not prove provider key operation, enrollment, TLS use,
revocation, multi-DC replication or production suitability. A single-DC lab cannot prove
replication. Untested combinations and enrollment require their own recorded results.
