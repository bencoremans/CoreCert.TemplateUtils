# Repeatable module tests

## Offline suites

From the repository root on Windows PowerShell5.1:

```powershell
.\tests\Run-OfflineTests.ps1
# Optional: run the real pkix extension suites using an existing PSPKI Library directory.
.\tests\Run-OfflineTests.ps1 -LibraryPath 'C:\TestDependencies\PSPKI\Library'
```

The runner creates a new temporary output directory and starts **one fresh PowerShell
process per suite**. `results.json` records Pass/Fail/Skip, exit codes, source hashes and
separate stdout/stderr files. Existing evidence is not overwritten. Integration scripts
are never started by this runner. Supply `-OutputDirectory` for an explicit new location.

There are two dependency levels:

- Ordinary suites use explicit fixtures and storage/transport doubles, without AD,
  CertEnroll, installed PSPKI or key generation.
- `Policy-RoundTrip.Tests.ps1` and `Custom-ApplicationPolicy.Tests.ps1` require actual
  pkix.net extension classes from installed PSPKI or `-LibraryPath`. Missing libraries
  yield **Skip**, not Pass. A provided invalid library path fails the test.

| Coverage | Executable tests | Limit |
|---|---|---|
| Ten original examples | Examples | Input/OID validation, independent EKU/flag/period contracts, exact single-policy derivations; no AD import |
| RSA/ECC/providers | Algorithm-Fidelity | RSA2048/3072/4096, P256/P384/P521, schema3/4 plus legacyRSA, provider order and exported/imported expectation; no provider/key operation |
| Create reconciliation | Create-Reconciliation | Real importer flow with COM/LDAP doubles, reset combinations and fail-closed storage outcomes |
| Updates/revisions/no-op | Import-ControlFlow, Review-Fixes | Supported update, repeat no-op, unsupported difference refusal, revisions and preflight; mocked directory |
| Removal | Review-Fixes | Ownership/shared-OID/ambiguity, first-delete refusal, partial second-delete failure, missing objects and WhatIf |
| Policy registration | Policy-Registration, Import-ControlFlow | Conflicts, missing/incomplete registrations, reuse and registration-before-template ordering; mocked directory/registration |
| Custom ApplicationPolicy distinct from EKU | Examples, Custom-ApplicationPolicy, Policy-RoundTrip | Structural/bundle coverage always; real extension decoding only with pkix dependency |
| Nil XML and concurrent-change baseline | Strict-OptionalXml, Reconciliation-Usn | Missing/empty containers, numeric COM/Int64 version checks and refusal; not an atomic concurrency guarantee |

`fixtures/CustomApplicationPolicy.json` is a separate synthetic test profile.
It has Server Authentication EKU, **different** custom ApplicationPolicy OID `1.2.3.4`,
and complete registration metadata in its PolicyRegistrations array.
The OID is an offline placeholder, not a claim of enterprise ownership. Before live registration, supply your own authorized test OID and matching bundle; the lifecycle script refuses registration of this placeholder.
The original examples are not modified to supply missing test data.

## Explicit live acceptance cases (not run by the offline runner)

These scripts contain real module/native calls. Their default invocation returns Skip
before any directory or enrollment action. They are supplied for separately authorized
lab runs; merely adding or parsing these tests does not prove live acceptance.

### Template/policy lifecycle

`integration/Template-Lifecycle.Integration.ps1` runs one phase per invocation:
`Create`, `Update`, `Export`, `Remove` or `PolicyExport`. It requires `-RunLive`, a pinned
`-Server`, a `TU-Test-*` name and new `-ReportPath`. Create refuses an existing name.
Other object phases require its exact `-ExpectedObjectGuid` and `-ExpectedTemplateOid`.
Choose one JSON bundle using `-BundlePath`; it contains complete custom registration
metadata. PolicyExport compares exported OID/group/name values with the input bundle.

Create uses the actual public importer and compares actual AD/PSPKI export with source
settings. Update exercises a changed display name, one minor revision increment, then
repeats that same import and checks that it is a no-op. Use the same source profile and
revision as the creation; this case deliberately is not a source-revision upgrade test.
Remove checks that the explicitly bound template and its owned OID disappear; it does
not delete custom ApplicationPolicy registrations. Choose Remove separately after
reviewing evidence. **There is no automatic cleanup, retry, publication or ACL change.**

Run with an existing account that has the required template/OID permissions, on a domain
member with Windows PowerShell5.1, CertEnroll, this module and actual PSPKI. Preserve the
baseline/report before removal. A failure may leave the new object/registration in AD.

### Replication

`integration/Replication.Integration.ps1 -RunLive` requires two distinct DCs through
`-PrimaryServer` and `-SecondaryServer`, plus `-Name` and `-ExpectedObjectGuid` from the new Create result. RootDSE hostnames must also differ
(aliases of one DC are rejected), and both must share one forest configuration context. It reads the newly created object and compares GUID, OID and
selected profile fields. It neither forces replication nor compares USNs between DCs.
One-DC labs cannot run this acceptance case. A mismatch is a failure, not automatic retry.

### Enrollment

`integration/Enrollment.Integration.ps1` requires **both** `-RunLive` and
`-AllowEnrollment`, an existing published `TU-Test-*` template, `-CaConfig`, exact current
`-ExpectedIdentity`, `-ExpectedTemplateOid`, `-DnsName`, `-Provider 'Microsoft Software Key Storage Provider'`
and a new `-OutputDirectory`. Prepare the existing pilot account/template/CA separately;
the script does not create accounts, grant ACLs or publish templates.

This case creates a nonexportable current-user RSA2048/SHA256 request, submits it and
checks the issued subject, public key against its own CSR, single DNS SAN, Server Authentication EKU, expected template OID and chain/revocation. It does not install the
certificate or test application TLS. Pending approval is not a Pass. It can leave a
private key and CA request behind after failure; no deletion or resubmission is automatic.
Other providers/key algorithms and application TLS acceptance need
separate cases before broader deployment claims.

## Evidence status before the 3.0 JSON API change

The initial expanded offline run had eleven passing suites and two dependency skips on
its host. Both dependency suites subsequently passed on Windows PowerShell5.1 with
real PSPKI4.4/pkix.net. The final complete isolated run passed all sixteen suites with
zero skips or failures using those libraries. A JSON bundle regression covers one- and multiple-entry
arrays on PowerShell5.1; consumers must assign ConvertFrom-Json output directly.

The opt-in WebServer lifecycle Create/export and Update/no-op phases passed live:
one minor revision increment, unchanged GUID/OID, and no write on the identical second
import. The template remained unpublished. The first Remove phase exposed an ADSI
adapter issue: Parent resolved to a string rather than the .NET DirectoryEntry.
The correction explicitly uses PSBase.Parent/Children/Dispose. Focused regressions cover
both adapted-parent lookup and member lookup after deletion. After a separate controlled
cleanup of the owned unused registration, a fresh public Create/export followed by the
public Remove passed live: both the new template and its exact owned template OID were
removed, the other OID registrations were unchanged, and the CA list remained empty.
The historical failed attempts remain failures; the fresh pass proves the corrected path.
Application/issuance-policy registration removal is not part of this proof.
All ten supplied source profiles have now passed live import, real PSPKI/AD export
comparison and public removal of their own template/OID. Two additional templates
shared the same newly registered ApplicationPolicy and IssuancePolicy: registration
export matched the sidecar; removing one retained the other and both registrations;
removing the second still retained both policy registrations. Their identities and
metadata remained unchanged. No policy-registration deletion was performed.

Replication and certificate enrollment remain untested by these cases. Serialization
and template import do not prove cryptographic provider behavior or deployment readiness.

## Read-only policy usage report

`integration/Policy-Usage.Integration.ps1 -RunLive -Server <dc> -Oid <oid> -ReportPath <new.json>`
reads all templates and policy registrations from one DC. It checks exact OID tokens in
EKU, application policy, issuance policy and both RA policy attributes, including the
schema-dependent legacy/packed RA form; template-identity collisions are also reported.
Unrecognized/unreadable metadata produces `Unknown`, never an unused-policy assertion.
Group links and registration ambiguity are reported. The helper never authorizes deletion:
no template references does not establish absence of external certificate/application use.

`Policy-Usage.Tests.ps1` covers all five reference attributes, shared references, exact
matching, malformed/schema-inconsistent metadata and group links. The optional report
script defaults to Skip; it is not a policy cleanup API.
## Version 3.0 bundle tests

Bundle-Format tests array shapes; Bundle-Contract tests the public API, automatic source registration export, absent-registration preservation, invalid envelopes and WhatIf/Confirm. Import-ControlFlow invokes the actual importer through the public JSON wrapper. The older live results above remain baselines. The 3.0 runner passed all seventeen suites with actual PSPKI4.4 and no skipped dependencies. No XML/sidecar public compatibility is retained.

A live bundle with two templates and four custom registrations (two application, two issuance) passed public import, automatic registration creation, real export and identical no-op reimport. OID/type/name, object identity and revisions were retained. Both templates and their exact owned template OIDs were separately removed; all four policy registrations were deliberately retained. A private caller output-array error interrupted cleanup after the first successful removal. The reviewed continuation removed only the remaining template, without repeating the first removal.

Six additional JSON profiles passed actual import, real PSPKI/AD export comparison and separately selected removal:

| Profile | Schema | Hash | Provider |
| --- | --- | --- | --- |
| RSA3072 | 3 | SHA384 | Microsoft Software Key Storage Provider |
| RSA4096 | 4 | SHA512 | Microsoft Software Key Storage Provider |
| ECDSA P256 | 4 | SHA256 | Microsoft Software Key Storage Provider |
| ECDSA P384 | 3 | SHA384 | Microsoft Software Key Storage Provider |
| ECDSA P521 | 4 | SHA512 | Microsoft Software Key Storage Provider |
| RSA2048 legacy | 2 | No explicit modern hash metadata | Microsoft RSA SChannel Cryptographic Provider |

The ECC profiles retained KeySpec0, signing-only CNG usage and DigitalSignature key usage. The schema2 profile used legacy metadata semantics. These are template storage/export results, not evidence of provider key generation or signing.

The RSA3072 profile additionally retained RA signature count1, Certificate Request Agent application policy and a custom issuance policy. Its supported update changed enrollment flags to manager approval and validity/renewal to180/30 days, advanced revision100.5 to100.6, and preserved identity. Repeating that import left the numeric USN unchanged.

Separate negative live calls refused an explicit revision downgrade, an unsupported hash update, an invalid second template in a bundle and conflicting policy-registration metadata. Each matched its predetermined error and preserved template identity/revision/USN, policy identities/USNs and directory object sets. WhatIf with a new template and absent policy registration created neither object. The CA publication list stayed empty throughout; no certificates were requested or issued.

These results do not establish enrollment, provider key operation, TLS, revocation, multi-DC replication or arbitrary combinations of template settings.
