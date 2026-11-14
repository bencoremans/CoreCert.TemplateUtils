# Source template examples

Start with **one** file, such as [CC-WebServer.json](CC-WebServer.json).
[CC-Templates.json](CC-Templates.json) contains all ten original policies; it is
provided as the bundle containing the unchanged source XML, not a command to import or publish everything.

Each bundle has FormatVersion=1, TemplateXml and PolicyRegistrations=[]. No custom policy registration metadata is invented for these original profiles. Each individual file retains its exact source policy and the complete original OID table.
Extra, unused OID-table entries are intentional. No algorithms, flags or permissions were
silently changed.

## First import

Run Windows PowerShell 5.1 with appropriate template-management rights, install the
module and PSPKI as described in the main README, and choose your writable DC:

```powershell
Import-Module .\CoreCert.TemplateUtils.psd1
$json = Get-Content .\examples\templates\CC-WebServer.json -Raw

# Review the single-template operation first; WhatIf does not create anything.
Import-ADCSTemplate -JsonString $json -Server 'dc01.example.test' `
    -Name 'Example-ServerTLS' -DisplayName 'Example Server TLS' -WhatIf

# After reviewing the profile and target name, perform that same import.
Import-ADCSTemplate -JsonString $json -Server 'dc01.example.test' `
    -Name 'Example-ServerTLS' -DisplayName 'Example Server TLS'
```

`-Name` is available for single-template bundles only. Use a new name for an isolated trial.
A name that already exists follows the module's update rules; it is not another create.
The source contains forest-specific template OIDs. Creation allocates a new target
identity; source OIDs are not instructions to reuse another forest's template identity.
Policy/EKU OIDs retain their meaning. Template enrollment ACLs and publication on a CA
are separate administrative steps. Importing this bundle does not authorize requesters or
prove that certificate enrollment succeeds. Do not publish all examples automatically.

Before the 3.0 JSON API change, all ten source profiles passed live public import, real PSPKI/AD export comparison
and removal of their own test template/OID on one DC. WebServer additionally passed a
display-name update and identical no-op import. This does not prove certificate
enrollment, provider operation, replication or production suitability.

## What is actually in these profiles?

All ten use schema4 and a minimum key length of 2048 bits. Algorithm references are nil
in the original source (the importer interprets this as RSA); that is not an explicit
provider restriction. Eight profiles specify SHA256. The two request-agent profiles
have a nil hash reference and therefore do **not** specify SHA256; review their legacy
provider/hash settings before use.

| File | Actual EKU purpose | Validity / renewal | Provider / hash notes |
|---|---|---|---|
| [CC-CepEncryption](CC-CepEncryption.json) | Certificate Request Agent (`1.3.6.1.4.1.311.20.2.1`) |365 /42 days| RSA SChannel CSP; hash nil |
| [CC-ClientAuth](CC-ClientAuth.json) | Client Authentication (`1.3.6.1.5.5.7.3.2`) |365 /42 days| Provider list nil; SHA256 |
| [CC-CodeSigning](CC-CodeSigning.json) | Code Signing (`1.3.6.1.5.5.7.3.3`) |365 /42 days| Provider list nil; SHA256 |
| [CC-DomainController](CC-DomainController.json) | KDC Authentication (`1.3.6.1.5.2.3.5`), Smart Card Logon (`1.3.6.1.4.1.311.20.2.2`), Server and Client Authentication |365 /42 days| Provider list nil; SHA256 |
| [CC-EnrollmentAgentComputer](CC-EnrollmentAgentComputer.json) | Certificate Request Agent (`1.3.6.1.4.1.311.20.2.1`) |365 /42 days| Enhanced/Base CSP list; hash nil |
| [CC-NDESDevice](CC-NDESDevice.json) | Client Authentication (`1.3.6.1.5.5.7.3.2`) |365 /42 days| Provider list nil; SHA256 |
| [CC-OCSPSigning](CC-OCSPSigning.json) | OCSP Signing (`1.3.6.1.5.5.7.3.9`) |14 /2 days| Provider list nil; SHA256; private-key service SDDL |
| [CC-UserAuth](CC-UserAuth.json) | Smart Card Logon and Client Authentication |365 /42 days| Provider list nil; SHA256; exportable-key bit set |
| [CC-WebServer](CC-WebServer.json) | Server Authentication (`1.3.6.1.5.5.7.3.1`) |365 /42 days| Provider list nil; SHA256; live-tested profile |
| [CC-WinRM](CC-WinRM.json) | Server Authentication (`1.3.6.1.5.5.7.3.1`) |365 /42 days| Provider list nil; SHA256 |

**CC-CepEncryption's name does not describe its actual EKU.** This export grants the
Certificate Request Agent purpose, not a distinct CEP-encryption EKU. It is retained
unchanged so the discrepancy is visible; do not infer suitability from its filename.

The OCSP source includes private-key SDDL for Administrators, SYSTEM and the fixed
`NT SERVICE\OCSPSvc` service SID (`S-1-5-80-3804348527-3718992918-2141599610-3686422417-2726379419`).
This is service-specific key metadata, not an exported domain-user SID or the template
DACL. Review it for the intended responder service; it has not been rewritten.

## Raw flags for review

Values below are copied from the XML, in hexadecimal. `Private` is privateKeyFlags,
`Subject` is subjectNameFlags, `Enrollment` is enrollmentFlags and `General` is generalFlags.
These examples preserve the source policy; they are not recommended security defaults.

| Template | Private | Subject | Enrollment | General |
|---|---|---|---|---|
| CC-CepEncryption |0x05050100|0x48000000|0x00000020|0x00020241|
| CC-ClientAuth |0x06060000|0x00000009|0x00000000|0x00020260|
| CC-CodeSigning |0x06060000|0x00000001|0x00000000|0x00020220|
| CC-DomainController |0x06060000|0x08400000|0x00000020|0x00020060|
| CC-EnrollmentAgentComputer |0x05050100|0x48000000|0x00000020|0x00020260|
| CC-NDESDevice |0x06060000|0x00000009|0x00000000|0x00020241|
| CC-OCSPSigning |0x06060000|0x18000000|0x00005020|0x00020240|
| CC-UserAuth |0x06060010|0x00000001|0x00000000|0x00020200|
| CC-WebServer |0x06060000|0x00000009|0x00000000|0x00020241|
| CC-WinRM |0x06060000|0x00000009|0x00000000|0x00020241|

In particular, supplied-subject profiles require an enrollment/SAN authorization design;
none of these files adds manager approval on your behalf. Legacy-provider profiles may
fall outside the module's bounded packed-metadata reconciliation support. Review and test
one profile before granting enrollment rights or publishing it on a CA.
