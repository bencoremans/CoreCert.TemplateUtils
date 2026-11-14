# Source template examples

Start with **one** file, such as [CC-WebServer.xcep.xml](CC-WebServer.xcep.xml).
[CC-Templates.xcep.xml](CC-Templates.xcep.xml) contains all ten original policies; it is
provided as the unchanged source export, not a command to import or publish everything.

Each individual file retains its exact source policy and the complete original OID table.
Extra, unused OID-table entries are intentional. No algorithms, flags or permissions were
silently changed. The separate JSON export from another revision is not included.

## First import

Run Windows PowerShell 5.1 with appropriate template-management rights, install the
module and PSPKI as described in the main README, and choose your writable DC:

```powershell
Import-Module .\CoreCert.TemplateUtils.psd1
$xml = Get-Content .\examples\templates\CC-WebServer.xcep.xml -Raw

# Review the single-template operation first; WhatIf does not create anything.
Import-ADCSTemplate -XmlString $xml -Server 'dc01.example.test' `
    -Name 'Example-ServerTLS' -DisplayName 'Example Server TLS' -WhatIf

# After reviewing the profile and target name, perform that same import.
Import-ADCSTemplate -XmlString $xml -Server 'dc01.example.test' `
    -Name 'Example-ServerTLS' -DisplayName 'Example Server TLS'
```

`-Name` is available for single-policy XML only. Use a new name for an isolated trial.
A name that already exists follows the module's update rules; it is not another create.
The source contains forest-specific template OIDs. Creation allocates a new target
identity; source OIDs are not instructions to reuse another forest's template identity.
Policy/EKU OIDs retain their meaning. Template enrollment ACLs and publication on a CA
are separate administrative steps. Importing this XML does not authorize requesters or
prove that certificate enrollment succeeds. Do not publish all examples automatically.

Only **CC-WebServer** has been tested here through real COM creation, automatic XML
reconciliation and export from AD/PSPKI. It remained unpublished, with revision100.5 and
SHA256 preserved. The other nine are source examples, not live-tested recipes.

## What is actually in these profiles?

All ten use schema4 and a minimum key length of 2048 bits. Algorithm references are nil
in the original source (the importer interprets this as RSA); that is not an explicit
provider restriction. Eight profiles specify SHA256. The two request-agent profiles
have a nil hash reference and therefore do **not** specify SHA256; review their legacy
provider/hash settings before use.

| File | Actual EKU purpose | Validity / renewal | Provider / hash notes |
|---|---|---|---|
| [CC-CepEncryption](CC-CepEncryption.xcep.xml) | Certificate Request Agent (`1.3.6.1.4.1.311.20.2.1`) |365 /42 days| RSA SChannel CSP; hash nil |
| [CC-ClientAuth](CC-ClientAuth.xcep.xml) | Client Authentication (`1.3.6.1.5.5.7.3.2`) |365 /42 days| Provider list nil; SHA256 |
| [CC-CodeSigning](CC-CodeSigning.xcep.xml) | Code Signing (`1.3.6.1.5.5.7.3.3`) |365 /42 days| Provider list nil; SHA256 |
| [CC-DomainController](CC-DomainController.xcep.xml) | KDC Authentication (`1.3.6.1.5.2.3.5`), Smart Card Logon (`1.3.6.1.4.1.311.20.2.2`), Server and Client Authentication |365 /42 days| Provider list nil; SHA256 |
| [CC-EnrollmentAgentComputer](CC-EnrollmentAgentComputer.xcep.xml) | Certificate Request Agent (`1.3.6.1.4.1.311.20.2.1`) |365 /42 days| Enhanced/Base CSP list; hash nil |
| [CC-NDESDevice](CC-NDESDevice.xcep.xml) | Client Authentication (`1.3.6.1.5.5.7.3.2`) |365 /42 days| Provider list nil; SHA256 |
| [CC-OCSPSigning](CC-OCSPSigning.xcep.xml) | OCSP Signing (`1.3.6.1.5.5.7.3.9`) |14 /2 days| Provider list nil; SHA256; private-key service SDDL |
| [CC-UserAuth](CC-UserAuth.xcep.xml) | Smart Card Logon and Client Authentication |365 /42 days| Provider list nil; SHA256; exportable-key bit set |
| [CC-WebServer](CC-WebServer.xcep.xml) | Server Authentication (`1.3.6.1.5.5.7.3.1`) |365 /42 days| Provider list nil; SHA256; live-tested profile |
| [CC-WinRM](CC-WinRM.xcep.xml) | Server Authentication (`1.3.6.1.5.5.7.3.1`) |365 /42 days| Provider list nil; SHA256 |

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