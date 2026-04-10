# CoreCert.TemplateUtils

PowerShell module voor het beheren van AD CS-certificaatsjablonen: exporteren naar portable XML, idempotent importeren/updaten, multi-tenant naam-override en opruimen — zonder AD-module-dependency voor import/update.

## Achtergrond

Vadims Podans ([@Crypt32](https://github.com/Crypt32)) ontdekte dat de COM-interfaces van MS-XCEP hergebruikt kunnen worden om certificaatsjablonen te exporteren naar een portable XML-formaat en te importeren in een AD-forest zonder forestvertrouwen. Zijn aanpak is gedocumenteerd in [Export and import certificate templates with PowerShell](https://www.sysadmins.lv/blog-en/export-and-import-certificate-templates-with-powershell.aspx).

Deze module bouwt op dat fundament met:

- **Idempotente import**: `Import-SerializedTemplate` detecteert automatisch of een sjabloon nieuw is (aanmaken) of al bestaat (diff → alleen gewijzigde attributen schrijven → versienummer ophogen). Geen aparte update-stap nodig.
- **Multi-tenant naam-override**: dezelfde XML importeren onder een andere naam per klant/forest.
- **Geen AD-module vereist** voor import- en updateoperaties — alleen PSPKI (voor export via `ConvertTo-SerializedTemplate`) en `Get-ADCSTemplate` (voor inspectie via `Get-ADObject`).

---

## Vereisten

- PowerShell 5.1 of nieuwer
- Windows Server 2008 R2 / Windows 7 of nieuwer (CertEnroll COM voor import)
- [PSPKI module](https://github.com/Crypt32/PSPKI) (`Install-Module PSPKI`) — vereist voor `ConvertTo-SerializedTemplate` en `Get-ADCSTemplate`
- Enterprise Administrator-rechten (sjablonen staan in de AD Configuration-partitie)

---

## Installatie

```powershell
# Via PowerShell Gallery
Install-Module CoreCert.TemplateUtils

# Of handmatig klonen en importeren
Import-Module .\CoreCert.TemplateUtils.psd1
```

---

## Hoe het werkt

### Export (`ConvertTo-SerializedTemplate`)

Leest een sjabloonobject via PSPKI's `Get-CertificateTemplate` en serialiseert het naar een **MS-XCEP-compatibele XML-string**. De XML bevat alle sjablooninstellingen: cryptografie, geldigheid, EKU, onderwerpvlaggen, extensies, sleutelarchiefopties en RA-vereisten.

### Import / Update (`Import-SerializedTemplate`)

Eén functie die de volledige levenscyclus afhandelt:

| Situatie | Gedrag |
|----------|--------|
| Sjabloon bestaat **niet** | Nieuw aanmaken via directe LDAP-schrijfoperatie + OID-registratie |
| Sjabloon **bestaat** (zelfde naam/OID) | XCEP-attributen vergelijken met AD; alleen gewijzigde attributen schrijven; versienummer ophogen |
| Sjabloon **niet gevonden**, OID **wel** | Orphan OID-fout met opruiminstructie |
| Geen wijzigingen | No-op (niets schrijven) |

De update-path gebruikt directe `System.DirectoryServices`-LDAP-operaties — geen AD-module nodig.

### Naam-override (multi-tenant / multi-forest)

Via `-Name` en `-DisplayName` wordt de XML in geheugen overschreven vóór import. Het bronbestand op disk blijft ongewijzigd. Bij naam- of displayname-override wordt altijd een nieuwe OID gemunt om conflicten te voorkomen.

```powershell
# Dezelfde XML, andere naam per klant
Import-SerializedTemplate -XmlString $xml -Name "ACME-WebServer"    -DisplayName "ACME Web Server"
Import-SerializedTemplate -XmlString $xml -Name "CONTOSO-WebServer" -DisplayName "Contoso Web Server"
```

---

## Functies

### `ConvertTo-SerializedTemplate`

Exporteert een of meer sjabloonobjecten naar een MS-XCEP XML-string.

```powershell
# Eén sjabloon exporteren
$xml = Get-CertificateTemplate -Name "CC-WebServer" | ConvertTo-SerializedTemplate

# Meerdere sjablonen exporteren (alle CC-* sjablonen)
$xml = Get-CertificateTemplate | Where-Object { $_.Name -like "CC-*" } | ConvertTo-SerializedTemplate

# Opslaan als bestand (versiebeheervriendelijk)
$xml | Set-Content -Path ".\templates\CC-Templates.xml" -Encoding ASCII
```

**Parameters:**

| Parameter | Type | Verplicht | Beschrijving |
|-----------|------|-----------|--------------|
| `-Template` | `CertificateTemplate[]` | Ja | Sjabloonobject(en) van `Get-CertificateTemplate` (PSPKI) |

---

### `Import-SerializedTemplate`

Importeert sjablonen vanuit MS-XCEP XML naar Active Directory — aanmaken als nieuw, updaten als bestaand.

```powershell
# Basisimport — originele naam behouden
Import-SerializedTemplate -XmlString $xml

# Importeren naar specifieke DC
Import-SerializedTemplate -XmlString $xml -Server "dc01.contoso.com"

# Importeren met nieuwe naam (multi-tenant)
Import-SerializedTemplate -XmlString $xml -Name "ACME-WebServer" -DisplayName "ACME Web Server"

# Versiebeheer: beginnen bij een schone versie
Import-SerializedTemplate -XmlString $xml -Name "CC-WebServer" -Version "100.1"

# Dry-run (geen schrijfoperaties)
Import-SerializedTemplate -XmlString $xml -Name "TEST-WebServer" -WhatIf
```

**Gedrag bij re-import (update):**

Wanneer een sjabloon met dezelfde naam al bestaat in AD, vergelijkt de functie alle XCEP-attributen met de AD-waarden. Alleen gewijzigde attributen worden geschreven; het versienummer (revision) wordt opgehoogd. Is er niets gewijzigd, dan is de operatie een no-op.

**Parameters:**

| Parameter | Type | Verplicht | Beschrijving |
|-----------|------|-----------|--------------|
| `-XmlString` | `string` | Ja | MS-XCEP XML van `ConvertTo-SerializedTemplate` |
| `-Name` | `string` | Nee | Nieuwe sjabloon-CN in AD. Overschrijft de originele naam; mingt een nieuwe OID. |
| `-DisplayName` | `string` | Nee | Nieuwe weergavenaam in AD. Overschrijft origineel; mingt een nieuwe OID. |
| `-Version` | `string` | Nee | Versie als `"major.minor"` (bijv. `"100.1"`). Overschrijft bronversie. |
| `-Server` | `string` | Nee | Doel-DC FQDN. Standaard: dichtstbijzijnde beschrijfbare DC. |
| `-Domain` | `string` | Nee | Domein-DN. Wordt automatisch ontdekt als niet opgegeven. |

---

### `Get-ADCSTemplate`

Leest sjablooneigenschappen rechtstreeks uit de AD Configuration-partitie. Handig voor inspectie, ACL-controle en het ophalen van een overzicht van alle sjablonen in AD.

> **Let op:** Deze functie vereist de ActiveDirectory-module (`RSAT` of `ActiveDirectory` PowerShell module), in tegenstelling tot `Import-SerializedTemplate`.

```powershell
# Alle sjablonen
Get-ADCSTemplate

# Specifiek sjabloon
Get-ADCSTemplate -Name "CC-WebServer"

# Van een specifieke DC
Get-ADCSTemplate -Server "dc01.contoso.com"

# Gesorteerd overzicht
Get-ADCSTemplate | Sort-Object Name | Format-Table Name, Created, Modified

# ACL bekijken
$t = Get-ADCSTemplate -Name "CC-WebServer"
$t.nTSecurityDescriptor.Access
ConvertFrom-SddlString -Sddl $t.nTSecurityDescriptor.Sddl -Type ActiveDirectoryRights
```

**Parameters:**

| Parameter | Type | Verplicht | Beschrijving |
|-----------|------|-----------|--------------|
| `-Name` | `string` | Nee | Sjabloon-CN. Geeft alle sjablonen terug als weggelaten. |
| `-Server` | `string` | Nee | Doel-DC FQDN. Standaard: dichtstbijzijnde DC. |

---

### `Remove-CertTemplateFromAD`

Verwijdert een sjabloon en de bijbehorende OID-registratie uit AD.

```powershell
# Verwijderen (vraagt om bevestiging)
Remove-CertTemplateFromAD -Name "CC-WebServer"

# Verwijderen zonder bevestiging
Remove-CertTemplateFromAD -Name "CC-WebServer" -Confirm:$false

# Dry-run
Remove-CertTemplateFromAD -Name "CC-WebServer" -WhatIf
```

**Parameters:**

| Parameter | Type | Verplicht | Beschrijving |
|-----------|------|-----------|--------------|
| `-Name` | `string` | Ja | CN van het te verwijderen sjabloon |
| `-Server` | `string` | Nee | Doel-DC FQDN |
| `-Domain` | `string` | Nee | Domein-DN (automatisch ontdekt als weggelaten) |

---

## Volledige workflow

```powershell
Import-Module PSPKI
Import-Module CoreCert.TemplateUtils

# 1. Exporteer sjablonen vanuit bronforest (of handmatig aangemaakte sjablonen in AD)
$xml = Get-CertificateTemplate | Where-Object { $_.Name -like "CC-*" } |
       ConvertTo-SerializedTemplate

# Sla op voor versiebeheer
$xml | Set-Content -Path ".\templates\CC-Templates.xml" -Encoding ASCII

# 2. Importeer in doelforest — zelfde naam
Import-SerializedTemplate -XmlString $xml -Server "dc01.target.com"

# 3. Of importeer met klant-specifieke naam
Import-SerializedTemplate -XmlString $xml `
    -Name "ACME-WebServer" `
    -DisplayName "ACME Web Server" `
    -Server "dc01.acme.com"

# 4. Re-importeer na aanpassing aan het bronsjabloon — automatisch update of no-op
Import-SerializedTemplate -XmlString $updatedXml -Name "ACME-WebServer" -Server "dc01.acme.com"

# 5. Inspecteer resultaat
Get-ADCSTemplate -Name "ACME-WebServer" -Server "dc01.acme.com" |
    Select-Object Name, DisplayName, Created, Modified

# 6. Opruimen (bijv. na test of vervanging)
Remove-CertTemplateFromAD -Name "ACME-WebServer" -Server "dc01.acme.com"
```

---

## Getest op

- Windows Server 2019 / 2022
- PowerShell 5.1
- PSPKI 4.4.0
- AD CS Enterprise CA

---

## Referenties

- [Export and import certificate templates with PowerShell](https://www.sysadmins.lv/blog-en/export-and-import-certificate-templates-with-powershell.aspx) — Vadims Podans
- [MS-XCEP: X.509 Certificate Enrollment Policy Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xcep/)
- [MS-CRTD: Certificate Template Structure](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/)
- [PSPKI PowerShell module](https://github.com/Crypt32/PSPKI)

## Credits

Originele export/import-techniek door [Vadims Podans](https://www.sysadmins.lv/). Deze module implementeert zijn aanpak in modulaire PowerShell-vorm en voegt idempotente import/update, multi-tenant naam-override en opschooningsondersteuning toe.
