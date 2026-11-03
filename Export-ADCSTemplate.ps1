
<#
.SYNOPSIS
    Exports one or more certificate templates to an MS-XCEP XML string.

.DESCRIPTION
    Serializes certificate template objects to the MS-XCEP GetPoliciesResponse XML format
    used by CX509EnrollmentPolicyWebService / Import-ADCSTemplate.

    Each template requires both the PSPKI template object (Get-CertificateTemplate) and the
    AD object (Get-ADCSTemplate) as input. The AD object supplies attributes not available
    through PSPKI alone (msPKI-Private-Key-Flag and exact validity/renewal intervals).

.PARAMETER Template
    One or more hashtables with keys:
        templatePSPKI  - Output of Get-CertificateTemplate
        templateADO    - Output of Get-ADCSTemplate

.EXAMPLE
    $t = @{
        templatePSPKI = Get-CertificateTemplate -Name "CC-WebServer"
        templateADO   = Get-ADCSTemplate        -Name "CC-WebServer"
    }
    $xml = Export-ADCSTemplate -Template $t

.EXAMPLE
    # Export multiple templates
    $templates = "CC-WebServer","CC-User" | ForEach-Object {
        @{
            templatePSPKI = Get-CertificateTemplate -Name $_
            templateADO   = Get-ADCSTemplate        -Name $_
        }
    }
    $xml = Export-ADCSTemplate -Template $templates
    $xml | Set-Content ".\templates\CC-Templates.xml" -Encoding UTF8

.NOTES
    Requires the PSPKI module (Install-Module PSPKI).
    Requires Enterprise Administrator permissions.
#>
function Export-ADCSTemplate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Template
    )

    if (-not (Get-Module -Name PSPKI -ErrorAction SilentlyContinue)) {
        try {
            Import-Module -Name PSPKI -ErrorAction Stop
        } catch {
            throw [InvalidOperationException]::new(
                "Export-ADCSTemplate requires PSPKI and could not load it. Install it with 'Install-Module PSPKI', then retry. Loader error: $($_.Exception.Message)",
                $_.Exception)
        }
    }

    # Normalize to array for consistent iteration
    if ($Template -is [hashtable] -or ($Template.PSObject.Properties.Name -contains 'templatePSPKI')) {
        $Template = @($Template)
    }

    if ($Template.Count -lt 1) {
        throw "At least one template must be specified in the 'Template' parameter."
    }

    foreach ($t in $Template) {
        if (-not $t.templatePSPKI -or -not $t.templateADO) {
            throw "Each template entry must contain 'templatePSPKI' and 'templateADO' keys."
        }
    }

    $ErrorActionPreference = "Stop"

    #region enums
    $HashAlgorithmGroup      = 1
    $EncryptionAlgorithmGroup = 2
    $PublicKeyIdGroup        = 3
    $ExtensionAttributeGroup = 6
    $EKUGroup                = 7
    $CertificatePolicyGroup  = 8
    $EnrollmentObjectGroup   = 9
    #endregion

    function Get-OIDid {
        param(
            [Parameter(Mandatory = $true)]
            [Security.Cryptography.Oid]$OID,
            [Parameter(Mandatory = $true)]
            [int]$group
        )
        if (-not $OID.Value) { Write-Error "OID Value is required."; return }
        for ($i = 0; $i -lt $oids.Count; $i++) {
            if ($oids[$i].Value -eq $OID.Value -and $oids[$i].Group -eq $group) { return $i + 1 }
        }
        $oids.Add([PSCustomObject]@{
            Value = $OID.Value
            Group = $group
            Name  = if ($OID.FriendlyName) { $OID.FriendlyName } else { "Unknown" }
        })
        return $oids.Count
    }

    function ConvertTo-XmlText {
        param([AllowNull()][string]$Value)
        if ($null -eq $Value) { return '' }
        [void][System.Xml.XmlConvert]::VerifyXmlChars($Value)
        return [System.Security.SecurityElement]::Escape($Value)
    }

    function Get-ADPeriodSeconds {
        param($Object, [string]$Attribute)
        $property = $Object.PSObject.Properties[$Attribute]
        if ($null -eq $property -or $null -eq $property.Value) {
            throw "Missing AD attribute '$Attribute'. Supply the full Get-ADCSTemplate object."
        }
        [byte[]]$bytes = $property.Value
        if ($bytes.Length -ne 8) { throw "AD attribute '$Attribute' must contain eight bytes." }
        [long]$ticks = [BitConverter]::ToInt64($bytes, 0)
        if ($ticks -gt 0 -or ($ticks % [TimeSpan]::TicksPerSecond) -ne 0) {
            throw "AD attribute '$Attribute' must be a nonpositive interval in whole seconds; refusing to round."
        }
        return (-[decimal]$ticks / [TimeSpan]::TicksPerSecond).ToString('0', [Globalization.CultureInfo]::InvariantCulture)
    }

    function Get-TemplateProviders {
        param($Cryptography)
        # PSPKI versions expose different property names. Missing is not the same as an empty list.
        $property = $Cryptography.PSObject.Properties['ProviderList']
        if ($null -eq $property) { $property = $Cryptography.PSObject.Properties['CSPList'] }
        if ($null -eq $property) {
            throw 'PSPKI cryptography object has neither ProviderList nor CSPList. Refusing to export an unrestricted provider list.'
        }
        foreach ($provider in $property.Value) {
            if ($provider -isnot [string] -or [string]::IsNullOrWhiteSpace($provider)) {
                throw 'PSPKI returned an invalid provider name.'
            }
            $provider
        }
    }

    $SB = New-Object Text.StringBuilder
    [void]$SB.Append(@"
<GetPoliciesResponse xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy">
    <response>
        <policyID/>
        <policyFriendlyName/>
        <nextUpdateHours>8</nextUpdateHours>
        <policiesNotChanged a:nil="true" xmlns:a="http://www.w3.org/2001/XMLSchema-instance"/>
        <policies>
"@)

    $oids = [Collections.Generic.List[object]]::new()

    foreach ($temp in $Template) {
        # The two objects must describe the same source template.
        if ([string]$temp.templatePSPKI.Name -cne [string]$temp.templateADO.Name) {
            throw 'PSPKI and AD template names differ.'
        }
        $privateFlags = $temp.templateADO.PSObject.Properties['msPKI-Private-Key-Flag']
        if ($null -eq $privateFlags -or $null -eq $privateFlags.Value) {
            throw 'Missing AD msPKI-Private-Key-Flag; refusing to substitute zero.'
        }
        $crypto = $temp.templatePSPKI.Settings.Cryptography
        foreach ($required in @('MinimalKeyLength', 'KeySpec', 'CNGKeyUsage', 'KeyAlgorithm', 'HashAlgorithm')) {
            if ($null -eq $crypto.PSObject.Properties[$required] -or $null -eq $crypto.$required) {
                throw "Missing PSPKI cryptography property '$required'."
            }
        }
        if ([string]::IsNullOrWhiteSpace($crypto.KeyAlgorithm.Value) -or
            [string]::IsNullOrWhiteSpace($crypto.HashAlgorithm.Value)) {
            throw 'PSPKI algorithm and hash OIDs must be populated.'
        }
        [void]$SB.Append("<policy>")

        $OID    = New-Object Security.Cryptography.Oid $temp.templatePSPKI.OID.Value, $temp.templatePSPKI.DisplayName
        $tempID = Get-OIDid $OID $EnrollmentObjectGroup

        $validity = Get-ADPeriodSeconds $temp.templateADO 'pKIExpirationPeriod'
        $renewal  = Get-ADPeriodSeconds $temp.templateADO 'pKIOverlapPeriod'

        $KU = if ([int]$temp.templatePSPKI.Settings.Cryptography.CNGKeyUsage -eq 0) {
            '<keyUsageProperty xmlns:a="http://www.w3.org/2001/XMLSchema-instance" a:nil="true"/>'
        } else {
            "<keyUsageProperty>$([int]$temp.templatePSPKI.Settings.Cryptography.CNGKeyUsage)</keyUsageProperty>"
        }

        $PKS = if ([string]::IsNullOrEmpty($temp.templatePSPKI.Settings.Cryptography.PrivateKeySecuritySDDL)) {
            '<permissions xmlns:a="http://www.w3.org/2001/XMLSchema-instance" a:nil="true"/>'
        } else {
            "<permissions>$(ConvertTo-XmlText $temp.templatePSPKI.Settings.Cryptography.PrivateKeySecuritySDDL)</permissions>"
        }

        $KeyAlgorithm = if ($temp.templatePSPKI.Settings.Cryptography.KeyAlgorithm.Value -eq "1.2.840.113549.1.1.1") {
            '<algorithmOIDReference xmlns:a="http://www.w3.org/2001/XMLSchema-instance" a:nil="true"/>'
        } else {
            $kalgID = Get-OIDid $temp.templatePSPKI.Settings.Cryptography.KeyAlgorithm $PublicKeyIdGroup
            "<algorithmOIDReference>$kalgID</algorithmOIDReference>"
        }

        $superseded = if ($temp.templatePSPKI.Settings.SupersededTemplates.Length -eq 0) {
            '<supersededPolicies xmlns:a="http://www.w3.org/2001/XMLSchema-instance" a:nil="true"/>'
        } else {
            $str = "<supersededPolicies>"
            $temp.templatePSPKI.Settings.SupersededTemplates | ForEach-Object { $str += "<commonName>$(ConvertTo-XmlText $_)</commonName>" }
            $str + "</supersededPolicies>"
        }

        $providers = @(Get-TemplateProviders $temp.templatePSPKI.Settings.Cryptography)
        $CSPs = if ($providers.Count -eq 0) {
            '<cryptoProviders xmlns:a="http://www.w3.org/2001/XMLSchema-instance" a:nil="true"/>'
        } else {
            $str = "<cryptoProviders>`n"
            $providers | ForEach-Object { $str += "<provider>$(ConvertTo-XmlText $_)</provider>`n" }
            $str + "</cryptoProviders>"
        }

        if ([string]$temp.templatePSPKI.Version -notmatch '^(\d+)\.(\d+)$') { throw 'Invalid source template version.' }
        $major = $matches[1]; $minor = $matches[2]
        foreach ($part in @($major,$minor)) {
            [int]$parsed=0
            if (-not [int]::TryParse($part,[ref]$parsed) -or $parsed -lt 0) { throw 'Invalid source template version range.' }
        }

        $hash = if ($temp.templatePSPKI.Settings.Cryptography.HashAlgorithm.Value -eq "1.3.14.3.2.26") {
            '<hashAlgorithmOIDReference xmlns:a="http://www.w3.org/2001/XMLSchema-instance" a:nil="true"/>'
        } else {
            $hashID = Get-OIDid $temp.templatePSPKI.Settings.Cryptography.HashAlgorithm $HashAlgorithmGroup
            "<hashAlgorithmOIDReference>$hashID</hashAlgorithmOIDReference>"
        }

        $RAR = if ($temp.templatePSPKI.Settings.RegistrationAuthority.SignatureCount -eq 0) {
            '<rARequirements xmlns:a="http://www.w3.org/2001/XMLSchema-instance" a:nil="true"/>'
        } else {
            $str = "<rARequirements><rASignatures>$($temp.templatePSPKI.Settings.RegistrationAuthority.SignatureCount)</rASignatures>"
            if ([string]::IsNullOrEmpty($temp.templatePSPKI.Settings.RegistrationAuthority.ApplicationPolicy.Value)) {
                $str += '<rAEKUs xmlns:a="http://www.w3.org/2001/XMLSchema-instance" a:nil="true"/>'
            } else {
                $raapID = Get-OIDid $temp.templatePSPKI.Settings.RegistrationAuthority.ApplicationPolicy $EKUGroup
                $str += "<rAEKUs><oIDReference>$raapID</oIDReference></rAEKUs>"
            }
            if ($temp.templatePSPKI.Settings.RegistrationAuthority.CertificatePolicies.Count -eq 0) {
                $str += '<rAPolicies xmlns:a="http://www.w3.org/2001/XMLSchema-instance" a:nil="true"/>'
            } else {
                $str += "<rAPolicies>"
                $temp.templatePSPKI.Settings.RegistrationAuthority.CertificatePolicies | ForEach-Object {
                    $raipID = Get-OIDid $_ $CertificatePolicyGroup
                    $str += "<oIDReference>$raipID</oIDReference>"
                }
                $str += "</rAPolicies>"
            }
            $str += "</rARequirements>"
            $str
        }

        $KAS = if (-not $temp.templatePSPKI.Settings.KeyArchivalSettings.KeyArchival) {
            '<keyArchivalAttributes xmlns:a="http://www.w3.org/2001/XMLSchema-instance" a:nil="true"/>'
        } else {
            $kasID = Get-OIDid $temp.templatePSPKI.Settings.KeyArchivalSettings.EncryptionAlgorithm $EncryptionAlgorithmGroup
            "<keyArchivalAttributes><symmetricAlgorithmOIDReference>$kasID</symmetricAlgorithmOIDReference><symmetricAlgorithmKeyLength>$($temp.templatePSPKI.Settings.KeyArchivalSettings.KeyLength)</symmetricAlgorithmKeyLength></keyArchivalAttributes>"
        }

        $sFlags = [Convert]::ToUInt32(("{0:x2}" -f [int]$temp.templatePSPKI.Settings.SubjectName), 16)

        [void]$SB.Append(@"
<policyOIDReference>$tempID</policyOIDReference>
<cAs><cAReference>0</cAReference></cAs>
<attributes>
    <commonName>$(ConvertTo-XmlText $temp.templatePSPKI.Name)</commonName>
    <policySchema>$($temp.templatePSPKI.SchemaVersion)</policySchema>
    <certificateValidity>
        <validityPeriodSeconds>$validity</validityPeriodSeconds>
        <renewalPeriodSeconds>$renewal</renewalPeriodSeconds>
    </certificateValidity>
    <permission><enroll>false</enroll><autoEnroll>false</autoEnroll></permission>
    <privateKeyAttributes>
        <minimalKeyLength>$($temp.templatePSPKI.Settings.Cryptography.MinimalKeyLength)</minimalKeyLength>
        <keySpec>$([int]$temp.templatePSPKI.Settings.Cryptography.KeySpec)</keySpec>
        $KU
        $PKS
        $KeyAlgorithm
        $CSPs
    </privateKeyAttributes>
    <revision><majorRevision>$major</majorRevision><minorRevision>$minor</minorRevision></revision>
    $superseded
    <privateKeyFlags>$([int]$temp.templateADO.'msPKI-Private-Key-Flag')</privateKeyFlags>
    <subjectNameFlags>$sFlags</subjectNameFlags>
    <enrollmentFlags>$([int]$temp.templatePSPKI.Settings.EnrollmentOptions)</enrollmentFlags>
    <generalFlags>$([int]$temp.templatePSPKI.Settings.GeneralFlags)</generalFlags>
    $hash
    $RAR
    $KAS
    <extensions>
"@)

        foreach ($ext in $temp.templatePSPKI.Settings.Extensions) {
            $extID    = Get-OIDid ($ext.Oid) $ExtensionAttributeGroup
            $critical = $ext.Critical.ToString().ToLower()
            $value    = [Convert]::ToBase64String($ext.RawData)
            [void]$SB.Append("<extension><oIDReference>$extID</oIDReference><critical>$critical</critical><value>$value</value></extension>")
        }

        [void]$SB.Append("</extensions></attributes></policy>")
    }

    [void]$SB.Append("</policies></response><oIDs>")

    $n = 1
    foreach ($oid in $oids) {
        [void]$SB.Append("<oID><value>$(ConvertTo-XmlText $oid.Value)</value><group>$($oid.Group)</group><oIDReferenceID>$n</oIDReferenceID><defaultName>$(ConvertTo-XmlText $oid.Name)</defaultName></oID>")
        $n++
    }

    [void]$SB.Append("</oIDs></GetPoliciesResponse>")
    # Validate the entire document before returning any XML to the caller.
    [xml]$document = $SB.ToString()
    return $document.OuterXml
}

