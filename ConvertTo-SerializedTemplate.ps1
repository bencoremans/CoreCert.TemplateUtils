<#
.SYNOPSIS
Converts template objects into a serialized format for use in certificate policies.

.DESCRIPTION
This function takes template objects as input and converts them to a serialized format that is used to define certificate policies. The function extracts and processes various properties from the input templates, including cryptographic settings, validity periods, key usage, and more.

.PARAMETER Template
Specifies the template object or objects to be converted. Each template object should contain PSPKI properties.

.EXAMPLE
templatePSPKI = Get-CertificateTemplate -Name "WebServer" -ErrorAction Stop | Select-Object *

ConvertTo-SerializedTemplate -Template $templateObject

Converts the specified template object into a serialized format for certificate policies.

.NOTES
The user must manually create the template for the first time in the ADCS Management Console. This allows users to use the GUI for initial template creation and then automate template modifications using this PowerShell function.

Before running this function, ensure that at least one template is specified in the 'Template' parameter. The function will throw an error if no templates are provided.

The original function is made by Vadims Podans.

.LINK
https://www.sysadmins.lv/blog-en/export-and-import-certificate-templates-with-powershell.aspx

#>
function ConvertTo-SerializedTemplate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Template
    )
        if ($Template.Name.count -lt 1) {
        throw "At least one template must be specified in the 'Template' parameter."
    }
    $ErrorActionPreference = "Stop"
    
    #region enums
    $HashAlgorithmGroup = 1
    $EncryptionAlgorithmGroup = 2
    $PublicKeyIdGroup = 3
    $SigningAlgorithmIdGroup = 4
    $RDNIdGroup = 5
    $ExtensionAttributeGroup = 6
    $EKUGroup = 7
    $CertificatePolicyGroup = 8
    $EnrollmentObjectGroup = 9
    #endregion
    
    function Get-OIDid {
        param (
            [Parameter(Mandatory = $true)]
            [Security.Cryptography.Oid]$OID,
    
            [Parameter(Mandatory = $true)]
            [int]$group
        )
    
        # Validate OID input
        if (-not $OID.Value) {
            Write-Error "OID Value is required."
            return
        }
    
        # Initialize the script-scoped OID array if it doesn't exist
        if (-not (Test-Path Variable:script:oids)) {
            $script:oids = @()
        }
    
        # Search for existing OID in the script-scoped array
        for ($i = 0; $i -lt $script:oids.Count; $i++) {
            if ($script:oids[$i].Value -eq $OID.Value) {
                # Return existing OID ID (increment by 1 because array index is zero-based)
                return $i + 1
            }
        }
    
        # OID not found, add new OID to the array
        $newOidObject = New-Object PSObject -Property @{
            Value = $OID.Value
            Group = $group
            Name  = if ($OID.FriendlyName) { $OID.FriendlyName } else { "Unknown" }
        }
    
        $script:oids += $newOidObject
        return $script:oids.Count # Return the new OID ID
    }
    
    function Get-Seconds {
        param (
            [Parameter(Mandatory = $true)]
            [string]$str
        )
    
        if (-not ("$str" -match "(\d+)\s(\w+)")) {
            Write-Error "Input string does not match the expected format ('number unit')."
            return
        }
    
        $period = $matches[1] -as [int]
        if ($period -eq $null) {
            Write-Error "The numeric part of the input was not recognized as an integer."
            return
        }
    
        $units = $matches[2].ToLower() # Normalize to lower case for consistent comparison
        $secondsPerUnit = @{
            "hours"   = 3600
            "days"    = 3600 * 24
            "weeks"   = 3600 * 168
            "months"  = 3600 * 720  # Approximation
            "years"   = 3600 * 8760
        }
    
        if ($units -in $secondsPerUnit.Keys) {
            return $period * $secondsPerUnit[$units]
        } else {
            Write-Error "Unrecognized time unit: $units. Supported units are hours, days, weeks, months, years."
        }
    }
    
    $SB = New-Object Text.StringBuilder
    [void]$SB.Append(
        @"
<GetPoliciesResponse xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy">
    <response>
        <policyID/>
        <policyFriendlyName/>
        <nextUpdateHours>8</nextUpdateHours>
        <policiesNotChanged a:nil="true" xmlns:a="http://www.w3.org/2001/XMLSchema-instance"/>
        <policies>
"@)
    $script:oids = @()
    foreach ($temp in $Template) {
        [void]$SB.Append("<policy>")
        $OID = New-Object Security.Cryptography.Oid $temp.OID.Value, $temp.DisplayName
        $tempID = Get-OIDid $OID $EnrollmentObjectGroup
        # validity/renewal
        $validity = Get-Seconds $temp.Settings.ValidityPeriod
        $renewal = Get-Seconds $temp.Settings.RenewalPeriod
        # key usages
        $KU = if ([int]$temp.Settings.Cryptography.CNGKeyUsage -eq 0) {
            '<keyUsageProperty xmlns:a="http://www.w3.org/2001/XMLSchema-instance" a:nil="true"/>'
        }
        else {
            "<keyUsageProperty>$([int]$temp.Settings.CNGKeyUsage)</keyUsageProperty>"
        }
        # private key security
        $PKS = if ([string]::IsNullOrEmpty($temp.Settings.Cryptography.PrivateKeySecuritySDDL)) {
            '<permissions xmlns:a="http://www.w3.org/2001/XMLSchema-instance" a:nil="true"/>'
        }
        else {
            "<permissions>$($temp.Settings.PrivateKeySecuritySDDL)</permissions>"
        }
        # public key algorithm
        $KeyAlgorithm = if ($temp.Settings.Cryptography.KeyAlgorithm.Value -eq "1.2.840.113549.1.1.1") {
            '<algorithmOIDReference xmlns:a="http://www.w3.org/2001/XMLSchema-instance" a:nil="true"/>'
        }
        else {
            $kalgID = Get-OIDid $temp.Settings.Cryptography.KeyAlgorithm $PublicKeyIdGroup
            "<algorithmOIDReference>$kalgID</algorithmOIDReference>"
        }
        # superseded templates
        $superseded = if ($temp.Settings.SupersededTemplates.Length -eq 0) {
            '<supersededPolicies xmlns:a="http://www.w3.org/2001/XMLSchema-instance" a:nil="true"/>'    
        }
        else {
            $str = "<supersededPolicies>"
            $temp.Settings.SupersededTemplates | ForEach-Object { $str += "<commonName>$_</commonName>" }
            $str + "</supersededPolicies>"
        }
        # list of CSPs
        $CSPs = if ($temp.Settings.Cryptography.ProviderList.Count -eq 0) {
            '<cryptoProviders xmlns:a="http://www.w3.org/2001/XMLSchema-instance" a:nil="true"/>'
        }
        else {
            $str = "<cryptoProviders>`n"
            $temp.Settings.Cryptography.ProviderList | ForEach-Object {
                $str += "<provider>$_</provider>`n"
            }
            $str + "</cryptoProviders>"
        }
        # version
        [void]($temp.Version -match "(\d+)\.(\d+)")
        $major = $matches[1]
        $minor = $matches[2]
        # hash algorithm
        $hash = if ($temp.Settings.Cryptography.HashAlgorithm.Value -eq "1.3.14.3.2.26") {
            '<hashAlgorithmOIDReference xmlns:a="http://www.w3.org/2001/XMLSchema-instance" a:nil="true"/>'
        }
        else {
            $hashID = Get-OIDid $temp.Settings.Cryptography.HashAlgorithm $HashAlgorithmGroup
            "<hashAlgorithmOIDReference>$hashID</hashAlgorithmOIDReference>"
        }
        # enrollment agent
        $RAR = if ($temp.Settings.RegistrationAuthority.SignatureCount -eq 0) {
            '<rARequirements xmlns:a="http://www.w3.org/2001/XMLSchema-instance" a:nil="true"/>'
        }
        else {
            $str = @"
<rARequirements>
<rASignatures>$($temp.Settings.RegistrationAuthority.SignatureCount)</rASignatures>
"@
            if ([string]::IsNullOrEmpty($temp.Settings.RegistrationAuthority.ApplicationPolicy.Value)) {
                $str += '<rAEKUs xmlns:a="http://www.w3.org/2001/XMLSchema-instance" a:nil="true"/>'
            }
            else {
                $raapID = Get-OIDid $temp.Settings.RegistrationAuthority.ApplicationPolicy $EKUGroup
                $str += @"
<rAEKUs>
    <oIDReference>$raapID</oIDReference>
</rAEKUs>
"@
            }
            if ($temp.Settings.RegistrationAuthority.CertificatePolicies.Count -eq 0) {
                $str += '<rAPolicies xmlns:a="http://www.w3.org/2001/XMLSchema-instance" a:nil="true"/>'
            }
            else {
                $str += "                       <rAPolicies>"
                $temp.Settings.RegistrationAuthority.CertificatePolicies | ForEach-Object {
                    $raipID = Get-OIDid $_ $CertificatePolicyGroup
                    $str += "<oIDReference>$raipID</oIDReference>`n"
                }
                $str += "</rAPolicies>`n"
            }
            $str += "</rARequirements>`n"
            $str
        }
        # key archival
        $KAS = if (!$temp.Settings.KeyArchivalSettings.KeyArchival) {
            '<keyArchivalAttributes xmlns:a="http://www.w3.org/2001/XMLSchema-instance" a:nil="true"/>'
        }
        else {
            $kasID = Get-OIDid $temp.Settings.KeyArchivalSettings.EncryptionAlgorithm $EncryptionAlgorithmGroup
            @"
<keyArchivalAttributes>
    <symmetricAlgorithmOIDReference>$kasID</symmetricAlgorithmOIDReference>
    <symmetricAlgorithmKeyLength>$($temp.Settings.KeyArchivalSettings.KeyLength)</symmetricAlgorithmKeyLength>
</keyArchivalAttributes>
"@
        }
        $sFlags = [Convert]::ToUInt32($("{0:x2}" -f [int]$temp.Settings.SubjectName), 16)
        [void]$SB.Append(
            @"
<policyOIDReference>$tempID</policyOIDReference>
<cAs>
    <cAReference>0</cAReference>
</cAs>
<attributes>
    <commonName>$($temp.Name)</commonName>
    <policySchema>$($temp.SchemaVersion)</policySchema>
    <certificateValidity>
        <validityPeriodSeconds>$validity</validityPeriodSeconds>
        <renewalPeriodSeconds>$renewal</renewalPeriodSeconds>
    </certificateValidity>
    <permission>
        <enroll>false</enroll>
        <autoEnroll>false</autoEnroll>
    </permission>
    <privateKeyAttributes>
        <minimalKeyLength>$($temp.Settings.Cryptography.MinimalKeyLength)</minimalKeyLength>
        <keySpec>$([int]$temp.Settings.Cryptography.KeySpec)</keySpec>
        $KU
        $PKS
        $KeyAlgorithm
        $CSPs
    </privateKeyAttributes>
    <revision>
        <majorRevision>$major</majorRevision>
        <minorRevision>$minor</minorRevision>
    </revision>
    $superseded
    <privateKeyFlags>$([int]$temp.Settings.Cryptography.PrivateKeyOptions)</privateKeyFlags>
    <subjectNameFlags>$sFlags</subjectNameFlags>
    <enrollmentFlags>$([int]$temp.Settings.EnrollmentOptions)</enrollmentFlags>
    <generalFlags>$([int]$temp.Settings.GeneralFlags)</generalFlags>
    $hash
    $rar
    $KAS
<extensions>
"@)
        foreach ($ext in $temp.Settings.Extensions) {
            $extID = Get-OIDid ($ext.Oid) $ExtensionAttributeGroup
            $critical = $ext.Critical.ToString().ToLower()
            $value = [Convert]::ToBase64String($ext.RawData)
            [void]$SB.Append("<extension><oIDReference>$extID</oIDReference><critical>$critical</critical><value>$value</value></extension>")
        }
        [void]$SB.Append("</extensions></attributes></policy>")
    }
    [void]$SB.Append("</policies></response>")
    [void]$SB.Append("<oIDs>")
    $n = 1
    $script:oids | ForEach-Object {
        [void]$SB.Append(@"
<oID>
    <value>$($_.Value)</value>
    <group>$($_.Group)</group>
    <oIDReferenceID>$n</oIDReferenceID>
    <defaultName>$($_.Name)</defaultName>
</oID>
"@)
        $n++
    }
    [void]$SB.Append("</oIDs></GetPoliciesResponse>")
    Return $SB.ToString()
}