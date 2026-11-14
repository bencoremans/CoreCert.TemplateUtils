. (Join-Path $PSScriptRoot 'TemplatePolicyLibrary.ps1')

# Internal helpers. Verification reads raw LDAP, independently of CertEnroll's save path.
function ConvertTo-TemplateInt32 {
    param($Value)
    [long]$number = [long]::Parse([string]$Value, [Globalization.CultureInfo]::InvariantCulture)
    if ($number -lt [int]::MinValue -or $number -gt [uint32]::MaxValue) { throw 'Invalid 32-bit template value.' }
    if ($number -gt [int]::MaxValue) { $number -= 4294967296 }
    return [int]$number
}

function ConvertTo-TemplateLdapFilterValue {
    param([string]$Value)
    $Value.Replace('\', '\5c').Replace('*', '\2a').Replace('(', '\28').Replace(')', '\29').Replace([string][char]0, '\00')
}

function Read-TemplateDerElement {
    param([byte[]]$Bytes, [ref]$Offset)
    $start = [int]$Offset.Value
    if ($start + 2 -gt $Bytes.Length) { throw 'Truncated extension DER.' }
    $tag = $Bytes[$start]; $position = $start + 2; [long]$length = $Bytes[$start + 1]
    if ($length -ge 128) {
        $count = $length -band 127
        if ($count -eq 0 -or $count -gt 4 -or $position + $count -gt $Bytes.Length) { throw 'Invalid DER length.' }
        if ($Bytes[$position] -eq 0) { throw 'Noncanonical DER length.' }
        $length = 0
        for ($i = 0; $i -lt $count; $i++) { $length = ($length * 256) + $Bytes[$position++ ] }
    }
    if ($Bytes[$start + 1] -ge 128 -and $length -lt 128) { throw 'Noncanonical DER length.' }
    if ($position + $length -gt $Bytes.Length) { throw 'Truncated extension DER value.' }
    $end = [int]($position + $length)
    [byte[]]$value = @(); if ($length) { $value = $Bytes[$position..($end - 1)] }
    $Offset.Value = $end
    [pscustomobject]@{ Tag = $tag; Value = $value }
}

function Read-TemplatePolicyOids {
    param([byte[]]$Bytes, [string]$ExtensionOid = '2.5.29.32')
    $offset = 0; $outer = Read-TemplateDerElement $Bytes ([ref]$offset)
    if ($outer.Tag -ne 48 -or $offset -ne $Bytes.Length -or $outer.Value.Length -eq 0) { throw 'Invalid policy extension DER.' }
    $offset = 0
    while ($offset -lt $outer.Value.Length) {
        $policy = Read-TemplateDerElement $outer.Value ([ref]$offset)
        if ($policy.Tag -ne 48) { throw 'Invalid policy information DER.' }
        $inner = 0; $oid = Read-TemplateDerElement $policy.Value ([ref]$inner)
        if ($oid.Tag -ne 6) { throw 'Expected policy OID.' }
        # Qualifiers may depend on forest OID registrations; do not claim they were verified.
        if ($inner -ne $policy.Value.Length) { throw 'Policy qualifiers cannot be verified from template LDAP attributes. Import stopped before writing.' }
    }
    # Keep the structural/qualifier check above. pkix.net handles decoding the OIDs.
    $typeName = switch ($ExtensionOid) {
        '1.3.6.1.4.1.311.21.10' { 'SysadminsLV.PKI.Cryptography.X509Certificates.X509ApplicationPoliciesExtension' }
        '2.5.29.32' { 'SysadminsLV.PKI.Cryptography.X509Certificates.X509CertificatePoliciesExtension' }
        default { throw "Unsupported policy extension '$ExtensionOid'." }
    }
    Import-TemplatePolicyLibrary 'Template policy verification' $typeName
    $encoded = [Security.Cryptography.AsnEncodedData]::new($Bytes)
    if ($ExtensionOid -eq '1.3.6.1.4.1.311.21.10') {
        $extension = [SysadminsLV.PKI.Cryptography.X509Certificates.X509ApplicationPoliciesExtension]::new($encoded, $false)
        foreach ($item in $extension.ApplicationPolicies) { $item.Value }
    } else {
        $extension = [SysadminsLV.PKI.Cryptography.X509Certificates.X509CertificatePoliciesExtension]::new($encoded, $false)
        foreach ($item in $extension.Policies) { $item.PolicyOid.Value }
    }
}

function Get-TemplateXmlExpectation {
    param([xml]$Document, $Policy, [string]$DisplayName)
    $a = $Policy.attributes
    $oidTable = @{}
    foreach ($oid in $Document.GetPoliciesResponse.oIDs.oID) {
        $id = [string]$oid.oIDReferenceID
        if ($oidTable.ContainsKey($id)) { throw "Duplicate OID reference '$id'." }
        $oidTable[$id] = [string]$oid.value
    }
    function Resolve-Oid($Node, [string]$Default = '') {
        if ($null -eq $Node -or ($Node -is [Xml.XmlElement] -and $Node.GetAttribute('nil', 'http://www.w3.org/2001/XMLSchema-instance') -eq 'true')) { return $Default }
        $id = [string]$Node
        if (-not $oidTable.ContainsKey($id)) { throw "Unresolved OID reference '$id'." }
        $oidTable[$id]
    }
    $expected = [ordered]@{ cn = [string]$a.commonName; displayName = $DisplayName }
    $map = @{
        'msPKI-Private-Key-Flag' = $a.privateKeyFlags
        'msPKI-Certificate-Name-Flag' = $a.subjectNameFlags
        'msPKI-Enrollment-Flag' = $a.enrollmentFlags
        flags = $a.generalFlags
        'msPKI-Template-Schema-Version' = $a.policySchema
        pKIDefaultKeySpec = $a.privateKeyAttributes.keySpec
        'msPKI-Minimal-Key-Size' = $a.privateKeyAttributes.minimalKeyLength
        revision = $a.revision.majorRevision
        'msPKI-Template-Minor-Revision' = $a.revision.minorRevision
    }
    foreach ($key in $map.Keys) {
        if ([string]::IsNullOrWhiteSpace([string]$map[$key])) { throw "Missing required XML value for '$key'." }
        $expected[$key] = ConvertTo-TemplateInt32 $map[$key]
    }
    foreach ($pair in @(@('pKIExpirationPeriod', $a.certificateValidity.validityPeriodSeconds), @('pKIOverlapPeriod', $a.certificateValidity.renewalPeriodSeconds))) {
        [long]$seconds = 0
        if (-not [long]::TryParse([string]$pair[1], [ref]$seconds) -or $seconds -lt 0 -or $seconds -gt 922337203685) { throw "Invalid period '$($pair[0])'." }
        $expected[$pair[0]] = [Convert]::ToBase64String([BitConverter]::GetBytes([long](-[decimal]$seconds * 10000000)))
    }
    # Nil optional containers have no child properties. XPath keeps absence
    # explicit and works when callers enable StrictMode.
    $raCount=$a.SelectSingleNode('*[local-name()="rARequirements"]/*[local-name()="rASignatures"]')
    $expected['msPKI-RA-Signature'] = if ($null -ne $raCount) { ConvertTo-TemplateInt32 $raCount.InnerText } else { 0 }
    $expected['msPKI-Supersede-Templates'] = @($a.SelectNodes('*[local-name()="supersededPolicies"]/*[local-name()="commonName"]') | ForEach-Object { $_.InnerText })
    $expected['Providers'] = @($a.SelectNodes('*[local-name()="privateKeyAttributes"]/*[local-name()="cryptoProviders"]/*[local-name()="provider"]') | ForEach-Object { $_.InnerText })
    $expected['AsymmetricAlgorithm'] = Resolve-Oid $a.privateKeyAttributes.algorithmOIDReference '1.2.840.113549.1.1.1'
    $expected['HashAlgorithm'] = Resolve-Oid $a.hashAlgorithmOIDReference '1.3.14.3.2.26'
    $expected['CngKeyUsage'] = if ($a.privateKeyAttributes.keyUsageProperty -is [string]) { ConvertTo-TemplateInt32 $a.privateKeyAttributes.keyUsageProperty } else { 0 }
    $expected['PrivateKeySDDL'] = if ($a.privateKeyAttributes.permissions -is [string]) { [string]$a.privateKeyAttributes.permissions } else { '' }
    $expected['RAApplicationPolicies'] = @($a.SelectNodes('*[local-name()="rARequirements"]/*[local-name()="rAEKUs"]/*[local-name()="oIDReference"]') | ForEach-Object { Resolve-Oid $_.InnerText })
    $expected['msPKI-RA-Policies'] = @($a.SelectNodes('*[local-name()="rARequirements"]/*[local-name()="rAPolicies"]/*[local-name()="oIDReference"]') | ForEach-Object { Resolve-Oid $_.InnerText })
    $symmetric=$a.SelectSingleNode('*[local-name()="keyArchivalAttributes"]/*[local-name()="symmetricAlgorithmOIDReference"]')
    if ($null -ne $symmetric) {
        $expected['SymmetricAlgorithm'] = Resolve-Oid $symmetric.InnerText
        $expected['SymmetricKeyLength'] = ConvertTo-TemplateInt32 $a.SelectSingleNode('*[local-name()="keyArchivalAttributes"]/*[local-name()="symmetricAlgorithmKeyLength"]').InnerText
    }
    $expected['KeyUsage'] = 0
    $expected['BasicConstraintsPresent'] = $false
    $expected['OcspNoCheck'] = $false
    $expected['pKIExtendedKeyUsage'] = @()
    $expected['msPKI-Certificate-Application-Policy'] = @()
    $expected['msPKI-Certificate-Policy'] = @()
    $critical = @(); $seen = @{}
    foreach ($extension in $a.SelectNodes('*[local-name()="extensions"]/*[local-name()="extension"]')) {
        if ($null -eq $extension) { continue }
        $oid = Resolve-Oid $extension.oIDReference
        if ($seen.ContainsKey($oid)) { throw "Duplicate extension '$oid'." }; $seen[$oid] = $true
        if ([string]$extension.critical -notin @('true', 'false')) { throw "Invalid critical flag for '$oid'." }
        if ($extension.critical -eq 'true') { $critical += $oid }
        [byte[]]$bytes = [Convert]::FromBase64String([string]$extension.value)
        $raw = [Security.Cryptography.X509Certificates.X509Extension]::new($oid, $bytes, $false)
        switch ($oid) {
            '2.5.29.15' {
                $decoded = [Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(); $decoded.CopyFrom($raw)
                $expected['KeyUsage'] = [int]$decoded.KeyUsages
            }
            '2.5.29.37' {
                $decoded = [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new(); $decoded.CopyFrom($raw)
                $expected['pKIExtendedKeyUsage'] = @($decoded.EnhancedKeyUsages | ForEach-Object { $_.Value })
            }
            '1.3.6.1.4.1.311.21.10' { $expected['msPKI-Certificate-Application-Policy'] = @(Read-TemplatePolicyOids $bytes $oid) }
            '2.5.29.32' { $expected['msPKI-Certificate-Policy'] = @(Read-TemplatePolicyOids $bytes $oid) }
            '2.5.29.19' {
                $expected['BasicConstraintsPresent'] = $true
                $decoded = [Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new(); $decoded.CopyFrom($raw)
                $expected['BasicConstraintsCA'] = $decoded.CertificateAuthority
                $expected['pKIMaxIssuingDepth'] = if ($decoded.HasPathLengthConstraint) { $decoded.PathLengthConstraint } else { -1 }
            }
            '1.3.6.1.5.5.7.48.1.5' {
                if ([Convert]::ToBase64String($bytes) -ne 'BQA=') { throw 'Invalid OCSP no-check extension.' }
                $expected['OcspNoCheck'] = $true
            }
            '1.3.6.1.4.1.311.21.7' { } # Source template identity changes; revisions checked separately.
            '1.3.6.1.4.1.311.20.2' { } # Source template name changes with -Name.
            default { throw "Extension '$oid' cannot be verified. Import stopped before writing." }
        }
    }
    $expected['pKICriticalExtensions'] = $critical
    return $expected
}

function Read-TemplateVerificationState {
    param([string]$Server, [string]$TemplateBase, [string]$Name)
    $root = [DirectoryServices.DirectoryEntry]::new("LDAP://$Server/$TemplateBase")
    $searcher = [DirectoryServices.DirectorySearcher]::new($root)
    try {
        $searcher.SearchScope = 'OneLevel'
        $escaped = ConvertTo-TemplateLdapFilterValue $Name
        $searcher.Filter = "(&(objectClass=pKICertificateTemplate)(cn=$escaped))"
        $result = $searcher.FindOne()
        if ($null -eq $result) { throw "Template '$Name' could not be read back from '$Server'." }
        $entry = $result.GetDirectoryEntry()
        try {
            $entry.RefreshCache()
            $values = @{}
            foreach ($key in $entry.Properties.PropertyNames) { $values[$key] = $entry.Properties[$key].Value }
            if ($values.ContainsKey('uSNChanged')) { $values['uSNChanged']=ConvertTo-TemplateUsn $values['uSNChanged'] }
            return $values
        } finally { $entry.Dispose() }
    } finally { $searcher.Dispose(); $root.Dispose() }
}

function Compare-TemplateVerificationState {
    param([System.Collections.IDictionary]$Expected, [hashtable]$Actual)
    $values = $Actual.Clone()
    $metadata = @{}
    $ra = [string]$Actual['msPKI-RA-Application-Policies']
    if ($ra.Contains('`')) {
        $parts = $ra.TrimEnd([char]'`').Split([char]'`')
        if ($parts.Count % 3 -ne 0) { throw 'Malformed msPKI-RA-Application-Policies metadata.' }
        for ($i = 0; $i -lt $parts.Count; $i += 3) {
            if ($metadata.ContainsKey($parts[$i])) { throw "Duplicate cryptographic metadata '$($parts[$i])'." }
            $field=$parts[$i]; $type=$parts[$i+1]
            $expectedType=if ($field -in @('msPKI-Key-Usage','msPKI-Symmetric-Key-Length')) { 'DWORD' } else { 'PZPWSTR' }
            if ($field -notin @('msPKI-Asymmetric-Algorithm','msPKI-Hash-Algorithm','msPKI-Key-Security-Descriptor','msPKI-Key-Usage','msPKI-Symmetric-Algorithm','msPKI-Symmetric-Key-Length','msPKI-RA-Application-Policies') -or $type -cne $expectedType) { throw "Unsupported cryptographic metadata '$field' of type '$type'." }
            $metadata[$field] = $parts[$i + 2]
        }
        $ra = [string]$metadata['msPKI-RA-Application-Policies']
    }
    function Resolve-Algorithm([string]$Name, [string]$Default, [int]$Group) {
        if (-not $Name) { return $Default }
        if ($Name -match '^\d+(\.\d+)+$') { return $Name }
        # Windows OID registry knows CSP/KSP algorithm names, including curve-specific OIDs.
        try { return [Security.Cryptography.Oid]::FromFriendlyName($Name, [Security.Cryptography.OidGroup]$Group).Value }
        catch { return "Unresolved algorithm: $Name" }
    }
    $values['AsymmetricAlgorithm'] = Resolve-Algorithm $metadata['msPKI-Asymmetric-Algorithm'] '1.2.840.113549.1.1.1' 3
    $values['HashAlgorithm'] = Resolve-Algorithm $metadata['msPKI-Hash-Algorithm'] '1.3.14.3.2.26' 1
    $values['SymmetricAlgorithm'] = Resolve-Algorithm $metadata['msPKI-Symmetric-Algorithm'] '' 2
    $values['SymmetricKeyLength'] = $metadata['msPKI-Symmetric-Key-Length']
    $values['PrivateKeySDDL'] = [string]$metadata['msPKI-Key-Security-Descriptor']
    $values['CngKeyUsage'] = if ($metadata.ContainsKey('msPKI-Key-Usage')) { ConvertTo-TemplateInt32 $metadata['msPKI-Key-Usage'] } else { 0 }
    $values['RAApplicationPolicies'] = @($ra.Split(',') | Where-Object { $_ })
    $providers = @($Actual['pKIDefaultCSPs'] | Where-Object { $null -ne $_ } | ForEach-Object {
        if ($_ -notmatch '^(\d+),(.*)$') { throw "Malformed provider entry '$_'." }
        [pscustomobject]@{ Index = [int]$matches[1]; Name = $matches[2] }
    })
    $values['Providers'] = @($providers | Sort-Object Index | ForEach-Object { $_.Name })
    foreach ($key in @('pKIExpirationPeriod', 'pKIOverlapPeriod')) {
        $values[$key] = if ($null -ne $Actual[$key]) { [Convert]::ToBase64String([byte[]]$Actual[$key]) } else { $null }
    }
    $values['KeyUsage'] = 0
    if ($null -ne $Actual['pKIKeyUsage']) {
        [byte[]]$ku = $Actual['pKIKeyUsage']; [int]$bits = 0
        if ($ku.Length -gt 2) { throw 'Invalid pKIKeyUsage length.' }
        for ($i = 0; $i -lt $ku.Length; $i++) { $bits = $bits -bor ([int]$ku[$i] -shl (8 * $i)) }
        $values['KeyUsage'] = $bits
    }
    $values['BasicConstraintsCA'] = (([int]$Actual['flags'] -band 128) -ne 0) -or (([int]$Actual['flags'] -band 2048) -ne 0)
    $values['BasicConstraintsPresent'] = $values['BasicConstraintsCA'] -or (([int]$Actual['msPKI-Enrollment-Flag'] -band 32768) -ne 0)
    if ($null -eq $values['pKIMaxIssuingDepth']) { $values['pKIMaxIssuingDepth'] = -1 }
    $values['OcspNoCheck'] = ([int]$Actual['msPKI-Enrollment-Flag'] -band 4096) -ne 0
    foreach ($key in $Expected.Keys) {
        $want = $Expected[$key]; $got = $values[$key]
        # AD multivalued attributes are sets; provider preference is encoded by numeric prefixes.
        if ($want -is [array]) {
            $left = @($want | ForEach-Object { [string]$_ }); $right = @($got | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ })
            if ($key -ne 'Providers') { $left = @($left | Sort-Object -CaseSensitive); $right = @($right | Sort-Object -CaseSensitive) }
            $same = ($left.Count -eq $right.Count)
            for ($i = 0; $same -and $i -lt $left.Count; $i++) { $same = $left[$i] -ceq $right[$i] }
        } else {
            $same = $null -ne $got -and [string]$want -ceq [string]$got
            # Optional RA signature count is zero when absent.
            if ($key -eq 'msPKI-RA-Signature' -and $null -eq $got -and $want -eq 0) { $same = $true }
        }
        if (-not $same) { [pscustomobject]@{ Property = $key; Expected = $want; Actual = $got } }
    }
}

function Get-TemplateCreateReconciliationPlan {
    param([System.Collections.IDictionary]$Expected, [hashtable]$Actual)
    $differences = @(Compare-TemplateVerificationState $Expected $Actual)
    if (-not $differences.Count) { return }
    $direct=@('displayName','msPKI-Private-Key-Flag','msPKI-Certificate-Name-Flag','msPKI-Enrollment-Flag','flags','pKIDefaultKeySpec','msPKI-Minimal-Key-Size','msPKI-RA-Signature','msPKI-Supersede-Templates','msPKI-RA-Policies','pKIExtendedKeyUsage','msPKI-Certificate-Application-Policy','msPKI-Certificate-Policy','pKICriticalExtensions','pKIMaxIssuingDepth')
    $packed=@{
        AsymmetricAlgorithm=@('msPKI-Asymmetric-Algorithm','PZPWSTR',3)
        HashAlgorithm=@('msPKI-Hash-Algorithm','PZPWSTR',1)
        SymmetricAlgorithm=@('msPKI-Symmetric-Algorithm','PZPWSTR',2)
        SymmetricKeyLength=@('msPKI-Symmetric-Key-Length','DWORD',0)
        PrivateKeySDDL=@('msPKI-Key-Security-Descriptor','PZPWSTR',0)
        CngKeyUsage=@('msPKI-Key-Usage','DWORD',0)
        RAApplicationPolicies=@('msPKI-RA-Application-Policies','PZPWSTR',0)
    }
    # Preserve well-formed unrelated metadata tokens; change only XML differences.
    $raw=[string]$Actual['msPKI-RA-Application-Policies']
    $tokens=[Collections.Generic.List[string]]::new()
    if ($raw.Contains('`')) { $tokens.AddRange([string[]]$raw.TrimEnd([char]'`').Split([char]'`')) }
    elseif ($raw) { $tokens.AddRange([string[]]@('msPKI-RA-Application-Policies','PZPWSTR',$raw)) }
    $changes=@{}; $projected=$Actual.Clone(); $packedChanged=$false
    foreach ($difference in $differences) {
        $key=$difference.Property; $value=$Expected[$key]
        if ($key -in @('cn','revision','msPKI-Template-Minor-Revision','msPKI-Template-Schema-Version')) { throw "Identity/schema/revision mismatch '$key'; nothing reconciled." }
        if ($key -in $direct) { $changes[$key]=$value }
        elseif ($key -in @('pKIExpirationPeriod','pKIOverlapPeriod')) { $changes[$key]=[Convert]::FromBase64String($value) }
        elseif ($key -eq 'KeyUsage') { $changes['pKIKeyUsage']=[byte[]]@(([int]$value -band 255),(([int]$value -shr 8) -band 255)) }
        elseif ($key -eq 'Providers') { $index=0; $changes['pKIDefaultCSPs']=@($value | ForEach-Object { $index++; "$index,$_" }) }
        elseif ($packed.ContainsKey($key)) {
            $spec=$packed[$key]
            if ($spec[2] -and [string]$value) {
                $oid=[Security.Cryptography.Oid]::FromOidValue([string]$value,[Security.Cryptography.OidGroup]$spec[2])
                if (-not $oid.FriendlyName -or $oid.FriendlyName -match '^\d+(\.\d+)+$') { throw "Unsupported algorithm '$value'; nothing reconciled." }
                $value=$oid.FriendlyName
            } elseif ($key -eq 'RAApplicationPolicies') { $value=$value -join ',' }
            $position=-1
            for ($i=0;$i -lt $tokens.Count;$i+=3) { if ($tokens[$i] -ceq $spec[0]) { $position=$i+2 } }
            if ([string]$value -eq '') {
                if ($position -ge 0) { $tokens.RemoveRange($position-2,3) }
            }
            elseif ($position -ge 0) { $tokens[$position]=[string]$value }
            else { $tokens.AddRange([string[]]@($spec[0],$spec[1],[string]$value)) }
            $packedChanged=$true
        } elseif ($key -notin @('BasicConstraintsPresent','BasicConstraintsCA','OcspNoCheck')) { throw "Unsupported post-create difference '$key'; nothing reconciled." }
    }
    $schema=[int]$Expected['msPKI-Template-Schema-Version']
    $syntax2=$schema -eq 3 -or ($schema -eq 4 -and ([int]$Expected['msPKI-Private-Key-Flag'] -band 256) -eq 0)
    if ($packedChanged -and -not $syntax2) { throw 'Legacy cryptographic metadata reconciliation is unsupported; nothing reconciled.' }
    if ($packedChanged) { $changes['msPKI-RA-Application-Policies']=if($tokens.Count){($tokens -join '`')+'`'}else{$null} }
    foreach ($key in $changes.Keys) { $projected[$key]=$changes[$key] }
    if (@(Compare-TemplateVerificationState $Expected $projected).Count) { throw 'Projected reconciliation does not match XML.' }
    return $changes
}

function ConvertTo-TemplateUsn {
    param($Value)
    if ($null -eq $Value) { throw 'Missing template uSNChanged.' }
    if ($Value -is [long] -or $Value -is [int]) { $number=[long]$Value }
    else {
        # ADSI exposes LargeInteger as IADsLargeInteger, not a printable number.
        # LowPart is signed Int32 but represents the unsigned low 32 bits.
        if ([Runtime.InteropServices.Marshal]::IsComObject($Value)) {
            $rawHigh=$Value.GetType().InvokeMember('HighPart',[Reflection.BindingFlags]::GetProperty,$null,$Value,$null)
            $rawLow=$Value.GetType().InvokeMember('LowPart',[Reflection.BindingFlags]::GetProperty,$null,$Value,$null)
        } else { $rawHigh=$Value.HighPart; $rawLow=$Value.LowPart }
        if ($null -eq $rawHigh -or $null -eq $rawLow -or
            ($rawHigh -isnot [int] -and $rawHigh -isnot [long]) -or
            ($rawLow -isnot [int] -and $rawLow -isnot [long])) { throw 'Invalid template uSNChanged parts.' }
        [long]$high=$rawHigh; [long]$low=$rawLow
        if ($high -lt 0 -or $high -gt [int]::MaxValue -or $low -lt [int]::MinValue -or $low -gt [int]::MaxValue) { throw 'Invalid template uSNChanged parts.' }
        if ($low -lt 0) { $low+=4294967296 }
        $number=($high * [long]4294967296)+$low
    }
    if ($number -lt 0) { throw 'Invalid negative template uSNChanged.' }
    return [long]$number
}

function Assert-TemplateReconciliationBaseline {
    param([hashtable]$Baseline,[hashtable]$Current)
    if ((ConvertTo-TemplateUsn $Current['uSNChanged']) -ne (ConvertTo-TemplateUsn $Baseline['uSNChanged'])) { throw 'Template changed before reconciliation: uSNChanged' }
    foreach ($name in @('revision','msPKI-Template-Minor-Revision')) {
        if ([string]$Current[$name] -cne [string]$Baseline[$name]) { throw "Template changed before reconciliation: $name" }
    }
}

function Write-TemplateCreateReconciliation {
    param([string]$Server, [hashtable]$Baseline, [hashtable]$Changes)
    if (-not $Changes.Count) { return }
    if (-not $Baseline['objectGUID'] -or $null -eq $Baseline['uSNChanged']) { throw 'Missing reconciliation identity/version baseline.' }
    $guid=[guid]::new([byte[]]$Baseline['objectGUID'])
    $entry=[DirectoryServices.DirectoryEntry]::new("LDAP://$Server/<GUID=$($guid.ToString('D'))>")
    try {
        $entry.RefreshCache()
        # Same object and version observed during planning, including all concurrent
        # LDAP changes via uSNChanged. This is a pre-write check, not a transaction.
        $current=@{}
        foreach ($name in @('uSNChanged','revision','msPKI-Template-Minor-Revision')) { $current[$name]=$entry.Properties[$name].Value }
        Assert-TemplateReconciliationBaseline $Baseline $current
        foreach ($name in $Changes.Keys) {
            $value=$Changes[$name]
            if ($null -eq $value -or ($value -is [array] -and $value.Count -eq 0)) { $entry.Properties[$name].Clear() }
            else { $entry.Properties[$name].Value=$value }
        }
        $entry.CommitChanges()
    } finally { $entry.Dispose() }
}

function Complete-TemplateCreateVerification {
    param([System.Collections.IDictionary]$Expected, [string]$Server, [string]$TemplateBase, [guid]$ExpectedObjectGuid=[guid]::Empty)
    $actual=Read-TemplateVerificationState $Server $TemplateBase $Expected['cn']
    $guid=[guid]::new([byte[]]$actual['objectGUID'])
    if ($ExpectedObjectGuid -ne [guid]::Empty -and $guid -ne $ExpectedObjectGuid) { throw 'Unexpected template identity; nothing reconciled.' }
    $plan=Get-TemplateCreateReconciliationPlan $Expected $actual
    if ($null -ne $plan) {
        Write-TemplateCreateReconciliation $Server $actual $plan
        Write-Verbose "Reconciled XML fields for '$($Expected['cn'])'; revision preserved."
    }
    $after=Read-TemplateVerificationState $Server $TemplateBase $Expected['cn']
    if ([guid]::new([byte[]]$after['objectGUID']) -ne $guid) { throw 'Template identity changed during reconciliation.' }
    if ([string]$after['msPKI-Cert-Template-OID'] -cne [string]$actual['msPKI-Cert-Template-OID']) { throw 'Template OID changed during reconciliation.' }
    Assert-TemplateVerification $Expected $Server $TemplateBase
}

function Assert-TemplateVerification {
    param([System.Collections.IDictionary]$Expected, [string]$Server, [string]$TemplateBase)
    $actual = Read-TemplateVerificationState -Server $Server -TemplateBase $TemplateBase -Name $Expected['cn']
    $differences = @(Compare-TemplateVerificationState $Expected $actual)
    if ($differences.Count) {
        $details = $differences | ForEach-Object { "$($_.Property): expected=[$($_.Expected -join ', ')]; actual=[$($_.Actual -join ', ')]" }
        $exception = [InvalidOperationException]::new("Verification failed for '$($Expected['cn'])' on '$Server'. Changes may already be saved; no rollback was attempted.`n$($details -join "`n")")
        $exception.Data['Differences'] = $differences
        throw $exception
    }
    Write-Verbose "Verified '$($Expected['cn'])' against the source XML on '$Server'."
}

function Read-TemplatePolicyDocument {
    param([string]$XmlString)
    $settings=[Xml.XmlReaderSettings]::new(); $settings.DtdProcessing='Prohibit'; $settings.XmlResolver=$null
    $textReader=[IO.StringReader]::new($XmlString); $reader=[Xml.XmlReader]::Create($textReader,$settings)
    try { $doc=[Xml.XmlDocument]::new(); $doc.XmlResolver=$null; $doc.Load($reader) } finally { $reader.Dispose(); $textReader.Dispose() }
    if ($doc.DocumentElement.LocalName -ne 'GetPoliciesResponse' -or $doc.DocumentElement.NamespaceURI -ne 'http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy') { throw 'Expected an MS-XCEP GetPoliciesResponse document.' }
    $ns=$doc.DocumentElement.NamespaceURI
    foreach ($element in $doc.SelectNodes('//*')) {
        if ($element.NamespaceURI -ne $ns) { throw "Unexpected XML namespace on '$($element.LocalName)'." }
    }
    foreach ($path in @('/*/*[local-name()="response"]','/*/*[local-name()="oIDs"]','/*/*[local-name()="response"]/*[local-name()="policies"]')) {
        if ($doc.SelectNodes($path).Count -ne 1) { throw 'Missing or duplicate MS-XCEP document container.' }
    }
    return ,$doc
}
function Assert-TemplatePolicyInput {
    param([xml]$Document, $Policy)
    $ns='http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy'
    foreach ($element in $Policy.SelectNodes('.//*')) {
        if ($element.NamespaceURI -ne $ns) { throw "Unexpected namespace on '$($element.LocalName)'." }
        $nil=$element.GetAttribute('nil','http://www.w3.org/2001/XMLSchema-instance')
        if ($nil -and $nil -notin @('true','false')) { throw "Invalid nil value on '$($element.LocalName)'." }
        if ($nil -eq 'true' -and ($element.HasChildNodes -or $element.InnerText)) { throw "Nil element '$($element.LocalName)' contains data." }
        # XCEP children are singleton except these explicit list containers.
        if ($element.LocalName -notin @('cryptoProviders','supersededPolicies','rAEKUs','rAPolicies','extensions','cAs')) {
            $duplicates=@($element.ChildNodes | Where-Object { $_ -is [Xml.XmlElement] } | Group-Object LocalName | Where-Object Count -gt 1)
            if ($duplicates.Count) { throw "Duplicate XML field in '$($element.LocalName)'." }
        }
    }
    $a=$Policy.attributes
    foreach ($path in @('commonName','policySchema','certificateValidity','privateKeyAttributes','revision','privateKeyFlags','subjectNameFlags','enrollmentFlags','generalFlags','extensions','rARequirements','keyArchivalAttributes','hashAlgorithmOIDReference','supersededPolicies')) {
        if (@($a.SelectNodes("*[local-name()='$path']")).Count -ne 1) { throw "Missing required XML field '$path'." }
    }
    foreach ($path in @('minimalKeyLength','keySpec','keyUsageProperty','permissions','algorithmOIDReference','cryptoProviders')) {
        if (@($a.privateKeyAttributes.SelectNodes("*[local-name()='$path']")).Count -ne 1) { throw "Missing required XML field '$path'." }
    }
    $name=[string]$a.commonName
    if ([string]::IsNullOrWhiteSpace($name) -or $name -match '["+,;<=>]') { throw "Invalid template common name '$name'." }
    foreach ($node in @($a.policySchema,$a.privateKeyAttributes.minimalKeyLength,$a.privateKeyAttributes.keySpec,$a.revision.majorRevision,$a.revision.minorRevision)) {
        [int]$number=0
        if (-not [int]::TryParse([string]$node,[ref]$number) -or $number -lt 0) { throw 'Invalid nonnegative template integer.' }
    }
    if ([int]$a.policySchema -notin @(1,2,3,4) -or [int]$a.privateKeyAttributes.minimalKeyLength -le 0 -or [int]$a.privateKeyAttributes.keySpec -notin @(0,1,2)) { throw 'Invalid schema, key size or key spec.' }
    if ($a.rARequirements.GetAttribute('nil','http://www.w3.org/2001/XMLSchema-instance') -ne 'true') {
        [int]$count=0
        if (-not [int]::TryParse([string]$a.rARequirements.rASignatures,[ref]$count) -or $count -lt 0) { throw 'Invalid RA signature count.' }
    }
    if ($a.keyArchivalAttributes.GetAttribute('nil','http://www.w3.org/2001/XMLSchema-instance') -ne 'true') {
        [int]$length=0
        if (-not $a.keyArchivalAttributes.symmetricAlgorithmOIDReference -or -not [int]::TryParse([string]$a.keyArchivalAttributes.symmetricAlgorithmKeyLength,[ref]$length) -or $length -le 0) { throw 'Invalid key archival attributes.' }
    }
    $table=@{}
    foreach ($oid in $Document.GetPoliciesResponse.oIDs.oID) {
        [int]$id=0
        if (-not [int]::TryParse([string]$oid.oIDReferenceID,[ref]$id) -or $id -lt 0 -or $table.ContainsKey([string]$id) -or [string]$oid.value -notmatch '^\d+(\.\d+)+$') { throw 'Invalid or duplicate OID table entry.' }
        $table[[string]$id]=$oid
    }
    $templateOid=$table[[string]$Policy.policyOIDReference]
    if ($null -eq $templateOid -or [string]$templateOid.group -ne '9') { throw 'Missing group-9 template OID reference.' }
    foreach ($reference in $Policy.SelectNodes('.//*[local-name()="oIDReference" or local-name()="algorithmOIDReference" or local-name()="hashAlgorithmOIDReference" or local-name()="symmetricAlgorithmOIDReference"]')) {
        if ($reference.GetAttribute('nil','http://www.w3.org/2001/XMLSchema-instance') -eq 'true') { continue }
        $oid=$table[$reference.InnerText]
        if ($null -eq $oid) { throw "Unresolved OID reference '$($reference.InnerText)'." }
        $group=switch ($reference.LocalName) {
            algorithmOIDReference {3}; hashAlgorithmOIDReference {1}; symmetricAlgorithmOIDReference {2}
            default { switch ($reference.ParentNode.LocalName) { extension {6}; rAEKUs {7}; rAPolicies {8}; default {throw 'Unknown OID reference context.'} } }
        }
        if ([int]$oid.group -ne $group) { throw 'OID reference uses an incorrect group.' }
    }
}

function Get-TemplateUpdateRevision {
    param([int]$CurrentMajor,[int]$CurrentMinor,[int]$SourceMajor,[int]$SourceMinor,[bool]$ContentChanged,[bool]$Explicit)
    $older=$SourceMajor -lt $CurrentMajor -or ($SourceMajor -eq $CurrentMajor -and $SourceMinor -lt $CurrentMinor)
    $newer=$SourceMajor -gt $CurrentMajor -or ($SourceMajor -eq $CurrentMajor -and $SourceMinor -gt $CurrentMinor)
    if ($Explicit -and $older) { throw 'Explicit template revision would downgrade the existing revision.' }
    if ($newer) { return @($SourceMajor,$SourceMinor) }
    if ($ContentChanged) {
        if ($CurrentMinor -eq [int]::MaxValue) { throw 'Template minor revision overflow.' }
        return @($CurrentMajor,($CurrentMinor+1))
    }
    return @($CurrentMajor,$CurrentMinor)
}
