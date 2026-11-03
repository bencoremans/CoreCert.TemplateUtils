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
        $length = 0
        for ($i = 0; $i -lt $count; $i++) { $length = ($length * 256) + $Bytes[$position++ ] }
    }
    if ($position + $length -gt $Bytes.Length) { throw 'Truncated extension DER value.' }
    $end = [int]($position + $length)
    [byte[]]$value = @(); if ($length) { $value = $Bytes[$position..($end - 1)] }
    $Offset.Value = $end
    [pscustomobject]@{ Tag = $tag; Value = $value }
}

function Read-TemplatePolicyOids {
    param([byte[]]$Bytes, [string]$ExtensionOid = '2.5.29.32')
    $offset = 0; $outer = Read-TemplateDerElement $Bytes ([ref]$offset)
    if ($outer.Tag -ne 48 -or $offset -ne $Bytes.Length) { throw 'Invalid policy extension DER.' }
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
    Import-TemplatePolicyLibrary 'Template policy verification'
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
    $expected['msPKI-RA-Signature'] = if ($a.rARequirements.rASignatures) { ConvertTo-TemplateInt32 $a.rARequirements.rASignatures } else { 0 }
    $expected['msPKI-Supersede-Templates'] = @($a.supersededPolicies.commonName | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ })
    $expected['Providers'] = @($a.privateKeyAttributes.cryptoProviders.provider | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ })
    $expected['AsymmetricAlgorithm'] = Resolve-Oid $a.privateKeyAttributes.algorithmOIDReference '1.2.840.113549.1.1.1'
    $expected['HashAlgorithm'] = Resolve-Oid $a.hashAlgorithmOIDReference '1.3.14.3.2.26'
    $expected['CngKeyUsage'] = if ($a.privateKeyAttributes.keyUsageProperty -is [string]) { ConvertTo-TemplateInt32 $a.privateKeyAttributes.keyUsageProperty } else { 0 }
    $expected['PrivateKeySDDL'] = if ($a.privateKeyAttributes.permissions -is [string]) { [string]$a.privateKeyAttributes.permissions } else { '' }
    $expected['RAApplicationPolicies'] = @($a.rARequirements.rAEKUs.oIDReference | Where-Object { $null -ne $_ } | ForEach-Object { Resolve-Oid $_ })
    $expected['msPKI-RA-Policies'] = @($a.rARequirements.rAPolicies.oIDReference | Where-Object { $null -ne $_ } | ForEach-Object { Resolve-Oid $_ })
    if ($a.keyArchivalAttributes.symmetricAlgorithmOIDReference) {
        $expected['SymmetricAlgorithm'] = Resolve-Oid $a.keyArchivalAttributes.symmetricAlgorithmOIDReference
        $expected['SymmetricKeyLength'] = ConvertTo-TemplateInt32 $a.keyArchivalAttributes.symmetricAlgorithmKeyLength
    }
    $expected['KeyUsage'] = 0
    $expected['BasicConstraintsPresent'] = $false
    $expected['OcspNoCheck'] = $false
    $expected['pKIExtendedKeyUsage'] = @()
    $expected['msPKI-Certificate-Application-Policy'] = @()
    $expected['msPKI-Certificate-Policy'] = @()
    $critical = @(); $seen = @{}
    foreach ($extension in $a.extensions.extension) {
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
