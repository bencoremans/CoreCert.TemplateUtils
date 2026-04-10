<#
.SYNOPSIS
Compares attributes of two certificate templates and returns a hashtable of differences.

.DESCRIPTION
Takes two PSObjects representing certificate template states and compares their attributes.
Handles type-specific normalization to avoid false positives from null/0 and empty/missing
multi-value attributes:

  int    : null/missing treated as 0; cast to [int] before compare
  bytes  : null/missing treated as empty byte[]; Base64-encode for stable compare
  strings: null/missing treated as empty array; sorted for order-independent compare
  other  : trimmed string comparison

The "current" object (Obj1) is typically the result of Get-ADCSTemplate / Get-ADObject.
The "desired" object (Obj2) is typically built from ConvertTo-SerializedTemplate XML
or from a JSON representation of the desired state.

.PARAMETER Obj1
Current state -- usually the live AD template object.

.PARAMETER Obj2
Desired state -- usually built from serialized source XML or JSON.

.OUTPUTS
[hashtable] Keys: attribute names that differ. Values: the desired value to write.
            Empty hashtable means no differences.

.EXAMPLE
$current = Get-ADCSTemplate -Name "CC-WebServer"
$diffs   = Compare-TemplateAttributes -Obj1 $current -Obj2 $desired
#>
function Compare-TemplateAttributes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject]$Obj1,

        [Parameter(Mandatory)]
        [psobject]$Obj2
    )

    # Attribute type classification
    $intAttrs    = [System.Collections.Generic.HashSet[string]]@(
        'flags','msPKI-Certificate-Name-Flag','msPKI-Enrollment-Flag',
        'msPKI-Minimal-Key-Size','msPKI-Private-Key-Flag',
        'msPKI-Template-Minor-Revision','msPKI-Template-Schema-Version',
        'msPKI-RA-Signature','pKIMaxIssuingDepth','pKIDefaultKeySpec','revision'
    )
    $strArrayAttrs = [System.Collections.Generic.HashSet[string]]@(
        'msPKI-Certificate-Application-Policy','msPKI-Certificate-Policy',
        'pKICriticalExtensions','pKIDefaultCSPs','pKIExtendedKeyUsage',
        'msPKI-RA-Application-Policies'
    )
    $byteAttrs   = [System.Collections.Generic.HashSet[string]]@(
        'pKIExpirationPeriod','pKIKeyUsage','pKIOverlapPeriod'
    )

    # -- Normalization helpers --

    # Canonical int: null/missing -> 0
    function Norm-Int([object]$v) {
        if ($null -eq $v) { return 0 }
        # ADPropertyValueCollection: take first element
        if ($v -is [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]) {
            if ($v.Count -eq 0) { return 0 }
            return [int]$v[0]
        }
        return [int]$v
    }

    # Canonical bytes: null/missing -> ""; else Base64 of byte[]
    function Norm-Bytes([object]$v) {
        if ($null -eq $v) { return "" }
        if ($v -is [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]) {
            if ($v.Count -eq 0) { return "" }
            $v = $v[0]
        }
        if ($v -is [byte[]]) { return [Convert]::ToBase64String($v) }
        return [Convert]::ToBase64String([byte[]]$v)
    }

    # Canonical string array: null/missing -> @(); sort for order-independence
    function Norm-StrArray([object]$v) {
        if ($null -eq $v) { return @() }
        if ($v -is [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]) {
            $arr = @($v | ForEach-Object { $_.ToString().Trim() } | Where-Object { $_ })
        } elseif ($v -is [System.Collections.IEnumerable] -and $v -isnot [string]) {
            $arr = @($v | ForEach-Object { $_.ToString().Trim() } | Where-Object { $_ })
        } else {
            $arr = @($v.ToString().Trim()) | Where-Object { $_ }
        }
        return ($arr | Sort-Object)
    }

    $differences = @{}

    # Only compare properties defined in the desired state (Obj2).
    # Obj1 (current ADObject) carries many read-only metadata properties
    # (DistinguishedName, ObjectGUID, whenCreated, ...) that are not part of
    # the desired state and must not be diffed.
    $properties = @($Obj2.PSObject.Properties.Name)

    foreach ($prop in $properties) {
        $v1 = $Obj1.$prop
        $v2 = $Obj2.$prop

        if ($intAttrs.Contains($prop)) {
            $n1 = Norm-Int $v1
            $n2 = Norm-Int $v2
            if ($n1 -ne $n2) {
                Write-Verbose "  Diff [$prop] int: AD=$n1  src=$n2"
                $differences[$prop] = $n2
            }
        }
        elseif ($byteAttrs.Contains($prop)) {
            $n1 = Norm-Bytes $v1
            $n2 = Norm-Bytes $v2
            if ($n1 -ne $n2) {
                Write-Verbose "  Diff [$prop] bytes: AD=$n1  src=$n2"
                # Write the actual byte[] value from desired, not the Base64 string
                $rawV2 = if ($v2 -is [byte[]]) { $v2 } else { [Convert]::FromBase64String($n2) }
                $differences[$prop] = $rawV2
            }
        }
        elseif ($strArrayAttrs.Contains($prop)) {
            $n1 = Norm-StrArray $v1
            $n2 = Norm-StrArray $v2
            $diff = Compare-Object -ReferenceObject @($n1) -DifferenceObject @($n2) -ErrorAction SilentlyContinue
            if ($diff) {
                Write-Verbose "  Diff [$prop] strings: AD=[$($n1 -join '|')]  src=[$($n2 -join '|')]"
                $rawV2 = Norm-StrArray $v2   # already normalized string array
                $differences[$prop] = if ($rawV2.Count -gt 0) { $rawV2 } else { $null }
            }
        }
        else {
            # Generic string / other
            $s1 = if ($null -eq $v1) { "" } else { $v1.ToString().Trim() }
            $s2 = if ($null -eq $v2) { "" } else { $v2.ToString().Trim() }
            if ($s1 -ne $s2) {
                Write-Verbose "  Diff [$prop] string: AD='$s1'  src='$s2'"
                $differences[$prop] = if ($s2 -eq "") { $null } else { $s2 }
            }
        }
    }

    return $differences
}
