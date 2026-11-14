param([string]$SourceRoot=(Split-Path $PSScriptRoot))
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $SourceRoot 'TemplateVerification.ps1')
function Assert-Equal($a,$b,$why){if($a -cne $b){throw $why}}
function Assert-Throws([scriptblock]$Body,[string]$Pattern){try{&$Body}catch{if($_.Exception.Message -like $Pattern){return};throw};throw 'Expected refusal'}
function New-LargeInteger([int]$High,[int]$Low){$o=[pscustomobject]@{HighPart=$High;LowPart=$Low};$o|Add-Member ScriptMethod ToString {'System.__ComObject'} -Force;return $o}
$a=New-LargeInteger 0 17473;$b=New-LargeInteger 0 17474
Assert-Equal ([string]$a) ([string]$b) 'Reproduce indistinguishable COM strings'
Assert-Equal (ConvertTo-TemplateUsn $a) ([long]17473) 'Exact low USN'
Assert-Equal (ConvertTo-TemplateUsn (New-LargeInteger 1 -1)) ([long]8589934591) 'Unsigned low part'
Assert-Equal (ConvertTo-TemplateUsn (New-LargeInteger 2147483647 -1)) ([long]::MaxValue) 'Int64 upper boundary'
Assert-Equal (ConvertTo-TemplateUsn ([long]17473)) ([long]17473) 'Native Int64'
$baseline=@{uSNChanged=$a;revision=100;'msPKI-Template-Minor-Revision'=5}
$current=@{uSNChanged=$b;revision=100;'msPKI-Template-Minor-Revision'=5}
Assert-Throws {Assert-TemplateReconciliationBaseline $baseline $current} '*uSNChanged*'
$current.uSNChanged=[long]17473;Assert-TemplateReconciliationBaseline $baseline $current
$current.revision=101;Assert-Throws {Assert-TemplateReconciliationBaseline $baseline $current} '*revision*'
Assert-Throws {ConvertTo-TemplateUsn $null} '*Missing*'
Assert-Throws {ConvertTo-TemplateUsn 'System.__ComObject'} '*HighPart*'
Assert-Throws {ConvertTo-TemplateUsn (New-LargeInteger -1 0)} '*Invalid*'
Set-StrictMode -Off
Assert-Throws {ConvertTo-TemplateUsn ([pscustomobject]@{Other='not a USN'})} '*Invalid*'
Assert-Throws {ConvertTo-TemplateUsn ([pscustomobject]@{HighPart=$null;LowPart=0})} '*Invalid*'
Assert-Throws {ConvertTo-TemplateUsn ([pscustomobject]@{HighPart='1';LowPart=0})} '*Invalid*'
'PASS: numeric USN baseline rejects distinct COM values, signed-low conversion and fail-closed inputs.'
