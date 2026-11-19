# Optional read-only report. No policy or template deletion is implemented here.
param([switch]$RunLive,[string]$Server,[ValidatePattern('^\d+(\.\d+)+$')][string]$Oid,[string]$ReportPath)
$ErrorActionPreference='Stop'
if(-not $RunLive){'SKIP: policy usage report requires -RunLive and explicit Server/Oid/ReportPath';return}
if(-not $Server -or -not $Oid -or -not $ReportPath){throw 'Explicit Server, Oid and new ReportPath are required'}
if(Test-Path $ReportPath){throw 'Report already exists'}
. (Join-Path $PSScriptRoot '../../TemplateDirectory.ps1')
. (Join-Path $PSScriptRoot '../helpers/PolicyUsage.ps1')
$context=Get-TemplateDirectoryContext $Server
$templates=@(Find-TemplateDirectoryObject $context.Server $context.TemplateBase '(objectClass=pKICertificateTemplate)')
$registrations=@(Find-TemplateDirectoryObject $context.Server $context.OidBase '(objectClass=msPKI-Enterprise-Oid)')
$report=Get-TestPolicyUsage -Oid $Oid -Templates $templates -Registrations $registrations
$stream=[IO.File]::Open($ReportPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
try{$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($report|ConvertTo-Json -Depth 8));$stream.Write($bytes,0,$bytes.Length)}finally{$stream.Dispose()}
$report
