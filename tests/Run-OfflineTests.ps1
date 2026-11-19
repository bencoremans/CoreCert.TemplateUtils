# Every suite runs in a fresh process; fixture modules and mocks cannot leak.
param([string]$OutputDirectory=(Join-Path ([IO.Path]::GetTempPath()) ('TemplateUtils-tests-'+[guid]::NewGuid().ToString('N'))),[string]$LibraryPath)
$ErrorActionPreference='Stop'
if(Test-Path -LiteralPath $OutputDirectory){throw 'Choose a new output directory; existing evidence is not overwritten.'}
[void](New-Item -ItemType Directory -Path $OutputDirectory)
$exe=[Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
$results=@()
foreach($suite in Get-ChildItem -LiteralPath $PSScriptRoot -Filter '*.Tests.ps1' -File|Sort-Object Name){
 $out=Join-Path $OutputDirectory ($suite.BaseName+'.stdout.txt');$err=Join-Path $OutputDirectory ($suite.BaseName+'.stderr.txt')
 $args='-NoProfile -NonInteractive -File "'+$suite.FullName+'"'
 if($LibraryPath -and $suite.Name -in @('Policy-RoundTrip.Tests.ps1','Custom-ApplicationPolicy.Tests.ps1')){
  if($LibraryPath.Contains('"')){throw 'Invalid library path'};$args+=' -LibraryPath "'+$LibraryPath+'"'
 }
 $process=Start-Process -FilePath $exe -ArgumentList $args -WindowStyle Hidden -RedirectStandardOutput $out -RedirectStandardError $err -PassThru -Wait
 $status=if($process.ExitCode -ne 0){'Fail'}elseif(Select-String -Path $out -Pattern '^SKIP:' -Quiet){'Skip'}else{'Pass'}
 $results+=[pscustomobject]@{Suite=$suite.Name;Status=$status;ExitCode=$process.ExitCode;SourceSHA256=(Get-FileHash $suite.FullName).Hash;Stdout=$out;Stderr=$err}
}
$report=[pscustomobject]@{FinishedUtc=[datetime]::UtcNow.ToString('o');PowerShell=$PSVersionTable.PSVersion.ToString();Results=$results;Integration='NotRun; explicit opt-in scripts are never invoked by this runner'}
$report|ConvertTo-Json -Depth 6|Set-Content (Join-Path $OutputDirectory 'results.json') -Encoding UTF8
$results|Format-Table Suite,Status,ExitCode
if(@($results|Where-Object Status -eq 'Fail').Count){throw "Offline suites failed; see $OutputDirectory"}