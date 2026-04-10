foreach ($file in 
  (Get-ChildItem -File -Recurse -LiteralPath $PSScriptRoot -Filter *.ps1)
) { 
  . (Join-Path -Path $PSScriptRoot -ChildPath $file)
}