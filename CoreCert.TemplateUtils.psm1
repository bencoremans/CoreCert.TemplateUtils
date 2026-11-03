foreach ($file in 
  (Get-ChildItem -File -LiteralPath $PSScriptRoot -Filter *.ps1)
) { 
  . (Join-Path -Path $PSScriptRoot -ChildPath $file)
}
