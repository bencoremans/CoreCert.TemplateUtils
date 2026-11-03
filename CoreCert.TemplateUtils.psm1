foreach ($file in 
  (Get-ChildItem -File -LiteralPath $PSScriptRoot -Filter *.ps1)
) { 
  . $file.FullName
}
