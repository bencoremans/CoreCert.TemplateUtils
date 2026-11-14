$ErrorActionPreference='Stop'
# Replace only the LDAP constructor boundary; execute the actual deletion helper.
# An extended Parent property models the string returned by the ADSI adapter.
if(-not ('RemovalEntryFixture' -as [type])){
 Add-Type @"
public class RemovalChildrenFixture {
 public int Calls; public bool Fail;
 public void Remove(RemovalEntryFixture entry) { if(Fail) throw new System.InvalidOperationException("delete denied"); Calls++; entry.Removed=true; }
}
public class RemovalEntryFixture : System.IDisposable {
 public RemovalEntryFixture Parent {get;set;}
 public RemovalChildrenFixture Children {get;set;}
 public bool Disposed; public bool Removed;
 public void Dispose(){Disposed=true;}
}
"@
}
$path=Join-Path $PSScriptRoot '../TemplateDirectory.ps1'
$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Resolve-Path $path),[ref]$tokens,[ref]$errors)
$fn=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Remove-TemplateDirectoryObject'},$true)
$body=$fn.Extent.Text.Replace('[DirectoryServices.DirectoryEntry]::new($Path)','$script:fixtureEntry')
. ([scriptblock]::Create($body))
foreach($fail in @($false,$true)){
 $script:fixtureEntry=[RemovalEntryFixture]::new();$nativeParent=[RemovalEntryFixture]::new();$children=[RemovalChildrenFixture]::new();$children.Fail=$fail
 $nativeParent.Children=$children;$script:fixtureEntry.Parent=$nativeParent
 $script:fixtureEntry|Add-Member -MemberType NoteProperty -Name Parent -Value 'LDAP://example/container' -Force
 $script:fixtureEntry|Add-Member -MemberType ScriptMethod -Name Dispose -Value {if($this.Removed){throw 'Adapted member lookup rebound deleted object'};$this.PSBase.Dispose()} -Force
 if($script:fixtureEntry.Parent -isnot [string] -or $script:fixtureEntry.psbase.Parent -isnot [RemovalEntryFixture]){throw 'Fixture does not reproduce adapter/base distinction'}
 $caught=$null
 try{Remove-TemplateDirectoryObject 'LDAP://example/test'}catch{$caught=$_}
 if($fail){if(-not $caught -or $caught.Exception.Message -notlike '*delete denied*'){throw 'Deletion error was lost'}}
 elseif($caught){throw $caught}
 if($children.Calls -ne [int](-not $fail)){throw 'Wrong removal count'}
 if(-not $script:fixtureEntry.Disposed -or -not $nativeParent.Disposed){throw 'Entry/parent not disposed'}
}
'PASS: actual directory removal helper bypasses adapted Parent and preserves failures/disposal'
