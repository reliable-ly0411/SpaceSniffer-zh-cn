param([Parameter(Mandatory=$true)][string]$Root, [Parameter(Mandatory=$true)][string]$Output)
$ErrorActionPreference = 'Stop'
$osName=(Get-CimInstance Win32_OperatingSystem).Caption
$dirs=@(Get-ChildItem $Root -Directory)
if ($dirs.Count -ne 1) {throw 'Expected exactly one candidate'}
Add-Type @'
using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public class ZhWindows {
 public delegate bool Callback(IntPtr h, IntPtr p);
 [DllImport("user32.dll")] static extern bool EnumWindows(Callback c, IntPtr p);
 [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h, out uint p);
 [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern int GetWindowText(IntPtr h, StringBuilder b,int n);
 [DllImport("user32.dll")] static extern IntPtr GetMenu(IntPtr h);
 [DllImport("user32.dll")] static extern int GetMenuItemCount(IntPtr h);
 [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern int GetMenuString(IntPtr h,uint i,StringBuilder b,int n,uint f);
 public static string[] Read(uint pid) {
  var result=new List<string>();
  EnumWindows(delegate(IntPtr h,IntPtr p) { uint id;GetWindowThreadProcessId(h,out id);if(id!=pid)return true;
   var b=new StringBuilder(2048);GetWindowText(h,b,b.Capacity);result.Add(b.ToString());
   var m=GetMenu(h);for(uint i=0;i<GetMenuItemCount(m);i++){b.Clear();GetMenuString(m,i,b,b.Capacity,0x400);result.Add(b.ToString());} return true;
  },IntPtr.Zero);return result.ToArray();
 }
}
'@
$results=@()
foreach($dir in $dirs) {
 $p=Start-Process "$($dir.FullName)\SpaceSniffer.exe" -WorkingDirectory $dir.FullName -PassThru
 try {
  $deadline=(Get-Date).AddSeconds(20)
  do {
   Start-Sleep -Milliseconds 500
   $p.Refresh(); $texts=[ZhWindows]::Read([uint32]$p.Id)
   $menusOk=$true
   foreach($word in @('文件','编辑','窗口','帮助')) {if (!($texts -match "^$word\(")) {$menusOk=$false}}
  } while (!$p.HasExited -and !$menusOk -and (Get-Date) -lt $deadline)
  Start-Sleep -Seconds 2
  $p.Refresh()
  $ok=(!$p.HasExited) -and $menusOk -and (($texts -join ' ') -match '[\u4e00-\u9fff]')
  $results+= [pscustomobject]@{version=$dir.Name;alive=(!$p.HasExited);chinese=$ok;menus_ok=$menusOk;environment=$osName;tested_utc=(Get-Date).ToUniversalTime().ToString("o");scope="Process startup and four native Chinese menus; not full usage validation";exe_sha256=(Get-FileHash "$($dir.FullName)\SpaceSniffer.exe" -Algorithm SHA256).Hash.ToLower();text=@($texts | Where-Object {$_})}
 } finally {if(!$p.HasExited){Stop-Process -Id $p.Id -Force}}
}
ConvertTo-Json -InputObject @($results) -Depth 5 | Set-Content -LiteralPath $Output -Encoding UTF8
if (@($results | Where-Object {!$_.alive -or !$_.chinese}).Count) {throw 'Native startup/Chinese UI validation failed'}
Write-Output ('Passed '+$results.Count+' versions')
