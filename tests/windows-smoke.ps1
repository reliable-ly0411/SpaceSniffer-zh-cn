param([Parameter(Mandatory=$true)][string]$Root)
$ErrorActionPreference = 'Stop'
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
foreach($dir in Get-ChildItem $Root -Directory) {
 $p=Start-Process "$($dir.FullName)\SpaceSniffer.exe" -WorkingDirectory $dir.FullName -PassThru
 try {
  Start-Sleep -Seconds 3
  $p.Refresh(); $texts=[ZhWindows]::Read([uint32]$p.Id)
  $ok=(!$p.HasExited) -and (($texts -join ' ') -match '[\u4e00-\u9fff]')
  $results+= [pscustomobject]@{version=$dir.Name;alive=(!$p.HasExited);chinese=$ok;exe_sha256=(Get-FileHash "$($dir.FullName)\SpaceSniffer.exe" -Algorithm SHA256).Hash.ToLower();text=@($texts | Where-Object {$_})}
 } finally {if(!$p.HasExited){Stop-Process -Id $p.Id -Force}}
}
$results | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath "$root\smoke.json" -Encoding UTF8
if (@($results | Where-Object {!$_.alive -or !$_.chinese}).Count) {throw 'Native startup/Chinese UI validation failed'}
Write-Output ('Passed '+$results.Count+' versions')
