<#
.SYNOPSIS
    Get-WHFBKeys.ps1 - Windows Hello for Business / NGC enumeration & key-material harvester.

.DESCRIPTION
    Enumerates everything related to Windows Hello for Business (WHFB) / Windows Hello
    convenience-PIN (NGC "Next Generation Credentials") on the local machine and dumps
    the associated key material:

      1. TPM presence, version and readiness.
      2. Device join state + NGC provisioning prerequisites (dsregcmd parse).
      3. WHFB / PassportForWork policy (HKLM + HKCU) and NGC service state.
      4. On-disk NGC container store walk (containers -> protectors -> crypto keys),
         with hex dumps of the protector / cached-key blobs. Requires SYSTEM; the
         script self-elevates from an elevated-admin context via a one-shot SYSTEM task.
      5. NCrypt key enumeration through the Microsoft Passport KSP and the Microsoft
         Platform Crypto Provider (TPM). Exports PUBLIC key blobs (base64) and key
         properties (algorithm, length, TPM-backing, export policy, PIN protector).
      6. Platform Crypto Provider (PCP / TPM) key files on disk.
      7. Biometric (WinBio) enrollment summary.

    IMPORTANT / HONEST LIMITATION:
      NGC/WHFB private keys are generated inside and sealed by the TPM and are marked
      NON-EXPORTABLE. Neither this tool nor any user-mode code can extract the raw
      private key in plaintext -- that is the entire security guarantee of the TPM.
      What CAN be obtained and is dumped here:
        * public keys,
        * full key metadata / TPM key properties,
        * the on-disk protector blobs (the encrypted key-decryption material that a
          correct PIN/bio unlocks) -- this is the material used in offline WHFB PIN
          research such as the "Shattered Hello" class of attacks.
      Extracting usable private key operations requires unlocking the protector via the
      TPM with the correct gesture (PIN/bio), which this tool does NOT attempt.

.PARAMETER OutDir
    Directory for the JSON report + protector blob dumps. Default: script folder.

.PARAMETER DumpBlobs
    Also write raw NGC container/protector .dat blobs to <OutDir>\blobs\.

.PARAMETER NoElevate
    Do not self-elevate to SYSTEM; only enumerate what the current token can read.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Get-WHFBKeys.ps1 -DumpBlobs

.NOTES
    Author : security research tooling (authorized use on your own machine only)
    Scope  : local host enumeration. Read-only; creates & deletes one transient
             scheduled task named 'WHFBKeysSys_<random>' when self-elevating.
#>
[CmdletBinding()]
param(
    [string]$OutDir = (Split-Path -Parent $MyInvocation.MyCommand.Definition),
    [switch]$DumpBlobs,
    [switch]$NoElevate,
    # internal: set when re-launched under SYSTEM to do the privileged store walk
    [string]$SystemPhaseOut
)

$ErrorActionPreference = 'Continue'
$script:Report = [ordered]@{}

function Write-Head($t) {
    Write-Host ""
    Write-Host ("=" * 72) -ForegroundColor DarkCyan
    Write-Host "  $t" -ForegroundColor Cyan
    Write-Host ("=" * 72) -ForegroundColor DarkCyan
}
function Write-KV($k, $v, $color = 'Gray') {
    Write-Host ("  {0,-26}: " -f $k) -NoNewline
    Write-Host $v -ForegroundColor $color
}

# ---------------------------------------------------------------------------
#  NCrypt P/Invoke layer (Passport KSP + Platform Crypto Provider enumeration)
# ---------------------------------------------------------------------------
function Initialize-NCrypt {
    if ("WHFB.Helper" -as [type]) { return }
    Add-Type -TypeDefinition @'
    using System;
    using System.Runtime.InteropServices;
    using System.Collections.Generic;

    namespace WHFB {

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct NCryptKeyName {
        public string pszName;
        public string pszAlgid;
        public uint   dwLegacyKeySpec;
        public uint   dwFlags;
    }

    public static class N {
    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    public static extern int NCryptOpenStorageProvider(out IntPtr phProvider, string pszProviderName, uint dwFlags);
    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    public static extern int NCryptEnumKeys(IntPtr hProvider, string pszScope, out IntPtr ppKeyName, ref IntPtr ppEnumState, uint dwFlags);
    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    public static extern int NCryptOpenKey(IntPtr hProvider, out IntPtr phKey, string pszKeyName, uint dwLegacyKeySpec, uint dwFlags);
    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    public static extern int NCryptExportKey(IntPtr hKey, IntPtr hExportKey, string pszBlobType, IntPtr pParameterList, byte[] pbOutput, int cbOutput, out int pcbResult, uint dwFlags);
    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    public static extern int NCryptGetProperty(IntPtr hObject, string pszProperty, byte[] pbOutput, int cbOutput, out int pcbResult, uint dwFlags);
    [DllImport("ncrypt.dll")]
    public static extern int NCryptFreeBuffer(IntPtr pvInput);
    [DllImport("ncrypt.dll")]
    public static extern int NCryptFreeObject(IntPtr hObject);
    }

    public class KeyInfo {
        public string Name;
        public string Algorithm;
        public uint   Flags;         // 1 = machine key, else user key
        public int    Length;
        public string ExportPolicy;
        public string TpmBacked;
        public string PublicKeyB64;
        public string Error;
    }

    public static class Helper {
        static string PropStr(IntPtr h, string p) {
            int cb; if (N.NCryptGetProperty(h, p, null, 0, out cb, 0) != 0 || cb == 0) return null;
            byte[] b = new byte[cb]; if (N.NCryptGetProperty(h, p, b, cb, out cb, 0) != 0) return null;
            return System.Text.Encoding.Unicode.GetString(b, 0, cb).TrimEnd('\0');
        }
        static int PropInt(IntPtr h, string p) {
            int cb; if (N.NCryptGetProperty(h, p, null, 0, out cb, 0) != 0 || cb < 4) return -1;
            byte[] b = new byte[cb]; if (N.NCryptGetProperty(h, p, b, cb, out cb, 0) != 0) return -1;
            return BitConverter.ToInt32(b, 0);
        }

        public static List<KeyInfo> Enumerate(string provider, out string provError) {
            provError = null;
            var list = new List<KeyInfo>();
            IntPtr hProv;
            int st = N.NCryptOpenStorageProvider(out hProv, provider, 0);
            if (st != 0) { provError = "NCryptOpenStorageProvider=0x" + st.ToString("X8"); return list; }
            try {
                // enumerate both user (0) and machine (0x20 = NCRYPT_MACHINE_KEY_FLAG) scopes
                foreach (uint scopeFlag in new uint[] { 0, 0x20 }) {
                    IntPtr enumState = IntPtr.Zero;
                    while (true) {
                        IntPtr pName;
                        int e = N.NCryptEnumKeys(hProv, null, out pName, ref enumState, scopeFlag);
                        if (e != 0) break; // 0x8009002A = NTE_NO_MORE_ITEMS
                        NCryptKeyName kn = (NCryptKeyName)Marshal.PtrToStructure(pName, typeof(NCryptKeyName));
                        var ki = new KeyInfo { Name = kn.pszName, Algorithm = kn.pszAlgid, Flags = scopeFlag };
                        N.NCryptFreeBuffer(pName);
                        try {
                            IntPtr hKey;
                            int o = N.NCryptOpenKey(hProv, out hKey, ki.Name, 0, scopeFlag);
                            if (o != 0) { ki.Error = "OpenKey=0x" + o.ToString("X8"); list.Add(ki); continue; }
                            try {
                                ki.Length       = PropInt(hKey, "Length");
                                int exp          = PropInt(hKey, "Export Policy");
                                ki.ExportPolicy  = (exp <= 0) ? "NON-EXPORTABLE" : ("0x" + exp.ToString("X"));
                                string impl      = PropStr(hKey, "Impl Type");
                                int implI        = PropInt(hKey, "PCP_PLATFORM_TYPE"); // hint only
                                ki.TpmBacked     = "unknown";
                                // heuristic: platform crypto provider keys are TPM-backed
                                if (provider.IndexOf("Platform", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                    provider.IndexOf("Passport", StringComparison.OrdinalIgnoreCase) >= 0)
                                    ki.TpmBacked = "yes (provider-backed)";
                                // export public key
                                foreach (string bt in new string[] { "RSAPUBLICBLOB", "ECCPUBLICBLOB", "PUBLICBLOB" }) {
                                    int cb;
                                    int x = N.NCryptExportKey(hKey, IntPtr.Zero, bt, IntPtr.Zero, null, 0, out cb, 0);
                                    if (x == 0 && cb > 0) {
                                        byte[] blob = new byte[cb];
                                        if (N.NCryptExportKey(hKey, IntPtr.Zero, bt, IntPtr.Zero, blob, cb, out cb, 0) == 0) {
                                            ki.PublicKeyB64 = Convert.ToBase64String(blob);
                                            break;
                                        }
                                    }
                                }
                            } finally { N.NCryptFreeObject(hKey); }
                        } catch (Exception ex) { ki.Error = ex.Message; }
                        list.Add(ki);
                    }
                    if (enumState != IntPtr.Zero) N.NCryptFreeBuffer(enumState);
                }
            } finally { N.NCryptFreeObject(hProv); }
            return list;
        }
    }

    } // namespace WHFB
'@ -ErrorAction Stop
}

function Get-ProviderKeys([string]$provider) {
    Initialize-NCrypt
    $err = ""
    $keys = [WHFB.Helper]::Enumerate($provider, [ref]$err)
    [pscustomobject]@{ Provider = $provider; ProviderError = $err; Keys = $keys }
}

# ---------------------------------------------------------------------------
#  SYSTEM-phase: privileged walk of the NGC on-disk store (runs as NT AUTHORITY\SYSTEM)
# ---------------------------------------------------------------------------
function Invoke-SystemPhase([string]$outFile, [bool]$dump, [string]$blobDir) {
    $result = [ordered]@{ Whoami = (whoami); Containers = @(); StoreRoots = @() }
    $roots = @(
        "$env:windir\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc",
        "$env:windir\ServiceProfiles\LocalService\AppData\Roaming\Microsoft\Crypto\Keys",
        "$env:ProgramData\Microsoft\Crypto\PCPKSP",
        "$env:ProgramData\Microsoft\Crypto\Keys"
    )
    foreach ($root in $roots) {
        if (-not (Test-Path $root)) { continue }
        $rootInfo = [ordered]@{ Root = $root; Items = @() }
        try {
            Get-ChildItem -Force -Recurse $root -ErrorAction Stop | ForEach-Object {
                $rec = [ordered]@{
                    Path     = $_.FullName
                    IsDir    = [bool]$_.PSIsContainer
                    Size     = if ($_.PSIsContainer) { $null } else { $_.Length }
                    Modified = $_.LastWriteTime.ToString('s')
                    Sha256   = $null
                    Head     = $null
                }
                if (-not $_.PSIsContainer -and $_.Length -gt 0 -and $_.Length -lt 1MB) {
                    try {
                        $bytes = [System.IO.File]::ReadAllBytes($_.FullName)
                        $sha = [System.Security.Cryptography.SHA256]::Create()
                        $rec.Sha256 = ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','').ToLower()
                        $n = [Math]::Min(64, $bytes.Length)
                        $rec.Head = ([BitConverter]::ToString($bytes,0,$n)).Replace('-',' ')
                        if ($dump) {
                            if (-not (Test-Path $blobDir)) { New-Item -ItemType Directory -Force $blobDir | Out-Null }
                            $safe = ($_.FullName -replace '[:\\/]','_')
                            [System.IO.File]::WriteAllBytes((Join-Path $blobDir $safe), $bytes)
                        }
                    } catch { $rec.Head = "READ_ERR: $($_.Exception.Message)" }
                }
                $rootInfo.Items += $rec
            }
        } catch { $rootInfo.Items += @{ Error = $_.Exception.Message } }
        $result.StoreRoots += $rootInfo
    }
    # ---- Parse provisioned NGC containers (Container.json / Protectors.json / Keys) ----
    $result.NgcContainers = @()
    $ngcRoot = "$env:windir\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc"
    if (Test-Path $ngcRoot) {
        Get-ChildItem $ngcRoot -Directory -Force -EA SilentlyContinue |
          Where-Object { $_.Name -match '^\{[0-9A-Fa-f-]+\}$' } | ForEach-Object {
            $cdir = $_.FullName
            $ci = [ordered]@{ Guid = $_.Name; Path = $cdir; Sid = $null; Account = $null; Protectors = @(); Keys = @() }
            $cjP = Join-Path $cdir 'Container.json'
            if (Test-Path $cjP) {
                try {
                    $cj = Get-Content $cjP -Raw | ConvertFrom-Json
                    $ci.Sid = $cj.sid; $ci.TrustLevel = $cj.trustLevel; $ci.PolicyB64 = $cj.policy
                    try { $ci.Account = (New-Object Security.Principal.SecurityIdentifier($cj.sid)).Translate([Security.Principal.NTAccount]).Value } catch {}
                } catch { $ci.ContainerError = $_.Exception.Message }
            }
            $pjP = Join-Path $cdir 'Protectors.json'
            if (Test-Path $pjP) {
                try {
                    $pj = Get-Content $pjP -Raw | ConvertFrom-Json
                    foreach ($pName in $pj.PSObject.Properties.Name) {
                        $node = $pj.$pName
                        $pinfo = [ordered]@{ Type = $pName }
                        if ($pName -eq 'pin' -and $node) {
                            $pinfo.SoftLockoutAttemptLimit = $node.softLockoutAttemptLimit
                            $pinfo.SoftLockoutAttemptCount = $node.softLockoutAttemptCount
                            $pinfo.ProgressiveLockoutIndex = $node.progressiveLockoutIndex
                            $pinfo.DeviceWipeAttemptCount  = $node.deviceWipeAttemptCount
                            $pinfo.Characteristics         = $node.characteristics
                            $pinfo.SealedLockoutAuthBytes  = if ($node.sealedLockoutAuth) { ([Convert]::FromBase64String($node.sealedLockoutAuth)).Length } else { 0 }
                            $pinfo.SealedHistoryBytes      = if ($node.sealedHistory) { ([Convert]::FromBase64String($node.sealedHistory)).Length } else { 0 }
                        }
                        if ($node.secretStore -and $node.secretStore.encryptedCbor) {
                            $pinfo.SecretStoreCborBytes = ([Convert]::FromBase64String($node.secretStore.encryptedCbor)).Length
                            $pinfo.SecretStoreType      = $node.secretStore.type
                        }
                        $ci.Protectors += $pinfo
                    }
                } catch { $ci.ProtectorsError = $_.Exception.Message }
            }
            $kdir = Join-Path $cdir 'Keys'
            if (Test-Path $kdir) {
                Get-ChildItem $kdir -Filter *.json -Force -EA SilentlyContinue | ForEach-Object {
                    try {
                        $k = Get-Content $_.FullName -Raw | ConvertFrom-Json
                        $ci.Keys += [ordered]@{
                            File = $_.Name; Alg = $k.alg; Bits = $k.bits; Usage = $k.usage
                            LogonCapable = $k.logonCapable; NCryptName = $k.ncryptName; Name = $k.name
                            EncryptedPrivBytes = if ($k.encrypted.encryptedCbor) { ([Convert]::FromBase64String($k.encrypted.encryptedCbor)).Length } else { 0 }
                            HasCert = [bool]$k.cert; FidoSignCount = $k.fidoSignCount
                        }
                    } catch {}
                }
            }
            $result.NgcContainers += $ci
        }
    }

    # Passport KSP + Platform Crypto Provider enumeration under SYSTEM too
    try {
        $result.PassportKSP = (Get-ProviderKeys "Microsoft Passport Key Storage Provider")
        $result.PlatformKSP = (Get-ProviderKeys "Microsoft Platform Crypto Provider")
    } catch { $result.NCryptError = $_.Exception.Message }

    $result | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 $outFile
}

# If invoked as the SYSTEM child, just do the privileged phase and exit.
if ($SystemPhaseOut) {
    Invoke-SystemPhase -outFile $SystemPhaseOut -dump:$DumpBlobs.IsPresent -blobDir (Join-Path $OutDir 'blobs')
    return
}

# ===========================================================================
#  MAIN (user/admin context)
# ===========================================================================
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Force $OutDir | Out-Null }
$id      = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

Write-Head "CONTEXT"
Write-KV "Host"      $env:COMPUTERNAME
Write-KV "User"      $id.Name
Write-KV "Elevated" $isAdmin ($(if($isAdmin){'Green'}else{'Yellow'}))
Write-KV "Time"      (Get-Date).ToString('u')
$script:Report.Context = @{ Host=$env:COMPUTERNAME; User=$id.Name; Elevated=$isAdmin; Time=(Get-Date).ToString('u') }

# ---- 1. TPM ----------------------------------------------------------------
Write-Head "TPM"
try {
    $tpm = Get-Tpm
    Write-KV "Present"   $tpm.TpmPresent ($(if($tpm.TpmPresent){'Green'}else{'Red'}))
    Write-KV "Ready"     $tpm.TpmReady
    Write-KV "Enabled"   $tpm.TpmEnabled
    Write-KV "Owned"     $tpm.TpmOwned
    $wmi = Get-CimInstance -Namespace 'root\cimv2\security\microsofttpm' -ClassName Win32_Tpm -ErrorAction SilentlyContinue
    if ($wmi) {
        Write-KV "Spec Version"  $wmi.SpecVersion
        Write-KV "Manufacturer"  $wmi.ManufacturerIdTxt
        Write-KV "FW Version"    $wmi.ManufacturerVersion
    }
    $script:Report.Tpm = @{
        Present=$tpm.TpmPresent; Ready=$tpm.TpmReady; Enabled=$tpm.TpmEnabled; Owned=$tpm.TpmOwned
        SpecVersion=$wmi.SpecVersion; Manufacturer=$wmi.ManufacturerIdTxt; Firmware=$wmi.ManufacturerVersion
    }
} catch { Write-KV "TPM error" $_.Exception.Message Red; $script:Report.Tpm=@{Error=$_.Exception.Message} }

# ---- 2. Device join / NGC prerequisites -----------------------------------
Write-Head "DEVICE JOIN & NGC PREREQUISITES (dsregcmd)"
$ds = (dsregcmd /status) 2>&1
$parse = {
    param($label)
    ($ds | Select-String -SimpleMatch $label | Select-Object -First 1) -replace '.*:\s*',''
}
$joinKeys = 'AzureAdJoined','DomainJoined','WorkplaceJoined','NgcSet','PolicyEnabled','DeviceEligible','PreReqResult','CertEnrollment'
$join = [ordered]@{}
foreach ($k in $joinKeys) {
    $v = (& $parse "$k :"); if (-not $v) { $v = (& $parse "$k ") }
    $v = ($v | Out-String).Trim()
    if ($v) { Write-KV $k $v; $join[$k] = $v }
}
$script:Report.DeviceJoin = $join

# ---- 3. WHFB policy + services --------------------------------------------
Write-Head "WHFB / PASSPORT POLICY & SERVICES"
$polReport = [ordered]@{}
foreach ($hive in 'HKLM','HKCU') {
    $path = "${hive}:\SOFTWARE\Policies\Microsoft\PassportForWork"
    if (Test-Path $path) {
        Write-KV "$hive PassportForWork" "PRESENT" Yellow
        $props = Get-ItemProperty $path
        $props.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
            Write-KV "  $($_.Name)" $_.Value
        }
        $polReport[$hive] = $props
    } else {
        Write-KV "$hive PassportForWork" "not configured" DarkGray
    }
}
$svcReport = @{}
foreach ($s in 'NgcSvc','NgcCtnrSvc','WbioSrvc') {
    $svc = Get-Service $s -ErrorAction SilentlyContinue
    if ($svc) { Write-KV "svc $s" "$($svc.Status)"; $svcReport[$s] = "$($svc.Status)" }
}
# NGC credential-provider registrations (per-SID -> a PIN/NGC cred exists for that user)
$cpPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{D6886603-9D2F-4EB2-B667-1971041FA96B}'
$ngcCredUsers = @()
if (Test-Path $cpPath) {
    Get-ChildItem $cpPath -ErrorAction SilentlyContinue | ForEach-Object {
        $sid = Split-Path $_.Name -Leaf
        $name = try { (New-Object Security.Principal.SecurityIdentifier($sid)).Translate([Security.Principal.NTAccount]).Value } catch { $sid }
        Write-KV "NGC cred provider SID" "$sid ($name)" Yellow
        $ngcCredUsers += @{ Sid=$sid; Account=$name }
    }
}
$script:Report.Policy   = $polReport
$script:Report.Services = $svcReport
$script:Report.NgcCredentialUsers = $ngcCredUsers

# ---- 4. NGC on-disk store (privileged) ------------------------------------
Write-Head "NGC ON-DISK STORE (containers / protectors / crypto keys)"
$sysOut = Join-Path $OutDir ("ngc_system_{0}.json" -f ([guid]::NewGuid().ToString('N').Substring(0,8)))
$needSystem = $true
if ($needSystem -and -not $NoElevate) {
    if (-not $isAdmin) {
        Write-KV "elevation" "NOT elevated - cannot self-elevate to SYSTEM. Re-run as admin, or use -NoElevate." Yellow
    } else {
        $self  = $MyInvocation.MyCommand.Definition
        $tn    = "WHFBKeysSys_" + ([guid]::NewGuid().ToString('N').Substring(0,6))
        $dumpArg = if ($DumpBlobs) { '-DumpBlobs' } else { '' }
        $cmd   = "powershell.exe -NonInteractive -ExecutionPolicy Bypass -File `"$self`" -SystemPhaseOut `"$sysOut`" -OutDir `"$OutDir`" $dumpArg"
        Write-KV "self-elevation" "creating one-shot SYSTEM task '$tn'..." DarkGray
        schtasks /Create /TN $tn /TR $cmd /SC ONCE /ST 23:59 /RU "SYSTEM" /RL HIGHEST /F | Out-Null
        schtasks /Run   /TN $tn | Out-Null
        $deadline = (Get-Date).AddSeconds(30)
        while (-not (Test-Path $sysOut) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 400 }
        Start-Sleep -Milliseconds 600
        schtasks /Delete /TN $tn /F | Out-Null
    }
}
if (Test-Path $sysOut) {
    $sysData = Get-Content $sysOut -Raw | ConvertFrom-Json
    Write-KV "privileged phase as" $sysData.Whoami Green
    $containerCount = 0
    foreach ($rootInfo in $sysData.StoreRoots) {
        Write-Host ""
        Write-Host "  [store] $($rootInfo.Root)" -ForegroundColor White
        $items = @($rootInfo.Items)
        if (-not $items -or $items.Count -eq 0) { Write-Host "    (empty)" -ForegroundColor DarkGray; continue }
        foreach ($it in $items) {
            if ($it.Error) { Write-Host "    ERR: $($it.Error)" -ForegroundColor Red; continue }
            $tag = if ($it.IsDir) { '<DIR>' } else { "$($it.Size) B" }
            $rel = $it.Path.Substring($rootInfo.Root.Length).TrimStart('\')
            Write-Host ("    {0,-10} {1}" -f $tag, $rel) -ForegroundColor Gray
            if ($it.Head -and -not $it.IsDir) {
                Write-Host ("               sha256={0}" -f $it.Sha256) -ForegroundColor DarkGray
                Write-Host ("               head  ={0}" -f $it.Head)   -ForegroundColor DarkGray
            }
            # container GUID folders look like {GUID} or 32-hex under the Ngc root
            if ($it.IsDir -and $rel -match '^[0-9a-fA-F]{8}' ) { $containerCount++ }
        }
    }
    $script:Report.NgcStore      = $sysData.StoreRoots
    $script:Report.NgcContainers = $sysData.NgcContainers
    $script:Report.PassportKSP   = $sysData.PassportKSP
    $script:Report.PlatformKSP   = $sysData.PlatformKSP
    foreach ($ci in @($sysData.NgcContainers)) {
        Write-Host ""
        Write-Host "  >>> PROVISIONED NGC CONTAINER $($ci.Guid)" -ForegroundColor Magenta
        Write-KV "  owner" "$($ci.Account) [$($ci.Sid)]"
        Write-KV "  trustLevel" $ci.TrustLevel
        foreach ($p in @($ci.Protectors)) {
            if ($p.Type -eq 'pin') {
                Write-Host ("    protector[pin]      lockoutLimit={0} attempts={1} progIdx={2} wipeCnt={3} sealedAuth={4}B sealedHist={5}B secretCbor={6}B" -f `
                    $p.SoftLockoutAttemptLimit,$p.SoftLockoutAttemptCount,$p.ProgressiveLockoutIndex,$p.DeviceWipeAttemptCount,$p.SealedLockoutAuthBytes,$p.SealedHistoryBytes,$p.SecretStoreCborBytes) -ForegroundColor Yellow
            } else {
                Write-Host ("    protector[{0,-8}]  secretCbor={1}B" -f $p.Type, $p.SecretStoreCborBytes) -ForegroundColor Gray
            }
        }
        foreach ($k in @($ci.Keys)) {
            Write-Host ("    key {0} {1}-bit usage={2} logonCapable={3} encPriv={4}B ncrypt='{5}'" -f `
                $k.Alg,$k.Bits,$k.Usage,$k.LogonCapable,$k.EncryptedPrivBytes,$k.NCryptName) -ForegroundColor Green
        }
    }
    foreach ($kspProp in 'PassportKSP','PlatformKSP') {
        $ksp = $sysData.$kspProp
        if ($ksp -and $ksp.Keys) {
            Write-Host ""
            Write-Host ("  [SYSTEM-phase] $($ksp.Provider): $(@($ksp.Keys).Count) key(s)") -ForegroundColor White
            foreach ($k in @($ksp.Keys)) {
                $scope = if ($k.Flags -band 0x20) { 'machine' } else { 'user' }
                Write-Host ("    - {0}  [alg={1} len={2} scope={3} export={4} tpm={5}]" -f $k.Name,$k.Algorithm,$k.Length,$scope,$k.ExportPolicy,$k.TpmBacked) -ForegroundColor Green
            }
        }
    }
    if ($containerCount -eq 0) {
        Write-Host ""
        Write-KV "NGC containers" "0 provisioned (only pregen pool / framework files present)" Yellow
    }
    Remove-Item $sysOut -Force -ErrorAction SilentlyContinue
} else {
    Write-KV "privileged phase" "did not produce output (store may be unreadable in this context)" Yellow
}

# ---- 5. NCrypt key enumeration (also in user context) ---------------------
Write-Head "KEY ENUMERATION via NCrypt (Passport KSP + Platform Crypto / TPM)"
foreach ($prov in "Microsoft Passport Key Storage Provider","Microsoft Platform Crypto Provider","Microsoft Software Key Storage Provider") {
    $r = Get-ProviderKeys $prov
    Write-Host ""
    Write-Host "  [$prov]" -ForegroundColor White
    if ($r.ProviderError) { Write-Host "    provider error: $($r.ProviderError)" -ForegroundColor Yellow }
    if (-not $r.Keys -or $r.Keys.Count -eq 0) { Write-Host "    (no keys enumerable in this context)" -ForegroundColor DarkGray; continue }
    foreach ($k in $r.Keys) {
        $scope = if ($k.Flags -band 0x20) { 'machine' } else { 'user' }
        Write-Host ("    - {0}" -f $k.Name) -ForegroundColor Green
        Write-Host ("        alg={0} len={1} scope={2} export={3} tpm={4}" -f $k.Algorithm,$k.Length,$scope,$k.ExportPolicy,$k.TpmBacked) -ForegroundColor Gray
        if ($k.Error)        { Write-Host ("        note: {0}" -f $k.Error) -ForegroundColor DarkYellow }
        if ($k.PublicKeyB64) { Write-Host ("        pubkey(b64,{0}b)={1}..." -f ([Convert]::FromBase64String($k.PublicKeyB64).Length), $k.PublicKeyB64.Substring(0,[Math]::Min(44,$k.PublicKeyB64.Length))) -ForegroundColor DarkGray }
    }
    # store (avoid clobbering the richer SYSTEM-phase results)
    $key = ($prov -replace '[^A-Za-z]','')
    if (-not $script:Report.Contains($key)) { $script:Report[$key] = $r }
}

# ---- 6. Biometrics ---------------------------------------------------------
Write-Head "BIOMETRIC (WinBio) ENROLLMENT"
$wbDb = "$env:windir\System32\WinBioDatabase"
if (Test-Path $wbDb) {
    $files = Get-ChildItem $wbDb -Force -ErrorAction SilentlyContinue
    if ($files) { $files | ForEach-Object { Write-KV $_.Name "$($_.Length) B, $($_.LastWriteTime.ToString('s'))" } }
    else { Write-KV "WinBioDatabase" "present but unreadable in this context" Yellow }
    $script:Report.Biometrics = @{ Path=$wbDb; Files=@($files | Select-Object Name,Length) }
} else { Write-KV "WinBioDatabase" "not present"; $script:Report.Biometrics=@{Present=$false} }

# ---- write JSON report -----------------------------------------------------
Write-Head "REPORT"
$jsonPath = Join-Path $OutDir ("whfb_report_{0:yyyyMMdd_HHmmss}.json" -f (Get-Date))
$script:Report | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 $jsonPath
Write-KV "JSON report" $jsonPath Green
if ($DumpBlobs) { Write-KV "Blob dumps" (Join-Path $OutDir 'blobs') Green }

Write-Host ""
Write-Host "  NOTE: WHFB/NGC private keys are TPM-sealed and NON-EXPORTABLE by design." -ForegroundColor Yellow
Write-Host "        This tool dumps public keys, key metadata, and on-disk protector" -ForegroundColor Yellow
Write-Host "        blobs. Raw private keys cannot be extracted in plaintext." -ForegroundColor Yellow
