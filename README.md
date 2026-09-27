# WHFB-PinCapture

## TL;DR

On a host where Windows Hello is protected by **VBS/VSM (an isolated NgcIso container in
VTL1) + a TPM**, the PIN is **not recoverable offline** and online brute-force is **blocked**
by the secure-kernel trustlet. The only reliable route is **capture-at-entry**.

This project captures the PIN by placing a **CPU hardware breakpoint** on the function that
packages the typed PIN inside `LogonUI.exe`, reading the argument from the trapped thread
context in a Vectored Exception Handler, and letting the **original, unmodified instruction
execute**, so the PIN login still succeeds normally.

It also ships `Get-WHFBKeys.ps1`, a full WHFB/NGC/TPM enumeration and key-material harvester.

Validated end-to-end on **Windows 11 26200 (Home)** with an Intel fTPM 2.0 and VBS running.

## Why offline attacks don't work here

| Protection observed | Consequence |
|---|---|
| **VBS / VSM running** (`Win32_DeviceGuard` VBS status = 2, `LsaIso.exe` present) | Key hierarchy lives in **VTL1** (secure kernel), unreachable from SYSTEM in VTL0 |
| **NgcIso container** (`NgcIsoHeader_…` in `Container.json` / protector blobs `NgcIsoCtnr.dll` loaded in `NgcSvc`) | PIN secret is unsealed *inside* the trustlet, not in normal user mode |
| **TPM-sealed** master material (`srk` in `Container.json`, `impl` key type) | No plaintext key on disk, unseal requires the TPM |
| **Anti-hammering** (`softLockoutAttemptLimit = 5`, `sealedLockoutAuth` in `Protectors.json`) | Online guessing locks out, the counter is enforced by VTL1, not resettable from disk |

## Where the cleartext PIN lives

At lock-screen / sign-in, the PIN is typed into the **NGC credential provider hosted by
`LogonUI.exe`** (runs as `SYSTEM`, **not** a PPL, spawned on demand). The provider hands the
typed PIN to `ngckeyenum.dll!NgcSerializeConvenienceCredential`, whose **arg1 (RCX)** points to:

```c
struct {                 // arg1
    uint64_t type;       // 1  (convenience-PIN credential)
    void*    buffer;     // -> ASCII PIN, e.g. 0x32 0x30 0x30 0x32 = "2002" example PIN
    uint32_t length;     // digit count (e.g. 4)
};
// arg2 = full NGC key name  "S-1-5-...-1001/<container-guid>//<key-guid>"
// arg3 = username, arg4 = computername, arg5 = SID, arg6 = "Negotiate"
```

## The key insight: intrusive hooking BREAKS the PIN login

Classic inline/trampoline hooking of `NgcSerializeConvenienceCredential` (or of
`NgcPackAuthBuffer`) **corrupts** the serialized logon credential. The symptom is nasty and
silent: the sign-in screen **just reloads with no error**, the correct PIN is rejected, and
repeated rejections **soft-lock the PIN** (forcing password sign-in). Force-killing `NgcSvc`
similarly disrupts the container.

We need a capture primitive that reads the argument **without changing a single byte of code
or the control flow** of the target function.

## The technique: hardware-breakpoint capture

`ngccap.dll` (see [`src/ngccap.c`](src/ngccap.c)) is injected into `LogonUI.exe` and:

1. **Arms a CPU hardware execute breakpoint.** It resolves
   `ngckeyenum!NgcSerializeConvenienceCredential`, then sets **DR0 = target** and
   **DR7 = L0 | exec | len-1** on **every thread** of the process (via
   `CreateToolhelp32Snapshot` → `OpenThread` → `SuspendThread` → `GetThreadContext` /
   `SetThreadContext` with `CONTEXT_DEBUG_REGISTERS` → `ResumeThread`).

2. **Handles the trap in a Vectored Exception Handler.** When the function is entered, the CPU
   raises `EXCEPTION_SINGLE_STEP` **before** executing the instruction. The VEH checks
   `ContextRecord->Rip == target`, reads `Rcx` → `{buffer, length}`, copies out the ASCII PIN,
   then:
   - sets the **Resume Flag (RF)** in `EFlags` so the breakpoint doesn't immediately re-fire, and
   - returns **`EXCEPTION_CONTINUE_EXECUTION`**.

3. **The original instruction runs, unmodified.** Because no code was patched and no
   trampoline/extra stack frame was introduced, `NgcSerializeConvenienceCredential` executes
   exactly as it would have. The credential is built correctly, LSA accepts it, and the
   **PIN login succeeds normally**.

4. **Self-cleans.** After the first capture the DLL clears DR0/DR7 on all threads and removes
   the VEH, leaving the process pristine.

## Repository layout

```
WHFB-PIN-Capture/
├─ README.md
├─ Get-WHFBKeys.ps1        # WHFB/NGC/TPM enumerator + key-material harvester
└─ src/
   ├─ ngccap.c             # HW-breakpoint capture DLL
   ├─ build.bat            # cl.exe build (MSVC 2022 Build Tools)
   └─ logonui_watch.ps1    # injects ngccap.dll into LogonUI on sight
```

## Requirements

- Windows 10/11 with a Windows Hello **convenience PIN** enrolled.
- **Elevated Administrator** (the injector enables `SeDebugPrivilege`). `LogonUI` runs as
  SYSTEM but is not PPL, so an elevated admin token can open and inject it.

## Build & run

```bat
:: 1) build the capture DLL
cd src
build.bat

:: 2) start the injector (elevated admin PowerShell)
powershell -ExecutionPolicy Bypass -File .\logonui_watch.ps1
```

```
3) Lock the workstation (Win+L) and sign back in with your PIN, it works normally.
4) Read the captured PIN:
     type C:\Windows\Temp\pin_capture.log
   -> >>> PIN CAPTURED = "1234"
```

Paths are configurable: `LOGPATH` at the top of `ngccap.c` and `$plog` in `logonui_watch.ps1`
must match (default `C:\Windows\Temp\pin_capture.log`).

## Enumeration tool

`Get-WHFBKeys.ps1` reports TPM status, device-join / NGC provisioning, WHFB policy, the on-disk
NGC container store (containers → protectors → keys, self-elevating to SYSTEM), NCrypt keys
(Passport KSP / Platform Crypto Provider / Software KSP with public-key export), and biometric
enrollment, emitting a JSON report. It never extracts private keys (TPM-sealed, non-exportable);
it dumps public keys, metadata and on-disk protector blobs.

```powershell
powershell -ExecutionPolicy Bypass -File .\Get-WHFBKeys.ps1 -DumpBlobs -OutDir .\out
```
offline and brute-force paths shown to be closed, and the PIN captured **while the owner signed
in normally with the correct PIN** using the hardware-breakpoint DLL.

## License

For educational and authorized security-research use only. No warranty.
