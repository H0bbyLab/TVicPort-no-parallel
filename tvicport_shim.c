/*
 * TVicPort.dll replacement for the Hi-Lo ALL-11 device modules
 */
#include <windows.h>
#include <stdio.h>

/* ---------------- TVicPort stubs ---------------- */

BOOL  __stdcall OpenTVicPort(void)              { return FALSE; }   /* ord 1  */
void  __stdcall CloseTVicPort(void)             { }                 /* ord 2  */
BOOL  __stdcall IsDriverOpened(void)            { return FALSE; }   /* ord 3  */
void  __stdcall SetHardAccess(BOOL b)           { (void)b; }        /* ord 5  */
BYTE  __stdcall ReadPort(WORD port)             { (void)port; return 0xFF; } /* ord 6 */
void  __stdcall WritePort(WORD port, BYTE v)    { (void)port; (void)v; }     /* ord 7 */
BYTE  __stdcall GetLPTNumber(void)              { return 1; }       /* ord 16 */
void  __stdcall SetLPTNumber(BYTE n)            { (void)n; }        /* ord 17 */
BYTE  __stdcall GetLPTNumPorts(void)            { return 0; }       /* ord 18 */
WORD  __stdcall GetLPTBasePort(void)            { return 0x378; }   /* ord 19 */
BOOL  __stdcall GetPin(BYTE pin)                { (void)pin; return FALSE; } /* ord 20 */
void  __stdcall SetPin(BYTE pin, BOOL v)        { (void)pin; (void)v; }      /* ord 21 */

/* ---------------- serial trace ---------------- */

static CRITICAL_SECTION g_lock;
static FILE  *g_log;
static HANDLE g_com = INVALID_HANDLE_VALUE;
static char   g_dir;            /* 'T' or 'R' for the line being built */
static int    g_col;
static DWORD  g_t0;

static HANDLE (WINAPI *Real_CreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
static BOOL   (WINAPI *Real_ReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
static BOOL   (WINAPI *Real_WriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
static BOOL   (WINAPI *Real_CloseHandle)(HANDLE);
static BOOL   (WINAPI *Real_SetCommState)(HANDLE, LPDCB);
static BOOL   (WINAPI *Real_PurgeComm)(HANDLE, DWORD);

static void log_end_line(void)
{
    if (g_log && g_dir) { fputc('\n', g_log); g_dir = 0; g_col = 0; }
}

static void log_event(const char *fmt, ...)
{
    va_list ap;
    if (!g_log) return;
    EnterCriticalSection(&g_lock);
    log_end_line();
    fprintf(g_log, "%9.3f  ", (GetTickCount() - g_t0) / 1000.0);
    va_start(ap, fmt); vfprintf(g_log, fmt, ap); va_end(ap);
    fputc('\n', g_log);
    fflush(g_log);
    LeaveCriticalSection(&g_lock);
}

static void log_bytes(char dir, const BYTE *p, DWORD n)
{
    DWORD i;
    if (!g_log || !n) return;
    EnterCriticalSection(&g_lock);
    for (i = 0; i < n; i++) {
        if (g_dir != dir || g_col >= 32) {
            log_end_line();
            fprintf(g_log, "%9.3f  %cX", (GetTickCount() - g_t0) / 1000.0, dir);
            g_dir = dir;
        }
        fprintf(g_log, " %02X", p[i]);
        g_col++;
    }
    fflush(g_log); /* keep the log complete even if the module is killed */
    LeaveCriticalSection(&g_lock);
}

static BOOL is_com_name(LPCSTR name)
{
    if (!name) return FALSE;
    if (!_strnicmp(name, "\\\\.\\", 4)) name += 4;
    return !_strnicmp(name, "COM", 3);
}

static HANDLE WINAPI Hook_CreateFileA(LPCSTR name, DWORD acc, DWORD share, LPSECURITY_ATTRIBUTES sa,
                                      DWORD disp, DWORD flags, HANDLE tmpl)
{
    HANDLE h = Real_CreateFileA(name, acc, share, sa, disp, flags, tmpl);
    if (is_com_name(name)) {
        log_event("OPEN %s -> %s", name, h == INVALID_HANDLE_VALUE ? "FAIL" : "ok");
        if (h != INVALID_HANDLE_VALUE) g_com = h;
    }
    return h;
}

static BOOL WINAPI Hook_ReadFile(HANDLE h, LPVOID buf, DWORD n, LPDWORD got, LPOVERLAPPED ov)
{
    BOOL r = Real_ReadFile(h, buf, n, got, ov);
    if (h == g_com && h != INVALID_HANDLE_VALUE && r && got && *got)
        log_bytes('R', (const BYTE *)buf, *got);
    return r;
}

static BOOL WINAPI Hook_WriteFile(HANDLE h, LPCVOID buf, DWORD n, LPDWORD put, LPOVERLAPPED ov)
{
    BOOL r = Real_WriteFile(h, buf, n, put, ov);
    if (h == g_com && h != INVALID_HANDLE_VALUE)
        log_bytes('T', (const BYTE *)buf, (r && put) ? *put : 0);
    return r;
}

static BOOL WINAPI Hook_CloseHandle(HANDLE h)
{
    if (h == g_com && h != INVALID_HANDLE_VALUE) {
        log_event("CLOSE");
        g_com = INVALID_HANDLE_VALUE;
    }
    return Real_CloseHandle(h);
}

static BOOL WINAPI Hook_SetCommState(HANDLE h, LPDCB dcb)
{
    if (h == g_com && dcb)
        log_event("BAUD %lu  bits=%u parity=%u stop=%u", dcb->BaudRate, dcb->ByteSize, dcb->Parity, dcb->StopBits);
    return Real_SetCommState(h, dcb);
}

static BOOL WINAPI Hook_PurgeComm(HANDLE h, DWORD f)
{
    if (h == g_com) log_event("PURGE %lX", f);
    return Real_PurgeComm(h, f);
}

/* Patch one kernel32 import in the main EXE's IAT. */
static void patch_iat(HMODULE mod, const char *fn, void *hook, void **real)
{
    BYTE *base = (BYTE *)mod;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + ((IMAGE_DOS_HEADER *)base)->e_lfanew);
    IMAGE_DATA_DIRECTORY dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    IMAGE_IMPORT_DESCRIPTOR *imp;
    void *target = (void *)GetProcAddress(GetModuleHandleA("kernel32.dll"), fn);

    if (!dir.VirtualAddress || !target) return;
    *real = target;
    for (imp = (IMAGE_IMPORT_DESCRIPTOR *)(base + dir.VirtualAddress); imp->Name; imp++) {
        IMAGE_THUNK_DATA *t = (IMAGE_THUNK_DATA *)(base + imp->FirstThunk);
        for (; t->u1.Function; t++) {
            if ((void *)t->u1.Function == target) {
                DWORD old;
                VirtualProtect(&t->u1.Function, sizeof(void *), PAGE_READWRITE, &old);
                t->u1.Function = (ULONG_PTR)hook;
                VirtualProtect(&t->u1.Function, sizeof(void *), old, &old);
            }
        }
    }
}

static void start_trace(void)
{
    char path[MAX_PATH], exe[MAX_PATH], env[8];
    char *slash, *dot;
    SYSTEMTIME st;
    HMODULE mod = GetModuleHandleA(NULL);

    if (GetEnvironmentVariableA("ALL11_TRACE", env, sizeof env) && env[0] == '0') return;

    GetModuleFileNameA(mod, path, sizeof path);
    slash = strrchr(path, '\\');
    lstrcpynA(exe, slash ? slash + 1 : path, sizeof exe);
    if ((dot = strrchr(exe, '.')) != NULL) *dot = 0;
    if (slash) slash[1] = 0; else path[0] = 0;

    GetLocalTime(&st);
    sprintf(path + strlen(path), "trace_%s_%04u%02u%02u_%02u%02u%02u.log",
            exe, st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    g_log = fopen(path, "w");
    if (!g_log) return;
    g_t0 = GetTickCount();
    fprintf(g_log, "# ALL-11 serial trace: %s  cmdline: %s\n", exe, GetCommandLineA());
    fflush(g_log);

    patch_iat(mod, "CreateFileA",  Hook_CreateFileA,  (void **)&Real_CreateFileA);
    patch_iat(mod, "ReadFile",     Hook_ReadFile,     (void **)&Real_ReadFile);
    patch_iat(mod, "WriteFile",    Hook_WriteFile,    (void **)&Real_WriteFile);
    patch_iat(mod, "CloseHandle",  Hook_CloseHandle,  (void **)&Real_CloseHandle);
    patch_iat(mod, "SetCommState", Hook_SetCommState, (void **)&Real_SetCommState);
    patch_iat(mod, "PurgeComm",    Hook_PurgeComm,    (void **)&Real_PurgeComm);
}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID res)
{
    (void)inst; (void)res;
    if (reason == DLL_PROCESS_ATTACH) {
        InitializeCriticalSection(&g_lock);
        start_trace();
    } else if (reason == DLL_PROCESS_DETACH && g_log) {
        EnterCriticalSection(&g_lock);
        log_end_line();
        fclose(g_log);
        g_log = NULL;
        LeaveCriticalSection(&g_lock);
    }
    return TRUE;
}
