/*
 * Goodix Milan Engine In-Process Loader and Bridge
 *
 * Implements native in-process PE loader for GoodixEngineAdapter.dll on Linux.
 * Maps sections with W^X memory protection via memfd_create.
 * Configures %gs TEB and executes MS-ABI algorithm exports.
 *
 * Based on the native PE loader from the goodix-5e0a project by
 * jitendradara12 (https://github.com/jitendradara12/goodix-5e0a),
 * originally in libfprint-driver/goodix_milan.c. Adapted by Lutfor for the
 * 27c6:5117 lutfor511 driver: 88x80 -> 64x80 preprocessing, composite
 * template packing, persisted RAW FpPrint storage and libfprint hooks.
 *
 * GoodixEngineAdapter.dll / AlgoChicago.dll are proprietary Goodix binaries
 * and are NOT distributed with this project; the user must supply them.
 *
 * Copyright (C) 2026 The libfprint Goodix 5e0a contributors
 * Integration changes Copyright (C) 2026 Lutfor <lutfor183.du@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "goodix_milan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <math.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <asm/prctl.h>
#include <glib.h>

#define MS __attribute__((ms_abi))
#define DLL_PROCESS_ATTACH 1

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef struct __attribute__((packed)) {
    uint8_t *data;          /* +0x00: pointer to 8-bit pixels */
    int16_t width;          /* +0x08: 80 (profile 10) */
    int16_t height;         /* +0x0a: 64 (profile 10) */
    int16_t reserved1;      /* +0x0c: 0 */
    uint8_t bits;           /* +0x0e: 8 */
    uint8_t channels;       /* +0x0f: 1 */
    uint64_t reserved2;     /* +0x10: 0 */
    int16_t frame_count;    /* +0x18: 1 */
    int16_t reserved3;      /* +0x1a: 0 */
    uint32_t sensor_type;   /* +0x1c: 10 or 12 */
    uint64_t reserved4;     /* +0x20: 0 */
    uint8_t quality;        /* +0x28 */
    uint8_t overlap;        /* +0x29 */
    uint8_t reserved5[6];   /* +0x2a: 0 */
} GoodixImage;

static u8 *g_image = NULL;
static u64 g_imagebase = 0;
static u8 *g_file = NULL;
static long g_filelen = 0;

static u32 f32(u64 o) { return *(u32*)(g_file + o); }
static u64 f64(u64 o) { return *(u64*)(g_file + o); }
static u16 f16(u64 o) { return *(u16*)(g_file + o); }

/* Fake TEB / gs */
static u8 g_teb[0x2000] __attribute__((aligned(4096)));
static u8 g_peb[0x1000] __attribute__((aligned(4096)));
static void *g_tls_array[64];
static u8 g_tls_block[0x2000];

static inline void ensure_gs(void) {
    syscall(SYS_arch_prctl, ARCH_SET_GS, g_teb);
}

/* Import Shim Table */
typedef struct {
    const char *dll;
    const char *name;
    uint32_t ordinal;
    void *fn;
} Shim;

static Shim g_shims[512];
static int g_nshims = 0;

static void reg_name(const char *name, void *fn) {
    if (g_nshims >= (int)(sizeof(g_shims) / sizeof(g_shims[0]))) abort();
    g_shims[g_nshims].dll = NULL;
    g_shims[g_nshims].name = name;
    g_shims[g_nshims].ordinal = 0;
    g_shims[g_nshims].fn = fn;
    g_nshims++;
}

static void reg_ord(const char *dll, uint32_t ord, void *fn) {
    if (g_nshims >= (int)(sizeof(g_shims) / sizeof(g_shims[0]))) abort();
    g_shims[g_nshims].dll = dll;
    g_shims[g_nshims].name = NULL;
    g_shims[g_nshims].ordinal = ord;
    g_shims[g_nshims].fn = fn;
    g_nshims++;
}

static void* find_shim(const char *name) {
    for (int i = 0; i < g_nshims; i++) {
        if (g_shims[i].name && strcmp(g_shims[i].name, name) == 0) return g_shims[i].fn;
    }
    return NULL;
}

static void* find_shim_ordinal(const char *dll, uint32_t ord) {
    for (int i = 0; i < g_nshims; i++) {
        if (g_shims[i].ordinal == ord) {
            if (!g_shims[i].dll || !dll || strcasecmp(g_shims[i].dll, dll) == 0) return g_shims[i].fn;
        }
    }
    return NULL;
}

/* Shim implementations */
static u32 g_lasterr = 0;
static int g_crt_errno = 0;

static void MS sh_SetLastError(u32 e) { g_lasterr = e; }
static u32  MS sh_GetLastError(void) { return g_lasterr; }

static void* MS sh_GetProcessHeap(void) { return (void*)0x100; }
static void* MS sh_HeapAlloc(void *h, u32 flags, u64 size) {
    void *p = malloc(size ? size : 1);
    if (p && (flags & 8)) memset(p, 0, size);
    return p;
}
static int MS sh_HeapFree(void *h, u32 f, void *p) { free(p); return 1; }
static void* MS sh_LocalFree(void *h) { free(h); return NULL; }

static void* MS sh_malloc(size_t s) { return malloc(s ? s : 1); }
static void* MS sh_calloc(size_t n, size_t s) { return calloc(n ? n : 1, s ? s : 1); }
static void* MS sh_realloc(void *p, size_t s) {
    if (!s) { free(p); return NULL; }
    return realloc(p, s);
}
static void  MS sh_free(void *p) { free(p); }

static void MS sh_InitCS(void *p) { }
static u32  MS sh_InitCSSpin(void *p, u32 s) __attribute__((unused));
static u32  MS sh_InitCSSpin(void *p, u32 s) { return 1; }
static void MS sh_EnterCS(void *p) { }
static void MS sh_LeaveCS(void *p) { }
static void MS sh_DeleteCS(void *p) { }

static void MS sh_InitConditionVariable(void *p) { }
static void MS sh_WakeAllConditionVariable(void *p) { }
static int  MS sh_SleepConditionVariableCS(void *cv, void *cs, u32 ms) { return 1; }
static void MS sh_InitSList(void *p) { memset(p, 0, 16); }
static void* MS sh_FlushSList(void *p) { return NULL; }
static void* MS sh_PushEntrySList(void *h, void *e) { return NULL; }

static u32 g_tls_next = 1;
static void *g_tls_vals[1088];
static u32  MS sh_TlsAlloc(void) { if (g_tls_next >= 1088) return 0xFFFFFFFF; return g_tls_next++; }
static int  MS sh_TlsFree(u32 i) { return 1; }
static void* MS sh_TlsGetValue(u32 i) { g_lasterr = 0; return (i < 1088) ? g_tls_vals[i] : NULL; }
static int  MS sh_TlsSetValue(u32 i, void *v) { if (i < 1088) g_tls_vals[i] = v; return 1; }

static u32  MS sh_FlsAlloc(void *cb) { return g_tls_next++; }
static int  MS sh_FlsFree(u32 i) { return 1; }
static void* MS sh_FlsGetValue(u32 i) { return (i < 1088) ? g_tls_vals[i] : NULL; }
static int  MS sh_FlsSetValue(u32 i, void *v) { if (i < 1088) g_tls_vals[i] = v; return 1; }

static void* MS sh_GetCurrentProcess(void) { return (void*)-1; }
static u32  MS sh_GetCurrentProcessId(void) { return 1234; }
static u32  MS sh_GetCurrentThreadId(void) { return 5678; }
static void* MS sh_GetModuleHandleW(void *n) { return (void*)g_image; }
static void* MS sh_CreateThread(void *sa, u64 st, void *fn, void *arg, u32 fl, u32 *id) {
    if (id) *id = 4321;
    return (void*)0x3000;
}
static void MS sh_TerminateProcess(void *h, u32 c) { }
static int  MS sh_TerminateThread(void *h, u32 c) { return 1; }

static void* MS sh_CreateEventW(void *sa, int man, int init, void *name) { return (void*)0x2000; }
static int  MS sh_SetEvent(void *h) { return 1; }
static int  MS sh_ResetEvent(void *h) { return 1; }
static u32  MS sh_WaitForSingleObject(void *h, u32 ms) { return 0; }
static u32  MS sh_WaitForMultipleObjects(u32 count, void **handles, int wait_all, u32 ms) { return 0; }
static void MS sh_Sleep(u32 ms) { usleep(ms * 1000); }

static u32 MS sh_timeGetTime(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (u32)(tv.tv_sec * 1000 + tv.tv_usec / 1000);
}
static void MS sh_GetSystemTimeAsFileTime(u64 *ft) {
    static u64 t = 0x01d0000000000000ULL;
    if (ft) *ft = (t += 100000);
}
static void MS sh_GetLocalTime(void *st) {
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    if (st) {
        u16 *w = (u16*)st;
        w[0] = tm->tm_year + 1900;
        w[1] = tm->tm_mon + 1;
        w[2] = tm->tm_wday;
        w[3] = tm->tm_mday;
        w[4] = tm->tm_hour;
        w[5] = tm->tm_min;
        w[6] = tm->tm_sec;
        w[7] = 0;
    }
}
static int MS sh_QueryPerformanceCounter(u64 *c) {
    static u64 t = 0;
    if (c) *c = (t += 1000);
    return 1;
}
static int MS sh_QueryPerformanceFrequency(u64 *f) {
    if (f) *f = 10000000ULL;
    return 1;
}

static int   MS sh_IsDebuggerPresent(void) { return 0; }
static int   MS sh_IsProcessorFeaturePresent(u32 f) { return 1; }
static void* MS sh_EncodePointer(void *p) { return p; }
static void  MS sh_GetStartupInfoW(void *si) { if (si) { memset(si, 0, 104); *(u32*)si = 104; } }
static u32   MS sh_GetSystemDirectoryW(u16 *b, u32 n) {
    const u16 sys[] = {'C',':','\\','W','i','n','d','o','w','s','\\','S','y','s','t','e','m','3','2',0};
    u32 len = 19;
    if (b && n > len) { memcpy(b, sys, sizeof(sys)); return len; }
    return 0;
}
static int MS sh_GetDiskFreeSpaceExW(void *d, u64 *fb, u64 *tb, u64 *tfb) {
    if (fb) *fb = 100ULL * 1024 * 1024 * 1024;
    if (tb) *tb = 500ULL * 1024 * 1024 * 1024;
    if (tfb) *tfb = 100ULL * 1024 * 1024 * 1024;
    return 1;
}

static void MS sh_OutputDebugStringW(const u16 *s) { }

static int MS sh_MultiByteToWideChar(u32 cp, u32 f, const char *mb, int mbc, u16 *wc, int wcc) {
    if (mbc < 0) mbc = strlen(mb) + 1;
    if (wcc == 0) return mbc;
    int n = (mbc < wcc) ? mbc : wcc;
    for (int i = 0; i < n; i++) wc[i] = (u8)mb[i];
    return n;
}
static int MS sh_WideCharToMultiByte(u32 cp, u32 f, const u16 *wc, int wcc, char *mb, int mbc, void *d, void *u) {
    if (wcc < 0) { wcc = 0; while (wc[wcc]) wcc++; wcc++; }
    if (mbc == 0) return wcc;
    int n = (wcc < mbc) ? wcc : mbc;
    for (int i = 0; i < n; i++) mb[i] = (char)wc[i];
    return n;
}

static void* MS sh_CreateFileW(void *n, u32 a, u32 s, void *sa, u32 c, u32 fl, void *t) { g_lasterr = 2; return (void*)-1; }
static int   MS sh_WriteFile(void *h, const void *b, u32 n, u32 *wr, void *o) { if (wr) *wr = n; return 1; }
static int   MS sh_CloseHandle(void *h) { return 1; }
static int   MS sh_DeleteFileW(void *n) { return 1; }
static int   MS sh_CopyFileW(void *e, void *n, int f) { return 1; }
static void* MS sh_FindFirstFileW(void *n, void *d) { g_lasterr = 2; return (void*)-1; }
static int   MS sh_DeviceIoControl(void *h, u32 c, void *ib, u32 il, void *ob, u32 ol, u32 *ret, void *ov) {
    if (ret) *ret = 0;
    return 1;
}
static int MS sh_GetOverlappedResult(void *h, void *o, u32 *b, int w) { if (b) *b = 0; return 1; }

static void* MS sh_SetUnhandledExceptionFilter(void *f) { return NULL; }
static u32   MS sh_UnhandledExceptionFilter(void *p) { return 1; }
static void* MS sh_RtlLookupFunctionEntry(u64 pc, u64 *base, void *hist) { if (base) *base = g_imagebase; return NULL; }
static void* MS sh_RtlVirtualUnwind(u32 t, u64 b, u64 pc, void *fe, void *ctx, void **hd, u64 *est, void *ctxp) { return NULL; }
static void  MS sh_RtlCaptureContext(void *ctx) { if (ctx) memset(ctx, 0, 1232); }
static void  MS sh_RtlUnwindEx(void *a, void *b, void *c, void *d, void *e, void *f) { }
static void* MS sh_RtlPcToFileHeader(void *pc, void **base) { if (base) *base = (void*)g_image; return (void*)g_image; }
static void  MS sh_RaiseException(u32 code, u32 fl, u32 n, void *a) { }
static void MS sh_C_specific_handler(void) { }

static int MS sh_CryptAcquireContextW(void **ph, void *cn, void *pn, u32 pt, u32 f) {
    if (ph) *ph = (void*)0xC001;
    return 1;
}
static int MS sh_CryptReleaseContext(void *h, u32 f) { return 1; }
static int MS sh_CryptGenRandom(void *h, u32 len, u8 *buf) {
    if (!buf) return 0;
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    ssize_t n = read(fd, buf, len);
    close(fd);
    return (n == (ssize_t)len) ? 1 : 0;
}
static u32 MS sh_EventUnregister(u64 h) { return 0; }
static u32 MS sh_RegOpenCurrentUser(u32 am, void **k) { if (k) *k = (void*)0x5001; return 0; }
static u32 MS sh_RegOpenKeyExW(void *k, void *s, u32 o, u32 am, void **rk) { if (rk) *rk = (void*)0x5002; return 0; }
static u32 MS sh_RegCreateKeyExW(void *k, void *s, u32 r, void *c, u32 o, u32 am, void *sa, void **rk, u32 *disp) {
    if (rk) *rk = (void*)0x5003;
    if (disp) *disp = 1;
    return 0;
}
static u32 MS sh_RegQueryValueExW(void *k, void *v, void *r, u32 *t, u8 *d, u32 *s) { return 2; }
static u32 MS sh_RegSetValueExW(void *k, void *v, u32 r, u32 t, const u8 *d, u32 s) { return 0; }
static u32 MS sh_RegCloseKey(void *k) { return 0; }
static int MS sh_LookupAccountNameW(void *s, void *an, void *sid, u32 *cb_sid, void *dom, u32 *cb_dom, void *use) { return 0; }

static int MS sh_CoInitializeEx(void *p, u32 c) { return 0; }
static void MS sh_CoUninitialize(void) { }
static int MS sh_CoCreateInstance(void *clsid, void *out, u32 ctx, void *iid, void **ppv) {
    if (ppv) *ppv = NULL;
    return 0x80004002;
}
static int MS sh_CoCreateGuid(void *guid) { if (guid) memset(guid, 0x42, 16); return 0; }
static int MS sh_CoSetProxyBlanket(void *p, u32 a, u32 b, void *c, u32 d, u32 e, void *f, u32 g) { return 0; }
static int MS sh_CoInitializeSecurity(void *p, long c, void *as, void *r1, u32 l, u32 il, void *r2, u32 cap, void *r3) { return 0; }

/* Live-BSTR tracker for sh_SysStringByteLen validation.
 * Every BSTR handed out by sh_SysAllocStringLen is recorded here and removed
 * by sh_SysFreeString. ByteLen only trusts the 4-byte length prefix for a
 * tracked (known-live) pointer; anything else — static, stack, or foreign
 * buffers — falls back to a bounded NUL scan so a non-BSTR pointer can never
 * cause an OOB read below the pointer. All engine calls are serialized by
 * g_milan_mutex, so no extra locking is needed. */
#define BSTR_TRACK_MAX 512
#define BSTR_FALLBACK_MAX_CHARS 0x100000u
static const u16 *g_bstr_live[BSTR_TRACK_MAX];
static u32 g_bstr_bytes[BSTR_TRACK_MAX];
static int g_bstr_nlive = 0;

static void bstr_track_add(const u16 *s, u32 byte_len) {
    if (g_bstr_nlive >= BSTR_TRACK_MAX) return;
    g_bstr_live[g_bstr_nlive] = s;
    g_bstr_bytes[g_bstr_nlive] = byte_len;
    g_bstr_nlive++;
}

static int bstr_tracked(const u16 *s) {
    for (int i = 0; i < g_bstr_nlive; i++) {
        if (g_bstr_live[i] == s) return 1;
    }
    return 0;
}

static void bstr_track_remove(const u16 *s) {
    for (int i = 0; i < g_bstr_nlive; i++) {
        if (g_bstr_live[i] == s) {
            g_bstr_nlive--;
            g_bstr_live[i] = g_bstr_live[g_bstr_nlive];
            g_bstr_bytes[i] = g_bstr_bytes[g_bstr_nlive];
            return;
        }
    }
}

static void* MS sh_SysAllocStringLen(const u16 *s, u32 l) {
    if (l >= 0x40000000) return NULL;
    u32 byte_len = l * sizeof(u16);
    u8 *buf = malloc(sizeof(u32) + byte_len + sizeof(u16));
    if (!buf) return NULL;
    *(u32*)buf = byte_len;
    u16 *str = (u16*)(buf + sizeof(u32));
    if (s) memcpy(str, s, byte_len);
    str[l] = 0;
    bstr_track_add(str, byte_len);
    return (void*)str;
}
static void* MS sh_SysAllocString(const u16 *s) {
    if (!s) return NULL;
    u32 l = 0;
    while (s[l]) l++;
    return sh_SysAllocStringLen(s, l);
}
static void  MS sh_SysFreeString(void *s) {
    if (!s) return;
    if (!bstr_tracked((const u16*)s)) return; /* static/stack/foreign: not ours, never free s-4 */
    bstr_track_remove((const u16*)s);
    free((u8*)s - sizeof(u32));
}
static u32   MS sh_SysStringByteLen(const u16 *s) {
    if (!s) return 0;
    /* Fast path: engine-supplied BSTRs were allocated by
     * sh_SysAllocStringLen above, so only a tracked live pointer may trust
     * the length prefix. */
    if (bstr_tracked(s))
        return *(const u32*)((const u8*)s - sizeof(u32));
    /* Unknown pointer: the prefix may be unmapped, so fall back to a
     * bounded NUL scan instead of an OOB read. */
    u32 l = 0;
    while (l < BSTR_FALLBACK_MAX_CHARS && s[l]) l++;
    return l * sizeof(u16);
}
static u32   MS sh_SysStringLen(const u16 *s) {
    return sh_SysStringByteLen(s) / sizeof(u16);
}
static void  MS sh_VariantInit(void *v) { if (v) memset(v, 0, 24); }
static int   MS sh_VariantClear(void *v) { if (v) memset(v, 0, 24); return 0; }
static int   MS sh_VariantCopy(void *d, void *s) { if (d && s) memcpy(d, s, 24); return 0; }

static void* MS sh_PowerSettingRegisterNotification(void *s, u32 f, void *h, void **ph) { if (ph) *ph = (void*)0x7001; return 0; }
static u32 MS sh_PowerSettingUnregisterNotification(void *h) { return 0; }
static int MS sh_MiniDumpWriteDump(void *hp, u32 pid, void *hf, u32 dt, void *ep, void *up, void *cp) { return 0; }

static int MS sh_WSAStartup(u16 v, void *d) { return 0; }
static int MS sh_WSACleanup(void) { return 0; }
static int MS sh_WSAGetLastError(void) { return 0; }
static u64 MS sh_socket(int af, int t, int p) { return ~0ULL; }
static int MS sh_closesocket(u64 s) { return 0; }
static int MS sh_bind(u64 s, void *a, int l) { return -1; }
static int MS sh_listen(u64 s, int b) { return -1; }
static u64 MS sh_accept(u64 s, void *a, void *l) { return ~0ULL; }
static int MS sh_connect(u64 s, void *a, int l) { return -1; }
static int MS sh_send(u64 s, const char *b, int l, int f) { return -1; }
static int MS sh_recv(u64 s, char *b, int l, int f) { return -1; }
static int MS sh_recvfrom(u64 s, char *b, int l, int f, void *from, void *fromlen) { return -1; }
static int MS sh_setsockopt(u64 s, int l, int on, const char *ov, int ol) { return 0; }
static int MS sh_getsockname(u64 s, void *a, void *l) { return -1; }
static u16 MS sh_htons(u16 hostshort) { return (hostshort >> 8) | (hostshort << 8); }
static u32 MS sh_inet_addr(const char *cp) { return 0x0100007f; }
static char* MS sh_inet_ntoa(u32 in) { static char ip[] = "127.0.0.1"; return ip; }

typedef void (MS *PVFV)(void);
typedef int (MS *PIFV)(void);
static void MS sh_initterm(PVFV *start, PVFV *end) {
    if (!start || !end) return;
    for (PVFV *fn = start; fn < end; ++fn) { if (*fn) (*fn)(); }
}
static int MS sh_initterm_e(PIFV *start, PIFV *end) {
    if (!start || !end) return 0;
    for (PIFV *fn = start; fn < end; ++fn) { if (*fn) { int r = (*fn)(); if (r != 0) return r; } }
    return 0;
}
static int  MS sh_initialize_narrow_environment(void) { return 0; }
static int  MS sh_configure_narrow_argv(int mode) { return 0; }
static int  MS sh_initialize_onexit_table(void *t) { return 0; }
static int  MS sh_register_onexit_function(void *t, void *f) { return 0; }
static int  MS sh_execute_onexit_table(void *t) { return 0; }
static int  MS sh_crt_atexit(void *f) { return 0; }
static int  MS sh_crt_at_quick_exit(void *f) { return 0; }
static void MS sh_cexit(void) { }
static int  MS sh_seh_filter_dll(u32 exc, void *ep) { return 0; }
static void MS sh_terminate(void) { abort(); }
static void MS sh_wassert(const u16 *expr, const u16 *file, u32 line) { abort(); }
static int* MS sh_errno(void) { return &g_crt_errno; }
static void MS sh_invalid_parameter_noinfo(void) { }
static void MS sh_invalid_parameter_noinfo_noreturn(void) { abort(); }
static u64  MS sh_beginthreadex(void *sa, u32 st, void *fn, void *arg, u32 fl, u32 *id) {
    if (id) *id = 4321;
    return 0x3001;
}

static size_t MS sh_strlen(const char *s) { return strlen(s); }
static size_t MS sh_wcslen(const u16 *s) { size_t l = 0; if (s) while (s[l]) l++; return l; }
static int    MS sh_strcmp(const char *s1, const char *s2) { return strcmp(s1, s2); }
static int    MS sh_strncmp(const char *s1, const char *s2, size_t n) { return strncmp(s1, s2, n); }
static int    MS sh_stricmp(const char *s1, const char *s2) { return strcasecmp(s1, s2); }
static int    MS sh_wcsicmp(const u16 *s1, const u16 *s2) {
    while (*s1 && *s2 && (*s1 == *s2 || (*s1 | 0x20) == (*s2 | 0x20))) { s1++; s2++; }
    return (*s1 | 0x20) - (*s2 | 0x20);
}
static void*  MS sh_memset(void *d, int c, size_t n) { return memset(d, c, n); }
static int    MS sh_strcpy_s(char *d, size_t dz, const char *s) {
    if (!d || !s || strlen(s) >= dz) return 1;
    strcpy(d, s); return 0;
}
static int MS sh_wcscpy_s(u16 *d, size_t dz, const u16 *s) {
    if (!d || !s) return 1;
    size_t l = 0; while (s[l]) l++;
    if (l >= dz) return 1;
    for (size_t i = 0; i <= l; i++) d[i] = s[i];
    return 0;
}
static u16* MS sh_wcscpy(u16 *d, const u16 *s) { u16 *p = d; while ((*p++ = *s++)); return d; }
static char* MS sh_strtok_s(char *s, const char *del, char **ctx) { return strtok_r(s, del, ctx); }
static long MS sh_atol(const char *s) { return atol(s); }
static int  MS sh_abs(int j) { return abs(j); }
static void MS sh_qsort(void *b, size_t n, size_t s, int (MS *cmp)(const void*, const void*)) {
    u8 *p = (u8*)b;
    for (size_t i = 0; i < n; i++) {
        for (size_t j = i + 1; j < n; j++) {
            if (cmp(p + i * s, p + j * s) > 0) {
                for (size_t k = 0; k < s; k++) {
                    u8 tmp = p[i * s + k];
                    p[i * s + k] = p[j * s + k];
                    p[j * s + k] = tmp;
                }
            }
        }
    }
}
static double MS sh_sqrt(double x) { return sqrt(x); }
static double MS sh_fabs(double x) { return fabs(x); }
static int    MS sh_isnan(double x) { return isnan(x); }
static int    MS sh_finite(double x) { return isfinite(x); }

static int MS sh_wremove(const u16 *p) { return 0; }
static int MS sh_waccess_s(const u16 *p, int m) { return -1; }
static int MS sh_access_s(const char *p, int m) { return -1; }
static int MS sh_wmkdir(const u16 *p) { return 0; }
static u64 MS sh_time64(u64 *t) { time_t n = time(NULL); if (t) *t = n; return n; }
struct win_tm {
    int tm_sec, tm_min, tm_hour, tm_mday, tm_mon, tm_year, tm_wday, tm_yday, tm_isdst;
};
static int MS sh_localtime64_s(void *tm_out, const u64 *t) {
    if (!tm_out || !t) return 1;
    time_t now = (time_t)*t;
    struct tm r;
    if (!localtime_r(&now, &r)) return 1;
    struct win_tm *w = (struct win_tm*)tm_out;
    w->tm_sec = r.tm_sec;   w->tm_min = r.tm_min;   w->tm_hour = r.tm_hour;
    w->tm_mday = r.tm_mday; w->tm_mon = r.tm_mon;   w->tm_year = r.tm_year;
    w->tm_wday = r.tm_wday; w->tm_yday = r.tm_yday; w->tm_isdst = r.tm_isdst;
    return 0;
}
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
static size_t MS sh_strftime(char *s, size_t max, const char *fmt, const void *tm) {
    if (!s || !fmt || !tm) return 0;
    const struct win_tm *w = (const struct win_tm*)tm;
    struct tm ltm = {
        .tm_sec = w->tm_sec, .tm_min = w->tm_min, .tm_hour = w->tm_hour,
        .tm_mday = w->tm_mday, .tm_mon = w->tm_mon, .tm_year = w->tm_year,
        .tm_wday = w->tm_wday, .tm_yday = w->tm_yday, .tm_isdst = w->tm_isdst,
    };
    return strftime(s, max, fmt, &ltm);
}
#pragma GCC diagnostic pop
static u64 MS sh_clock(void) { return (u64)clock(); }

static void* MS sh_acrt_iob_func(u32 idx) {
    if (idx == 0) return stdin;
    if (idx == 1) return stdout;
    return stderr;
}
static void* MS sh_fopen(const char *f, const char *m) { return NULL; }
static int   MS sh_fopen_s(void **fp, const char *f, const char *m) { if (fp) *fp = NULL; return 1; }
static void* MS sh_wfopen(const u16 *f, const u16 *m) { return NULL; }
static int   MS sh_wfopen_s(void **fp, const u16 *f, const u16 *m) { if (fp) *fp = NULL; return 1; }
static void* MS sh_fsopen(const char *f, const char *m, int sh) { return NULL; }
static void* MS sh_wfsopen(const u16 *f, const u16 *m, int sh) { return NULL; }
static int   MS sh_fclose(void *f) { return 0; }
static size_t MS sh_fread(void *b, size_t s, size_t c, void *f) { return 0; }
static size_t MS sh_fwrite(const void *b, size_t s, size_t c, void *f) { return c; }
static int   MS sh_fputs(const char *s, void *f) { return 0; }
static char* MS sh_fgets(char *s, int n, void *f) { return NULL; }
static int   MS sh_fseek(void *f, long o, int w) { return 0; }
static long  MS sh_ftell(void *f) { return 0; }
static u64   MS sh_ftelli64(void *f) { return 0; }
static int   MS sh_fflush(void *f) { return 0; }
static int   MS sh_ferror(void *f) { return 0; }
static int   MS sh_putchar(int c) { return putchar(c); }
static int   MS sh_getchar(void) { return -1; }

static int MS sh_stdio_common_vsprintf(u64 opt, char *buf, size_t max, const char *fmt, void *loc, __builtin_ms_va_list ap) {
    if (!buf || max == 0) return 0;
    buf[0] = '\0';
    return 0;
}
static int MS sh_stdio_common_vsprintf_s(u64 opt, char *buf, size_t max, const char *fmt, void *loc, __builtin_ms_va_list ap) {
    return sh_stdio_common_vsprintf(opt, buf, max, fmt, loc, ap);
}
static int MS sh_stdio_common_vsnprintf_s(u64 opt, char *buf, size_t max, size_t cnt, const char *fmt, void *loc, __builtin_ms_va_list ap) {
    return sh_stdio_common_vsprintf(opt, buf, max, fmt, loc, ap);
}
static int MS sh_stdio_common_vswprintf(u64 opt, u16 *buf, size_t max, const u16 *fmt, void *loc, __builtin_ms_va_list ap) {
    if (buf && max > 0) buf[0] = 0;
    return 0;
}
static int MS sh_stdio_common_vswprintf_s(u64 opt, u16 *buf, size_t max, const u16 *fmt, void *loc, __builtin_ms_va_list ap) {
    return sh_stdio_common_vswprintf(opt, buf, max, fmt, loc, ap);
}
static int MS sh_stdio_common_vfprintf(u64 opt, void *f, const char *fmt, void *loc, __builtin_ms_va_list ap) { return 0; }
static int MS sh_stdio_common_vfwprintf(u64 opt, void *f, const u16 *fmt, void *loc, __builtin_ms_va_list ap) { return 0; }

static void register_all_shims(void) {
    if (g_nshims > 0) return;

    reg_name("timeGetTime", sh_timeGetTime);
    reg_name("SetLastError", sh_SetLastError);
    reg_name("GetLastError", sh_GetLastError);
    reg_name("GetProcessHeap", sh_GetProcessHeap);
    reg_name("HeapAlloc", sh_HeapAlloc);
    reg_name("HeapFree", sh_HeapFree);
    reg_name("LocalFree", sh_LocalFree);
    reg_name("InitializeCriticalSection", sh_InitCS);
    reg_name("InitializeCriticalSectionEx", sh_InitCS);
    reg_name("EnterCriticalSection", sh_EnterCS);
    reg_name("LeaveCriticalSection", sh_LeaveCS);
    reg_name("DeleteCriticalSection", sh_DeleteCS);
    reg_name("InitializeConditionVariable", sh_InitConditionVariable);
    reg_name("WakeAllConditionVariable", sh_WakeAllConditionVariable);
    reg_name("SleepConditionVariableCS", sh_SleepConditionVariableCS);
    reg_name("InitializeSListHead", sh_InitSList);
    reg_name("InterlockedFlushSList", sh_FlushSList);
    reg_name("InterlockedPushEntrySList", sh_PushEntrySList);
    reg_name("TlsAlloc", sh_TlsAlloc);
    reg_name("TlsFree", sh_TlsFree);
    reg_name("TlsGetValue", sh_TlsGetValue);
    reg_name("TlsSetValue", sh_TlsSetValue);
    reg_name("FlsAlloc", sh_FlsAlloc);
    reg_name("FlsFree", sh_FlsFree);
    reg_name("FlsGetValue", sh_FlsGetValue);
    reg_name("FlsSetValue", sh_FlsSetValue);
    reg_name("GetCurrentProcess", sh_GetCurrentProcess);
    reg_name("GetCurrentProcessId", sh_GetCurrentProcessId);
    reg_name("GetCurrentThreadId", sh_GetCurrentThreadId);
    reg_name("CreateThread", sh_CreateThread);
    reg_name("TerminateProcess", sh_TerminateProcess);
    reg_name("TerminateThread", sh_TerminateThread);
    reg_name("CreateEventW", sh_CreateEventW);
    reg_name("SetEvent", sh_SetEvent);
    reg_name("ResetEvent", sh_ResetEvent);
    reg_name("WaitForSingleObject", sh_WaitForSingleObject);
    reg_name("WaitForMultipleObjects", sh_WaitForMultipleObjects);
    reg_name("Sleep", sh_Sleep);
    reg_name("GetSystemTimeAsFileTime", sh_GetSystemTimeAsFileTime);
    reg_name("GetLocalTime", sh_GetLocalTime);
    reg_name("QueryPerformanceCounter", sh_QueryPerformanceCounter);
    reg_name("QueryPerformanceFrequency", sh_QueryPerformanceFrequency);
    reg_name("IsDebuggerPresent", sh_IsDebuggerPresent);
    reg_name("IsProcessorFeaturePresent", sh_IsProcessorFeaturePresent);
    reg_name("EncodePointer", sh_EncodePointer);
    reg_name("GetStartupInfoW", sh_GetStartupInfoW);
    reg_name("GetModuleHandleW", sh_GetModuleHandleW);
    reg_name("GetSystemDirectoryW", sh_GetSystemDirectoryW);
    reg_name("GetDiskFreeSpaceExW", sh_GetDiskFreeSpaceExW);
    reg_name("OutputDebugStringW", sh_OutputDebugStringW);
    reg_name("MultiByteToWideChar", sh_MultiByteToWideChar);
    reg_name("WideCharToMultiByte", sh_WideCharToMultiByte);
    reg_name("CreateFileW", sh_CreateFileW);
    reg_name("WriteFile", sh_WriteFile);
    reg_name("CloseHandle", sh_CloseHandle);
    reg_name("DeleteFileW", sh_DeleteFileW);
    reg_name("CopyFileW", sh_CopyFileW);
    reg_name("FindFirstFileW", sh_FindFirstFileW);
    reg_name("DeviceIoControl", sh_DeviceIoControl);
    reg_name("GetOverlappedResult", sh_GetOverlappedResult);
    reg_name("SetUnhandledExceptionFilter", sh_SetUnhandledExceptionFilter);
    reg_name("UnhandledExceptionFilter", sh_UnhandledExceptionFilter);
    reg_name("RtlLookupFunctionEntry", sh_RtlLookupFunctionEntry);
    reg_name("RtlVirtualUnwind", sh_RtlVirtualUnwind);
    reg_name("RtlCaptureContext", sh_RtlCaptureContext);
    reg_name("RtlUnwindEx", sh_RtlUnwindEx);
    reg_name("RtlPcToFileHeader", sh_RtlPcToFileHeader);
    reg_name("RaiseException", sh_RaiseException);
    reg_name("__C_specific_handler", sh_C_specific_handler);

    reg_name("CryptAcquireContextW", sh_CryptAcquireContextW);
    reg_name("CryptReleaseContext", sh_CryptReleaseContext);
    reg_name("CryptGenRandom", sh_CryptGenRandom);
    reg_name("EventUnregister", sh_EventUnregister);
    reg_name("RegOpenCurrentUser", sh_RegOpenCurrentUser);
    reg_name("RegOpenKeyExW", sh_RegOpenKeyExW);
    reg_name("RegCreateKeyExW", sh_RegCreateKeyExW);
    reg_name("RegQueryValueExW", sh_RegQueryValueExW);
    reg_name("RegSetValueExW", sh_RegSetValueExW);
    reg_name("RegCloseKey", sh_RegCloseKey);
    reg_name("LookupAccountNameW", sh_LookupAccountNameW);

    reg_name("CoInitializeEx", sh_CoInitializeEx);
    reg_name("CoUninitialize", sh_CoUninitialize);
    reg_name("CoCreateInstance", sh_CoCreateInstance);
    reg_name("CoCreateGuid", sh_CoCreateGuid);
    reg_name("CoSetProxyBlanket", sh_CoSetProxyBlanket);
    reg_name("CoInitializeSecurity", sh_CoInitializeSecurity);

    reg_ord("OLEAUT32.dll", 2, sh_SysAllocString);
    reg_ord("OLEAUT32.dll", 6, sh_SysFreeString);
    reg_ord("OLEAUT32.dll", 8, sh_VariantInit);
    reg_ord("OLEAUT32.dll", 9, sh_VariantClear);
    reg_ord("OLEAUT32.dll", 12, sh_VariantCopy);
    reg_ord("OLEAUT32.dll", 200, sh_SysAllocStringLen);
    reg_ord("OLEAUT32.dll", 201, sh_SysStringLen);
    reg_ord("OLEAUT32.dll", 202, sh_SysStringByteLen);

    reg_name("PowerSettingRegisterNotification", sh_PowerSettingRegisterNotification);
    reg_name("PowerSettingUnregisterNotification", sh_PowerSettingUnregisterNotification);
    reg_name("MiniDumpWriteDump", sh_MiniDumpWriteDump);

    reg_ord("WS2_32.dll", 1, sh_accept);
    reg_ord("WS2_32.dll", 2, sh_bind);
    reg_ord("WS2_32.dll", 3, sh_closesocket);
    reg_ord("WS2_32.dll", 4, sh_connect);
    reg_ord("WS2_32.dll", 6, sh_getsockname);
    reg_ord("WS2_32.dll", 8, sh_htons);
    reg_ord("WS2_32.dll", 9, sh_inet_addr);
    reg_ord("WS2_32.dll", 11, sh_inet_ntoa);
    reg_ord("WS2_32.dll", 13, sh_listen);
    reg_ord("WS2_32.dll", 15, sh_recv);
    reg_ord("WS2_32.dll", 16, sh_recvfrom);
    reg_ord("WS2_32.dll", 19, sh_send);
    reg_ord("WS2_32.dll", 21, sh_setsockopt);
    reg_ord("WS2_32.dll", 23, sh_socket);
    reg_ord("WS2_32.dll", 111, sh_WSAGetLastError);
    reg_ord("WS2_32.dll", 115, sh_WSAStartup);
    reg_ord("WS2_32.dll", 116, sh_WSACleanup);

    reg_name("malloc", sh_malloc);
    reg_name("_malloc_base", sh_malloc);
    reg_name("calloc", sh_calloc);
    reg_name("_calloc_base", sh_calloc);
    reg_name("realloc", sh_realloc);
    reg_name("free", sh_free);
    reg_name("_free_base", sh_free);

    reg_name("strlen", sh_strlen);
    reg_name("wcslen", sh_wcslen);
    reg_name("strcmp", sh_strcmp);
    reg_name("strncmp", sh_strncmp);
    reg_name("_stricmp", sh_stricmp);
    reg_name("_wcsicmp", sh_wcsicmp);
    reg_name("memset", sh_memset);
    reg_name("strcpy_s", sh_strcpy_s);
    reg_name("wcscpy_s", sh_wcscpy_s);
    reg_name("wcscpy", sh_wcscpy);
    reg_name("strtok_s", sh_strtok_s);

    reg_name("_initterm", sh_initterm);
    reg_name("_initterm_e", sh_initterm_e);
    reg_name("_initialize_narrow_environment", sh_initialize_narrow_environment);
    reg_name("_configure_narrow_argv", sh_configure_narrow_argv);
    reg_name("_initialize_onexit_table", sh_initialize_onexit_table);
    reg_name("_register_onexit_function", sh_register_onexit_function);
    reg_name("_execute_onexit_table", sh_execute_onexit_table);
    reg_name("_crt_atexit", sh_crt_atexit);
    reg_name("_crt_at_quick_exit", sh_crt_at_quick_exit);
    reg_name("_cexit", sh_cexit);
    reg_name("_seh_filter_dll", sh_seh_filter_dll);
    reg_name("terminate", sh_terminate);
    reg_name("abort", abort);
    reg_name("_wassert", sh_wassert);
    reg_name("_errno", sh_errno);
    reg_name("_invalid_parameter_noinfo", sh_invalid_parameter_noinfo);
    reg_name("_invalid_parameter_noinfo_noreturn", sh_invalid_parameter_noinfo_noreturn);
    reg_name("_beginthreadex", sh_beginthreadex);

    reg_name("qsort", sh_qsort);
    reg_name("abs", sh_abs);
    reg_name("sqrt", sh_sqrt);
    reg_name("fabs", sh_fabs);
    reg_name("_isnan", sh_isnan);
    reg_name("_finite", sh_finite);
    reg_name("atol", sh_atol);

    reg_name("_wremove", sh_wremove);
    reg_name("_waccess_s", sh_waccess_s);
    reg_name("_access_s", sh_access_s);
    reg_name("_wmkdir", sh_wmkdir);
    reg_name("_time64", sh_time64);
    reg_name("_localtime64_s", sh_localtime64_s);
    reg_name("strftime", sh_strftime);
    reg_name("clock", sh_clock);

    reg_name("__acrt_iob_func", sh_acrt_iob_func);
    reg_name("fopen", sh_fopen);
    reg_name("fopen_s", sh_fopen_s);
    reg_name("_wfopen", sh_wfopen);
    reg_name("_wfopen_s", sh_wfopen_s);
    reg_name("_fsopen", sh_fsopen);
    reg_name("_wfsopen", sh_wfsopen);
    reg_name("fclose", sh_fclose);
    reg_name("fread", sh_fread);
    reg_name("fwrite", sh_fwrite);
    reg_name("fputs", sh_fputs);
    reg_name("fgets", sh_fgets);
    reg_name("fseek", sh_fseek);
    reg_name("ftell", sh_ftell);
    reg_name("_ftelli64", sh_ftelli64);
    reg_name("fflush", sh_fflush);
    reg_name("ferror", sh_ferror);
    reg_name("putchar", sh_putchar);
    reg_name("getchar", sh_getchar);

    reg_name("__stdio_common_vsprintf", sh_stdio_common_vsprintf);
    reg_name("__stdio_common_vsprintf_s", sh_stdio_common_vsprintf_s);
    reg_name("__stdio_common_vsnprintf_s", sh_stdio_common_vsnprintf_s);
    reg_name("__stdio_common_vswprintf", sh_stdio_common_vswprintf);
    reg_name("__stdio_common_vswprintf_s", sh_stdio_common_vswprintf_s);
    reg_name("__stdio_common_vfprintf", sh_stdio_common_vfprintf);
    reg_name("__stdio_common_vfwprintf", sh_stdio_common_vfwprintf);
}

static u32 g_sizeofimage = 0;

static inline int rva_ok(u32 rva, u32 need) {
    return need <= g_sizeofimage && rva <= g_sizeofimage - need;
}

static void* get_export(const char *want) {
    if (!g_image || !g_sizeofimage) return NULL;
    u32 e = *(u32*)(g_image + 0x3c);
    if (e + 24 + 112 + 8 > g_sizeofimage) return NULL;
    u32 exprva = *(u32*)(g_image + e + 24 + 112 + 8 * 0);
    if (!exprva || exprva + 40 > g_sizeofimage) return NULL;
    u32 nnames = *(u32*)(g_image + exprva + 24);
    u32 fns = *(u32*)(g_image + exprva + 28);
    u32 names = *(u32*)(g_image + exprva + 32);
    u32 ords = *(u32*)(g_image + exprva + 36);
    if (names + nnames * 4 > g_sizeofimage || ords + nnames * 2 > g_sizeofimage) return NULL;

    for (u32 i = 0; i < nnames; i++) {
        u32 nrva = *(u32*)(g_image + names + i * 4);
        if (nrva >= g_sizeofimage) continue;
        /* Bound the export-name read to the mapped image, like the
         * import-name checks in load_pe_file: skip unterminated names. */
        if (strnlen((char*)(g_image + nrva), g_sizeofimage - nrva) >= g_sizeofimage - nrva) continue;
        if (strcmp((char*)(g_image + nrva), want) == 0) {
            u16 ord = *(u16*)(g_image + ords + i * 2);
            if (fns + (u32)ord * 4 + 4 > g_sizeofimage) return NULL;
            u32 frva = *(u32*)(g_image + fns + ord * 4);
            if (frva >= g_sizeofimage) return NULL;
            return g_image + frva;
        }
    }
    return NULL;
}

static int load_pe_file(const char *path) {
    const char *step = "open";
    int fd = -1, mfd = -1;
    u8 *img = NULL;
    u32 sizeofimage = 0;
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) goto fail;
    step = "seek";
    g_filelen = lseek(fd, 0, SEEK_END);
    if (g_filelen < 0 || lseek(fd, 0, SEEK_SET) < 0) goto fail;
    step = "PE header";
    if (g_filelen < 64) { errno = ENOEXEC; goto fail; }
    step = "allocate file";
    g_file = malloc(g_filelen);
    if (!g_file) goto fail;
    step = "read";
    for (size_t off = 0; off < (size_t)g_filelen;) {
        ssize_t n = read(fd, g_file + off, g_filelen - off);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { if (n == 0) errno = EIO; goto fail; }
        off += n;
    }
    close(fd);
    fd = -1;

    /* This is a loader for a trusted vendor DLL, not a general PE runtime. */
    step = "PE header";
    u32 e = f32(0x3c);
    if (f16(0) != 0x5a4d || (u64)e + 264 > (u64)g_filelen ||
        f32(e) != 0x4550 || f16(e + 4) != 0x8664 ||
        f16(e + 24) != 0x20b) { errno = ENOEXEC; goto fail; }
    g_imagebase = f64(e + 24 + 24);
    sizeofimage = f32(e + 24 + 56);
    g_sizeofimage = sizeofimage;
    u32 entry = f32(e + 24 + 16);
    u16 nsec = f16(e + 6);
    u16 optsize = f16(e + 20);
    u64 sectbl = e + 24 + optsize;
    u32 hdrsize = f32(e + 24 + 60);

    if (optsize < 240 || sectbl + (u64)nsec * 40 > (u64)g_filelen ||
        !sizeofimage || hdrsize > (u64)g_filelen || hdrsize > sizeofimage ||
        entry >= sizeofimage) { errno = ENOEXEC; goto fail; }
    step = "allocate image";
    img = calloc(1, sizeofimage);
    if (!img) goto fail;
    memcpy(img, g_file, hdrsize);

    for (int i = 0; i < nsec; i++) {
        u64 s = sectbl + i * 40;
        u32 vaddr = f32(s + 12), vsize = f32(s + 8), rawsize = f32(s + 16), rawptr = f32(s + 20);
        step = "PE section";
        if ((u64)rawptr + rawsize > (u64)g_filelen ||
            (u64)vaddr + rawsize > sizeofimage) { errno = ENOEXEC; goto fail; }
        u32 copysize = (vsize && vsize < rawsize) ? vsize : rawsize;
        if (copysize) memcpy(img + vaddr, g_file + rawptr, copysize);
    }

    u32 imprva = f32(e + 24 + 112 + 8 * 1);
    step = "PE imports";
    for (u64 d = imprva; ; d += 20) {
        if (d + 20 > sizeofimage) { errno = ENOEXEC; goto fail; }
        u32 orig = *(u32*)(img + d), namer = *(u32*)(img + d + 12), fthunk = *(u32*)(img + d + 16);
        if (namer == 0) break;
        if (!rva_ok(namer, 1) ||
            strnlen((char*)(img + namer), sizeofimage - namer) >= sizeofimage - namer) { errno = ENOEXEC; goto fail; }
        const char *dllname = (char*)(img + namer);
        u64 rt = orig ? orig : fthunk;
        if (!rt || rt >= sizeofimage) { errno = ENOEXEC; goto fail; }
        for (int j = 0; ; j++) {
            u64 off = rt + (u64)j * 8, soff = (u64)fthunk + (u64)j * 8;
            if (off + 8 > sizeofimage || soff + 8 > sizeofimage) { errno = ENOEXEC; goto fail; }
            u64 ent = *(u64*)(img + off);
            if (!ent) break;
            u64 *slot = (u64*)(img + soff);
            void *sh = NULL;
            if (ent >> 63) {
                u32 ord = (u32)(ent & 0xffff);
                sh = find_shim_ordinal(dllname, ord);
            } else {
                u32 nrva = (u32)(ent & 0x7fffffff);
                if (!rva_ok(nrva, 3) ||
                    strnlen((char*)(img + nrva + 2), sizeofimage - nrva - 2) >= sizeofimage - nrva - 2) { errno = ENOEXEC; goto fail; }
                const char *fn = (char*)(img + nrva + 2);
                sh = find_shim(fn);
            }
            *slot = (u64)sh;
        }
    }

    step = "memfd_create";
    mfd = memfd_create("goodix_engine", MFD_CLOEXEC);
    if (mfd < 0) goto fail;
    step = "memfd write";
    for (size_t off = 0; off < sizeofimage;) {
        ssize_t n = write(mfd, img + off, sizeofimage - off);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { if (n == 0) errno = EIO; goto fail; }
        off += n;
    }
    free(img);
    img = NULL;

    step = "mmap reserve";
    void *m = mmap((void*)g_imagebase, sizeofimage, PROT_NONE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (m == MAP_FAILED) goto fail;
    if (m != (void*)g_imagebase) {
        munmap(m, sizeofimage);
        errno = EADDRNOTAVAIL;
        goto fail;
    }
    g_image = m;

    step = "mmap headers";
    u32 hdrmap = (hdrsize + 0xfff) & ~0xfffu;
    if (mmap(g_image, hdrmap, PROT_READ, MAP_PRIVATE | MAP_FIXED, mfd, 0) == MAP_FAILED)
        goto fail;

    for (int i = 0; i < nsec; i++) {
        u64 s = sectbl + i * 40;
        u32 vaddr = f32(s + 12), vsize = f32(s + 8), rawsize = f32(s + 16), chars = f32(s + 36);
        u32 seglen = (vsize > rawsize ? vsize : rawsize);
        seglen = (seglen + 0xfff) & ~0xfffu;
        if (vaddr + seglen > sizeofimage) seglen = sizeofimage - vaddr;
        if (!seglen) continue;

        int prot = PROT_READ;
        if (chars & 0x20000000) prot |= PROT_EXEC;
        if (chars & 0x80000000) prot |= PROT_WRITE;
        step = "mmap section";
        if (mmap(g_image + vaddr, seglen, prot, MAP_PRIVATE | MAP_FIXED, mfd, vaddr) == MAP_FAILED)
            goto fail;
    }
    close(mfd);
    mfd = -1;

    memset(g_teb, 0, sizeof(g_teb));
    memset(g_peb, 0, sizeof(g_peb));
    *(u64*)(g_teb + 0x30) = (u64)g_teb;
    *(u64*)(g_teb + 0x08) = (u64)(g_teb + sizeof(g_teb));
    *(u64*)(g_teb + 0x10) = (u64)g_teb;
    *(u64*)(g_teb + 0x58) = (u64)g_tls_array;
    *(u64*)(g_teb + 0x60) = (u64)g_peb;

    step = "arch_prctl";
    if (syscall(SYS_arch_prctl, ARCH_SET_GS, g_teb) != 0) goto fail;

    u32 tlsrva = f32(e + 24 + 112 + 8 * 9);
    if (tlsrva) {
        u64 start = *(u64*)(g_image + tlsrva);
        u64 end = *(u64*)(g_image + tlsrva + 8);
        u64 idxaddr = *(u64*)(g_image + tlsrva + 16);
        u64 cbaddr = *(u64*)(g_image + tlsrva + 24);
        u64 tlen = end - start;
        memset(g_tls_block, 0, sizeof(g_tls_block));
        if (tlen && tlen <= sizeof(g_tls_block)) memcpy(g_tls_block, (void*)start, tlen);
        g_tls_array[0] = g_tls_block;
        if (idxaddr) *(u32*)idxaddr = 0;
        if (cbaddr) {
            for (u64 *cb = (u64*)cbaddr; *cb; cb++) {
                void(MS *f)(void*, u32, void*) = (void*)*cb;
                f((void*)g_imagebase, DLL_PROCESS_ATTACH, 0);
            }
        }
    }

    /* Skip DllMain: crashes under Linux shim environment.
     * Exports are called directly after import resolution. */
    (void)entry;
    close(mfd); mfd = -1;
    free(g_file); g_file = NULL; g_filelen = 0;
    return 0;

fail:;
    int saved_errno = errno;
    g_warning("5e0a: %s: %s failed for %s: errno=%d (%s)%s",
              __func__, step, path, saved_errno, g_strerror(saved_errno),
              saved_errno == EACCES || saved_errno == EPERM
              ? "; check file permissions and SELinux/AppArmor audit denials; see README" : "");
    if (fd >= 0) close(fd);
    if (mfd >= 0) close(mfd);
    free(img);
    if (g_image) { munmap(g_image, sizeofimage); g_image = NULL; }
    g_sizeofimage = 0;
    free(g_file);
    g_file = NULL;
    g_filelen = 0;
    errno = saved_errno;
    return -1;
}

/* Engine Function Pointers */
static int (MS *m_getAlgorithmVersion)(char*) = NULL;
static int (MS *m_ppp_param_init)(int) = NULL;
static void* (MS *m_enrolStartEx)(int*) = NULL;
static int (MS *m_enrolAddImage)(void*, GoodixImage*, void*, void*, u8, u32*) = NULL;
static int (MS *m_enrolGetTemplate)(void*, void**) = NULL;
static int (MS *m_enrolFinish)(void*) = NULL;
static int (MS *m_templateGetPackedSize)(void*) = NULL;
static int (MS *m_templatePack)(void*, void*) = NULL;
static int (MS *m_templateUnPack)(const void*, int, void*, void**) = NULL;
static int (MS *m_templateDelete)(void*) = NULL;
static int (MS *m_identifyImage)(GoodixImage*, void*, void**, int, int*, int*, u32*, int, int, void*, int) = NULL;
/* Optional native quality export: without it, frame selection uses
 * residual range and active area instead of failing engine init. */
static int (MS *m_getQuality)(GoodixImage*, u32*) = NULL;

static gboolean g_milan_available = FALSE;
static char g_milan_version[128] = "Unknown";
static GRecMutex g_milan_mutex;

/* This GLib version provides no G_REC_MUTEX_INIT static initializer, so the
 * mutex is initialized in a constructor before any wrapper can lock it. */
__attribute__((constructor)) static void goodix_milan_mutex_init(void) {
    g_rec_mutex_init(&g_milan_mutex);
}

static const char *default_search_paths[] = {
    "/var/lib/fprint/GoodixEngineAdapter.dll",
    "/run/current-system/sw/lib/GoodixEngineAdapter.dll",
    "/etc/goodix/GoodixEngineAdapter.dll",
    "/usr/lib/goodix/GoodixEngineAdapter.dll",
    "/usr/local/lib/GoodixEngineAdapter.dll",
    NULL,
};

gboolean goodix_milan_init (const char *dll_path) {
    g_rec_mutex_lock (&g_milan_mutex);
    if (g_milan_available) {
        g_rec_mutex_unlock (&g_milan_mutex);
        return TRUE;
    }

    g_nshims = 0;
    register_all_shims();

    const char *target = dll_path;
    if (!target) {
        target = g_getenv("GOODIX_ENGINE_DLL_PATH");
    }

    int loaded = -1;
    if (target && *target) {
        loaded = load_pe_file(target);
    } else {
        for (int i = 0; default_search_paths[i]; i++) {
            if (access(default_search_paths[i], R_OK) == 0) {
                target = default_search_paths[i];
                loaded = load_pe_file(target);
                if (loaded == 0) break;
            }
        }
    }

    if (loaded != 0) {
        g_warning("5e0a: failed to load GoodixEngineAdapter.dll");
        g_rec_mutex_unlock (&g_milan_mutex);
        return FALSE;
    }

    m_getAlgorithmVersion = get_export("getAlgorithmVersion");
    m_ppp_param_init = get_export("ppp_param_init");
    m_enrolStartEx = get_export("enrolStartEx");
    m_enrolAddImage = get_export("enrolAddImage");
    m_enrolGetTemplate = get_export("enrolGetTemplate");
    m_enrolFinish = get_export("enrolFinish");
    m_templateGetPackedSize = get_export("templateGetPackedSize");
    m_templatePack = get_export("templatePack");
    m_templateUnPack = get_export("templateUnPack");
    m_templateDelete = get_export("templateDelete");
    m_identifyImage = get_export("identifyImage");
    /* Ticket 76: optional native quality export (see declaration comment).
     * Resolved outside the required-export gate below on purpose. */
    m_getQuality = get_export("getQuality");

    if (!m_getAlgorithmVersion || !m_ppp_param_init || !m_enrolStartEx ||
        !m_enrolAddImage || !m_enrolGetTemplate || !m_enrolFinish ||
        !m_templateGetPackedSize || !m_templatePack || !m_templateUnPack ||
        !m_templateDelete || !m_identifyImage) {
        g_warning("5e0a: required Milan engine exports missing");
        if (g_image) { munmap(g_image, g_sizeofimage); g_image = NULL; }
        g_sizeofimage = 0;
        g_rec_mutex_unlock (&g_milan_mutex);
        return FALSE;
    }
    if (!m_getQuality)
        g_debug ("5e0a: Milan getQuality export missing; frame judging falls back to residual range and active area");

    ensure_gs();
    m_getAlgorithmVersion(g_milan_version);
    m_ppp_param_init(12); /* Profile 12: ChicagoHS 64x80 */

    g_message("5e0a: Milan biometric matching engine loaded successfully (%s)", g_milan_version);
    g_milan_available = TRUE;
    g_rec_mutex_unlock (&g_milan_mutex);
    return TRUE;
}

const char *goodix_milan_get_version (void) {
    return g_milan_version;
}

static guint8 *make_goodix_image(GoodixImage *img, const uint8_t *pix, int width, int height, int sensor_type) {
    memset(img, 0, sizeof(GoodixImage));
    img->data = (uint8_t*)pix;
    img->width = width;
    img->height = height;
    img->bits = 8;
    img->channels = 1;
    img->frame_count = 1;
    img->sensor_type = sensor_type;
    img->quality = 100;
    img->overlap = 100;
    /* Profile 10 consumes 64 rows of 80 columns. Callers keep the sensor's
     * canonical 64-wide, 80-high raster; transpose only at this boundary.
     * The caller owns the returned buffer through the engine call. */
    guint8 *native = g_malloc(width * height);
    for (int y = 0; y < height; y++)
        for (int x = 0; x < width; x++)
            native[x * height + y] = pix[y * width + x];
    img->data = native;
    img->width = height;
    img->height = width;
    return native;
}

/* Ticket 76: native quality probe. Ticket-72 offline ranges: good
 * local-contrast frames report quality 18-19 / overlap 98-100, while blank,
 * noise, and poor-clarity frames report 0/0 — enough range to rank a burst.
 * The caller passes the 64x80 normalized buffer (the exact bytes verify
 * feeds identifyImage), never the 128x160 scaled FpImage. */
guint goodix_milan_frame_quality (const uint8_t *pixels,
                                  int width,
                                  int height,
                                  guint *out_quality,
                                  guint *out_overlap) {
    if (out_quality) *out_quality = 0;
    if (out_overlap) *out_overlap = 0;
    /* Only canonical 64x80 sensor inputs are supported. The shared bridge
     * converts them to profile 10's 80x64 engine raster. */
    if (!pixels || width != 64 || height != 80)
        return 0;
    g_rec_mutex_lock (&g_milan_mutex);
    if (!g_milan_available || !m_getQuality) {
        g_rec_mutex_unlock (&g_milan_mutex);
        return 0;
    }
    ensure_gs();

    GoodixImage img;
    g_autofree guint8 *image_storage = make_goodix_image(&img, pixels, width, height, 12);
    u32 qout[2] = {0};
    m_getQuality(&img, qout);

    guint q = img.quality;
    guint o = img.overlap;
    if (out_quality) *out_quality = q;
    if (out_overlap) *out_overlap = o;
    g_rec_mutex_unlock (&g_milan_mutex);
    return (q << 8) | o;
}

void *goodix_milan_enroll_start (int *max_images) {
    if (!g_milan_available && !goodix_milan_init(NULL)) return NULL;
    g_rec_mutex_lock (&g_milan_mutex);
    ensure_gs();
    int max_imgs = 16;
    void *ctx = m_enrolStartEx(&max_imgs);
    if (!ctx) {
        g_rec_mutex_unlock (&g_milan_mutex);
        return NULL;
    }
    if (max_images) *max_images = max_imgs;
    *(u16*)((char*)ctx + 8) = 12; /* Target 12 enrollment touches */
    g_rec_mutex_unlock (&g_milan_mutex);
    return ctx;
}

int goodix_milan_enroll_add_image (void *ctx,
                                   const uint8_t *pixels,
                                   int width,
                                   int height,
                                   int *enrolled_count,
                                   int *progress_pct) {
    if (!ctx || !pixels || width != 64 || height != 80) return -1;
    g_rec_mutex_lock (&g_milan_mutex);
    ensure_gs();

    GoodixImage img;
    g_autofree guint8 *image_storage = make_goodix_image(&img, pixels, width, height, 12);
    u32 status_out[2] = {0};

    int add_res = m_enrolAddImage(ctx, &img, NULL, NULL, 0, status_out);
    if (enrolled_count) *enrolled_count = *(u16*)((char*)ctx + 10);
    if (progress_pct) *progress_pct = *(int*)((char*)ctx + 12);
    g_rec_mutex_unlock (&g_milan_mutex);
    return add_res;
}

int goodix_milan_enroll_commit (void *ctx,
                                uint8_t **out_blob,
                                size_t *out_len) {
    if (!ctx || !out_blob || !out_len) return -1;
    g_rec_mutex_lock (&g_milan_mutex);
    ensure_gs();

    void *master_template = NULL;
    int t_res = m_enrolGetTemplate(ctx, &master_template);
    if (t_res != 0 || !master_template) {
        g_rec_mutex_unlock (&g_milan_mutex);
        return -2;
    }

    int packed_size = m_templateGetPackedSize(master_template);
    if (packed_size <= 0) {
        /* master_template is borrowed from ctx (freed by enrolFinish);
         * never templateDelete it here (ticket-72 harness precedent). */
        g_rec_mutex_unlock (&g_milan_mutex);
        return -3;
    }

    uint8_t *packed_buf = malloc(packed_size);
    if (!packed_buf) {
        g_rec_mutex_unlock (&g_milan_mutex);
        return -4;
    }

    int pack_res = m_templatePack(master_template, packed_buf);
    /* Do NOT templateDelete(master_template): it is owned by ctx and
     * freed by enrolFinish. Deleting it here double-frees and corrupts
     * the engine heap (hang after 12th stage, verify no-match). */
    if (pack_res != 0) {
        free(packed_buf);
        g_rec_mutex_unlock (&g_milan_mutex);
        return -5;
    }

    *out_blob = packed_buf;
    *out_len = (size_t)packed_size;
    g_rec_mutex_unlock (&g_milan_mutex);
    return 0;
}

void goodix_milan_enroll_finish (void *ctx) {
    if (!ctx) return;
    g_rec_mutex_lock (&g_milan_mutex);
    ensure_gs();
    m_enrolFinish(ctx);
    g_rec_mutex_unlock (&g_milan_mutex);
}

int goodix_milan_verify_image (const uint8_t *pixels,
                               int width,
                               int height,
                               const uint8_t *template_blob,
                               size_t template_len,
                               int *out_score) {
    if (!pixels || !template_blob || template_len == 0) return 0;
    if (width != 64 || height != 80) return 0;
    if (!g_milan_available && !goodix_milan_init(NULL)) return 0;
    g_rec_mutex_lock (&g_milan_mutex);
    ensure_gs();

    void *unpacked_template = NULL;
    int unpack_res = m_templateUnPack(template_blob, (int)template_len, NULL, &unpacked_template);
    if (unpack_res != 0 || !unpacked_template) {
        g_warning("5e0a: templateUnPack failed (err=%d)", unpack_res);
        g_rec_mutex_unlock (&g_milan_mutex);
        return 0;
    }

    GoodixImage probe;
    g_autofree guint8 *image_storage = make_goodix_image(&probe, pixels, width, height, 12);
    void *active_templates[1] = { unpacked_template };
    int matched_idx = -999;
    int match_score = -999;
    u32 details[2] = {0};

    int id_res = m_identifyImage(&probe, NULL, active_templates, 1,
                                 &matched_idx, &match_score, details,
                                 0, 0, NULL, 0);
    (void)id_res;

    m_templateDelete(unpacked_template);

    int is_match = (matched_idx == 0 && match_score > 0);
    if (out_score) *out_score = (match_score >= 0) ? match_score : 0;
    g_rec_mutex_unlock (&g_milan_mutex);
    return is_match;
}

/* Ticket 77: single-call N-gallery identify. Same >0 gate as verify; the
 * engine ranks internally, so the winner index is authoritative. */
int goodix_milan_identify_image (const uint8_t *pixels,
                                 int width,
                                 int height,
                                 const uint8_t **template_blobs,
                                 const size_t *template_lens,
                                 int n_templates,
                                 int *out_idx,
                                 int *out_score) {
    if (out_idx) *out_idx = -1;
    if (out_score) *out_score = 0;
    if (!pixels || !template_blobs || !template_lens || n_templates <= 0)
        return 0;
    if (width != 64 || height != 80)
        return 0;
    if (!g_milan_available && !goodix_milan_init(NULL)) return 0;
    g_rec_mutex_lock (&g_milan_mutex);
    ensure_gs();

    g_autofree guint8 *image_storage = NULL;
    void **unpacked = g_new0 (void *, n_templates);
    for (int i = 0; i < n_templates; i++) {
        if (!template_blobs[i] || template_lens[i] == 0) goto fail_closed;
        if (m_templateUnPack (template_blobs[i], (int) template_lens[i],
                              NULL, &unpacked[i]) != 0 || !unpacked[i])
            goto fail_closed;
    }

    GoodixImage probe;
    image_storage = make_goodix_image(&probe, pixels, width, height, 12);
    int matched_idx = -999, match_score = -999;
    u32 details[2] = {0};
    m_identifyImage (&probe, NULL, unpacked, n_templates,
                     &matched_idx, &match_score, details, 0, 0, NULL, 0);

    for (int i = 0; i < n_templates; i++)
        if (unpacked[i]) m_templateDelete (unpacked[i]);
    g_free (unpacked);

    int is_match = (matched_idx >= 0 && matched_idx < n_templates && match_score > 0);
    if (out_idx) *out_idx = is_match ? matched_idx : -1;
    if (out_score) *out_score = (match_score >= 0) ? match_score : 0;
    g_rec_mutex_unlock (&g_milan_mutex);
    return is_match;

fail_closed:
    g_warning ("5e0a: gallery templateUnPack failed; rejecting without match");
    for (int i = 0; i < n_templates; i++)
        if (unpacked[i]) m_templateDelete (unpacked[i]);
    g_free (unpacked);
    g_rec_mutex_unlock (&g_milan_mutex);
    return 0;
}
