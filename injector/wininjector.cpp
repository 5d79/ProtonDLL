#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <tlhelp32.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>

typedef enum {
    methodmanual = 0,
    methodloadlib = 1,
    methodhijack = 2
} injectmethod;

typedef HMODULE (WINAPI *fnloadliba)(LPCSTR);
typedef FARPROC (WINAPI *fngetproc)(HMODULE, LPCSTR);
typedef BOOL (WINAPI *fndllmain)(HINSTANCE, DWORD, LPVOID);

typedef void* pruntimefunction;
typedef LONG (WINAPI *fnrtladdfunctiontable)(pruntimefunction, DWORD, DWORD64);

typedef struct {
    LPVOID imagebase;
    fnloadliba pfnloadliba;
    fngetproc pfngetproc;
    fnrtladdfunctiontable pfnrtladdfunctiontable;
    DWORD status;
} mapdata;

__attribute__((noinline, optimize("O0")))
static DWORD WINAPI maploader(mapdata* pdata) {
    if (!pdata || !pdata->imagebase) return 1;

    LPBYTE base = (LPBYTE)pdata->imagebase;
    PIMAGE_DOS_HEADER pdos = (PIMAGE_DOS_HEADER)base;
    if (pdos->e_magic != IMAGE_DOS_SIGNATURE) {
        pdata->status = 10;
        return 10;
    }

    PIMAGE_NT_HEADERS pnt = (PIMAGE_NT_HEADERS)(base + pdos->e_lfanew);
    if (pnt->Signature != IMAGE_NT_SIGNATURE) {
        pdata->status = 11;
        return 11;
    }

    ULONG_PTR delta = (ULONG_PTR)base - pnt->OptionalHeader.ImageBase;
    if (delta != 0) {
        DWORD relocrva = pnt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        DWORD relocsize = pnt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
        if (relocrva && relocsize) {
            PIMAGE_BASE_RELOCATION preloc = (PIMAGE_BASE_RELOCATION)(base + relocrva);
            while (preloc->VirtualAddress != 0 && preloc->SizeOfBlock != 0) {
                DWORD count = (preloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD* plist = (WORD*)(preloc + 1);
                for (DWORD i = 0; i < count; i++) {
                    WORD entry = plist[i];
                    WORD type = entry >> 12;
                    WORD offset = entry & 0x0FFF;
#ifdef _WIN64
                    if (type == IMAGE_REL_BASED_DIR64) {
                        ULONG_PTR* ppatch = (ULONG_PTR*)(base + preloc->VirtualAddress + offset);
                        *ppatch += delta;
                    }
#else
                    if (type == IMAGE_REL_BASED_HIGHLOW) {
                        DWORD* ppatch = (DWORD*)(base + preloc->VirtualAddress + offset);
                        *ppatch += (DWORD)delta;
                    }
#endif
                }
                preloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)preloc + preloc->SizeOfBlock);
            }
        }
    }

    DWORD importrva = pnt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    DWORD importsize = pnt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    if (importrva && importsize) {
        PIMAGE_IMPORT_DESCRIPTOR pimport = (PIMAGE_IMPORT_DESCRIPTOR)(base + importrva);
        while (pimport->Name != 0) {
            char* modname = (char*)(base + pimport->Name);
            HMODULE hmod = pdata->pfnloadliba(modname);
            if (!hmod) {
                pdata->status = 1;
                return 1;
            }
            PIMAGE_THUNK_DATA pthunk = (PIMAGE_THUNK_DATA)(base + (pimport->OriginalFirstThunk ? pimport->OriginalFirstThunk : pimport->FirstThunk));
            PIMAGE_THUNK_DATA pfunc = (PIMAGE_THUNK_DATA)(base + pimport->FirstThunk);
            while (pthunk->u1.AddressOfData != 0) {
                if (IMAGE_SNAP_BY_ORDINAL(pthunk->u1.Ordinal)) {
                    LPCSTR ordinal = (LPCSTR)IMAGE_ORDINAL(pthunk->u1.Ordinal);
                    pfunc->u1.Function = (ULONG_PTR)pdata->pfngetproc(hmod, ordinal);
                } else {
                    PIMAGE_IMPORT_BY_NAME pibn = (PIMAGE_IMPORT_BY_NAME)(base + pthunk->u1.AddressOfData);
                    pfunc->u1.Function = (ULONG_PTR)pdata->pfngetproc(hmod, (LPCSTR)pibn->Name);
                }
                if (!pfunc->u1.Function) {
                    pdata->status = 2;
                    return 2;
                }
                pthunk++;
                pfunc++;
            }
            pimport++;
        }
    }

    DWORD tlsrva = pnt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    DWORD tlssize = pnt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size;
    if (tlsrva && tlssize) {
        PIMAGE_TLS_DIRECTORY ptls = (PIMAGE_TLS_DIRECTORY)(base + tlsrva);
        PIMAGE_TLS_CALLBACK* pcallback = (PIMAGE_TLS_CALLBACK*)ptls->AddressOfCallBacks;
        if (pcallback && (LPBYTE)pcallback >= base && (LPBYTE)pcallback < base + pnt->OptionalHeader.SizeOfImage) {
            while (*pcallback) {
                (*pcallback)((LPVOID)base, DLL_PROCESS_ATTACH, NULL);
                pcallback++;
            }
        }
    }

    DWORD exceptrva = pnt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
    DWORD exceptsize = pnt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;
    if (exceptrva && exceptsize && pdata->pfnrtladdfunctiontable) {
        pdata->pfnrtladdfunctiontable((pruntimefunction)(base + exceptrva),
                                      exceptsize / 12, (DWORD64)base);
    }

    if (pnt->OptionalHeader.AddressOfEntryPoint != 0) {
        fndllmain pdllmain = (fndllmain)(base + pnt->OptionalHeader.AddressOfEntryPoint);
        BOOL success = pdllmain((HINSTANCE)base, DLL_PROCESS_ATTACH, NULL);
        if (!success) {
            pdata->status = 3;
            return 3;
        }
    }

    pdata->status = 0;
    return 0;
}
__attribute__((noinline, optimize("O0")))
static void maploaderend(void) {}

static void printusage(const wchar_t* progname) {
    wprintf(L"Usage: %ls <PID | ProcessName.exe> <PathToDLL> [options]\n", progname);
    wprintf(L"Options:\n");
    wprintf(L"  --method <manual|loadlibrary>  Injection technique (default: manual)\n");
    wprintf(L"  --erase-pe                    Wipe PE headers from memory after manual mapping\n");
    wprintf(L"  --wait <seconds>              Wait up to N seconds for target process to appear\n");
}

static DWORD findprocessbyname(const wchar_t* name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe = { 0 };
    pe.dwSize = sizeof(pe);
    DWORD pid = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

static bool isnumeric(const wchar_t* str) {
    if (!str || !*str) return false;
    for (size_t i = 0; str[i]; i++) {
        if (str[i] < L'0' || str[i] > L'9') return false;
    }
    return true;
}

static int injectloadlib(HANDLE hprocess, const wchar_t* fulldllpath) {
    wprintf(L"[*] Executing Standard Injection (CreateRemoteThread + LoadLibraryW)...\n");
    size_t pathbytes = (wcslen(fulldllpath) + 1) * sizeof(wchar_t);
    LPVOID remotemem = VirtualAllocEx(hprocess, NULL, pathbytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remotemem) {
        wprintf(L"[!] VirtualAllocEx failed (Error code: %u)\n", GetLastError());
        return 4;
    }
    SIZE_T written = 0;
    if (!WriteProcessMemory(hprocess, remotemem, fulldllpath, pathbytes, &written) || written != pathbytes) {
        wprintf(L"[!] WriteProcessMemory failed (Error code: %u)\n", GetLastError());
        VirtualFreeEx(hprocess, remotemem, 0, MEM_RELEASE);
        return 5;
    }
    HMODULE hkernel = GetModuleHandleW(L"kernel32.dll");
    if (!hkernel) {
        wprintf(L"[!] GetModuleHandleW failed\n");
        VirtualFreeEx(hprocess, remotemem, 0, MEM_RELEASE);
        return 6;
    }
    LPTHREAD_START_ROUTINE ploadlib = (LPTHREAD_START_ROUTINE)GetProcAddress(hkernel, "LoadLibraryW");
    if (!ploadlib) {
        wprintf(L"[!] GetProcAddress failed\n");
        VirtualFreeEx(hprocess, remotemem, 0, MEM_RELEASE);
        return 7;
    }
    wprintf(L"[*] Spawning remote thread via LoadLibraryW...\n");
    HANDLE hthread = CreateRemoteThread(hprocess, NULL, 0, ploadlib, remotemem, 0, NULL);
    if (!hthread) {
        wprintf(L"[!] CreateRemoteThread failed (Error code: %u)\n", GetLastError());
        VirtualFreeEx(hprocess, remotemem, 0, MEM_RELEASE);
        return 8;
    }
    DWORD waitresult = WaitForSingleObject(hthread, 15000);
    if (waitresult == WAIT_TIMEOUT) {
        wprintf(L"[!] Timed out waiting for remote LoadLibraryW thread\n");
    }
    DWORD exitcode = 0;
    GetExitCodeThread(hthread, &exitcode);
    VirtualFreeEx(hprocess, remotemem, 0, MEM_RELEASE);
    CloseHandle(hthread);
    if (exitcode == 0) {
        wprintf(L"[!] LoadLibraryW returned NULL in remote process.\n");
        return 9;
    }
    wprintf(L"[+] SUCCESS: Injected successfully! Module handle: 0x%08X\n", exitcode);
    return 0;
}

static int injectmanualmap(HANDLE hprocess, const wchar_t* fulldllpath, bool erasepe) {
    wprintf(L"[*] Executing Manual PE Mapping...\n");
    HANDLE hfile = CreateFileW(fulldllpath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hfile == INVALID_HANDLE_VALUE) {
        wprintf(L"[!] Failed to open DLL file: %ls (Error code: %u)\n", fulldllpath, GetLastError());
        return 10;
    }
    DWORD filesize = GetFileSize(hfile, NULL);
    if (filesize == INVALID_FILE_SIZE || filesize == 0) {
        wprintf(L"[!] Invalid DLL file size\n");
        CloseHandle(hfile);
        return 11;
    }
    BYTE* filebuffer = (BYTE*)malloc(filesize);
    if (!filebuffer) {
        wprintf(L"[!] Memory allocation failed\n");
        CloseHandle(hfile);
        return 12;
    }
    DWORD bytesread = 0;
    if (!ReadFile(hfile, filebuffer, filesize, &bytesread, NULL) || bytesread != filesize) {
        wprintf(L"[!] Failed reading DLL file\n");
        free(filebuffer);
        CloseHandle(hfile);
        return 13;
    }
    CloseHandle(hfile);

    PIMAGE_DOS_HEADER pdos = (PIMAGE_DOS_HEADER)filebuffer;
    if (pdos->e_magic != IMAGE_DOS_SIGNATURE) {
        wprintf(L"[!] Invalid DOS Header signature\n");
        free(filebuffer);
        return 14;
    }
    PIMAGE_NT_HEADERS pnt = (PIMAGE_NT_HEADERS)(filebuffer + pdos->e_lfanew);
    if (pnt->Signature != IMAGE_NT_SIGNATURE) {
        wprintf(L"[!] Invalid NT Header signature\n");
        free(filebuffer);
        return 15;
    }
#ifdef _WIN64
    if (pnt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        wprintf(L"[!] Architecture Mismatch: Target DLL is not 64-bit AMD64.\n");
        free(filebuffer);
        return 16;
    }
#else
    if (pnt->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) {
        wprintf(L"[!] Architecture Mismatch: Target DLL is not 32-bit i386.\n");
        free(filebuffer);
        return 16;
    }
#endif

    DWORD imagesize = pnt->OptionalHeader.SizeOfImage;
    wprintf(L"[*] Mapping PE Image into remote memory (Size: %u bytes / %u KB)...\n", imagesize, imagesize / 1024);

    LPVOID remoteimage = VirtualAllocEx(hprocess, (LPVOID)pnt->OptionalHeader.ImageBase, imagesize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteimage) {
        wprintf(L"[*] Preferred base occupied; dynamically allocating...\n");
        remoteimage = VirtualAllocEx(hprocess, NULL, imagesize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }
    if (!remoteimage) {
        wprintf(L"[!] VirtualAllocEx failed for remote image (Error code: %u)\n", GetLastError());
        free(filebuffer);
        return 17;
    }
    wprintf(L"[+] Remote image base allocated at: 0x%p\n", remoteimage);

    DWORD headersize = pnt->OptionalHeader.SizeOfHeaders;
    if (!WriteProcessMemory(hprocess, remoteimage, filebuffer, headersize, NULL)) {
        wprintf(L"[!] Failed writing PE headers (Error code: %u)\n", GetLastError());
        VirtualFreeEx(hprocess, remoteimage, 0, MEM_RELEASE);
        free(filebuffer);
        return 18;
    }

    PIMAGE_SECTION_HEADER psection = IMAGE_FIRST_SECTION(pnt);
    for (WORD i = 0; i < pnt->FileHeader.NumberOfSections; i++, psection++) {
        if (psection->SizeOfRawData == 0) continue;
        LPVOID dest = (LPBYTE)remoteimage + psection->VirtualAddress;
        LPCVOID src = (LPBYTE)filebuffer + psection->PointerToRawData;
        SIZE_T written = 0;
        if (!WriteProcessMemory(hprocess, dest, src, psection->SizeOfRawData, &written) || written != psection->SizeOfRawData) {
            wprintf(L"[!] Failed writing section '%.8hs' (Error code: %u)\n", psection->Name, GetLastError());
            VirtualFreeEx(hprocess, remoteimage, 0, MEM_RELEASE);
            free(filebuffer);
            return 19;
        }
    }
    wprintf(L"[+] Mapped %u sections successfully.\n", pnt->FileHeader.NumberOfSections);

    SIZE_T stubsize = (SIZE_T)((LPBYTE)maploaderend - (LPBYTE)maploader);
    if (stubsize == 0 || stubsize > 0x1000) stubsize = 0x1000;

    SIZE_T totalalloc = 0x2000;
    LPVOID remotestub = VirtualAllocEx(hprocess, (LPVOID)maploader, totalalloc, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remotestub) {
        remotestub = VirtualAllocEx(hprocess, NULL, totalalloc, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }
    if (!remotestub) {
        wprintf(L"[!] Failed allocating remote memory for loader stub (Error code: %u)\n", GetLastError());
        VirtualFreeEx(hprocess, remoteimage, 0, MEM_RELEASE);
        free(filebuffer);
        return 20;
    }
    LPVOID remotedata = (LPBYTE)remotestub + 0x1000;

    HMODULE hkernel = GetModuleHandleW(L"kernel32.dll");
    mapdata md = { 0 };
    md.imagebase = remoteimage;
    md.pfnloadliba = (fnloadliba)GetProcAddress(hkernel, "LoadLibraryA");
    md.pfngetproc = (fngetproc)GetProcAddress(hkernel, "GetProcAddress");
    md.pfnrtladdfunctiontable = (fnrtladdfunctiontable)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlAddFunctionTable");
    md.status = 0xFFFFFFFF;

    if (!WriteProcessMemory(hprocess, remotestub, (LPCVOID)maploader, stubsize, NULL) ||
        !WriteProcessMemory(hprocess, remotedata, &md, sizeof(md), NULL)) {
        wprintf(L"[!] Failed writing loader stub or mapping data (Error code: %u)\n", GetLastError());
        VirtualFreeEx(hprocess, remotestub, 0, MEM_RELEASE);
        VirtualFreeEx(hprocess, remoteimage, 0, MEM_RELEASE);
        free(filebuffer);
        return 21;
    }

    wprintf(L"[*] Executing remote loader thread (Stub: 0x%p, Size: %zu bytes)...\n", remotestub, stubsize);
    HANDLE hthread = CreateRemoteThread(hprocess, NULL, 0, (LPTHREAD_START_ROUTINE)remotestub, remotedata, 0, NULL);
    if (!hthread) {
        wprintf(L"[!] CreateRemoteThread failed for loader stub (Error code: %u)\n", GetLastError());
        VirtualFreeEx(hprocess, remotestub, 0, MEM_RELEASE);
        VirtualFreeEx(hprocess, remoteimage, 0, MEM_RELEASE);
        free(filebuffer);
        return 22;
    }

    DWORD waitresult = WaitForSingleObject(hthread, 15000);
    if (waitresult == WAIT_TIMEOUT) {
        wprintf(L"[!] Timed out waiting for remote loader stub execution\n");
    }
    DWORD exitcode = 0;
    GetExitCodeThread(hthread, &exitcode);
    ReadProcessMemory(hprocess, remotedata, &md, sizeof(md), NULL);
    CloseHandle(hthread);
    VirtualFreeEx(hprocess, remotestub, 0, MEM_RELEASE);

    if (md.status != 0) {
        wprintf(L"[!] Manual mapping loader returned error: Status %u\n", md.status);
        switch (md.status) {
            case 1:  wprintf(L"    -> Reason: Failed to load a required dependency DLL.\n"); break;
            case 2:  wprintf(L"    -> Reason: Failed to resolve an imported function.\n"); break;
            case 3:  wprintf(L"    -> Reason: DllMain returned FALSE.\n"); break;
            case 10: wprintf(L"    -> Reason: Corrupted DOS Header signature.\n"); break;
            case 11: wprintf(L"    -> Reason: Corrupted NT Header signature.\n"); break;
            default: wprintf(L"    -> Reason: Unknown failure code.\n"); break;
        }
        VirtualFreeEx(hprocess, remoteimage, 0, MEM_RELEASE);
        free(filebuffer);
        return 23;
    }

    psection = IMAGE_FIRST_SECTION(pnt);
    for (WORD i = 0; i < pnt->FileHeader.NumberOfSections; i++, psection++) {
        DWORD protect = PAGE_NOACCESS;
        DWORD chars = psection->Characteristics;
        if (chars & IMAGE_SCN_MEM_EXECUTE) {
            if (chars & IMAGE_SCN_MEM_WRITE) protect = PAGE_EXECUTE_READWRITE;
            else if (chars & IMAGE_SCN_MEM_READ) protect = PAGE_EXECUTE_READ;
            else protect = PAGE_EXECUTE;
        } else {
            if (chars & IMAGE_SCN_MEM_WRITE) protect = PAGE_READWRITE;
            else if (chars & IMAGE_SCN_MEM_READ) protect = PAGE_READONLY;
        }
        DWORD oldprotect = 0;
        DWORD secsize = psection->Misc.VirtualSize ? psection->Misc.VirtualSize : psection->SizeOfRawData;
        VirtualProtectEx(hprocess, (LPBYTE)remoteimage + psection->VirtualAddress, secsize, protect, &oldprotect);
    }

    if (erasepe) {
        wprintf(L"[*] Erasing PE headers from remote memory for anti-detection...\n");
        DWORD oldprotect = 0;
        VirtualProtectEx(hprocess, remoteimage, headersize, PAGE_READWRITE, &oldprotect);
        BYTE* zerobuf = (BYTE*)calloc(1, headersize);
        if (zerobuf) {
            WriteProcessMemory(hprocess, remoteimage, zerobuf, headersize, NULL);
            free(zerobuf);
        }
        VirtualProtectEx(hprocess, remoteimage, headersize, PAGE_NOACCESS, &oldprotect);
        wprintf(L"[+] PE headers sanitized successfully.\n");
    }

    free(filebuffer);
    wprintf(L"[+] SUCCESS: DLL manually mapped and initialized successfully!\n");
    wprintf(L"[+] Module Base Address: 0x%p\n", remoteimage);
    return 0;
}

static int injecthijack(HANDLE hprocess, const wchar_t* fulldllpath) {
    wprintf(L"[*] Executing Thread Hijack Injection (Suspended Remote Thread Trampoline)...\n");

    size_t pathbytes = (wcslen(fulldllpath) + 1) * sizeof(wchar_t);
    LPVOID remotemem = VirtualAllocEx(hprocess, NULL, pathbytes + 0x100, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remotemem) {
        wprintf(L"[!] VirtualAllocEx failed\n");
        return 35;
    }

    BYTE* codebase = (BYTE*)remotemem + pathbytes;

    BYTE stub[] = {
        0x48, 0x83, 0xEC, 0x08,
        0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00,
        0xC7, 0x44, 0x24, 0x04, 0x00, 0x00, 0x00, 0x00,
        0x50, 0x51, 0x52, 0x53, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53,
        0x48, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x48, 0x83, 0xEC, 0x20,
        0xFF, 0xD3,
        0x48, 0x83, 0xC4, 0x20,
        0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5B, 0x5A, 0x59, 0x58,
        0xC6, 0x05, 0xB0, 0xFF, 0xFF, 0xFF, 0x00,
        0xC3
    };

    *(ULONG_PTR*)(stub + 0x21) = (ULONG_PTR)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
    *(ULONG_PTR*)(stub + 0x2B) = (ULONG_PTR)remotemem;

    SIZE_T written = 0;
    if (!WriteProcessMemory(hprocess, remotemem, fulldllpath, pathbytes, &written) ||
        !WriteProcessMemory(hprocess, codebase, stub, sizeof(stub), &written)) {
        wprintf(L"[!] WriteProcessMemory failed\n");
        VirtualFreeEx(hprocess, remotemem, 0, MEM_RELEASE);
        return 36;
    }

    DWORD oldprotect = 0;
    VirtualProtectEx(hprocess, codebase, sizeof(stub), PAGE_EXECUTE_READ, &oldprotect);

    HANDLE hthread = CreateRemoteThread(hprocess, NULL, 0, (LPTHREAD_START_ROUTINE)codebase, NULL, CREATE_SUSPENDED, NULL);
    if (!hthread) {
        wprintf(L"[!] CreateRemoteThread failed (Error code: %u)\n", GetLastError());
        VirtualFreeEx(hprocess, remotemem, 0, MEM_RELEASE);
        return 37;
    }

    ResumeThread(hthread);

    BYTE flag = 1;
    for (int i = 0; i < 150; i++) {
        Sleep(100);
        ReadProcessMemory(hprocess, codebase, &flag, 1, NULL);
        if (flag == 0) break;
    }

    VirtualFreeEx(hprocess, remotemem, 0, MEM_RELEASE);
    CloseHandle(hthread);

    if (flag != 0) {
        wprintf(L"[!] Timed out waiting for trampoline to complete\n");
        return 38;
    }

    wprintf(L"[+] SUCCESS: Trampoline executed LoadLibraryW and completed cleanly\n");
    return 0;
}

int wmain(int argc, wchar_t* argv[]) {
    wprintf(L"[+] === Proton/Wine Win32 DLL Injector ===\n");
    if (argc < 3) {
        printusage(argv[0]);
        return 1;
    }

    const wchar_t* targetarg = argv[1];
    const wchar_t* dllpatharg = argv[2];
    int waitseconds = 0;
    injectmethod method = methodmanual;
    bool erasepe = false;

    for (int i = 3; i < argc; i++) {
        if (_wcsicmp(argv[i], L"--wait") == 0 && i + 1 < argc) {
            waitseconds = _wtoi(argv[++i]);
        } else if (_wcsicmp(argv[i], L"--method") == 0 && i + 1 < argc) {
            i++;
            if (_wcsicmp(argv[i], L"loadlibrary") == 0) {
                method = methodloadlib;
            } else if (_wcsicmp(argv[i], L"manual") == 0) {
                method = methodmanual;
            } else if (_wcsicmp(argv[i], L"hijack") == 0) {
                method = methodhijack;
            }
        } else if (_wcsicmp(argv[i], L"--erase-pe") == 0) {
            erasepe = true;
        }
    }

    DWORD pid = 0;
    if (isnumeric(targetarg)) {
        pid = (DWORD)_wtoi(targetarg);
    } else {
        wprintf(L"[*] Resolving process: %ls\n", targetarg);
        int attempts = 0;
        int maxattempts = waitseconds > 0 ? (waitseconds * 2) : 1;
        while (attempts < maxattempts) {
            pid = findprocessbyname(targetarg);
            if (pid != 0) break;
            if (maxattempts > 1) Sleep(500);
            attempts++;
        }
    }

    if (pid == 0) {
        wprintf(L"[!] Failed: Target process '%ls' not found.\n", targetarg);
        return 2;
    }
    wprintf(L"[+] Target PID: %u\n", pid);

    wchar_t fulldllpath[MAX_PATH] = { 0 };
    if (!GetFullPathNameW(dllpatharg, MAX_PATH, fulldllpath, NULL)) {
        wcsncpy(fulldllpath, dllpatharg, MAX_PATH - 1);
    }
    wprintf(L"[*] DLL Path: %ls\n", fulldllpath);

    DWORD attribs = GetFileAttributesW(fulldllpath);
    if (attribs == INVALID_FILE_ATTRIBUTES || (attribs & FILE_ATTRIBUTE_DIRECTORY)) {
        wprintf(L"[!] Warning: DLL file not directly accessible at path: %ls\n", fulldllpath);
    }

    HANDLE hprocess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, pid);
    if (!hprocess) {
        wprintf(L"[!] OpenProcess failed for PID %u (Error code: %u)\n", pid, GetLastError());
        return 3;
    }

    int result = 0;
    if (method == methodmanual) {
        result = injectmanualmap(hprocess, fulldllpath, erasepe);
    } else if (method == methodhijack) {
        result = injecthijack(hprocess, fulldllpath);
    } else {
        result = injectloadlib(hprocess, fulldllpath);
    }
    CloseHandle(hprocess);
    return result;
}
