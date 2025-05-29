# Reverse All The Scripts

Hello! In this repository you will find a collection of scripts that I am creating to test myself during my journey to become a Malware Analyst.

List of scripts and their features:

1. **PE static analysis** - automatic extraction of the juiciest information from a PE file
    - `python3 01-PE-static-analysis.py M3_Lab.exe`
        ```json
        {
            "NT_HEADER": {
                "AddressOfEntryPoint": "0x16FE",
                "ImageBase": "0x500000"
            },
            "SECTIONS": {
                ".text": {
                    "VirtualAddress": "0x1000",
                    "SizeOfRawData": "0xEA00",
                    "PointerToRawData": "0x0400"
                },
                ".rdata": {
                    "VirtualAddress": "0x10000",
                    "SizeOfRawData": "0x5C00",
                    "PointerToRawData": "0xEE00"
                },
                ".foo1": {
                    "VirtualAddress": "0x16000",
                    "SizeOfRawData": "0x0C00",
                    "PointerToRawData": "0x14A00"
                },
                ".reloc": {
                    "VirtualAddress": "0x18000",
                    "SizeOfRawData": "0x1000",
                    "PointerToRawData": "0x15600"
                }
            },
            "IMPORTS": {
                "VirtualAddress": "0x15444",
                "Size": "0x003C",
                "WININET.dll": [
                    "InternetOpenUrlA", "InternetCloseHandle", "InternetOpenA"
                ],
                "KERNEL32.dll": [
                    "WriteFile", "WriteConsoleW", "CreateFileW", "CloseHandle", "Sleep", "ResumeThread", "CreateProcessA",
                    "GetThreadContext", "SetThreadContext", "VirtualAllocEx", "WriteProcessMemory", "GetModuleHandleA",
                    "GetProcAddress", "UnhandledExceptionFilter", "SetUnhandledExceptionFilter", "GetCurrentProcess",
                    "TerminateProcess", "IsProcessorFeaturePresent", "QueryPerformanceCounter", "GetCurrentProcessId",
                    "GetCurrentThreadId", "GetSystemTimeAsFileTime", "InitializeSListHead", "IsDebuggerPresent",
                    "GetStartupInfoW", "GetModuleHandleW", "SetFilePointerEx", "RtlUnwind", "GetLastError",
                    "SetLastError", "EnterCriticalSection", "LeaveCriticalSection", "DeleteCriticalSection",
                    "InitializeCriticalSectionAndSpinCount", "TlsAlloc", "TlsGetValue", "TlsSetValue",
                    "TlsFree", "FreeLibrary", "LoadLibraryExW", "EncodePointer", "RaiseException",
                    "GetStdHandle", "DecodePointer", "GetModuleFileNameW", "ExitProcess", "GetModuleHandleExW",
                    "GetCommandLineA", "GetCommandLineW", "GetFileType", "CompareStringW", "LCMapStringW",
                    "HeapAlloc", "HeapFree", "FindClose", "FindFirstFileExW", "FindNextFileW",
                    "IsValidCodePage", "GetACP", "GetOEMCP", "GetCPInfo", "MultiByteToWideChar",
                    "WideCharToMultiByte", "GetEnvironmentStringsW", "FreeEnvironmentStringsW",
                    "SetEnvironmentVariableW", "SetStdHandle", "GetStringTypeW", "GetProcessHeap",
                    "GetConsoleCP", "GetConsoleMode", "HeapSize", "HeapReAlloc", "FlushFileBuffers"
                ]
            },
            "EXPORTS": {
                "VirtualAddress": "0x0000",
                "Size": "0x0000"
            }
        }
        ```

2. x64dbg script that automates process un-hollowing until memory dump. Output here: https://federicofantini.github.io/TheTrackerShow/scripts/x64dbg/01-lummastealer_process_unhollowing/