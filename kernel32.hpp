// kernel32.hpp
// Description: Emulation of selected kernel32.DLL functions for a custom Windows-like environment.
#pragma ONCE
#include <semaphore.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <pthread.h>
#include <mutex>
#include <chrono>
#include "global.h"
#include <dirent.h>
#include <sys/statvfs.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unicode/uchar.h>    // u_charType, u_charDirection, u_getCombiningClass, u_hasBinaryProperty, u_getIntPropertyValue, UProperty
#include <unicode/ubidi.h>    // ubidi stuff (we use u_charDirection from uchar.h)
#include <unicode/uscript.h>  // uscript_getScript
#include <unicode/utf16.h>    // U16_NEXT macro
#include <unicode/ustdio.h>   // optional
#include <unicode/uclean.h>   // u_cleanup (not mandatory)

#include "ucrtbase.hpp"

class Kernel32 {
public:
    std::unordered_map<std::wstring, void*> exports;

    inline Kernel32() = default;

    static std::unordered_map<std::wstring, EmulatedExport> get_exports_detailed();

    static void WINAPI ExitProcess(UINT exit_code);

    static void WINAPI SetLastError(DWORD error_code);

    static DWORD GetLastError();

    static void WINAPI Sleep(DWORD milliseconds);

    static DWORD WINAPI GetTickCount();

    static ULONGLONG WINAPI GetTickCount64();

    static DWORD WINAPI GetCurrentThreadId();

    static HANDLE WINAPI CreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
                                     LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
                                     DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);

    static BOOL WINAPI ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead,
                                LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);

    static BOOL WINAPI WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite,
                                 LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);

    static BOOL WINAPI DeleteFileW(LPCWSTR lpFileName);

    static BOOL WINAPI CloseHandle(HANDLE hObject);

    static DWORD WINAPI WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds);

    static DWORD WINAPI WaitForSingleObjectEx(HANDLE hHandle, DWORD dwMilliseconds, BOOL bAlertable);

    static DWORD WINAPI WaitForMultipleObjects(DWORD nCount, const HANDLE* lpHandles, BOOL bWaitAll, DWORD dwMilliseconds);

    static DWORD WINAPI WaitForMultipleObjectsEx(DWORD nCount, const HANDLE* lpHandles, BOOL bWaitAll, DWORD dwMilliseconds, BOOL bAlertable);

    static BOOL WINAPI QueueUserAPC(PAPCFUNC pfnAPC, HANDLE hThread, ULONG_PTR dwData);

    static DWORD WINAPI GetFileSize(HANDLE hFile, LPDWORD lpFileSizeHigh);

    static DWORD WINAPI SetFilePointer(HANDLE hFile, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod);

    static DWORD WINAPI SetFilePointerEx(HANDLE hFile, LARGE_INTEGER liDistanceToMove, PLARGE_INTEGER lpNewFilePointer, DWORD dwMoveMethod);

    static BOOL WINAPI FlushFileBuffers(HANDLE hFile);

    static INT WINAPI WideCharToMultiByte(UINT CodePage, DWORD dwFlags, LPCWCH lpWideCharStr, int cchWideChar,
                                          LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar,
                                          LPBOOL lpUsedDefaultChar);

    static INT WINAPI MultiByteToWideChar(UINT CodePage, DWORD dwFlags, LPCCH lpMultiByteStr, int cbMultiByte,
                                          LPWSTR lpWideCharStr, int cchWideChar);

private:
    // Helper function for pattern matching
    static bool match_pattern(const std::string& filename, const std::string& pattern, bool case_sensitive = false);

    // Convert Unix file attributes to Windows file attributes
    static DWORD WINAPI get_windows_attributes(const struct stat& file_stat, const std::string& filename);

    // Convert Unix timestamp to Windows FILETIME
    static FILETIME WINAPI unix_to_filetime(time_t unix_time);

    static bool fill_find_data(WIN32_FIND_DATAW* find_data, const std::string& filename,
                               const std::string& full_path, bool basic_info = false);

public:
    static HANDLE WINAPI FindFirstFileW(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData);

    static HANDLE WINAPI FindFirstFileExW(LPCWSTR lpFileName, FINDEX_INFO_LEVELS fInfoLevelId,
                                          LPVOID lpFindFileData, FINDEX_SEARCH_OPS fSearchOp,
                                          LPVOID lpSearchFilter, DWORD dwAdditionalFlags);

    static BOOL WINAPI FindNextFileW(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData);

    static BOOL WINAPI FindClose(HANDLE hFindFile);

    static LPCWSTR GetCommandLineW();

    static HANDLE GetCurrentProcess();

    static HMODULE GetModuleHandleW(LPCWSTR lpModuleName);

    static HMODULE WINAPI LoadLibraryW(LPCWSTR lpLibFileName);

    static FARPROC WINAPI GetProcAddress(HMODULE hModule, LPCSTR lpProcName);

    static BOOL WINAPI FreeLibrary(HMODULE hLibModule);

    static DWORD WINAPI GetModuleFileNameW(HMODULE hModule, LPWSTR lpFilename, DWORD nSize);

    static BOOL SetEnvironmentVariableW(LPCWSTR lpName, LPCWSTR lpValue);

    static DWORD WINAPI GetEnvironmentVariableW(LPCWSTR lpName, LPWSTR lpBuffer, DWORD nSize);

    // <idonotcare>
    static void WINAPI InitializeCriticalSection(LPCRITICAL_SECTION lpCriticalSection);

    static void WINAPI InitializeCriticalSectionEx(LPCRITICAL_SECTION lpCriticalSection, DWORD dwSpinCount, DWORD Flags);

    static void WINAPI InitializeCriticalSectionAndSpinCount(LPCRITICAL_SECTION lpCriticalSection, DWORD dwSpinCount);

    // </idonotcare>

    static void WINAPI EnterCriticalSection(LPCRITICAL_SECTION lpCriticalSection);

    static BOOL WINAPI TryEnterCriticalSection(LPCRITICAL_SECTION lpCriticalSection);

    static void WINAPI LeaveCriticalSection(LPCRITICAL_SECTION lpCriticalSection);

    static void WINAPI DeleteCriticalSection(LPCRITICAL_SECTION lpCriticalSection);

    static UINT WINAPI SetErrorMode(UINT uMode);

    static UINT WINAPI GetErrorMode();

    static HANDLE WINAPI CreateEventW(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset,
                                      BOOL bInitialState, LPCWSTR lpName);

    static BOOL WINAPI SetEvent(HANDLE hEvent);

    static BOOL WINAPI ResetEvent(HANDLE hEvent);

    static HANDLE WINAPI CreateSemaphoreW(LPSECURITY_ATTRIBUTES lpSemaphoreAttributes, LONG lInitialCount,
                                          LONG lMaximumCount, LPCWSTR lpName);

    static BOOL ReleaseSemaphore(HANDLE hSemaphore, LONG lReleaseCount, LPLONG lpPreviousCount);

    static HANDLE CreateMutexW(LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner,
                               LPCWSTR lpName);

    static BOOL ReleaseMutex(HANDLE hMutex);

    static LPWCH GetEnvironmentStringsW();

    static BOOL FreeEnvironmentStringsW(LPCWSTR penv);

    static void RaiseException(DWORD dwExceptionCode, DWORD dwExceptionFlags, DWORD nNumberOfArguments, const ULONG_PTR* lpArguments);

    static void GetSystemInfo(LPSYSTEM_INFO lpSystemInfo);

    static DWORD GetCurrentDirectoryW(DWORD nBufferLength, LPWSTR lpBuffer);

    static bool SwitchToThread(DWORD thread_id);

    static LPVOID VirtualAllocEx(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect, HANDLE hProcess);

    static BOOL VirtualFreeEx(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType, HANDLE hProcess);

    static BOOL VirtualProtectEx(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect, HANDLE hProcess);

    static SIZE_T VirtualQueryEx(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength, HANDLE hProcess);

    static HANDLE VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);

    static BOOL VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);

    static BOOL VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);

    static SIZE_T VirtualQuery(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength);

    static DWORD GetFullPathNameW(LPCWSTR lpFileName, DWORD nBufferLength, LPWSTR lpBuffer, LPWSTR* lpFilePart);

    static DWORD GetTempPathW(DWORD nBufferLength, LPWSTR lpBuffer);

    static BOOL GetExitCodeThread(HANDLE hThread, LPDWORD lpExitCode);

    static BOOL GetExitCodeProcess(HANDLE hProcess, LPDWORD lpExitCode);

    static DWORD GetFreeDiskSpaceExW(LPCWSTR lpDirectoryName, PULARGE_INTEGER lpFreeBytesAvailableToCaller,
                                     PULARGE_INTEGER lpTotalNumberOfBytes, PULARGE_INTEGER lpTotalNumberOfFreeBytes);

    static DWORD GetFreeDiskSpaceW(LPCWSTR lpDirectoryName, LPDWORD lpSectorsPerCluster,
                                   LPDWORD lpBytesPerSector, LPDWORD lpNumberOfFreeClusters,
                                   LPDWORD lpTotalNumberOfClusters);

    static void* _thread_func(void* arg);

    static HANDLE CreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize,
                               LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter,
                               DWORD dwCreationFlags, LPDWORD lpThreadId);

    static HANDLE GetCurrentThread();

    static DWORD GetCurrentProcessId();

    static BOOL TerminateThread(HANDLE hThread, DWORD dwExitCode);

    static BOOL ExitThread(DWORD dwExitCode);

    // Suspend/Resume:
    static DWORD SuspendThread(HANDLE hThread);

    static DWORD ResumeThread(HANDLE hThread);

    static BOOL SetConsoleCtrlHandler(PHANDLER_ROUTINE HandlerRoutine, BOOL Add);

    static DWORD SearchPathW(LPCWSTR lpPath, LPCWSTR lpFileName, LPCWSTR lpExtension, DWORD nBufferLength,
                             LPWSTR lpBuffer, LPWSTR* lpFilePart);

    static HANDLE GetStdHandle(DWORD nStdHandle);

    static BOOL SetStdHandle(DWORD nStdHandle, HANDLE hHandle);

    static BOOL IsDebuggerPresent();

    static void RtlCaptureContext(LPCONTEXT ContextRecord);

    // Helper to extract exception directory from PE
    static std::vector<RUNTIME_FUNCTION> extract_exception_table(
        const LIEF::PE::Binary& pe,
        const uintptr_t base_address);

    // Find a module containing the given address using global state
    static uintptr_t find_module_base(uintptr_t control_pc);

    // Validate that the function entry is within bounds and properly formed
    static bool validate_function_entry(const RUNTIME_FUNCTION& func, uintptr_t image_size);

public:
    // Full RtlLookupFunctionEntry implementation
    static PRUNTIME_FUNCTION WINAPI RtlLookupFunctionEntry(
        DWORD64 ControlPc,
        PDWORD64 ImageBase,
        PUNWIND_HISTORY_TABLE HistoryTable);

    // Helper function to register an exception table for a loaded module
    static void register_exception_table(uintptr_t base_address,
                                       const LIEF::PE::Binary& pe);

    // Alternative implementation for cases where PE binary is not available
    static void register_exception_table_raw(const uintptr_t base_address,
                                           const RUNTIME_FUNCTION* functions,
                                           const size_t count);

    // Cleanup function for when modules are unloaded
    static void unregister_exception_table(const uintptr_t base_address);


    static PEXCEPTION_ROUTINE RtlVirtualUnwind(DWORD HandlerType, DWORD64 ImageBase, DWORD64 ControlPc,
                                               PRUNTIME_FUNCTION FunctionEntry, PCONTEXT ContextRecord,
                                               PVOID* HandlerData, PDWORD64 EstablisherFrame, PULONG64 TargetGp);

    static LONG UnhandledExceptionFilter(EXCEPTION_POINTERS* ExceptionInfo);

    static LPTOP_LEVEL_EXCEPTION_FILTER SetUnhandledExceptionFilter(LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter);

    static BOOL WriteConsoleW(HANDLE hConsoleOutput, const void* lpBuffer, DWORD nNumberOfCharsToWrite,
                              LPDWORD lpNumberOfCharsWritten, LPVOID lpReserved);

    static HANDLE GetProcessHeap();

    static LPVOID HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);

    static BOOL HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);

    static SIZE_T HeapSize(HANDLE hHeap, DWORD dwFlags, LPCVOID lpMem);

    static HANDLE HeapCreate(DWORD flOptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize);

    static BOOL HeapDestroy(HANDLE hHeap);

    static LPVOID HeapReAlloc(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes);

    static DWORD GetProcessId();

    static DWORD GetThreadId();

    static void GetStartupInfoW(LPSTARTUPINFOW lpStartupInfo);

    static void InitializeSListHead(PSLIST_HEADER ListHead);

    static PSLIST_ENTRY InterlockedPushEntrySList(PSLIST_HEADER ListHead, PSLIST_ENTRY ListEntry);

    static PSLIST_ENTRY InterlockedPopEntrySList(PSLIST_HEADER ListHead);

    static PSLIST_ENTRY InterlockedFlushSList(PSLIST_HEADER ListHead);

    static PSLIST_ENTRY InterlockedPushListSList(PSLIST_HEADER ListHead, PSLIST_ENTRY List, PSLIST_ENTRY ListEnd, ULONG Count);

    static PSLIST_ENTRY RtlFirstEntrySList(PSLIST_HEADER ListHead);

    static USHORT QueryDepthSList(PSLIST_HEADER ListHead);

    static BOOL QueryPerformanceCounter(LARGE_INTEGER* lpPerformanceCount);

    static BOOL QueryPerformanceFrequency(LARGE_INTEGER* lpFrequency);

    static void GetSystemTimeAsFileTime(LPFILETIME lpSystemTimeAsFileTime);

    static BOOL IsProcessorFeaturePresent(DWORD ProcessorFeature);

    static BOOL TerminateProcess(HANDLE hProcess, UINT uExitCode);

    static void RtlUnwindEx(LPCONTEXT ContextRecord, PVOID TargetFrame, PVOID TargetIp, PEXCEPTION_RECORD ExceptionRecord, LPVOID ReturnValue, PCONTEXT OriginalContext, LPVOID HistoryTable);

    static void RtlUnwind(LPCONTEXT ContextRecord, PVOID TargetFrame, PVOID TargetIp, PEXCEPTION_RECORD ExceptionRecord, LPVOID ReturnValue);

    static LPVOID EncodePointer(LPVOID Ptr);

    static LPVOID DecodePointer(LPVOID Ptr);

    static PVOID WINAPI RtlPcToFileHeader(PVOID PcValue, PVOID *BaseOfImage);

    static DWORD TlsAlloc();

    static BOOL TlsFree(DWORD dwTlsIndex);

    static LPVOID TlsGetValue(DWORD dwTlsIndex);

    static BOOL TlsSetValue(DWORD dwTlsIndex, LPVOID lpTlsValue);

    static bool is_wchar_surrogate_high(WCHAR wc);

    static bool is_wchar_surrogate_low(WCHAR wc);

    static WORD map_category_to_C1(int8_t cat, UChar32 codepoint);

    // Map ICU bidi direction to C2 flags (Windows categories)
    static WORD map_bidi_to_C2(UCharDirection dir, UChar32 c);

    // Map to C3 flags based on ICU properties (best-effort)
    static WORD map_to_C3(UChar32 c);

    static BOOL WINAPI GetStringTypeW(DWORD dwInfoType, LPCWCH lpSrcStr, int cchSrc, LPWORD lpCharType);
};