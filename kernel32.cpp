//
// Created by wojtek on 9/15/25.
//

class UCRTBase;

#include "kernel32.hpp"
#include "ucrtbase.hpp"

#include <filesystem>
#include <LIEF/PE/Binary.hpp>
#include <LIEF/PE/Export.hpp>
#include <LIEF/PE/Parser.hpp>
#include <LIEF/PE/Section.hpp>

std::unordered_map<std::wstring, EmulatedExport> Kernel32::get_exports_detailed() {
    return {
        {L"ExitProcess", { L"ExitProcess", reinterpret_cast<uintptr_t>(ExitProcess), true, 0 }},
        {L"SetLastError", { L"SetLastError", reinterpret_cast<uintptr_t>(SetLastError), true, 0 }},
        {L"GetLastError", { L"GetLastError", reinterpret_cast<uintptr_t>(GetLastError), true, 0 }},
        {L"Sleep", { L"Sleep", reinterpret_cast<uintptr_t>(Sleep), true, 0 }},
        {L"GetTickCount", { L"GetTickCount", reinterpret_cast<uintptr_t>(GetTickCount), true, 0 }},
        {L"GetTickCount64", { L"GetTickCount64", reinterpret_cast<uintptr_t>(GetTickCount64), true, 0 }},
        {L"GetCurrentThreadId", { L"GetCurrentThreadId", reinterpret_cast<uintptr_t>(GetCurrentThreadId), true, 0 }},
        {L"CreateFileW", { L"CreateFileW", reinterpret_cast<uintptr_t>(CreateFileW), true, 0 }},
        {L"ReadFile", { L"ReadFile", reinterpret_cast<uintptr_t>(ReadFile), true, 0 }},
        {L"WriteFile", { L"WriteFile", reinterpret_cast<uintptr_t>(WriteFile), true, 0 }},
        {L"DeleteFileW", { L"DeleteFileW", reinterpret_cast<uintptr_t>(DeleteFileW), true, 0 }},
        {L"CloseHandle", { L"CloseHandle", reinterpret_cast<uintptr_t>(CloseHandle), true, 0 }},
        {L"WaitForSingleObject", { L"WaitForSingleObject", reinterpret_cast<uintptr_t>(WaitForSingleObject), true, 0 }},
        {L"WaitForSingleObjectEx", { L"WaitForSingleObjectEx", reinterpret_cast<uintptr_t>(WaitForSingleObjectEx), true, 0 }},
        {L"WaitForMultipleObjects", { L"WaitForMultipleObjects", reinterpret_cast<uintptr_t>(WaitForMultipleObjects), true, 0 }},
        {L"WaitForMultipleObjectsEx", { L"WaitForMultipleObjectsEx", reinterpret_cast<uintptr_t>(WaitForMultipleObjectsEx), true, 0 }},
        {L"QueueUserAPC", { L"QueueUserAPC", reinterpret_cast<uintptr_t>(QueueUserAPC), true, 0 }},
        {L"GetFileSize", { L"GetFileSize", reinterpret_cast<uintptr_t>(GetFileSize), true, 0 }},
        {L"SetFilePointer", { L"SetFilePointer", reinterpret_cast<uintptr_t>(SetFilePointer), true, 0 }},
        {L"SetFilePointerEx", { L"SetFilePointerEx", reinterpret_cast<uintptr_t>(SetFilePointerEx), true, 0 }},
        {L"FlushFileBuffers", { L"FlushFileBuffers", reinterpret_cast<uintptr_t>(FlushFileBuffers), true, 0 }},
        {L"WideCharToMultiByte", { L"WideCharToMultiByte", reinterpret_cast<uintptr_t>(WideCharToMultiByte), true, 0 }},
        {L"MultiByteToWideChar", { L"MultiByteToWideChar", reinterpret_cast<uintptr_t>(MultiByteToWideChar), true, 0 }},
        {L"FindFirstFileW", { L"FindFirstFileW", reinterpret_cast<uintptr_t>(FindFirstFileW), true, 0 }},
        {L"FindNextFileW", { L"FindNextFileW", reinterpret_cast<uintptr_t>(FindNextFileW), true, 0 }},
        {L"FindClose", { L"FindClose", reinterpret_cast<uintptr_t>(FindClose), true, 0 }},
        {L"FindFirstFileExW", { L"FindFirstFileExW", reinterpret_cast<uintptr_t>(FindFirstFileExW), true, 0 }},
        {L"LoadLibraryW", { L"LoadLibraryW", reinterpret_cast<uintptr_t>(LoadLibraryW), true, 0 }},
        {L"GetProcAddress", { L"GetProcAddress", reinterpret_cast<uintptr_t>(GetProcAddress), true, 0 }},
        {L"FreeLibrary", { L"FreeLibrary", reinterpret_cast<uintptr_t>(FreeLibrary), true, 0 }},
        {L"GetModuleFileNameW", { L"GetModuleFileNameW", reinterpret_cast<uintptr_t>(GetModuleFileNameW), true, 0 }},
        {L"GetModuleHandleW", { L"GetModuleHandleW", reinterpret_cast<uintptr_t>(GetModuleHandleW), true, 0 }},
        {L"CreateEventW", { L"CreateEventW", reinterpret_cast<uintptr_t>(CreateEventW), true, 0 }},
        {L"SetEvent", { L"SetEvent", reinterpret_cast<uintptr_t>(SetEvent), true, 0 }},
        {L"ResetEvent", { L"ResetEvent", reinterpret_cast<uintptr_t>(ResetEvent), true, 0 }},
        {L"CreateMutexW", { L"CreateMutexW", reinterpret_cast<uintptr_t>(CreateMutexW), true, 0 }},
        {L"ReleaseMutex", { L"ReleaseMutex", reinterpret_cast<uintptr_t>(ReleaseMutex), true, 0 }},
        {L"CreateSemaphoreW", { L"CreateSemaphoreW", reinterpret_cast<uintptr_t>(CreateSemaphoreW), true, 0 }},
        {L"ReleaseSemaphore", { L"ReleaseSemaphore", reinterpret_cast<uintptr_t>(ReleaseSemaphore), true, 0 }},
        {L"CreateThread", { L"CreateThread", reinterpret_cast<uintptr_t>(CreateThread), true, 0 }},
        {L"TerminateThread", { L"TerminateThread", reinterpret_cast<uintptr_t>(TerminateThread), true, 0 }},
        {L"GetExitCodeThread", { L"GetExitCodeThread", reinterpret_cast<uintptr_t>(GetExitCodeThread), true, 0 }},
        {L"VirtualAlloc", { L"VirtualAlloc", reinterpret_cast<uintptr_t>(VirtualAlloc), true, 0 }},
        {L"VirtualFree", { L"VirtualFree", reinterpret_cast<uintptr_t>(VirtualFree), true, 0 }},
        {L"VirtualProtect", { L"VirtualProtect", reinterpret_cast<uintptr_t>(VirtualProtect), true, 0 }},
        {L"VirtualQuery", { L"VirtualQuery", reinterpret_cast<uintptr_t>(VirtualQuery), true, 0 }},
        {L"VirtualAllocEx", { L"VirtualAllocEx", reinterpret_cast<uintptr_t>(VirtualAllocEx), true, 0 }},
        {L"VirtualFreeEx", { L"VirtualFreeEx", reinterpret_cast<uintptr_t>(VirtualFreeEx), true, 0 }},
        {L"VirtualProtectEx", { L"VirtualProtectEx", reinterpret_cast<uintptr_t>(VirtualProtectEx), true, 0 }},
        {L"HeapCreate", { L"HeapCreate", reinterpret_cast<uintptr_t>(HeapCreate), true, 0 }},
        {L"HeapAlloc", { L"HeapAlloc", reinterpret_cast<uintptr_t>(HeapAlloc), true, 0 }},
        {L"HeapFree", { L"HeapFree", reinterpret_cast<uintptr_t>(HeapFree), true, 0 }},
        {L"HeapDestroy", { L"HeapDestroy", reinterpret_cast<uintptr_t>(HeapDestroy), true, 0 }},
        {L"HeapSize", { L"HeapSize", reinterpret_cast<uintptr_t>(HeapSize), true, 0 }},
        {L"HeapReAlloc", { L"HeapReAlloc", reinterpret_cast<uintptr_t>(HeapReAlloc), true, 0 }},
        {L"GetProcessHeap", { L"GetProcessHeap", reinterpret_cast<uintptr_t>(GetProcessHeap), true, 0 }},
        {L"TlsAlloc", { L"TlsAlloc", reinterpret_cast<uintptr_t>(TlsAlloc), true, 0 }},
        {L"TlsFree", { L"TlsFree", reinterpret_cast<uintptr_t>(TlsFree), true, 0 }},
        {L"TlsSetValue", { L"TlsSetValue", reinterpret_cast<uintptr_t>(TlsSetValue), true, 0 }},
        {L"TlsGetValue", { L"TlsGetValue", reinterpret_cast<uintptr_t>(TlsGetValue), true, 0 }},
        {L"GetSystemInfo", { L"GetSystemInfo", reinterpret_cast<uintptr_t>(GetSystemInfo), true, 0 }},
        {L"GetStdHandle", { L"GetStdHandle", reinterpret_cast<uintptr_t>(GetStdHandle), true, 0 }},
        {L"WriteConsoleW", { L"WriteConsoleW", reinterpret_cast<uintptr_t>(WriteConsoleW), true, 0 }},
        {L"GetCurrentDirectoryW", { L"GetCurrentDirectoryW", reinterpret_cast<uintptr_t>(GetCurrentDirectoryW), true, 0 }},
        {L"GetTempPathW", { L"GetTempPathW", reinterpret_cast<uintptr_t>(GetTempPathW), true, 0 }},
        {L"GetFullPathNameW", { L"GetFullPathNameW", reinterpret_cast<uintptr_t>(GetFullPathNameW), true, 0 }},
        {L"TerminateProcess", { L"TerminateProcess", reinterpret_cast<uintptr_t>(TerminateProcess), true, 0 }},
        {L"GetExitCodeProcess", { L"GetExitCodeProcess", reinterpret_cast<uintptr_t>(GetExitCodeProcess), true, 0 }},
        {L"IsDebuggerPresent", { L"IsDebuggerPresent", reinterpret_cast<uintptr_t>(IsDebuggerPresent), true, 0 }},
        {L"GetCurrentProcess", { L"GetCurrentProcess", reinterpret_cast<uintptr_t>(GetCurrentProcess), true, 0 }},
        {L"GetCurrentProcessId", { L"GetCurrentProcessId", reinterpret_cast<uintptr_t>(GetCurrentProcessId), true, 0 }},
        {L"GetCurrentThread", { L"GetCurrentThread", reinterpret_cast<uintptr_t>(GetCurrentThread), true, 0 }},
        {L"SetConsoleCtrlHandler", { L"SetConsoleCtrlHandler", reinterpret_cast<uintptr_t>(SetConsoleCtrlHandler), true, 0 }},
        {L"SearchPathW", { L"SearchPathW", reinterpret_cast<uintptr_t>(SearchPathW), true, 0 }},
        {L"SetStdHandle", { L"SetStdHandle", reinterpret_cast<uintptr_t>(SetStdHandle), true, 0 }},
        {L"RtlCaptureContext", { L"RtlCaptureContext", reinterpret_cast<uintptr_t>(RtlCaptureContext), true, 0 }},
        {L"RtlLookupFunctionEntry", { L"RtlLookupFunctionEntry", reinterpret_cast<uintptr_t>(RtlLookupFunctionEntry), true, 0 }},
        {L"RtlVirtualUnwind", { L"RtlVirtualUnwind", reinterpret_cast<uintptr_t>(RtlVirtualUnwind), true, 0 }},
        {L"UnhandledExceptionFilter", { L"UnhandledExceptionFilter", reinterpret_cast<uintptr_t>(UnhandledExceptionFilter), true, 0 }},
        {L"SetUnhandledExceptionFilter", { L"SetUnhandledExceptionFilter", reinterpret_cast<uintptr_t>(SetUnhandledExceptionFilter), true, 0 }},
        {L"GetProcessId", { L"GetProcessId", reinterpret_cast<uintptr_t>(GetProcessId), true, 0 }},
        {L"GetThreadId", { L"GetThreadId", reinterpret_cast<uintptr_t>(GetThreadId), true, 0 }},
        {L"GetStartupInfoW", { L"GetStartupInfoW", reinterpret_cast<uintptr_t>(GetStartupInfoW), true, 0 }},
        {L"InitializeSListHead", { L"InitializeSListHead", reinterpret_cast<uintptr_t>(InitializeSListHead), true, 0 }},
        {L"InterlockedPushEntrySList", { L"InterlockedPushEntrySList", reinterpret_cast<uintptr_t>(InterlockedPushEntrySList), true, 0 }},
        {L"InterlockedPopEntrySList", { L"InterlockedPopEntrySList", reinterpret_cast<uintptr_t>(InterlockedPopEntrySList), true, 0 }},
        {L"InterlockedFlushSList", { L"InterlockedFlushSList", reinterpret_cast<uintptr_t>(InterlockedFlushSList), true, 0 }},
        {L"InterlockedPushListSList", { L"InterlockedPushListSList", reinterpret_cast<uintptr_t>(InterlockedPushListSList), true, 0 }},
        {L"RtlFirstEntrySList", { L"RtlFirstEntrySList", reinterpret_cast<uintptr_t>(RtlFirstEntrySList), true, 0 }},
        {L"QueryDepthSList", { L"QueryDepthSList", reinterpret_cast<uintptr_t>(QueryDepthSList), true, 0 }},
        {L"QueryPerformanceCounter", { L"QueryPerformanceCounter", reinterpret_cast<uintptr_t>(QueryPerformanceCounter), true, 0 }},
        {L"QueryPerformanceFrequency", { L"QueryPerformanceFrequency", reinterpret_cast<uintptr_t>(QueryPerformanceFrequency), true, 0 }},
        {L"GetSystemTimeAsFileTime", { L"GetSystemTimeAsFileTime", reinterpret_cast<uintptr_t>(GetSystemTimeAsFileTime), true, 0 }},
        {L"IsProcessorFeaturePresent", { L"IsProcessorFeaturePresent", reinterpret_cast<uintptr_t>(IsProcessorFeaturePresent), true, 0 }},
        {L"RtlUnwindEx", { L"RtlUnwindEx", reinterpret_cast<uintptr_t>(RtlUnwindEx), true, 0 }},
        {L"RtlUnwind", { L"RtlUnwind", reinterpret_cast<uintptr_t>(RtlUnwind), true, 0 }},
        {L"EncodePointer", { L"EncodePointer", reinterpret_cast<uintptr_t>(EncodePointer), true, 0 }},
        {L"DecodePointer", { L"DecodePointer", reinterpret_cast<uintptr_t>(DecodePointer), true, 0 }},
        {L"RtlPcToFileHeader", { L"RtlPcToFileHeader", reinterpret_cast<uintptr_t>(RtlPcToFileHeader), true, 0 }},
        {L"GetFreeDiskSpaceExW", { L"GetFreeDiskSpaceExW", reinterpret_cast<uintptr_t>(GetFreeDiskSpaceExW), true, 0 }},
        {L"GetFreeDiskSpaceW", { L"GetFreeDiskSpaceW", reinterpret_cast<uintptr_t>(GetFreeDiskSpaceW), true, 0 }},
        {L"GetCommandLineW", { L"GetCommandLineW", reinterpret_cast<uintptr_t>(GetCommandLineW), true, 0 }},
        {L"GetEnvironmentStringsW", { L"GetEnvironmentStringsW", reinterpret_cast<uintptr_t>(GetEnvironmentStringsW), true, 0 }},
        {L"FreeEnvironmentStringsW", { L"FreeEnvironmentStringsW", reinterpret_cast<uintptr_t>(FreeEnvironmentStringsW), true, 0 }},
        {L"SetEnvironmentVariableW", { L"SetEnvironmentVariableW", reinterpret_cast<uintptr_t>(SetEnvironmentVariableW), true, 0 }},
        {L"GetEnvironmentVariableW", { L"GetEnvironmentVariableW", reinterpret_cast<uintptr_t>(GetEnvironmentVariableW), true, 0 }},
        {L"GetStringTypeW", { L"GetStringTypeW", reinterpret_cast<uintptr_t>(GetStringTypeW), true, 0 }}
    };
}

void Kernel32::ExitProcess(UINT exit_code) {
    trace("ExitProcess implementation called. Arguments: exit_code=<UINT>[", exit_code, "]");
    std::exit(static_cast<int>(exit_code));
}

void Kernel32::SetLastError(DWORD error_code) {
    trace("SetLastError implementation called. Arguments: error_code=<DWORD>[", error_code, "]");
    tls.last_error = error_code;
    ret("Error set to: ", error_code, ", Return value: <VOID>[]");
}

DWORD Kernel32::GetLastError() {
    trace("GetLastError implementation called. Arguments:");
    ret("Error unset, Return Value: <DWORD>[", tls.last_error, "]");
    return tls.last_error;
}

void Kernel32::Sleep(DWORD milliseconds) {
    trace("Sleep implementation called. Arguments: milliseconds=<DWORD>[", milliseconds, "]");
    std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
    SetLastError(ERROR_SUCCESS);
    ret("Error set to: ERROR_SUCCESS, Return value: <VOID>[]");
}

DWORD Kernel32::GetTickCount() {
    trace("GetTickCount implementation called. Arguments:");
    SetLastError(ERROR_SUCCESS);
    ret("Error set to: ERROR_SUCCESS, Return value: <DWORD>[", static_cast<DWORD>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count()), "]");
    return static_cast<DWORD>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
}

ULONGLONG Kernel32::GetTickCount64() {
    trace("GetTickCount64 implementation called. Arguments:");
    SetLastError(ERROR_SUCCESS);
    ret("Error set to: ERROR_SUCCESS, Return value: <ULONGLONG>[", static_cast<ULONGLONG>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count()), "]");
    return static_cast<ULONGLONG>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
}

DWORD Kernel32::GetCurrentThreadId() {
    trace("GetCurrentThreadId implementation called. Arguments:");
    SetLastError(ERROR_SUCCESS);
    ret("Error set to: ERROR_SUCCESS, Return value: <DWORD>[", tls.thread, "]");
    return reinterpret_cast<uintptr_t>(tls.thread);
}

HANDLE Kernel32::CreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile) {
    char file_name[32768] = {};
    for (size_t i = 0; i < 32767 && lpFileName[i] != L'\0'; i++) {
        file_name[i] = lpFileName[i];
        file_name[i] = static_cast<char>(lpFileName[i]);
    }
    file_name[32767] = '\0';
    trace("CreateFileW implementation called. Arguments: lpFileName=<LPCWSTR>[", lpFileName,
          "], dwDesiredAccess=<DWORD>[", dwDesiredAccess, "], dwShareMode=<DWORD>[", dwShareMode,
          "], lpSecurityAttributes=<LPSECURITY_ATTRIBUTES>[", lpSecurityAttributes,
          "], dwCreationDisposition=<DWORD>[", dwCreationDisposition, "], dwFlagsAndAttributes=<DWORD>[",
          dwFlagsAndAttributes, "], hTemplateFile=<HANDLE>[", hTemplateFile, "]");

    int flags = 0;
    constexpr mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH; // 0666

    // Map desired access
    if (dwDesiredAccess & 0x80000000) { // GENERIC_READ
        flags |= O_RDONLY;
    }
    if (dwDesiredAccess & 0x40000000) { // GENERIC_WRITE
        flags |= O_WRONLY;
    }
    if (dwDesiredAccess & 0xC0000000) { // GENERIC_READ | GENERIC_WRITE
        flags |= O_RDWR;
    }

    // Map creation disposition
    switch (dwCreationDisposition) {
        case 1: // CREATE_NEW
            flags |= O_CREAT | O_EXCL;
            break;
        case 2: // CREATE_ALWAYS
            flags |= O_CREAT | O_TRUNC;
            break;
        case 3: // OPEN_EXISTING
            // No additional flags needed
            break;
        case 4: // OPEN_ALWAYS
            flags |= O_CREAT;
            break;
        case 5: // TRUNCATE_EXISTING
            flags |= O_TRUNC;
            break;
        default:
            warn("CreateFileW: Unknown creation disposition: ", dwCreationDisposition);
            SetLastError(ERROR_INVALID_PARAMETER);
            ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <HANDLE>[INVALID_HANDLE_VALUE]");
            return reinterpret_cast<HANDLE>(-1); // INVALID_HANDLE_VALUE
    }

    const int fd = open(file_name, flags, mode);
    if (fd == -1) {
        error("Failed to open file: ", strerror(errno));
        DWORD err;
        switch (errno) {
            case ENOENT:
                err = ERROR_FILE_NOT_FOUND;
                ret("Error set to: ERROR_FILE_NOT_FOUND, Return value: <HANDLE>[INVALID_HANDLE_VALUE]");
                break;
            case EACCES:
                err = ERROR_ACCESS_DENIED;
                ret("Error set to: ERROR_ACCESS_DENIED, Return value: <HANDLE>[INVALID_HANDLE_VALUE]");
                break;
            case EEXIST:
                err = ERROR_ALREADY_EXISTS;
                ret("Error set to: ERROR_ALREADY_EXISTS, Return value: <HANDLE>[INVALID_HANDLE_VALUE]");
                break;
            case EINVAL:
                err = ERROR_INVALID_PARAMETER;
                ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <HANDLE>[INVALID_HANDLE_VALUE]");
                break;
            default:
                err = ERROR_INVALID_FUNCTION; // Generic
                ret("Error set to: ERROR_INVALID_FUNCTION, Return value: <HANDLE>[INVALID_HANDLE_VALUE]");
                break;
        }
        SetLastError(err);
        return reinterpret_cast<HANDLE>(-1); // INVALID_HANDLE_VALUE
    }
    SetLastError(ERROR_SUCCESS);
    ret("Error set to: ERROR_SUCCESS, Return value: <HANDLE>[", reinterpret_cast<HANDLE>(fd), "]");
    process_info[tls.process].files[reinterpret_cast<HANDLE>(fd)] = fd;
    return reinterpret_cast<HANDLE>(fd);
}

BOOL Kernel32::ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead,
    LPOVERLAPPED lpOverlapped) {
    trace("ReadFile implementation called. Arguments: hFile=<HANDLE>[", hFile,
          "], lpBuffer=<LPVOID>[", lpBuffer, "], nNumberOfBytesToRead=<DWORD>[", nNumberOfBytesToRead,
          "], lpNumberOfBytesRead=<LPDWORD>[", lpNumberOfBytesRead, "], lpOverlapped=<LPOVERLAPPED>[", lpOverlapped, "]");
    if (!lpBuffer) {
        SetLastError(ERROR_INVALID_PARAMETER);
        ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <BOOL>[FALSE]");
        return FALSE;
    }

    const int fd = process_info[tls.process].files[hFile];
    const ssize_t bytes = ::read(fd, lpBuffer, static_cast<size_t>(nNumberOfBytesToRead));
    if (bytes == -1) {
        DWORD err;
        switch (errno) {
            case ENOENT:
                err = ERROR_FILE_NOT_FOUND;
                ret("Error set to: ERROR_FILE_NOT_FOUND, Return value: <HANDLE>[INVALID_HANDLE_VALUE]");
                break;
            case EACCES:
                err = ERROR_ACCESS_DENIED;
                ret("Error set to: ERROR_ACCESS_DENIED, Return value: <HANDLE>[INVALID_HANDLE_VALUE]");
                break;
            case EEXIST:
                err = ERROR_ALREADY_EXISTS;
                ret("Error set to: ERROR_ALREADY_EXISTS, Return value: <HANDLE>[INVALID_HANDLE_VALUE]");
                break;
            case EINVAL:
                err = ERROR_INVALID_PARAMETER;
                ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <HANDLE>[INVALID_HANDLE_VALUE]");
                break;
            default:
                err = ERROR_INVALID_FUNCTION; // Generic
                ret("Error set to: ERROR_INVALID_FUNCTION, Return value: <HANDLE>[INVALID_HANDLE_VALUE]");
                break;
        }
        SetLastError(err);
        return FALSE;
    }

    if (lpNumberOfBytesRead) {
        *lpNumberOfBytesRead = static_cast<DWORD>(bytes);
    }

    SetLastError(ERROR_SUCCESS);
    ret("Error set to: ERROR_SUCCESS, Return value: <BOOL>[TRUE], bytesRead=", static_cast<DWORD>(bytes));
    return TRUE;
}

BOOL Kernel32::WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite,
    LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) {
    trace("WriteFile implementation called. Arguments: hFile=<HANDLE>[", hFile,
          "], lpBuffer=<LPCVOID>[", lpBuffer, "], nNumberOfBytesToWrite=<DWORD>[", nNumberOfBytesToWrite,
          "], lpNumberOfBytesWritten=<LPDWORD>[", lpNumberOfBytesWritten, "], lpOverlapped=<LPOVERLAPPED>[", lpOverlapped, "]");
    if (!lpBuffer) {
        SetLastError(ERROR_INVALID_PARAMETER);
        ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <BOOL>[FALSE]");
        return FALSE;
    }

    const int fd = process_info[tls.process].files[hFile];
    const ssize_t bytes = ::write(fd, lpBuffer, static_cast<size_t>(nNumberOfBytesToWrite));
    if (bytes == -1) {
        DWORD err;
        switch (errno) {
            case ENOENT:
                err = ERROR_FILE_NOT_FOUND;
                ret("Error set to: ERROR_FILE_NOT_FOUND, Return value: <HANDLE>[INVALID_HANDLE_VALUE]");
                break;
            case EACCES:
                err = ERROR_ACCESS_DENIED;
                ret("Error set to: ERROR_ACCESS_DENIED, Return value: <HANDLE>[INVALID_HANDLE_VALUE]");
                break;
            case EEXIST:
                err = ERROR_ALREADY_EXISTS;
                ret("Error set to: ERROR_ALREADY_EXISTS, Return value: <HANDLE>[INVALID_HANDLE_VALUE]");
                break;
            case EINVAL:
                err = ERROR_INVALID_PARAMETER;
                ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <HANDLE>[INVALID_HANDLE_VALUE]");
                break;
            default:
                err = ERROR_INVALID_FUNCTION; // Generic
                ret("Error set to: ERROR_INVALID_FUNCTION, Return value: <HANDLE>[INVALID_HANDLE_VALUE]");
                break;
        }
        SetLastError(err);
        return FALSE;
    }

    if (lpNumberOfBytesWritten) {
        *lpNumberOfBytesWritten = static_cast<DWORD>(bytes);
    }

    SetLastError(ERROR_SUCCESS);
    ret("Error set to: ERROR_SUCCESS, Return value: <BOOL>[TRUE], bytesWritten=", static_cast<DWORD>(bytes));
    return TRUE;
}

BOOL Kernel32::DeleteFileW(LPCWSTR lpFileName) {
    char file_name[32768] = {};
    for (size_t i = 0; i < 32767 && lpFileName[i] != L'\0'; i++) {
        file_name[i] = static_cast<char>(lpFileName[i]);
    }
    file_name[32767] = '\0';
    trace("DeleteFileW implementation called. Arguments: lpFileName=<LPCWSTR>[", lpFileName, "]");

    if (file_name[0] == '\0') {
        SetLastError(ERROR_INVALID_PARAMETER);
        ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <BOOL>[FALSE]");
        return FALSE;
    }

    if (remove(file_name) != 0) {
        DWORD err;
        switch (errno) {
            case ENOENT:
                err = ERROR_FILE_NOT_FOUND;
                break;
            case EACCES:
                err = ERROR_ACCESS_DENIED;
                break;
            case EEXIST:
                err = ERROR_ALREADY_EXISTS;
                break;
            case EINVAL:
                err = ERROR_INVALID_PARAMETER;
                break;
            default:
                err = ERROR_INVALID_FUNCTION; // Generic
                break;
        }
        tls.last_error = err;
        ret("Error set to: ", err, ", Return value: <BOOL>[FALSE]");
        return FALSE;
    }

    SetLastError(ERROR_SUCCESS);
    ret("Error set to: ERROR_SUCCESS, Return value: <BOOL>[TRUE]");
    return TRUE;
}

BOOL Kernel32::CloseHandle(HANDLE hObject) {
    trace("CloseHandle implementation called. Arguments: hObject=<HANDLE>[", hObject, "]");
    if (const auto handle = reinterpret_cast<ULONG_PTR>(hObject); handle > process_info.size()) {
        SetLastError(ERROR_INVALID_HANDLE);
        ret("Error set to: ERROR_INVALID_HANDLE, Return value: <BOOL>[FALSE]");
        return FALSE;
    }

    // check if is a process handle
    if (process_info.contains(hObject)) {
        // kill all the threads
        for (const auto &thread: process_info[hObject].threads | std::views::values) {
            pthread_kill(thread.thread, SIGKILL);
        }
        // then kill the processes thread
        pthread_kill(process_info[hObject].process_thread, SIGKILL);
        process_info.erase(hObject);
        SetLastError(ERROR_SUCCESS);
        ret("Error set to: ERROR_SUCCESS, Return value: <BOOL>[TRUE]");
        return TRUE;
    }
    // check if it is a thread handle
    if (process_info[tls.process].threads.contains(hObject)) {
        pthread_kill(process_info[tls.process].threads[hObject].thread, SIGKILL);
        process_info[tls.process].threads.erase(hObject);
        SetLastError(ERROR_SUCCESS);
        ret("Error set to: ERROR_SUCCESS, Return value: <BOOL>[TRUE]");
        return TRUE;
    }

    // file handles
    if (process_info[tls.process].files.contains(hObject)) {
        close(process_info[tls.process].files[hObject]);
        process_info[tls.process].files.erase(hObject);
        SetLastError(ERROR_SUCCESS);
        ret("Error set to: ERROR_SUCCESS, Return value: <BOOL>[TRUE]");
        return TRUE;
    }

    // find handles
    if (process_info[tls.process].finds.contains(hObject)) {
        process_info[tls.process].finds.erase(hObject);
        SetLastError(ERROR_SUCCESS);
        ret("Error set to: ERROR_SUCCESS, Return value: <BOOL>[TRUE]");
        return TRUE;
    }

    // registry handles
    if (process_info[tls.process].registry_key_handles.contains(hObject)) {
        process_info[tls.process].registry_key_handles.erase(hObject);
        SetLastError(ERROR_SUCCESS);
        ret("Error set to: ERROR_SUCCESS, Return value: <BOOL>[TRUE]");
        return TRUE;
    }

    // module handles
    if (process_info[tls.process].modules.contains(hObject)) {
        process_info[tls.process].modules.erase(hObject);
        SetLastError(ERROR_SUCCESS);
        ret("Error set to: ERROR_SUCCESS, Return value: <BOOL>[TRUE]");
        return TRUE;
    }

    // event handles
    if (process_info[tls.process].events.contains(hObject)) {
        process_info[tls.process].events.erase(hObject);
        SetLastError(ERROR_SUCCESS);
        ret("Error set to: ERROR_SUCCESS, Return value: <BOOL>[TRUE]");
        return TRUE;
    }

    // semaphores
    if (process_info[tls.process].semaphores.contains(hObject)) {
        sem_destroy(&process_info[tls.process].semaphores[hObject]);
        process_info[tls.process].semaphores.erase(hObject);
        SetLastError(ERROR_SUCCESS);
        ret("Error set to: ERROR_SUCCESS, Return value: <BOOL>[TRUE]");
        return TRUE;
    }

    // mutexes
    if (process_info[tls.process].mutexes.contains(hObject)) {
        process_info[tls.process].mutexes.erase(hObject);
        SetLastError(ERROR_SUCCESS);
        ret("Error set to: ERROR_SUCCESS, Return value: <BOOL>[TRUE]");
        return TRUE;
    }

    SetLastError(ERROR_INVALID_HANDLE);
    ret("Error set to: ERROR_INVALID_HANDLE, Return value: <BOOL>[FALSE]");
    return FALSE;
}

DWORD Kernel32::WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds) {
    trace("WaitForSingleObject implementation called. Arguments: hHandle=<HANDLE>[", hHandle, "], dwMilliseconds=<DWORD>[", dwMilliseconds, "]");

    const auto timeout = (dwMilliseconds == INFINITE) ? -1 : static_cast<int>(dwMilliseconds);
    const auto timeout_time = (timeout == -1) ? std::chrono::steady_clock::time_point::max() : std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout);
    // process handles
    if (process_info.contains(hHandle)) {
        if (process_info[hHandle].process_thread) {
            if (timeout == -1) {
                pthread_join(process_info[hHandle].process_thread, nullptr);
                SetLastError(ERROR_SUCCESS);
                ret("Error set to: ERROR_SUCCESS, Return value: <DWORD>[WAIT_OBJECT_0]");
                return WAIT_OBJECT_0;
            }
            while (std::chrono::steady_clock::now() < timeout_time) {
                // Check if the thread is still alive
                if (pthread_kill(process_info[hHandle].process_thread, 0) != 0) {
                    SetLastError(ERROR_SUCCESS);
                    ret("Error set to: ERROR_SUCCESS, Return value: <DWORD>[WAIT_OBJECT_0]");
                    return WAIT_OBJECT_0;
                }
                Sleep(10); // Sleep for a short while before checking again
            }
            SetLastError(ERROR_SUCCESS);
            ret("Error set to: ERROR_SUCCESS, Return value: <DWORD>[WAIT_TIMEOUT]");
            return WAIT_TIMEOUT;
        } else {
            SetLastError(ERROR_INVALID_HANDLE);
            ret("Error set to: ERROR_INVALID_HANDLE, Return value: <DWORD>[WAIT_FAILED]");
            return WAIT_FAILED;
        }
    }
    // thread handles
    if (process_info[tls.process].threads.contains(hHandle)) {
        if (process_info[tls.process].threads[hHandle].thread) {
            if (timeout == -1) {
                pthread_join(process_info[tls.process].threads[hHandle].thread, nullptr);
                SetLastError(ERROR_SUCCESS);
                ret("Error set to: ERROR_SUCCESS, Return value: <DWORD>[", WAIT_OBJECT_0, "]");
                return WAIT_OBJECT_0;
            }
            while (std::chrono::steady_clock::now() < timeout_time) {
                // Check if the thread is still alive
                if (pthread_kill(process_info[tls.process].threads[hHandle].thread, 0) != 0) {
                    SetLastError(ERROR_SUCCESS);
                    ret("Error set to: ERROR_SUCCESS, Return value: <DWORD>[WAIT_OBJECT_0]");
                    return WAIT_OBJECT_0;
                }
                Sleep(10); // Sleep for a short while before checking again
            }
            SetLastError(ERROR_SUCCESS);
            ret("Error set to: ERROR_SUCCESS, Return value: <DWORD>[", WAIT_TIMEOUT, "]");
            return WAIT_TIMEOUT;
        }
        SetLastError(ERROR_INVALID_HANDLE);
        ret("Error set to: ERROR_INVALID_HANDLE, Return value: <DWORD>[WAIT_FAILED]");
        return WAIT_FAILED;
    }

    // event handles
    if (process_info[tls.process].events.contains(hHandle)) {
        Event &event = process_info[tls.process].events[hHandle];
        if (timeout == -1) {
            event.wait();
            SetLastError(ERROR_SUCCESS);
            ret("Error set to: ERROR_SUCCESS, Return value: <DWORD>[WAIT_OBJECT_0]");
            return WAIT_OBJECT_0;
        }
        while (std::chrono::steady_clock::now() < timeout_time) {
            if (event.is_set()) {
                SetLastError(ERROR_SUCCESS);
                ret("Error set to: ERROR_SUCCESS, Return value: <DWORD>[WAIT_OBJECT_0]");
                return WAIT_OBJECT_0;
            }
            Sleep(10); // Sleep for a short while before checking again
        }
        SetLastError(ERROR_SUCCESS);
        ret("Error set to: ERROR_SUCCESS, Return value: <DWORD>[", WAIT_TIMEOUT, "]");
        return WAIT_TIMEOUT;
    }

    // semaphore handles
    if (process_info[tls.process].semaphores.contains(hHandle)) {
        sem_t &sem = process_info[tls.process].semaphores[hHandle];
        if (timeout == -1) {
            while (sem_wait(&sem) == -1 && errno == EINTR) {}
            SetLastError(ERROR_SUCCESS);
            ret("Error set to: ERROR_SUCCESS, Return value: <DWORD>[WAIT_OBJECT_0]");
            return WAIT_OBJECT_0;
        }
        timespec ts{};
        if (clock_gettime(CLOCK_REALTIME, &ts) == -1) {
            SetLastError(ERROR_INVALID_FUNCTION);
            ret("Error set to: ERROR_INVALID_FUNCTION, Return value: <DWORD>[WAIT_FAILED]");
            return WAIT_FAILED;
        }
        ts.tv_sec += timeout / 1000;
        ts.tv_nsec += (timeout % 1000) * 1000000;
        if (ts.tv_nsec >= 1000000000) {
            ts.tv_sec += ts.tv_nsec / 1000000000;
            ts.tv_nsec = ts.tv_nsec % 1000000000;
        }
        while (sem_timedwait(&sem, &ts) == -1) {
            if (errno == ETIMEDOUT) {
                SetLastError(ERROR_SUCCESS);
                ret("Error set to: ERROR_SUCCESS, Return value: <DWORD>[", WAIT_TIMEOUT, "]");
                return WAIT_TIMEOUT;
            }
            if (errno != EINTR) {
                SetLastError(ERROR_INVALID_FUNCTION);
                ret("Error set to: ERROR_INVALID_FUNCTION, Return value: <DWORD>[WAIT_FAILED]");
                return WAIT_FAILED;
            }
        }
        SetLastError(ERROR_SUCCESS);
        ret("Error set to: ERROR_SUCCESS, Return value: <DWORD>[WAIT_OBJECT_0]");
        return WAIT_OBJECT_0;
    }

    // mutex handles
    if (process_info[tls.process].mutexes.contains(hHandle)) {
        std::mutex &mtx = process_info[tls.process].mutexes[hHandle];
        if (timeout == -1) {
            mtx.lock();
            SetLastError(ERROR_SUCCESS);
            ret("Error set to: ERROR_SUCCESS, Return value: <DWORD>[WAIT_OBJECT_0]");
            return WAIT_OBJECT_0;
        } else {
            while (std::chrono::steady_clock::now() < timeout_time) {
                if (mtx.try_lock()) {
                    SetLastError(ERROR_SUCCESS);
                    ret("Error set to: ERROR_SUCCESS, Return value: <DWORD>[WAIT_OBJECT_0]");
                    return WAIT_OBJECT_0;
                }
                Sleep(10); // Sleep for a short while before checking again
            }
            SetLastError(ERROR_SUCCESS);
            ret("Error set to: ERROR_SUCCESS, Return value: <DWORD>[", WAIT_TIMEOUT, "]");
            return WAIT_TIMEOUT;
        }
    }

    // else is invalid
    SetLastError(ERROR_INVALID_HANDLE);
    ret("Error set to: ERROR_INVALID_HANDLE, Return value: <DWORD>[WAIT_FAILED]");
    return WAIT_FAILED;
}

DWORD Kernel32::WaitForSingleObjectEx(HANDLE hHandle, DWORD dwMilliseconds, BOOL bAlertable) {
    trace("WaitForSingleObjectEx implementation called. Arguments: hHandle=<HANDLE>[", hHandle, "], dwMilliseconds=<DWORD>[", dwMilliseconds, "], bAlertable=<BOOL>[", bAlertable, "]");
    if (bAlertable) {
        // basically the same as WaitForSingleObject but with checks of apc queue
        // process handles
        if (process_info.contains(hHandle)) {
            if (process_info[hHandle].process_thread) {
                const auto now = std::chrono::steady_clock::now();
                if (dwMilliseconds == INFINITE) {
                    pthread_join(process_info[hHandle].process_thread, nullptr);
                    SetLastError(ERROR_SUCCESS);
                    ret("Error set to: ERROR_SUCCESS, Return value: <DWORD>[WAIT_OBJECT_0]");
                    return WAIT_OBJECT_0;
                }
                const auto timeout_time = now + std::chrono::milliseconds(dwMilliseconds);
                while (std::chrono::steady_clock::now() < timeout_time) {
                    // Check if the thread is still alive
                    if (pthread_kill(process_info[hHandle].process_thread, 0) != 0) {
                        SetLastError(ERROR_SUCCESS);
                        ret("Error set to: ERROR_SUCCESS, Return value: <DWORD>[WAIT_OBJECT_0]");
                        return WAIT_OBJECT_0;
                    }
                    // Check and execute APCs
                    if (!process_info[hHandle].apc_queues[tls.thread].empty()) {
                        process_info[hHandle].apc_queues[tls.thread].front()();
                        process_info[hHandle].apc_queues[tls.thread].erase(process_info[hHandle].apc_queues[tls.thread].begin());
                        return WAIT_IO_COMPLETION;
                    }
                    Sleep(10); // Sleep for a short while before checking again
                }
                SetLastError(ERROR_SUCCESS);
                ret("Error set to: ERROR_SUCCESS, Return value: <DWORD>[WAIT_TIMEOUT]");
                return WAIT_TIMEOUT;
            } else {
                SetLastError(ERROR_INVALID_HANDLE);
                ret("Error set to: ERROR_INVALID_HANDLE, Return value: <DWORD>[WAIT_FAILED]");
                return WAIT_FAILED;
            }
        }

    }
    return WaitForSingleObject(hHandle, dwMilliseconds);
}

DWORD Kernel32::WaitForMultipleObjects(DWORD nCount, const HANDLE *lpHandles, BOOL bWaitAll,
    DWORD dwMilliseconds) {
    trace("WaitForMultipleObjects implementation called. Arguments: nCount=<DWORD>[", nCount,
          "], lpHandles=<const HANDLE*>[", lpHandles, "], bWaitAll=<BOOL>[", bWaitAll,
          "], dwMilliseconds=<DWORD>[", dwMilliseconds, "]");

    if (nCount == 0 || !lpHandles) {
        SetLastError(ERROR_INVALID_PARAMETER);
        ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <DWORD>[WAIT_FAILED]");
        return WAIT_FAILED;
    }

    if (nCount > MAXIMUM_WAIT_OBJECTS) {
        SetLastError(ERROR_INVALID_PARAMETER);
        ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <DWORD>[WAIT_FAILED]");
        return WAIT_FAILED;
    }

    const auto timeout = (dwMilliseconds == INFINITE) ? -1 : static_cast<int>(dwMilliseconds);
    const auto timeout_time = (timeout == -1) ? std::chrono::steady_clock::time_point::max() : std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout);

    if (bWaitAll) {
        // Wait for all handles
        for (DWORD i = 0; i < nCount; ++i) {
            if (const DWORD result = WaitForSingleObject(lpHandles[i], dwMilliseconds); result != WAIT_OBJECT_0) {
                SetLastError(ERROR_SUCCESS);
                ret("Error set to: ERROR_SUCCESS, Return value: <DWORD>[", result, "]");
                return result;
            }
        }
        SetLastError(ERROR_SUCCESS);
        ret("Error set to: ERROR_SUCCESS, Return value: <DWORD>[WAIT_OBJECT_0]");
        return WAIT_OBJECT_0;
    }
    // Wait for any handle
    if (timeout == -1) {
        for (DWORD i = 0; i < nCount; ++i) {
            if (const DWORD result = WaitForSingleObject(lpHandles[i], 0); result == WAIT_OBJECT_0) {
                SetLastError(ERROR_SUCCESS);
                ret("Error set to: ERROR_SUCCESS, Return value: <DWORD>[", WAIT_OBJECT_0 + i, "]");
                return WAIT_OBJECT_0 + i;
            } else if (result == WAIT_FAILED) {
                SetLastError(ERROR_SUCCESS);
                ret("Error set to: ERROR_SUCCESS, Return value: <DWORD>[WAIT_FAILED]");
                return WAIT_FAILED;
            }
        }
    }
    else {
        while (std::chrono::steady_clock::now() < timeout_time) {
            for (DWORD i = 0; i < nCount; ++i) {
                if (const DWORD result = WaitForSingleObject(lpHandles[i], 0); result == WAIT_OBJECT_0) {
                    SetLastError(ERROR_SUCCESS);
                    ret("Error set to: ERROR_SUCCESS, Return value: <DWORD>[", WAIT_OBJECT_0 + i, "]");
                    return WAIT_OBJECT_0 + i;
                } else if (result == WAIT_FAILED) {
                    SetLastError(ERROR_SUCCESS);
                    ret("Error set to: ERROR_SUCCESS, Return value: <DWORD>[WAIT_FAILED]");
                    return WAIT_FAILED;
                }
            }
            Sleep(10); // Sleep for a short while before checking again
            SetLastError(ERROR_SUCCESS);
            ret("Error set to: ERROR_SUCCESS, Return value: <DWORD>[WAIT_TIMEOUT]");
            return WAIT_TIMEOUT;
        }
    }
    SetLastError(ERROR_SUCCESS);
    ret("Error set to: ERROR_SUCCESS, Return value: <DWORD>[WAIT_FAILED]");
    return WAIT_FAILED;
}

DWORD Kernel32::WaitForMultipleObjectsEx(DWORD nCount, const HANDLE *lpHandles, BOOL bWaitAll,
    DWORD dwMilliseconds, BOOL bAlertable) {
    trace("WaitForMultipleObjectsEx implementation called. Arguments: nCount=<DWORD>[", nCount,
          "], lpHandles=<const HANDLE*>[", lpHandles, "], bWaitAll=<BOOL>[", bWaitAll,
          "], dwMilliseconds=<DWORD>[", dwMilliseconds, "], bAlertable=<BOOL>[", bAlertable, "]");
    if (bAlertable) {
        // basically the same as WaitForMultipleObjects but with checks of apc queue
        if (nCount == 0 || !lpHandles) {
            SetLastError(ERROR_INVALID_PARAMETER);
            ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <DWORD>[WAIT_FAILED]");
            return WAIT_FAILED;
        }

        if (nCount > MAXIMUM_WAIT_OBJECTS) {
            SetLastError(ERROR_INVALID_PARAMETER);
            ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <DWORD>[WAIT_FAILED]");
        }
        const auto timeout = (dwMilliseconds == INFINITE) ? -1 : static_cast<int>(dwMilliseconds);
        const auto timeout_time = (timeout == -1) ? std::chrono::steady_clock::time_point::max() : std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout);
        if (bWaitAll) {
            // Wait for all handles
            for (DWORD i = 0; i < nCount; ++i) {
                if (const DWORD result = WaitForSingleObjectEx(lpHandles[i], dwMilliseconds, bAlertable); result != WAIT_OBJECT_0) {
                    SetLastError(ERROR_SUCCESS);
                    ret("Error set to: ERROR_SUCCESS, Return value: <DWORD>[", result, "]");
                    return result;
                }
            }
            SetLastError(ERROR_SUCCESS);
        }
        // Wait for any handle
        if (timeout == -1) {
            while (true) {
                for (DWORD i = 0; i < nCount; ++i) {
                    if (const DWORD result = WaitForSingleObjectEx(lpHandles[i], 0, bAlertable); result == WAIT_OBJECT_0) {
                        SetLastError(ERROR_SUCCESS);
                        ret("Error set to: ERROR_SUCCESS, Return value: <DWORD>[", WAIT_OBJECT_0 + i, "]");
                        return WAIT_OBJECT_0 + i;
                    } else if (result == WAIT_FAILED) {
                        SetLastError(ERROR_SUCCESS);
                        ret("Error set to: ERROR_SUCCESS, Return value: <DWORD>[WAIT_FAILED]");
                        return WAIT_FAILED;
                    } else if (result == WAIT_IO_COMPLETION) {
                        return WAIT_IO_COMPLETION;
                    }
                }
            }
        }
        while (std::chrono::steady_clock::now() < timeout_time) {
            for (DWORD i = 0; i < nCount; ++i) {
                if (const DWORD result = WaitForSingleObjectEx(lpHandles[i], 0, bAlertable); result == WAIT_OBJECT_0) {
                    SetLastError(ERROR_SUCCESS);
                    ret("Error set to: ERROR_SUCCESS, Return value: <DWORD>[", WAIT_OBJECT_0 + i, "]");
                    return WAIT_OBJECT_0 + i;
                } else if (result == WAIT_FAILED) {
                    SetLastError(ERROR_SUCCESS);
                    ret("Error set to: ERROR_SUCCESS, Return value: <DWORD>[WAIT_FAILED]");
                }
            }
        }
        SetLastError(ERROR_SUCCESS);
        ret("Error set to: ERROR_SUCCESS, Return value: <DWORD>[WAIT_FAILED]");
        return WAIT_FAILED;
    }
    return WaitForMultipleObjects(nCount, lpHandles, bWaitAll, dwMilliseconds);
}

BOOL Kernel32::QueueUserAPC(PAPCFUNC pfnAPC, HANDLE hThread, ULONG_PTR dwData) {
    trace("QueueUserAPC implementation called. Arguments: pfnAPC=<PAPCFUNC>[", pfnAPC,
          "], hThread=<HANDLE>[", hThread, "], dwData=<ULONG_PTR>[", dwData, "]");

    if (!pfnAPC || !hThread) {
        SetLastError(ERROR_INVALID_PARAMETER);
        ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <BOOL>[FALSE]");
        return FALSE;
    }

    if (!process_info[tls.process].threads.contains(hThread)) {
        SetLastError(ERROR_INVALID_HANDLE);
        ret("Error set to: ERROR_INVALID_HANDLE, Return value: <BOOL>[FALSE]");
        return FALSE;
    }

    process_info[tls.process].apc_queues[hThread].emplace_back([pfnAPC, dwData]() {
        pfnAPC(dwData);
    });

    SetLastError(ERROR_SUCCESS);
    ret("Error set to: ERROR_SUCCESS, Return value: <BOOL>[TRUE]");
    return TRUE;
}

DWORD Kernel32::GetFileSize(HANDLE hFile, LPDWORD lpFileSizeHigh) {
    trace("GetFileSize implementation called. Arguments: hFile=<HANDLE>[", hFile,
          "], lpFileSizeHigh=<LPDWORD>[", lpFileSizeHigh, "]");
    if (!process_info[tls.process].files.contains(hFile)) {
        SetLastError(ERROR_INVALID_HANDLE);
        ret("Error set to: ERROR_INVALID_HANDLE, Return value: <DWORD>[INVALID_FILE_SIZE]");
        return INVALID_FILE_SIZE;

    }

    const int fd = process_info[tls.process].files[hFile];
    struct stat st{};
    if (fstat(fd, &st) == -1) {
        SetLastError(ERROR_INVALID_FUNCTION);
        ret("Error set to: ERROR_INVALID_FUNCTION, Return value: <DWORD>[INVALID_FILE_SIZE]");
        return INVALID_FILE_SIZE;
    }

    DWORD fileSizeLow = st.st_size & 0xFFFFFFFF;
    DWORD fileSizeHigh = (st.st_size >> 32) & 0xFFFFFFFF;
    if (lpFileSizeHigh) {
        *lpFileSizeHigh = fileSizeHigh;
    }
    SetLastError(ERROR_SUCCESS);
    ret("Error set to: ERROR_SUCCESS, Return value: <DWORD>[", fileSizeLow, "]");
    return fileSizeLow;
}

DWORD Kernel32::SetFilePointer(HANDLE hFile, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh,
    DWORD dwMoveMethod) {
    trace("SetFilePointer implementation called. Arguments: hFile=<HANDLE>[", hFile,
          "], lDistanceToMove=<LONG>[", lDistanceToMove, "], lpDistanceToMoveHigh=<PLONG>[", lpDistanceToMoveHigh,
          "], dwMoveMethod=<DWORD>[", dwMoveMethod, "]");

    if (!process_info[tls.process].files.contains(hFile)) {
        SetLastError(ERROR_INVALID_HANDLE);
        ret("Error set to: ERROR_INVALID_HANDLE, Return value: <DWORD>[INVALID_FILE_SIZE]");
        return INVALID_FILE_SIZE;
    }

    int fd = process_info[tls.process].files[hFile];
    off_t offset = lDistanceToMove;
    if (lpDistanceToMoveHigh) {
        offset |= (static_cast<off_t>(*lpDistanceToMoveHigh) << 32);
    }

    int whence;
    switch (dwMoveMethod) {
        case FILE_BEGIN:
            whence = SEEK_SET;
            break;
        case FILE_CURRENT:
            whence = SEEK_CUR;
            break;
        case FILE_END:
            whence = SEEK_END;
            break;
        default:
            SetLastError(ERROR_INVALID_PARAMETER);
            ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <DWORD>[INVALID_FILE_SIZE]");
            return INVALID_FILE_SIZE;
    }

    off_t result = lseek(fd, offset, whence);
    if (result == static_cast<off_t>(-1)) {
        SetLastError(ERROR_INVALID_FUNCTION);
        ret("Error set to: ERROR_INVALID_FUNCTION, Return value: <DWORD>[INVALID_FILE_SIZE]");
        return INVALID_FILE_SIZE;
    }

    if (lpDistanceToMoveHigh) {
        *lpDistanceToMoveHigh = static_cast<LONG>((result >> 32) & 0xFFFFFFFF);
    }

    SetLastError(ERROR_SUCCESS);
    ret("Error set to: ERROR_SUCCESS, Return value: <DWORD>[", static_cast<DWORD>(result & 0xFFFFFFFF), "]");
    return static_cast<DWORD>(result & 0xFFFFFFFF);
}

DWORD Kernel32::SetFilePointerEx(HANDLE hFile, LARGE_INTEGER liDistanceToMove, PLARGE_INTEGER lpNewFilePointer,
    DWORD dwMoveMethod) {
    trace("SetFilePointerEx implementation called. Arguments: hFile=<HANDLE>[", hFile,
          "], liDistanceToMove=<LARGE_INTEGER>[", liDistanceToMove.QuadPart, "], lpNewFilePointer=<PLARGE_INTEGER>[", lpNewFilePointer,
          "], dwMoveMethod=<DWORD>[", dwMoveMethod, "]");

    if (!process_info[tls.process].files.contains(hFile)) {
        SetLastError(ERROR_INVALID_HANDLE);
        ret("Error set to: ERROR_INVALID_HANDLE, Return value: <DWORD>[INVALID_FILE_SIZE]");
        return INVALID_FILE_SIZE;
    }
    int fd = process_info[tls.process].files[hFile];
    off_t offset = liDistanceToMove.QuadPart;
    int whence;
    switch (dwMoveMethod) {
        case FILE_BEGIN:
            whence = SEEK_SET;
            break;
        case FILE_CURRENT:
            whence = SEEK_CUR;
            break;
        case FILE_END:
            whence = SEEK_END;
        default:
            SetLastError(ERROR_INVALID_PARAMETER);
            ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <DWORD>[INVALID_FILE_SIZE]");
            return INVALID_FILE_SIZE;
    }
    off_t result = lseek(fd, offset, whence);
    if (result == static_cast<off_t>(-1)) {
        SetLastError(ERROR_INVALID_FUNCTION);
        ret("Error set to: ERROR_INVALID_FUNCTION, Return value: <DWORD>[INVALID_FILE_SIZE]");
        return INVALID_FILE_SIZE;
    }
    if (lpNewFilePointer) {
        lpNewFilePointer->QuadPart = result;
    }
    SetLastError(ERROR_SUCCESS);
    ret("Error set to: ERROR_SUCCESS, Return value: <DWORD>[", static_cast<DWORD>(result & 0xFFFFFFFF), "]");
    return static_cast<DWORD>(result & 0xFFFFFFFF);
}

BOOL Kernel32::FlushFileBuffers(HANDLE hFile) {
    trace("FlushFileBuffers implementation called. Arguments: hFile=<HANDLE>[", hFile, "]");
    if (!process_info[tls.process].files.contains(hFile)) {
        SetLastError(ERROR_INVALID_HANDLE);
        ret("Error set to: ERROR_INVALID_HANDLE, Return value: <DWORD>[INVALID_FILE_SIZE]");
        return FALSE;
    }
    int fd = process_info[tls.process].files[hFile];
    if (fsync(fd) == -1) {
        SetLastError(ERROR_INVALID_FUNCTION);
        ret("Error set to: ERROR_INVALID_FUNCTION, Return value: <DWORD>[INVALID_FILE_SIZE]");
        return FALSE;
    }
    SetLastError(ERROR_SUCCESS);
    ret("Error set to: ERROR_SUCCESS, Return value: <DWORD>[0]");
    return TRUE;
}

INT Kernel32::WideCharToMultiByte(UINT CodePage, DWORD dwFlags, LPCWCH lpWideCharStr, int cchWideChar,
    LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar) {
    trace("WideCharToMultiByte implementation called. Arguments: CodePage=<UINT>[", CodePage,
          "], dwFlags=<DWORD>[", dwFlags, "], lpWideCharStr=<LPCWCH>[", lpWideCharStr,
          "], cchWideChar=<int>[", cchWideChar, "], lpMultiByteStr=<LPSTR>[", lpMultiByteStr,
          "], cbMultiByte=<int>[", cbMultiByte, "], lpDefaultChar=<LPCCH>[", lpDefaultChar,
          "], lpUsedDefaultChar=<LPBOOL>[", lpUsedDefaultChar, "]");

    if (!lpWideCharStr) {
        SetLastError(ERROR_INVALID_PARAMETER);
        ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <INT>[-1]");
        return -1;
    }

    const int required_size = static_cast<int>(UCRTBase::wcstombs_(nullptr, lpWideCharStr, 0));
    if (required_size == -1) {
        SetLastError(ERROR_INVALID_PARAMETER);
        ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <INT>[-1]");
        return -1;
    }

    if (cbMultiByte == 0) {
        SetLastError(ERROR_SUCCESS);
        ret("Error set to: ERROR_SUCCESS, Return value: <INT>[", required_size + 1, "]");
        return required_size + 1; // +1 for null terminator
    }

    if (!lpMultiByteStr || cbMultiByte < required_size + 1) {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        ret("Error set to: ERROR_INSUFFICIENT_BUFFER, Return value: <INT>[-1]");
        return -1;
    }

    int converted_size = static_cast<int>(UCRTBase::wcstombs_(lpMultiByteStr, lpWideCharStr, cbMultiByte));
    if (converted_size == -1) {
        SetLastError(ERROR_INVALID_PARAMETER);
        ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <INT>[-1]");
        return -1;
    }

    if (lpUsedDefaultChar) {
        *lpUsedDefaultChar = FALSE; // Not tracking default char usage
    }
    SetLastError(ERROR_SUCCESS);
    ret("Error set to: ERROR_SUCCESS, Return value: <INT>[", converted_size, "]");
    return converted_size;
}

INT Kernel32::MultiByteToWideChar(UINT CodePage, DWORD dwFlags, LPCCH lpMultiByteStr, int cbMultiByte,
    LPWSTR lpWideCharStr, int cchWideChar) {
    trace("MultiByteToWideChar implementation called. Arguments: CodePage=<UINT>[", CodePage,
          "], dwFlags=<DWORD>[", dwFlags, "], lpMultiByteStr=<LPCCH>[", lpMultiByteStr,
          "], cbMultiByte=<int>[", cbMultiByte, "], lpWideCharStr=<LPWSTR>[", lpWideCharStr,
          "], cchWideChar=<int>[", cchWideChar, "]");

    if (!lpMultiByteStr) {
        SetLastError(ERROR_INVALID_PARAMETER);
        ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <INT>[-1]");
        return -1;
    }

    const int required_size = static_cast<int>(std::mbstowcs(nullptr, lpMultiByteStr, 0));
    if (required_size == -1) {
        SetLastError(ERROR_INVALID_PARAMETER);
        ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <INT>[-1]");
        return -1;
    }

    if (cchWideChar == 0) {
        SetLastError(ERROR_SUCCESS);
        ret("Error set to: ERROR_SUCCESS, Return value: <INT>[", required_size + 1, "]");
        return required_size + 1; // +1 for null terminator
    }

    if (!lpWideCharStr || cchWideChar < required_size + 1) {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        ret("Error set to: ERROR_INSUFFICIENT_BUFFER, Return value: <INT>[-1]");
        return -1;
    }

    const int converted_size = static_cast<int>(UCRTBase::mbstowcs_(lpWideCharStr, lpMultiByteStr, cchWideChar));
    if (converted_size == -1) {
        SetLastError(ERROR_INVALID_PARAMETER);
        ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <INT>[-1]");
        return -1;
    }

    SetLastError(ERROR_SUCCESS);
    ret("Error set to: ERROR_SUCCESS, Return value: <INT>[", converted_size, "]");
    return converted_size;
}

bool Kernel32::match_pattern(const std::string &filename, const std::string &pattern, bool case_sensitive) {
    std::string test_filename = filename;
    std::string test_pattern = pattern;

    if (!case_sensitive) {
        std::ranges::transform(test_filename, test_filename.begin(), ::tolower);
        std::ranges::transform(test_pattern, test_pattern.begin(), ::tolower);
    }

    size_t fi = 0, pi = 0;
    const size_t fn = test_filename.length();
    const size_t pn = test_pattern.length();

    if (pn == 0) return fn == 0;

    std::vector<std::pair<size_t, size_t>> star_stack;

    while (fi < fn || pi < pn) {
        if (pi < pn && test_pattern[pi] == '*') {
            while (pi < pn && test_pattern[pi] == '*') pi++;
            if (pi == pn) return true;
            star_stack.emplace_back(fi, pi);
            continue;
        }

        if (fi < fn && pi < pn && (test_pattern[pi] == '?' || test_pattern[pi] == test_filename[fi])) {
            fi++;
            pi++;
            continue;
        }

        if (!star_stack.empty()) {
            auto [saved_fi, saved_pi] = star_stack.back();
            star_stack.pop_back();
            fi = saved_fi + 1;
            pi = saved_pi;
            star_stack.emplace_back(fi, pi);
            continue;
        }

        return false;
    }

    while (pi < pn && test_pattern[pi] == '*') pi++;
    return pi == pn;
}

DWORD Kernel32::get_windows_attributes(const struct stat &file_stat, const std::string &filename) {
    DWORD attrs = 0;

    if (S_ISDIR(file_stat.st_mode)) {
        attrs |= FILE_ATTRIBUTE_DIRECTORY;
    } else {
        attrs |= FILE_ATTRIBUTE_NORMAL;
    }

    if (!filename.empty() && filename[0] == '.' && filename != "." && filename != "..") {
        attrs |= FILE_ATTRIBUTE_HIDDEN;
    }

    if (!(file_stat.st_mode & S_IWUSR)) {
        attrs |= FILE_ATTRIBUTE_READONLY;
    }

    return attrs;
}

FILETIME Kernel32::unix_to_filetime(time_t unix_time) {
    FILETIME ft{};
    constexpr uint64_t EPOCH_DIFF = 116444736000000000ULL;
    const uint64_t file_time = (static_cast<uint64_t>(unix_time) * 10000000ULL) + EPOCH_DIFF;

    ft.dwLowDateTime = static_cast<DWORD>(file_time & 0xFFFFFFFF);
    ft.dwHighDateTime = static_cast<DWORD>((file_time >> 32) & 0xFFFFFFFF);
    return ft;
}

bool Kernel32::fill_find_data(WIN32_FIND_DATAW *find_data, const std::string &filename,
    const std::string &full_path, bool basic_info) {
    struct stat file_stat{};
    if (stat(full_path.c_str(), &file_stat) != 0) {
        return false;
    }

    memset(find_data, 0, sizeof(WIN32_FIND_DATAW));

    for (size_t i = 0; i < filename.length() && i < MAX_PATH - 1; ++i) {
        find_data->cFileName[i] = static_cast<_wchar_t>(filename[i]);
    }
    find_data->cFileName[MAX_PATH - 1] = L'\0';

    find_data->dwFileAttributes = get_windows_attributes(file_stat, filename);

    find_data->nFileSizeLow = static_cast<DWORD>(file_stat.st_size & 0xFFFFFFFF);
    find_data->nFileSizeHigh = static_cast<DWORD>((file_stat.st_size >> 32) & 0xFFFFFFFF);

    find_data->ftCreationTime = unix_to_filetime(file_stat.st_ctime);
    find_data->ftLastAccessTime = unix_to_filetime(file_stat.st_atime);
    find_data->ftLastWriteTime = unix_to_filetime(file_stat.st_mtime);

    if (basic_info) {
        find_data->cAlternateFileName[0] = L'\0';
    }

    return true;
}

HANDLE Kernel32::FindFirstFileW(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData) {
    trace("FindFirstFileW implementation called. Arguments: lpFileName=<LPCWSTR>[", lpFileName,
          "], lpFindFileData=<LPWIN32_FIND_DATAW>[", lpFindFileData, "]");

    if (!lpFileName || !lpFindFileData) {
        SetLastError(ERROR_INVALID_PARAMETER);
        ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <HANDLE>[INVALID_HANDLE_VALUE]");
        return INVALID_HANDLE_VALUE;
    }

    const std::string search_pattern('0', UCRTBase::wcslen_(lpFileName));

    std::string directory;
    std::string pattern;

    if (const size_t last_sep = search_pattern.find_last_of("/\\"); last_sep != std::string::npos) {
        directory = search_pattern.substr(0, last_sep);
        pattern = search_pattern.substr(last_sep + 1);
    } else {
        directory = ".";
        pattern = search_pattern;
    }

    if (directory.empty()) {
        directory = ".";
    }

    const auto find_state = std::make_unique<FindState>(directory, pattern);
    find_state->dir_handle = opendir(directory.c_str());

    if (!find_state->dir_handle) {
        DWORD err;
        switch (errno) {
            case ENOENT:
                err = ERROR_PATH_NOT_FOUND;
                break;
            case EACCES:
                err = ERROR_ACCESS_DENIED;
                break;
            case ENOTDIR:
                err = ERROR_DIRECTORY;
                break;
            default:
                err = ERROR_INVALID_FUNCTION;
                break;
        }
        SetLastError(err);
        ret("Error set to: ", err, ", Return value: <HANDLE>[INVALID_HANDLE_VALUE]");
        return INVALID_HANDLE_VALUE;
    }

    dirent* entry;
    while ((entry = readdir(find_state->dir_handle)) != nullptr) {
        std::string filename = entry->d_name;

        if ((filename == "." || filename == "..") &&
            pattern != "." && pattern != ".." && pattern != "*") {
            continue;
        }

        if (!match_pattern(filename, pattern)) {
            continue;
        }

        if (std::string full_path = directory.append("/").append(filename); fill_find_data(lpFindFileData, filename, full_path)) {
            HANDLE find_handle = next_handle;
            next_handle = static_cast<HANDLE>(static_cast<char*>(next_handle) + 1);

            // Store a placeholder FindState in process_info to mark the handle as valid
            process_info[tls.process].finds[find_handle] = std::move(*find_state);

            SetLastError(ERROR_SUCCESS);
            ret("Error set to: ERROR_SUCCESS, Return value: <HANDLE>[", find_handle, "]");
            return find_handle;
        }
    }

    SetLastError(ERROR_FILE_NOT_FOUND);
    ret("Error set to: ERROR_FILE_NOT_FOUND, Return value: <HANDLE>[INVALID_HANDLE_VALUE]");
    return INVALID_HANDLE_VALUE;
}

HANDLE Kernel32::FindFirstFileExW(LPCWSTR lpFileName, FINDEX_INFO_LEVELS fInfoLevelId, LPVOID lpFindFileData,
    FINDEX_SEARCH_OPS fSearchOp, LPVOID lpSearchFilter, DWORD dwAdditionalFlags) {
    trace("FindFirstFileExW implementation called. Arguments: lpFileName=<LPCWSTR>[", lpFileName,
          "], fInfoLevelId=<FINDEX_INFO_LEVELS>[", static_cast<int>(fInfoLevelId), "], lpFindFileData=<LPVOID>[", lpFindFileData,
          "], fSearchOp=<FINDEX_SEARCH_OPS>[", static_cast<int>(fSearchOp), "], lpSearchFilter=<LPVOID>[", lpSearchFilter,
          "], dwAdditionalFlags=<DWORD>[", dwAdditionalFlags, "]");

    if (!lpFileName || !lpFindFileData) {
        SetLastError(ERROR_INVALID_PARAMETER);
        ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <HANDLE>[INVALID_HANDLE_VALUE]");
        return INVALID_HANDLE_VALUE;
    }

    if (fInfoLevelId != FindExInfoStandard && fInfoLevelId != FindExInfoBasic) {
        SetLastError(ERROR_INVALID_PARAMETER);
        ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <HANDLE>[INVALID_HANDLE_VALUE]");
        return INVALID_HANDLE_VALUE;
    }

    if (fSearchOp != FindExSearchNameMatch &&
        fSearchOp != FindExSearchLimitToDirectories &&
        fSearchOp != FindExSearchLimitToDevices) {
        SetLastError(ERROR_INVALID_PARAMETER);
        ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <HANDLE>[INVALID_HANDLE_VALUE]");
        return INVALID_HANDLE_VALUE;
    }

    if (fSearchOp == FindExSearchNameMatch && lpSearchFilter != nullptr) {
        SetLastError(ERROR_INVALID_PARAMETER);
        ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <HANDLE>[INVALID_HANDLE_VALUE]");
        return INVALID_HANDLE_VALUE;
    }

    if (constexpr DWORD validFlags = FIND_FIRST_EX_CASE_SENSITIVE | FIND_FIRST_EX_LARGE_FETCH; dwAdditionalFlags & ~validFlags) {
        SetLastError(ERROR_INVALID_PARAMETER);
        ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <HANDLE>[INVALID_HANDLE_VALUE]");
        return INVALID_HANDLE_VALUE;
    }

    std::string search_pattern('0', UCRTBase::wcslen_(lpFileName));

    for (size_t i = 0; i < search_pattern.size(); ++i) {
        search_pattern[i] = static_cast<char>(lpFileName[i]);
    }

    std::string directory;
    std::string pattern;

    if (size_t last_sep = search_pattern.find_last_of("/\\"); last_sep != std::string::npos) {
        directory = search_pattern.substr(0, last_sep);
        pattern = search_pattern.substr(last_sep + 1);
    } else {
        directory = ".";
        pattern = search_pattern;
    }

    if (directory.empty()) {
        directory = ".";
    }

    auto find_state = std::make_unique<FindState>(directory, pattern);
    find_state->dir_handle = opendir(directory.c_str());

    if (!find_state->dir_handle) {
        DWORD err;
        switch (errno) {
            case ENOENT:
                err = ERROR_PATH_NOT_FOUND;
                break;
            case EACCES:
                err = ERROR_ACCESS_DENIED;
                break;
            case ENOTDIR:
                err = ERROR_DIRECTORY;
                break;
            default:
                err = ERROR_INVALID_FUNCTION;
                break;
        }
        SetLastError(err);
        ret("Error set to: ", err, ", Return value: <HANDLE>[INVALID_HANDLE_VALUE]");
        return INVALID_HANDLE_VALUE;
    }

    bool case_sensitive = (dwAdditionalFlags & FIND_FIRST_EX_CASE_SENSITIVE) != 0;

    struct dirent* entry;
    while ((entry = readdir(find_state->dir_handle)) != nullptr) {
        std::string filename = entry->d_name;

        if ((filename == "." || filename == "..") &&
            pattern != "." && pattern != ".." && pattern != "*") {
            continue;
        }

        if (!match_pattern(filename, pattern, case_sensitive)) {
            continue;
        }

        std::string full_path = directory.append("/").append(filename);
        struct stat file_stat{};
        if (stat(full_path.c_str(), &file_stat) != 0) {
            continue;
        }

        if (fSearchOp == FindExSearchLimitToDirectories && !S_ISDIR(file_stat.st_mode)) {
            continue;
        }

        if (fSearchOp == FindExSearchLimitToDevices && !S_ISCHR(file_stat.st_mode) && !S_ISBLK(file_stat.st_mode)) {
            continue;
        }

        auto* find_data = static_cast<WIN32_FIND_DATAW*>(lpFindFileData);

        if (const bool basic_info = (fInfoLevelId == FindExInfoBasic); fill_find_data(find_data, filename, full_path, basic_info)) {
            HANDLE find_handle = next_handle;

            process_info[tls.process].finds[find_handle] = FindState("", "");

            static std::unordered_map<HANDLE, std::unique_ptr<FindState>> global_find_states;
            global_find_states[find_handle] = std::move(find_state);

            SetLastError(ERROR_SUCCESS);
            ret("Error set to: ERROR_SUCCESS, Return value: <HANDLE>[", find_handle, "]");
            next_handle = static_cast<void*>(static_cast<char*>(next_handle) + 1); // Increment handle. C++ standard forces us to do this *unique* cast.
            return find_handle;
        }
    }

    SetLastError(ERROR_FILE_NOT_FOUND);
    ret("Error set to: ERROR_FILE_NOT_FOUND, Return value: <HANDLE>[INVALID_HANDLE_VALUE]");
    return INVALID_HANDLE_VALUE;
}

BOOL Kernel32::FindNextFileW(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData) {
    trace("FindNextFileW implementation called. Arguments: hFindFile=<HANDLE>[", hFindFile,
          "], lpFindFileData=<LPWIN32_FIND_DATAW>[", lpFindFileData, "]");

    if (!lpFindFileData) {
        SetLastError(ERROR_INVALID_PARAMETER);
        ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <BOOL>[FALSE]");
        return FALSE;
    }

    if (!process_info[tls.process].finds.contains(hFindFile)) {
        SetLastError(ERROR_INVALID_HANDLE);
        ret("Error set to: ERROR_INVALID_HANDLE, Return value: <BOOL>[FALSE]");
        return FALSE;
    }

    static std::unordered_map<HANDLE, std::unique_ptr<FindState>> global_find_states;
    auto it = global_find_states.find(hFindFile);
    if (it == global_find_states.end()) {
        SetLastError(ERROR_INVALID_HANDLE);
        ret("Error set to: ERROR_INVALID_HANDLE, Return value: <BOOL>[FALSE]");
        return FALSE;
    }

    FindState* find_state = it->second.get();
    if (!find_state->dir_handle) {
        SetLastError(ERROR_INVALID_HANDLE);
        ret("Error set to: ERROR_INVALID_HANDLE, Return value: <BOOL>[FALSE]");
        return FALSE;
    }

    struct dirent* entry;
    while ((entry = readdir(find_state->dir_handle)) != nullptr) {
        std::string filename = entry->d_name;

        if ((filename == "." || filename == "..") &&
            find_state->search_pattern != "." &&
            find_state->search_pattern != ".." &&
            find_state->search_pattern != "*") {
            continue;
        }

        if (!match_pattern(filename, find_state->search_pattern)) {
            continue;
        }

        std::string full_path = find_state->directory_path + "/" + filename;

        if (fill_find_data(lpFindFileData, filename, full_path)) {
            SetLastError(ERROR_SUCCESS);
            ret("Error set to: ERROR_SUCCESS, Return value: <BOOL>[TRUE]");
            return TRUE;
        }
    }

    SetLastError(ERROR_NO_MORE_FILES);
    ret("Error set to: ERROR_NO_MORE_FILES, Return value: <BOOL>[FALSE]");
    return FALSE;
}

BOOL Kernel32::FindClose(HANDLE hFindFile) {
    trace("FindClose implementation called. Arguments: hFindFile=<HANDLE>[", hFindFile, "]");

    if (!process_info[tls.process].finds.contains(hFindFile)) {
        SetLastError(ERROR_INVALID_HANDLE);
        ret("Error set to: ERROR_INVALID_HANDLE, Return value: <BOOL>[FALSE]");
        return FALSE;
    }

    static std::unordered_map<HANDLE, std::unique_ptr<FindState>> global_find_states;
    if (const auto it = global_find_states.find(hFindFile); it != global_find_states.end()) {
        global_find_states.erase(it);
    }

    process_info[tls.process].finds.erase(hFindFile);

    SetLastError(ERROR_SUCCESS);
    ret("Error set to: ERROR_SUCCESS, Return value: <BOOL>[TRUE]");
    return TRUE;
}

LPCWSTR Kernel32::GetCommandLineW() {
    trace("GetCommandLineW implementation called. No arguments.");
    return process_info[tls.process].cmdline_w;
}

HANDLE Kernel32::GetCurrentProcess() {
    trace("GetCurrentProcess implementation called. No arguments.");
    return reinterpret_cast<HANDLE>(-1); // Pseudo-handle for the current process
}

HMODULE Kernel32::GetModuleHandleW(LPCWSTR lpModuleName) {
    trace("GetModuleHandleW implementation called. Arguments: lpModuleName=<LPCWSTR>[", lpModuleName, "]");

    if (!lpModuleName) {
        // means current module
        SetLastError(ERROR_SUCCESS);
        ret("Error set to: ERROR_SUCCESS, Return value: <HMODULE>[", process_info[tls.process].process_hmodule, "]");
        return process_info[tls.process].process_hmodule;
    }

    std::string module_name('0', UCRTBase::wcslen_(lpModuleName));
    for (size_t i = 0; i < module_name.size(); ++i) {
        module_name[i] = tolower(static_cast<char>(lpModuleName[i]));
    }
    for (const auto& [hmodule, mod_info] : process_info[tls.process].modules) {
        std::string loaded_name = mod_info.name;
        std::ranges::transform(loaded_name, loaded_name.begin(), ::tolower);
        if (loaded_name == module_name) {
            SetLastError(ERROR_SUCCESS);
            ret("Error set to: ERROR_SUCCESS, Return value: <HMODULE>[", hmodule, "]");
            return hmodule;
        }
    }

    SetLastError(ERROR_MOD_NOT_FOUND);
    ret("Error set to: ERROR_MOD_NOT_FOUND, Return value: <HMODULE>[NULL]");
    return nullptr;
}

HMODULE Kernel32::LoadLibraryW(LPCWSTR lpLibFileName) {
    trace("LoadLibraryW implementation called. Arguments: lpLibFileName=<LPCWSTR>[", lpLibFileName, "]");

    if (!lpLibFileName) {
        SetLastError(ERROR_INVALID_PARAMETER);
        ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <HMODULE>[NULL]");
        return nullptr;
    }

    std::string lib_name('0', UCRTBase::wcslen_(lpLibFileName));
    for (size_t i = 0; i < lib_name.size(); ++i) {
        lib_name[i] = tolower(static_cast<char>(lpLibFileName[i]));
    }

    // Check if already loaded
    for (const auto& [hmodule, mod_info] : process_info[tls.process].modules) {
        std::string loaded_name = mod_info.name;
        std::ranges::transform(loaded_name, loaded_name.begin(), ::tolower);
        if (loaded_name == lib_name) {
            SetLastError(ERROR_SUCCESS);
            ret("Error set to: ERROR_SUCCESS, Return value: <HMODULE>[", hmodule, "] (already loaded)");
            return hmodule;
        }
    }

    // Try to find the library file
    std::filesystem::path lib_path;
    std::vector<std::filesystem::path> search_paths = {
        std::filesystem::current_path(),
        std::filesystem::current_path() / "System32",
        std::filesystem::current_path() / "SysWOW64",
        "/usr/lib",
        "/usr/local/lib",
        "/lib"
    };

    // Search for the library
    for (const auto& search_path : search_paths) {
        std::vector<std::string> name_variations = {
            lib_name,
            lib_name + ".DLL",
            lib_name.substr(0, lib_name.find_last_of('.')) + ".so",
            "lib" + lib_name.substr(0, lib_name.find_last_of('.')) + ".so"
        };

        for (const auto& variation : name_variations) {
            if (auto candidate = search_path / variation; std::filesystem::exists(candidate)) {
                lib_path = candidate;
                break;
            }
        }
        if (!lib_path.empty()) break;
    }

    if (lib_path.empty()) {
        SetLastError(ERROR_MOD_NOT_FOUND);
        ret("Error set to: ERROR_MOD_NOT_FOUND, Return value: <HMODULE>[NULL]");
        return nullptr;
    }

    try {
        // Parse the PE file
        auto pe_binary = LIEF::PE::Parser::parse(lib_path.string());
        if (!pe_binary) {
            // Not a PE file, fail
            SetLastError(ERROR_INVALID_EXE_SIGNATURE);
            ret("Error set to: ERROR_INVALID_EXE_SIGNATURE, Return value: <HMODULE>[NULL]");
            return nullptr;
        }

        // Allocate memory for the module
        size_t size = pe_binary->optional_header().sizeof_image();
        if (size < 4096) size = 4096;

        void* mem = mmap(nullptr, size, PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (mem == MAP_FAILED) {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            ret("Error set to: ERROR_NOT_ENOUGH_MEMORY, Return value: <HMODULE>[NULL]");
            return nullptr;
        }

        auto base_addr = reinterpret_cast<uintptr_t>(mem);
        memset(mem, 0, size);

        // Map sections
        for (const auto& section : pe_binary->sections()) {
            uint32_t sect_rva = section.virtual_address();
            auto raw_data = section.content();

            if (sect_rva + raw_data.size() <= size) {
                memcpy(reinterpret_cast<void*>(base_addr + sect_rva),
                       raw_data.data(), raw_data.size());
            }
        }

        // Create module info
        auto hModule = reinterpret_cast<HMODULE>(base_addr);
        ProcessModuleInfo mod_info;
        strncpy(mod_info.name, lib_name.c_str(), sizeof(mod_info.name) - 1);
        strncpy(mod_info.path, lib_path.string().c_str(), sizeof(mod_info.path) - 1);
        mod_info.base_address = base_addr;
        mod_info.size = size;

        // Extract exports
        if (pe_binary->has_exports()) {
            for (const auto& export_dir = pe_binary->get_export();
                 const auto& entry : export_dir->entries()) {
                if (!entry.name().empty()) {
                    mod_info.exports[entry.name()] = reinterpret_cast<HMODULE>(
                        base_addr + static_cast<uintptr_t>(entry.address()));
                }
            }
        }

        process_info[tls.process].modules[hModule] = mod_info;

        // Call DllMain if it's a DLL
        if ((pe_binary->header().characteristics() & 0x2000) != 0) {
            if (uint32_t entry_rva = pe_binary->optional_header().addressof_entrypoint(); entry_rva != 0) {
                try {
                    typedef BOOL (*DllMainProc)(HMODULE, DWORD, LPVOID);
                    auto dll_main = reinterpret_cast<DllMainProc>(base_addr + entry_rva);
                    dll_main(hModule, DLL_PROCESS_ATTACH, nullptr); // Changed to DLL_PROCESS_ATTACH for clarity
                } catch (const std::exception& e) {
                    warn("DllMain failed for " + lib_name + ": " + e.what());
                }
            }
        }

        SetLastError(ERROR_SUCCESS);
        ret("Error set to: ERROR_SUCCESS, Return value: <HMODULE>[", hModule, "]");
        return hModule;

    } catch (const std::exception& e) {
        error("LoadLibraryW failed: " + std::string(e.what()));
        SetLastError(ERROR_INVALID_FUNCTION);
        ret("Error set to: ERROR_INVALID_FUNCTION, Return value: <HMODULE>[NULL]");
        return nullptr;
    }
}

FARPROC Kernel32::GetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
    trace("GetProcAddress implementation called. Arguments: hModule=<HMODULE>[", hModule,
          "], lpProcName=<LPCSTR>[", lpProcName, "]");

    if (!hModule) {
        hModule = process_info[tls.process].process_hmodule; // Use main module
    }

    if (!lpProcName) {
        SetLastError(ERROR_INVALID_PARAMETER);
        ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <FARPROC>[NULL]");
        return nullptr;
    }

    std::string proc_name;

    // Check if lpProcName is an ordinal (high word is zero)
    if (reinterpret_cast<uintptr_t>(lpProcName) <= 0xFFFF) {
        const auto ordinal = static_cast<uint16_t>(reinterpret_cast<uintptr_t>(lpProcName));
        proc_name = "Ordinal_" + std::to_string(ordinal);
    } else {
        proc_name = lpProcName;
    }

    // Check emulated APIs first
    std::wstring wproc_name('0', strlen(lpProcName));
    for (size_t i = 0; i < wproc_name.size(); ++i) {
        wproc_name[i] = static_cast<wchar_t>(lpProcName[i]);
    }
    if (auto kernel32_exports = get_exports_detailed(); kernel32_exports.contains(wproc_name)) {
        SetLastError(ERROR_SUCCESS);
        ret("Error set to: ERROR_SUCCESS, Return value: <FARPROC>[", kernel32_exports[wproc_name].address, "] (emulated)");
        return reinterpret_cast<FARPROC>(kernel32_exports[wproc_name].address);
    }

    // Check loaded modules
    if (process_info[tls.process].modules.contains(hModule)) {
        if (const auto& mod_info = process_info[tls.process].modules[hModule]; mod_info.exports.contains(proc_name)) {
            SetLastError(ERROR_SUCCESS);
            ret("Error set to: ERROR_SUCCESS, Return value: <FARPROC>[",
                mod_info.exports.at(proc_name), "]");
            return reinterpret_cast<FARPROC>(mod_info.exports.at(proc_name));
        }
    }

    SetLastError(ERROR_PROC_NOT_FOUND);
    ret("Error set to: ERROR_PROC_NOT_FOUND, Return value: <FARPROC>[NULL]");
    return nullptr;
}

BOOL Kernel32::FreeLibrary(HMODULE hLibModule) {
    trace("FreeLibrary implementation called. Arguments: hLibModule=<HMODULE>[", hLibModule, "]");

    if (!hLibModule) {
        SetLastError(ERROR_INVALID_PARAMETER);
        ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <BOOL>[FALSE]");
        return FALSE;
    }

    // Check if the module is loaded
    if (!process_info[tls.process].modules.contains(hLibModule)) {
        SetLastError(ERROR_INVALID_HANDLE);
        ret("Error set to: ERROR_INVALID_HANDLE, Return value: <BOOL>[FALSE]");
        return FALSE;
    }

    try {
        const auto& mod_info = process_info[tls.process].modules[hLibModule];

        // Call DllMain with DLL_PROCESS_DETACH if it's a DLL
        // This is a simplified version - real implementation would need to track entry points

        // Unmap memory if it was mapped
        if (mod_info.base_address != 0 &&
            mod_info.base_address == reinterpret_cast<uintptr_t>(hLibModule)) {
            // Try to unmap - this might fail if memory wasn't mapped with mmap
            munmap(reinterpret_cast<void*>(mod_info.base_address), mod_info.size);
        }

        // Remove from loaded modules
        process_info[tls.process].modules.erase(hLibModule);

        SetLastError(ERROR_SUCCESS);
        ret("Error set to: ERROR_SUCCESS, Return value: <BOOL>[TRUE]");
        return TRUE;

    } catch (const std::exception& e) {
        error("FreeLibrary failed: " + std::string(e.what()));
        SetLastError(ERROR_INVALID_FUNCTION);
        ret("Error set to: ERROR_INVALID_FUNCTION, Return value: <BOOL>[FALSE]");
        return FALSE;
    }
}

DWORD Kernel32::GetModuleFileNameW(HMODULE hModule, LPWSTR lpFilename, DWORD nSize) {
    trace("GetModuleFileNameW implementation called. Arguments: hModule=<HMODULE>[", hModule,
          "], lpFilename=<LPWSTR>[", lpFilename, "], nSize=<DWORD>[", nSize, "]");

    if (!lpFilename || nSize == 0) {
        SetLastError(ERROR_INVALID_PARAMETER);
        ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <DWORD>[0]");
        return 0;
    }

    if (!hModule) {
        hModule = process_info[tls.process].process_hmodule;
    }

    if (!process_info[tls.process].modules.contains(hModule)) {
        SetLastError(ERROR_INVALID_HANDLE);
        ret("Error set to: ERROR_INVALID_HANDLE, Return value: <DWORD>[0]");
        return 0;
    }

    const auto& mod_info = process_info[tls.process].modules[hModule];
    _wchar_t path_w[32767];
    for (size_t i = 0; i < sizeof(mod_info.path) && mod_info.path[i] != '\0'; ++i) {
        path_w[i] = static_cast<wchar_t>(mod_info.path[i]);
    }

    if (UCRTBase::wcslen_(path_w) >= nSize) {
        // Buffer too small
        UCRTBase::wcsncpy_(lpFilename, path_w, nSize - 1);
        lpFilename[nSize - 1] = L'\0';
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        ret("Error set to: ERROR_INSUFFICIENT_BUFFER, Return value: <DWORD>[", nSize - 1, "]");
        return nSize - 1;
    } else {
        UCRTBase::wcscpy_(lpFilename, path_w);
        SetLastError(ERROR_SUCCESS);
        ret("Error set to: ERROR_SUCCESS, Return value: <DWORD>[", UCRTBase::wcslen_(path_w), "]");
        return static_cast<DWORD>(UCRTBase::wcslen_(path_w));
    }
}

BOOL Kernel32::SetEnvironmentVariableW(LPCWSTR lpName, LPCWSTR lpValue) {
    trace("SetEnvironmentVariableW implementation called. Arguments: lpName=<LPCWSTR>[", lpName,
          "], lpValue=<LPCWSTR>[", lpValue, "]");

    constexpr _wchar_t dummy[] = { '=', '\0' };

    if (!lpName || UCRTBase::wcslen_(lpName) == 0 || UCRTBase::wcscmp_(lpName, dummy) == 0) {
        SetLastError(ERROR_INVALID_PARAMETER);
        ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <BOOL>[FALSE]");
        return FALSE;
    }

    std::wstring name_w(L'0', UCRTBase::wcslen_(lpName));
    for (size_t i = 0; i < name_w.size(); ++i) {
        name_w[i] = lpName[i];
    }
    std::string name(name_w.begin(), name_w.end());

    if (lpValue) {
        std::wstring value_w(L'0', UCRTBase::wcslen_(lpValue));
        for (size_t i = 0; i < value_w.size(); ++i) {
            value_w[i] = lpValue[i];
        }
        const std::string value(value_w.begin(), value_w.end());
        //environment[name] = value;
        environment_vector.emplace_back(name + "=" + value);
        environment_vector_w.emplace_back(name_w + L"=" + value_w);
        trace("Environment variable set: ", std::wstring(name.begin(), name.end()));
    } else {
        //environment.erase(name);
        std::erase_if(environment_vector,
                      [&name](const std::string& env) {
                          return env.substr(0, env.find('=')) == name;
                      });
        std::erase_if(environment_vector_w,
                      [&name_w](const std::wstring& env) {
                          return env.substr(0, env.find(L'=')) == name_w;
                      });
        trace("Environment variable removed: ", name_w);
    }

    SetLastError(ERROR_SUCCESS);
    ret("Error set to: ERROR_SUCCESS, Return value: <BOOL>[TRUE]");
    return TRUE;
}

DWORD Kernel32::GetEnvironmentVariableW(LPCWSTR lpName, LPWSTR lpBuffer, DWORD nSize) {
    trace("GetEnvironmentVariableW implementation called. Arguments: lpName=<LPCWSTR>[", lpName,
          "], lpBuffer=<LPWSTR>[", lpBuffer, "], nSize=<DWORD>[", nSize, "]");

    _wchar_t dummy[] = { '=', '\0' };

    if (!lpName || UCRTBase::wcslen_(lpName) == 0 || UCRTBase::wcscmp_(lpName, dummy) == 0) {
        SetLastError(ERROR_INVALID_PARAMETER);
        ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <DWORD>[0]");
        return 0;
    }

    std::wstring name_w(L'0', UCRTBase::wcslen_(lpName));
    for (size_t i = 0; i < name_w.size(); ++i) {
        name_w[i] = lpName[i];
    }
    const std::string name(name_w.begin(), name_w.end());

    if (std::ranges::find_if(environment_vector,
                             [&name](const std::string& env) {
                                 return env.substr(0, env.find('=')) == name;
                             }) == environment_vector.end()) {
        SetLastError(ERROR_ENVVAR_NOT_FOUND);
        ret("Error set to: ERROR_ENVVAR_NOT_FOUND, Return value: <DWORD>[0]");
        return 0;
    }

    const std::string& value = environment_vector.at(
        std::ranges::find_if(environment_vector,
                             [&name](const std::string& env) {
                                 return env.substr(0, env.find('=')) == name;
                             }) - environment_vector.begin()
    ).substr(name.length() + 1); // +1 to skip '='
    const std::wstring value_w(value.begin(), value.end());
    const size_t required_size = value_w.length();

    if (nSize == 0) {
        SetLastError(ERROR_SUCCESS);
        ret("Error set to: ERROR_SUCCESS, Return value: <DWORD>[", required_size, "] (buffer size query)");
        return required_size;
    }
    if (nSize <= required_size) {
        if (nSize > 0) {
            //UCRTBase::wcsncpy_(lpBuffer, value_w.c_str(), nSize - 1);
            for (size_t i = 0; i < nSize - 1; ++i) {
                lpBuffer[i] = value_w[i];
            }
            lpBuffer[nSize - 1] = L'\0';
        }
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        ret("Error set to: ERROR_INSUFFICIENT_BUFFER, Return value: <DWORD>[", required_size, "]");
        return required_size;
    }
    for (size_t i = 0; i < value_w.length(); ++i) {
        lpBuffer[i] = value_w[i];
    }
    lpBuffer[value_w.length()] = L'\0';
    SetLastError(ERROR_SUCCESS);
    ret("Error set to: ERROR_SUCCESS, Return value: <DWORD>[", required_size, "]");
    return required_size;
}

void Kernel32::InitializeCriticalSection(LPCRITICAL_SECTION lpCriticalSection) {
    trace("InitializeCriticalSection implementation called. Arguments: lpCriticalSection=<CRITICAL_SECTION*>[", lpCriticalSection, "]");
    ret("Return value: <void>");
}

void Kernel32::
InitializeCriticalSectionEx(LPCRITICAL_SECTION lpCriticalSection, DWORD dwSpinCount, DWORD Flags) {
    trace("InitializeCriticalSectionEx implementation called. Arguments: lpCriticalSection=<CRITICAL_SECTION*>[", lpCriticalSection,
          "], dwSpinCount=<DWORD>[", dwSpinCount, "], Flags=<DWORD>[", Flags, "]");
    ret("Return value: <void>");
}

void Kernel32::InitializeCriticalSectionAndSpinCount(LPCRITICAL_SECTION lpCriticalSection, DWORD dwSpinCount) {
    trace("InitializeCriticalSectionAndSpinCount implementation called. Arguments: lpCriticalSection=<CRITICAL_SECTION*>[", lpCriticalSection,
          "], dwSpinCount=<DWORD>[", dwSpinCount, "]");
    ret("Return value: <void>");
}

void Kernel32::EnterCriticalSection(LPCRITICAL_SECTION lpCriticalSection) {
    trace("EnterCriticalSection implementation called. Arguments: lpCriticalSection=<CRITICAL_SECTION*>[", lpCriticalSection, "]");
    lpCriticalSection->enter();
    ret("Return value: <void>");
}

BOOL Kernel32::TryEnterCriticalSection(LPCRITICAL_SECTION lpCriticalSection) {
    trace("TryEnterCriticalSection implementation called. Arguments: lpCriticalSection=<CRITICAL_SECTION*>[", lpCriticalSection, "]");
    const BOOL result = lpCriticalSection->try_enter() ? TRUE : FALSE;
    ret("Return value: <BOOL>[", result, "]");
    return result;
}

void Kernel32::LeaveCriticalSection(LPCRITICAL_SECTION lpCriticalSection) {
    trace("LeaveCriticalSection implementation called. Arguments: lpCriticalSection=<CRITICAL_SECTION*>[", lpCriticalSection, "]");
    lpCriticalSection->leave();
    ret("Return value: <void>");
}

void Kernel32::DeleteCriticalSection(LPCRITICAL_SECTION lpCriticalSection) {
    trace("DeleteCriticalSection implementation called. Arguments: lpCriticalSection=<CRITICAL_SECTION*>[", lpCriticalSection, "]");
    lpCriticalSection->remove();
    ret("Return value: <void>");
}

UINT Kernel32::SetErrorMode(UINT uMode) {
    trace("SetErrorMode diserror-stub called. Arguments: uMode=<UINT>[", uMode, "]");
    return 0;
}

UINT Kernel32::GetErrorMode() {
    trace("GetErrorMode diserror-stub called.");
    return 0;
}

HANDLE Kernel32::CreateEventW(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState,
    LPCWSTR lpName) {
    trace("CreateEventW implementation called. Arguments: lpEventAttributes=<LPSECURITY_ATTRIBUTES>[", lpEventAttributes,
          "], bManualReset=<BOOL>[", bManualReset, "], bInitialState=<BOOL>[", bInitialState,
          "], lpName=<LPCWSTR>[", lpName, "]");

    Event new_event;
    new_event.manual_reset_ = (bManualReset != FALSE);
    if (bInitialState) {
        new_event.set();
    }
    HANDLE event_handle = next_handle;
    next_handle = static_cast<HANDLE>(static_cast<char*>(next_handle) + 1);
    process_info[tls.process].events[event_handle] = std::move(new_event);
    SetLastError(ERROR_SUCCESS);
    ret("Error set to: ERROR_SUCCESS, Return value: <HANDLE>[", event_handle, "]");
    return event_handle;
}

BOOL Kernel32::SetEvent(HANDLE hEvent) {
    trace("SetEvent implementation called. Arguments: hEvent=<HANDLE>[", hEvent, "]");

    if (!process_info[tls.process].events.contains(hEvent)) {
        SetLastError(ERROR_INVALID_HANDLE);
        ret("Error set to: ERROR_INVALID_HANDLE, Return value: <BOOL>[FALSE]");
        return FALSE;
    }

    process_info[tls.process].events[hEvent].set();
    SetLastError(ERROR_SUCCESS);
    ret("Error set to: ERROR_SUCCESS, Return value: <BOOL>[TRUE]");
    return TRUE;
}

BOOL Kernel32::ResetEvent(HANDLE hEvent) {
    trace("ResetEvent implementation called. Arguments: hEvent=<HANDLE>[", hEvent, "]");

    if (!process_info[tls.process].events.contains(hEvent)) {
        SetLastError(ERROR_INVALID_HANDLE);
        ret("Error set to: ERROR_INVALID_HANDLE, Return value: <BOOL>[FALSE]");
        return FALSE;
    }

    process_info[tls.process].events[hEvent].clear();
    SetLastError(ERROR_SUCCESS);
    ret("Error set to: ERROR_SUCCESS, Return value: <BOOL>[TRUE]");
    return TRUE;
}

HANDLE Kernel32::CreateSemaphoreW(LPSECURITY_ATTRIBUTES lpSemaphoreAttributes, LONG lInitialCount,
    LONG lMaximumCount, LPCWSTR lpName) {
    trace("CreateSemaphoreW implementation called. Arguments: lpSemaphoreAttributes=<LPSECURITY_ATTRIBUTES>[", lpSemaphoreAttributes,
          "], lInitialCount=<LONG>[", lInitialCount, "], lMaximumCount=<LONG>[", lMaximumCount,
          "], lpName=<LPCWSTR>[", lpName, "]");
    sem_t sem;

    if (sem_init(&sem, 0, lInitialCount) != 0) {
        SetLastError(ERROR_INVALID_FUNCTION);
        ret("Error set to: ERROR_INVALID_FUNCTION, Return value: <HANDLE>[NULL]");
        return nullptr;
    }

    HANDLE sem_handle = next_handle;
    next_handle = static_cast<HANDLE>(static_cast<char*>(next_handle) + 1);
    process_info[tls.process].semaphores[sem_handle] = sem;
    SetLastError(ERROR_SUCCESS);
    ret("Error set to: ERROR_SUCCESS, Return value: <HANDLE>[", sem_handle, "]");
    return sem_handle;
}

BOOL Kernel32::ReleaseSemaphore(HANDLE hSemaphore, LONG lReleaseCount, LPLONG lpPreviousCount) {
    trace("ReleaseSemaphore implementation called. Arguments: hSemaphore=<HANDLE>[", hSemaphore,
          "], lReleaseCount=<LONG>[", lReleaseCount, "], lpPreviousCount=<LPLONG>[", lpPreviousCount, "]");

    if (!process_info[tls.process].semaphores.contains(hSemaphore)) {
        SetLastError(ERROR_INVALID_HANDLE);
        ret("Error set to: ERROR_INVALID_HANDLE, Return value: <BOOL>[FALSE]");
        return FALSE;
    }

    sem_t& sem = process_info[tls.process].semaphores[hSemaphore];
    int sval;
    if (sem_getvalue(&sem, &sval) != 0) {
        SetLastError(ERROR_INVALID_FUNCTION);
        ret("Error set to: ERROR_INVALID_FUNCTION, Return value: <BOOL>[FALSE]");
        return FALSE;
    }

    if (lpPreviousCount) {
        *lpPreviousCount = sval;
    }

    for (LONG i = 0; i < lReleaseCount; ++i) {
        if (sem_post(&sem) != 0) {
            SetLastError(ERROR_INVALID_FUNCTION);
            ret("Error set to: ERROR_INVALID_FUNCTION, Return value: <BOOL>[FALSE]");
            return FALSE;
        }
    }

    SetLastError(ERROR_SUCCESS);
    ret("Error set to: ERROR_SUCCESS, Return value: <BOOL>[TRUE]");
    return TRUE;
}

HANDLE Kernel32::CreateMutexW(LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCWSTR lpName) {
    trace("CreateMutexW implementation called. Arguments: lpMutexAttributes=<LPSECURITY_ATTRIBUTES>[", lpMutexAttributes,
          "], bInitialOwner=<BOOL>[", bInitialOwner, "], lpName=<LPCWSTR>[", lpName, "]");

    HANDLE mutex_handle = next_handle;
    next_handle = static_cast<HANDLE>(static_cast<char*>(next_handle) + 1);
    process_info[tls.process].mutexes[mutex_handle];

    if (bInitialOwner) {
        process_info[tls.process].mutexes[mutex_handle].lock();
    }

    SetLastError(ERROR_SUCCESS);
    ret("Error set to: ERROR_SUCCESS, Return value: <HANDLE>[", mutex_handle, "]");
    return mutex_handle;
}

BOOL Kernel32::ReleaseMutex(HANDLE hMutex) {
    trace("ReleaseMutex implementation called. Arguments: hMutex=<HANDLE>[", hMutex, "]");

    if (!process_info[tls.process].mutexes.contains(hMutex)) {
        SetLastError(ERROR_INVALID_HANDLE);
        ret("Error set to: ERROR_INVALID_HANDLE, Return value: <BOOL>[FALSE]");
        return FALSE;
    }

    std::mutex& mtx = process_info[tls.process].mutexes[hMutex];
    // Note: This is a simplification. Real implementation should check ownership.
    mtx.unlock();

    SetLastError(ERROR_SUCCESS);
    ret("Error set to: ERROR_SUCCESS, Return value: <BOOL>[TRUE]");
    return TRUE;
}

LPWCH Kernel32::GetEnvironmentStringsW() {
    trace("GetEnvironmentStringsW implementation called. No arguments.");

    // Calculate the total size needed
    size_t total_size = 0;
    for (const auto& env : environment_vector) {
        total_size += env.length() + 1; // +1 for null terminator
    }
    total_size += 1; // Final null terminator

    // Allocate memory
    const auto env_block = new WCHAR[total_size];
    if (!env_block) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        ret("Error set to: ERROR_NOT_ENOUGH_MEMORY, Return value: <LPWCH>[NULL]");
        return nullptr;
    }

    // Fill the block
    WCHAR* ptr = env_block;
    for (const auto& env : environment_vector) {
        std::wstring env_w(env.begin(), env.end());
        for (size_t i = 0; i < env_w.length(); ++i) {
            ptr[i] = env_w[i];
        }
        ptr[env_w.length()] = L'\0';
        ptr += env_w.length() + 1;
    }
    *ptr = L'\0'; // Final null terminator

    SetLastError(ERROR_SUCCESS);
    ret("Error set to: ERROR_SUCCESS, Return value: <LPWCH>[", env_block, "]");
    return env_block;
}

BOOL Kernel32::FreeEnvironmentStringsW(LPCWSTR penv) {
    trace("FreeEnvironmentStringsW implementation called. Arguments: penv=<LPCWSTR>[", penv, "]");

    if (!penv) {
        SetLastError(ERROR_INVALID_PARAMETER);
        ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <BOOL>[FALSE]");
        return FALSE;
    }

    delete[] penv;

    SetLastError(ERROR_SUCCESS);
    ret("Error set to: ERROR_SUCCESS, Return value: <BOOL>[TRUE]");
    return TRUE;
}

void Kernel32::RaiseException(DWORD dwExceptionCode, DWORD dwExceptionFlags, DWORD nNumberOfArguments,
    const ULONG_PTR *lpArguments) {
    trace("RaiseException implementation called. Arguments: dwExceptionCode=<DWORD>[", dwExceptionCode,
          "], dwExceptionFlags=<DWORD>[", dwExceptionFlags, "], nNumberOfArguments=<DWORD>[", nNumberOfArguments,
          "], lpArguments=<const ULONG_PTR*>[", lpArguments, "]");
    throw std::runtime_error("RaiseException called with code " + std::to_string(dwExceptionCode) + " and flags " + std::to_string(dwExceptionFlags));
}

void Kernel32::GetSystemInfo(LPSYSTEM_INFO lpSystemInfo) {
    trace("GetSystemInfo implementation called. Arguments: lpSystemInfo=<LPSYSTEM_INFO>[", lpSystemInfo, "]");
    if (!lpSystemInfo) {
        return;
    }
    lpSystemInfo->dwPageSize = 4096;
    lpSystemInfo->lpMinimumApplicationAddress = reinterpret_cast<LPVOID>(0x10000);
    lpSystemInfo->lpMaximumApplicationAddress = reinterpret_cast<LPVOID>(0x7FFFFFFF);
    lpSystemInfo->dwActiveProcessorMask = 1;
    lpSystemInfo->dwNumberOfProcessors = 16; // Set to a reasonable default
    lpSystemInfo->dwProcessorType = 386;
    lpSystemInfo->dwAllocationGranularity = 65536;
    lpSystemInfo->wProcessorLevel = 3;
    lpSystemInfo->wProcessorRevision = 0;
    ret("Return value: <void>");
}

DWORD Kernel32::GetCurrentDirectoryW(DWORD nBufferLength, LPWSTR lpBuffer) {
    trace("GetCurrentDirectoryW implementation called. Arguments: nBufferLength=<DWORD>[", nBufferLength,
          "], lpBuffer=<LPWSTR>[", lpBuffer, "]");

    const std::wstring current_path_w = std::filesystem::current_path().wstring();
    const size_t path_length = current_path_w.length();

    if (nBufferLength == 0) {
        SetLastError(ERROR_SUCCESS);
        ret("Error set to: ERROR_SUCCESS, Return value: <DWORD>[", path_length, "] (buffer size query)");
        return path_length;
    }

    if (nBufferLength <= path_length) {
        if (nBufferLength > 0) {
            //UCRTBase::wcsncpy_(lpBuffer, current_path_w.c_str(), nBufferLength - 1);
            for (size_t i = 0; i < nBufferLength - 1; ++i) {
                lpBuffer[i] = current_path_w[i];
            }
            lpBuffer[nBufferLength - 1] = L'\0';
        }
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        ret("Error set to: ERROR_INSUFFICIENT_BUFFER, Return value: <DWORD>[", path_length, "]");
        return path_length;
    }

    for (size_t i = 0; i < current_path_w.length(); ++i) {
        lpBuffer[i] = current_path_w[i];
    }
    lpBuffer[current_path_w.length()] = L'\0';
    SetLastError(ERROR_SUCCESS);
    ret("Error set to: ERROR_SUCCESS, Return value: <DWORD>[", path_length, "]");
    return path_length;
}

bool Kernel32::SwitchToThread(DWORD thread_id) {
    trace("SwitchToThread implementation called. Arguments: thread_id=<DWORD>[", thread_id, "]");
    // <idontcare> just yield the CPU (real implementation would switch to another thread) </idontcare>
    std::this_thread::yield();
    ret("Return value: <bool>[true]");
    return true;
}

LPVOID Kernel32::VirtualAllocEx(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect,
    HANDLE hProcess) {
    trace("VirtualAllocEx implementation called. Arguments: lpAddress=<LPVOID>[", lpAddress,
          "], dwSize=<SIZE_T>[", dwSize, "], flAllocationType=<DWORD>[", flAllocationType,
          "], flProtect=<DWORD>[", flProtect, "], hProcess=<HANDLE>[", hProcess, "]");

    if (hProcess != GetCurrentProcess()) {
        SetLastError(ERROR_INVALID_HANDLE);
        ret("Error set to: ERROR_INVALID_HANDLE, Return value: <LPVOID>[NULL]");
        return nullptr;
    }

    if (dwSize == 0 || (flAllocationType & (MEM_COMMIT | MEM_RESERVE)) == 0) {
        SetLastError(ERROR_INVALID_PARAMETER);
        ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <LPVOID>[NULL]");
        return nullptr;
    }

    int prot = 0;
    if (flProtect & PAGE_READONLY) prot |= PROT_READ;
    if (flProtect & PAGE_READWRITE) prot |= PROT_READ | PROT_WRITE;
    if (flProtect & PAGE_EXECUTE) prot |= PROT_EXEC;
    if (flProtect & PAGE_EXECUTE_READ) prot |= PROT_EXEC | PROT_READ;
    if (flProtect & PAGE_EXECUTE_READWRITE) prot |= PROT_EXEC | PROT_READ | PROT_WRITE;

    void* addr = mmap(lpAddress, dwSize, prot,
                      MAP_PRIVATE | MAP_ANONYMOUS | (lpAddress ? MAP_FIXED : 0), -1, 0);
    if (addr == MAP_FAILED) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        ret("Error set to: ERROR_NOT_ENOUGH_MEMORY, Return value: <LPVOID>[NULL]");
        return nullptr;
    }

    process_info[hProcess].memory_map[addr] = {
        .mem = addr,
        .size = dwSize,
        .protect = flProtect,
        .state = flAllocationType,
        .type = (flAllocationType & MEM_COMMIT) ? MEM_PRIVATE : MEM_RESERVE
    };

    SetLastError(ERROR_SUCCESS);
    ret("Error set to: ERROR_SUCCESS, Return value: <LPVOID>[", addr, "]");
    return addr;
}

BOOL Kernel32::VirtualFreeEx(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType, HANDLE hProcess) {
    trace("VirtualFreeEx implementation called. Arguments: lpAddress=<LPVOID>[", lpAddress,
          "], dwSize=<SIZE_T>[", dwSize, "], dwFreeType=<DWORD>[", dwFreeType,
          "], hProcess=<HANDLE>[", hProcess, "]");

    if (hProcess != GetCurrentProcess()) {
        SetLastError(ERROR_INVALID_HANDLE);
        ret("Error set to: ERROR_INVALID_HANDLE, Return value: <BOOL>[FALSE]");
        return FALSE;
    }

    if (!lpAddress) {
        SetLastError(ERROR_INVALID_PARAMETER);
        ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <BOOL>[FALSE]");
        return FALSE;
    }

    const auto it = process_info[hProcess].memory_map.find(lpAddress);
    if (it == process_info[tls.process].memory_map.end()) {
        SetLastError(ERROR_INVALID_ADDRESS);
        ret("Error set to: ERROR_INVALID_ADDRESS, Return value: <BOOL>[FALSE]");
        return FALSE;
    }

    if (dwFreeType == MEM_RELEASE) {
        munmap(it->second.mem, it->second.size);
        process_info[hProcess].memory_map.erase(it);
        SetLastError(ERROR_SUCCESS);
        ret("Error set to: ERROR_SUCCESS, Return value: <BOOL>[TRUE] (MEM_RELEASE)");
        return TRUE;
    }
    if (dwFreeType == MEM_DECOMMIT) {
        it->second.state = MEM_RESERVE;
        SetLastError(ERROR_SUCCESS);
        ret("Error set to: ERROR_SUCCESS, Return value: <BOOL>[TRUE] (MEM_DECOMMIT)");
        return TRUE;
    }
    SetLastError(ERROR_INVALID_PARAMETER);
    ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <BOOL>[FALSE]");
    return FALSE;
}

BOOL Kernel32::VirtualProtectEx(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect,
    HANDLE hProcess) {
    trace("VirtualProtectEx implementation called. Arguments: lpAddress=<LPVOID>[", lpAddress,
          "], dwSize=<SIZE_T>[", dwSize, "], flNewProtect=<DWORD>[", flNewProtect,
          "], lpflOldProtect=<PDWORD>[", lpflOldProtect, "], hProcess=<HANDLE>[", hProcess, "]");

    if (hProcess != GetCurrentProcess()) {
        SetLastError(ERROR_INVALID_HANDLE);
        ret("Error set to: ERROR_INVALID_HANDLE, Return value: <BOOL>[FALSE]");
        return FALSE;
    }

    if (!lpAddress || dwSize == 0 || !lpflOldProtect) {
        SetLastError(ERROR_INVALID_PARAMETER);
        ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <BOOL>[FALSE]");
        return FALSE;
    }

    const auto it = process_info[hProcess].memory_map.find(lpAddress);
    if (it == process_info[hProcess].memory_map.end() || dwSize > it->second.size) {
        SetLastError(ERROR_INVALID_ADDRESS);
        ret("Error set to: ERROR_INVALID_ADDRESS, Return value: <BOOL>[FALSE]");
        return FALSE;
    }

    *lpflOldProtect = it->second.protect;
    it->second.protect = flNewProtect;

    int prot = 0;
    if (flNewProtect & PAGE_READONLY) prot |= PROT_READ;
    if (flNewProtect & PAGE_READWRITE) prot |= PROT_READ | PROT_WRITE;
    if (flNewProtect & PAGE_EXECUTE) prot |= PROT_EXEC;
    if (flNewProtect & PAGE_EXECUTE_READ) prot |= PROT_EXEC | PROT_READ;
    if (flNewProtect & PAGE_EXECUTE_READWRITE) prot |= PROT_EXEC | PROT_READ | PROT_WRITE;

    if (mprotect(it->second.mem, it->second.size, prot) != 0) {
        SetLastError(ERROR_INVALID_FUNCTION);
        ret("Error set to: ERROR_INVALID_FUNCTION, Return value: <BOOL>[FALSE]");
        return FALSE;
    }

    SetLastError(ERROR_SUCCESS);
    ret("Error set to: ERROR_SUCCESS, Return value: <BOOL>[TRUE]");
    return TRUE;
}

SIZE_T Kernel32::VirtualQueryEx(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength,
    HANDLE hProcess) {
    trace("VirtualQueryEx implementation called. Arguments: lpAddress=<LPCVOID>[", lpAddress,
          "], lpBuffer=<PMEMORY_BASIC_INFORMATION>[", lpBuffer, "], dwLength=<SIZE_T>[", dwLength,
          "], hProcess=<HANDLE>[", hProcess, "]");

    if (hProcess != GetCurrentProcess()) {
        SetLastError(ERROR_INVALID_HANDLE);
        ret("Error set to: ERROR_INVALID_HANDLE, Return value: <SIZE_T>[0]");
        return 0;
    }

    if (!lpAddress || !lpBuffer || dwLength < sizeof(MEMORY_BASIC_INFORMATION)) {
        SetLastError(ERROR_INVALID_PARAMETER);
        ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <SIZE_T>[0]");
        return 0;
    }

    const auto it = process_info[hProcess].memory_map.find(const_cast<LPVOID>(lpAddress));
    if (it == process_info[hProcess].memory_map.end()) {
        SetLastError(ERROR_INVALID_ADDRESS);
        ret("Error set to: ERROR_INVALID_ADDRESS, Return value: <SIZE_T>[0]");
        return 0;
    }

    lpBuffer->BaseAddress = it->second.mem;
    lpBuffer->AllocationBase = it->second.mem;
    lpBuffer->AllocationProtect = it->second.protect;
    lpBuffer->RegionSize = it->second.size;
    lpBuffer->State = it->second.state;
    lpBuffer->Protect = it->second.protect;
    lpBuffer->Type = it->second.type;

    SetLastError(ERROR_SUCCESS);
    ret("Error set to: ERROR_SUCCESS, Return value: <SIZE_T>[", sizeof(MEMORY_BASIC_INFORMATION), "]");
    return sizeof(MEMORY_BASIC_INFORMATION);
}

HANDLE Kernel32::VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
    trace("VirtualAlloc implementation called. Arguments: lpAddress=<LPVOID>[", lpAddress,
          "], dwSize=<SIZE_T>[", dwSize, "], flAllocationType=<DWORD>[", flAllocationType,
          "], flProtect=<DWORD>[", flProtect, "]");

    return VirtualAllocEx(lpAddress, dwSize, flAllocationType, flProtect, GetCurrentProcess());
}

BOOL Kernel32::VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) {
    trace("VirtualFree implementation called. Arguments: lpAddress=<LPVOID>[", lpAddress,
          "], dwSize=<SIZE_T>[", dwSize, "], dwFreeType=<DWORD>[", dwFreeType, "]");

    return VirtualFreeEx(lpAddress, dwSize, dwFreeType, GetCurrentProcess());
}

BOOL Kernel32::VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) {
    trace("VirtualProtect implementation called. Arguments: lpAddress=<LPVOID>[", lpAddress,
          "], dwSize=<SIZE_T>[", dwSize, "], flNewProtect=<DWORD>[", flNewProtect,
          "], lpflOldProtect=<PDWORD>[", lpflOldProtect, "]");

    return VirtualProtectEx(lpAddress, dwSize, flNewProtect, lpflOldProtect, GetCurrentProcess());
}

SIZE_T Kernel32::VirtualQuery(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength) {
    trace("VirtualQuery implementation called. Arguments: lpAddress=<LPCVOID>[", lpAddress,
          "], lpBuffer=<PMEMORY_BASIC_INFORMATION>[", lpBuffer, "], dwLength=<SIZE_T>[", dwLength, "]");

    return VirtualQueryEx(lpAddress, lpBuffer, dwLength, GetCurrentProcess());
}

DWORD Kernel32::GetFullPathNameW(LPCWSTR lpFileName, DWORD nBufferLength, LPWSTR lpBuffer, LPWSTR*lpFilePart) {
    trace("GetFullPathNameW implementation called. Arguments: lpFileName=<LPCWSTR>[", lpFileName,
          "], nBufferLength=<DWORD>[", nBufferLength, "], lpBuffer=<LPWSTR>[", lpBuffer,
          "], lpFilePart=<LPWSTR*>[", lpFilePart, "]");

    if (!lpFileName || nBufferLength == 0) {
        SetLastError(ERROR_INVALID_PARAMETER);
        ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <DWORD>[0]");
        return 0;
    }

    std::wstring input_path(L'\0', UCRTBase::wcslen_(lpFileName));
    for (size_t i = 0; i < input_path.size(); ++i) {
        input_path[i] = lpFileName[i];
    }
    const std::filesystem::path full_path = std::filesystem::absolute(input_path);
    const std::wstring full_path_w = full_path.wstring();
    const size_t path_length = full_path_w.length();

    if (nBufferLength <= path_length) {
        if (nBufferLength > 0) {
            //UCRTBase::wcsncpy_(lpBuffer, full_path_w.c_str(), nBufferLength - 1);
            for (size_t i = 0; i < nBufferLength - 1; ++i) {
                lpBuffer[i] = full_path_w[i];
            }
            lpBuffer[nBufferLength - 1] = L'\0';
        }
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        ret("Error set to: ERROR_INSUFFICIENT_BUFFER, Return value: <DWORD>[", path_length, "]");
        return path_length;
    }

    for (size_t i = 0; i < full_path_w.length(); ++i) {
        lpBuffer[i] = full_path_w[i];
    }
    lpBuffer[full_path_w.length()] = L'\0';
    if (lpFilePart) {
        *lpFilePart = lpBuffer + full_path_w.find_last_of(L"\\/") + 1;
    }

    SetLastError(ERROR_SUCCESS);
    ret("Error set to: ERROR_SUCCESS, Return value: <DWORD>[", path_length, "]");
    return path_length;
}

DWORD Kernel32::GetTempPathW(DWORD nBufferLength, LPWSTR lpBuffer) {
    trace("GetTempPathW implementation called. Arguments: nBufferLength=<DWORD>[", nBufferLength,
          "], lpBuffer=<LPWSTR>[", lpBuffer, "]");

    const std::wstring temp_path_w = std::filesystem::temp_directory_path().wstring();
    const size_t path_length = temp_path_w.length();

    if (nBufferLength == 0) {
        SetLastError(ERROR_SUCCESS);
        ret("Error set to: ERROR_SUCCESS, Return value: <DWORD>[", path_length, "] (buffer size query)");
        return path_length;
    }

    if (nBufferLength <= path_length) {
        if (nBufferLength > 0) {
            for (size_t i = 0; i < nBufferLength - 1; ++i) {
                lpBuffer[i] = temp_path_w[i];
            }
            lpBuffer[nBufferLength - 1] = L'\0';
        }
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        ret("Error set to: ERROR_INSUFFICIENT_BUFFER, Return value: <DWORD>[", path_length, "]");
        return path_length;
    }

    for (size_t i = 0; i < temp_path_w.length(); ++i) {
        lpBuffer[i] = temp_path_w[i];
    }
    lpBuffer[temp_path_w.length()] = L'\0';
    SetLastError(ERROR_SUCCESS);
    ret("Error set to: ERROR_SUCCESS, Return value: <DWORD>[", path_length, "]");
    return path_length;
}

BOOL Kernel32::GetExitCodeThread(HANDLE hThread, LPDWORD lpExitCode) {
    trace("GetExitCodeThread implementation called. Arguments: hThread=<HANDLE>[", hThread,
          "], lpExitCode=<LPDWORD>[", lpExitCode, "]");

    if (!lpExitCode) {
        SetLastError(ERROR_INVALID_PARAMETER);
        ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <BOOL>[FALSE]");
        return FALSE;
    }

    if (!process_info[tls.process].threads.contains(hThread)) {
        SetLastError(ERROR_INVALID_HANDLE);
        ret("Error set to: ERROR_INVALID_HANDLE, Return value: <BOOL>[FALSE]");
        return FALSE;
    }

    if (const auto& thread = process_info[tls.process].threads[hThread].thread; pthread_tryjoin_np(thread, nullptr) == EBUSY) {
        *lpExitCode = STILL_ACTIVE;
    } else {
        DWORD exitCode;
        pthread_join(thread, reinterpret_cast<void**>(&exitCode));
        *lpExitCode = exitCode;
    }

    SetLastError(ERROR_SUCCESS);
    ret("Error set to: ERROR_SUCCESS, Return value: <BOOL>[TRUE]");
    return TRUE;
}

BOOL Kernel32::GetExitCodeProcess(HANDLE hProcess, LPDWORD lpExitCode) {
    trace("GetExitCodeProcess implementation called. Arguments: hProcess=<HANDLE>[", hProcess,
          "], lpExitCode=<LPDWORD>[", lpExitCode, "]");

    if (!lpExitCode) {
        SetLastError(ERROR_INVALID_PARAMETER);
        ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <BOOL>[FALSE]");
        return FALSE;
    }

    if (hProcess != GetCurrentProcess()) {
        SetLastError(ERROR_INVALID_HANDLE);
        ret("Error set to: ERROR_INVALID_HANDLE, Return value: <BOOL>[FALSE]");
        return FALSE;
    }

    if (const auto& main_thread = process_info[tls.process].process_thread; pthread_tryjoin_np(main_thread, nullptr) == EBUSY) {
        *lpExitCode = STILL_ACTIVE;
    } else {
        DWORD exitCode;
        pthread_join(main_thread, reinterpret_cast<void**>(&exitCode));
        *lpExitCode = exitCode;
    }

    SetLastError(ERROR_SUCCESS);
    ret("Error set to: ERROR_SUCCESS, Return value: <BOOL>[TRUE]");
    return TRUE;
}

DWORD Kernel32::GetFreeDiskSpaceExW(LPCWSTR lpDirectoryName, PULARGE_INTEGER lpFreeBytesAvailableToCaller,
    PULARGE_INTEGER lpTotalNumberOfBytes, PULARGE_INTEGER lpTotalNumberOfFreeBytes) {
    trace("GetFreeDiskSpaceExW implementation called. Arguments: lpDirectoryName=<LPCWSTR>[", lpDirectoryName,
          "], lpFreeBytesAvailableToCaller=<PULARGE_INTEGER>[", lpFreeBytesAvailableToCaller,
          "], lpTotalNumberOfBytes=<PULARGE_INTEGER>[", lpTotalNumberOfBytes,
          "], lpTotalNumberOfFreeBytes=<PULARGE_INTEGER>[", lpTotalNumberOfFreeBytes, "]");

    if (!lpDirectoryName || !lpFreeBytesAvailableToCaller || !lpTotalNumberOfBytes || !lpTotalNumberOfFreeBytes) {
        SetLastError(ERROR_INVALID_PARAMETER);
        ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <DWORD>[0]");
        return 0;
    }

    std::wstring path_w('\0', MAX_PATH);
    for (size_t i = 0; i < MAX_PATH; ++i) {
        if (lpDirectoryName[i] == L'\0') {
            path_w.resize(i);
            break;
        }
        path_w[i] = lpDirectoryName[i];
    }
    std::string path(path_w.begin(), path_w.end());

    struct statvfs stat{};
    if (statvfs(path.c_str(), &stat) != 0) {
        SetLastError(ERROR_INVALID_PARAMETER);
        ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <DWORD>[0]");
        return 0;
    }

    lpFreeBytesAvailableToCaller->QuadPart = static_cast<ULONGLONG>(stat.f_bavail) * stat.f_frsize;
    lpTotalNumberOfBytes->QuadPart = static_cast<ULONGLONG>(stat.f_blocks) * stat.f_frsize;
    lpTotalNumberOfFreeBytes->QuadPart = static_cast<ULONGLONG>(stat.f_bfree) * stat.f_frsize;

    SetLastError(ERROR_SUCCESS);
    ret("Error set to: ERROR_SUCCESS, Return value: <DWORD>[1]");
    return 1;
}

DWORD Kernel32::GetFreeDiskSpaceW(LPCWSTR lpDirectoryName, LPDWORD lpSectorsPerCluster, LPDWORD lpBytesPerSector,
    LPDWORD lpNumberOfFreeClusters, LPDWORD lpTotalNumberOfClusters) {
    trace("GetFreeDiskSpaceW implementation called. Arguments: lpDirectoryName=<LPCWSTR>[", lpDirectoryName,
          "], lpSectorsPerCluster=<LPDWORD>[", lpSectorsPerCluster,
          "], lpBytesPerSector=<LPDWORD>[", lpBytesPerSector,
          "], lpNumberOfFreeClusters=<LPDWORD>[", lpNumberOfFreeClusters,
          "], lpTotalNumberOfClusters=<LPDWORD>[", lpTotalNumberOfClusters, "]");

    if (!lpDirectoryName || !lpSectorsPerCluster || !lpBytesPerSector || !lpNumberOfFreeClusters || !lpTotalNumberOfClusters) {
        SetLastError(ERROR_INVALID_PARAMETER);
        ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <DWORD>[0]");
        return 0;
    }

    std::wstring path_w('\0', MAX_PATH);
    for (size_t i = 0; i < MAX_PATH; ++i) {
        if (lpDirectoryName[i] == L'\0') {
            path_w.resize(i);
            break;
        }
        path_w[i] = lpDirectoryName[i];
    }
    const std::string path(path_w.begin(), path_w.end());
    // dikspace
    struct statvfs stat{};
    if (statvfs(path.c_str(), &stat) != 0) {
        SetLastError(ERROR_INVALID_PARAMETER);
        ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <DWORD>[0]");
        return 0;
    }

    *lpSectorsPerCluster = 1; // Simplification
    *lpBytesPerSector = stat.f_frsize;
    *lpNumberOfFreeClusters = stat.f_bavail;
    *lpTotalNumberOfClusters = stat.f_blocks;

    SetLastError(ERROR_SUCCESS);
    ret("Error set to: ERROR_SUCCESS, Return value: <DWORD>[1]");
    return 1;
}

void * Kernel32::_thread_func(void *arg) {
    auto [start_routine, param] = *static_cast<std::pair<LPTHREAD_START_ROUTINE, LPVOID>*>(arg);
    delete static_cast<std::pair<LPTHREAD_START_ROUTINE, LPVOID>*>(arg);
    const DWORD exit_code = start_routine(param);
    return reinterpret_cast<void*>(static_cast<uintptr_t>(exit_code));
}

HANDLE Kernel32::CreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) {
    trace("CreateThread implementation called. Arguments: lpThreadAttributes=<LPSECURITY_ATTRIBUTES>[", lpThreadAttributes,
          "], dwStackSize=<SIZE_T>[", dwStackSize, "], lpStartAddress=<LPTHREAD_START_ROUTINE>[", lpStartAddress,
          "], lpParameter=<LPVOID>[", lpParameter, "], dwCreationFlags=<DWORD>[", dwCreationFlags,
          "], lpThreadId=<LPDWORD>[", lpThreadId, "]");

    if (!lpStartAddress) {
        SetLastError(ERROR_INVALID_PARAMETER);
        ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <HANDLE>[NULL]");
        return nullptr;
    }

    pthread_t thread;

    HANDLE thread_handle = next_handle;
    next_handle = static_cast<HANDLE>(static_cast<char*>(next_handle) + 1);

    if (dwCreationFlags) {
        process_info[tls.process].threads[thread_handle] = ProcessThreadInfo{
            .is_suspended = true, .thread = 0, .attr = {}, .arg = new std::pair(lpStartAddress, lpParameter), .start_routine = _thread_func
        };
    }

    if (auto* arg = new std::pair(lpStartAddress, lpParameter); pthread_create(&thread, nullptr, _thread_func, arg) != 0) {
        delete arg;
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        ret("Error set to: ERROR_NOT_ENOUGH_MEMORY, Return value: <HANDLE>[NULL]");
        return nullptr;
    }

    process_info[tls.process].threads[thread_handle] = ProcessThreadInfo{
        .is_suspended = false, .thread = thread, .attr = {}, .arg = nullptr, .start_routine = nullptr
    };

    if (lpThreadId) {
        *lpThreadId = reinterpret_cast<uintptr_t>(thread_handle);
    }

    SetLastError(ERROR_SUCCESS);
    ret("Error set to: ERROR_SUCCESS, Return value: <HANDLE>[", thread_handle, "]");
    return thread_handle;
}

HANDLE Kernel32::GetCurrentThread() {
    trace("GetCurrentThread implementation called. No arguments.");
    const auto current_thread_handle = reinterpret_cast<HANDLE>(pthread_self());
    ret("Return value: <HANDLE>[", current_thread_handle, "]");
    return current_thread_handle;
}

DWORD Kernel32::GetCurrentProcessId() {
    trace("GetCurrentProcessId implementation called. No arguments.");
    const DWORD current_process_id = reinterpret_cast<uintptr_t>(tls.process);
    ret("Return value: <DWORD>[", current_process_id, "]");
    return current_process_id;
}

BOOL Kernel32::TerminateThread(HANDLE hThread, DWORD dwExitCode) {
    trace("TerminateThread implementation called. Arguments: hThread=<HANDLE>[", hThread,
          "], dwExitCode=<DWORD>[", dwExitCode, "]");
    if (!process_info[tls.process].threads.contains(hThread)) {
        SetLastError(ERROR_INVALID_HANDLE);
        ret("Error set to: ERROR_INVALID_HANDLE, Return value: <BOOL>[FALSE]");
        return FALSE;
    }
    pthread_cancel(process_info[tls.process].threads[hThread].thread);
    pthread_join(process_info[tls.process].threads[hThread].thread, nullptr);
    process_info[tls.process].threads.erase(hThread);
    SetLastError(ERROR_SUCCESS);
    ret("Error set to: ERROR_SUCCESS, Return value: <BOOL>[TRUE]");
    return TRUE;
}

BOOL Kernel32::ExitThread(DWORD dwExitCode) {
    trace("ExitThread implementation called. Arguments: dwExitCode=<DWORD>[", dwExitCode, "]");
    pthread_exit(reinterpret_cast<void*>(static_cast<uintptr_t>(dwExitCode)));
    // Unreachable
    return TRUE;
}

DWORD Kernel32::SuspendThread(HANDLE hThread) {
    trace("SuspendThread implementation called. Arguments: hThread=<HANDLE>[", hThread, "]");

    if (!process_info[tls.process].threads.contains(hThread)) {
        SetLastError(ERROR_INVALID_HANDLE);
        ret("Error set to: ERROR_INVALID_HANDLE, Return value: <DWORD>[0xFFFFFFFF]");
        return static_cast<DWORD>(-1);
    }

    if (const auto& thread = process_info[tls.process].threads[hThread]; thread.is_suspended) {
        SetLastError(ERROR_SUCCESS);
        ret("Error set to: ERROR_SUCCESS, Return value: <DWORD>[1] (already suspended)");
        return 1; // Already suspended
    }

    // Note: Actual thread suspension is complex and platform-dependent.
    // Here we just mark it as suspended for simulation purposes.
    //is_suspended = true; we do not mark it here; only marked via beginthreadex with CREATE_SUSPENDED bcz then we know it is suspended (not running yet, but here it would not be stopped)

    SetLastError(ERROR_SUCCESS);
    ret("Error set to: ERROR_SUCCESS, Return value: <DWORD>[0] (suspended)");
    return 0; // Successfully suspended
}

DWORD Kernel32::ResumeThread(HANDLE hThread) {
    trace("ResumeThread implementation called. Arguments: hThread=<HANDLE>[", hThread, "]");

    if (!process_info[tls.process].threads.contains(hThread)) {
        SetLastError(ERROR_INVALID_HANDLE);
        ret("Error set to: ERROR_INVALID_HANDLE, Return value: <DWORD>[0xFFFFFFFF]");
        return static_cast<DWORD>(-1);
    }

    auto& thread = process_info[tls.process].threads[hThread];
    if (!thread.is_suspended) {
        SetLastError(ERROR_SUCCESS);
        ret("Error set to: ERROR_SUCCESS, Return value: <DWORD>[0] (not suspended)");
        return 0; // Not suspended
    }

    auto thread_func = [](void* arg) -> void* {
        auto [start_routine, param] = *static_cast<std::pair<LPTHREAD_START_ROUTINE, LPVOID>*>(arg);
        delete static_cast<std::pair<LPTHREAD_START_ROUTINE, LPVOID>*>(arg);
        const DWORD exit_code = start_routine(param);
        return reinterpret_cast<void*>(static_cast<uintptr_t>(exit_code));
    };

    const std::pair arg = { process_info[tls.process].threads[hThread].start_routine, process_info[tls.process].threads[hThread].arg };

    thread.is_suspended = false;
    pthread_create(&process_info[tls.process].threads[hThread].thread, &process_info[tls.process].threads[hThread].attr, thread_func, new std::pair(arg));
    SetLastError(ERROR_SUCCESS);
    ret("Error set to: ERROR_SUCCESS, Return value: <DWORD>[1] (resumed)");
    return 1; // Successfully resumed
}

BOOL Kernel32::SetConsoleCtrlHandler(PHANDLER_ROUTINE HandlerRoutine, BOOL Add) {
    trace("SetConsoleCtrlHandler implementation called. Arguments: HandlerRoutine=<PHANDLER_ROUTINE>[", HandlerRoutine,
          "], Add=<BOOL>[", Add, "]");

    if (Add) {
        process_info[tls.process].console_control_handlers.insert(HandlerRoutine);
    } else {
        process_info[tls.process].console_control_handlers.erase(HandlerRoutine);
    }
    SetLastError(ERROR_SUCCESS);
    ret("Error set to: ERROR_SUCCESS, Return value: <BOOL>[TRUE]");
    return TRUE;
}

DWORD Kernel32::SearchPathW(LPCWSTR lpPath, LPCWSTR lpFileName, LPCWSTR lpExtension, DWORD nBufferLength,
    LPWSTR lpBuffer, LPWSTR*lpFilePart) {
    trace("SearchPathW implementation called. Arguments: lpPath=<LPCWSTR>[", lpPath,
          "], lpFileName=<LPCWSTR>[", lpFileName,
          "], lpExtension=<LPCWSTR>[", lpExtension,
          "], nBufferLength=<DWORD>[", nBufferLength,
          "], lpBuffer=<LPWSTR>[", lpBuffer,
          "], lpFilePart=<LPWSTR*>[", lpFilePart, "]");

    if (!lpFileName || nBufferLength == 0) {
        SetLastError(ERROR_INVALID_PARAMETER);
        ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <DWORD>[0]");
        return 0;
    }

    std::vector<std::filesystem::path> search_paths;
    if (lpPath) {
        std::wstring path_w('\0', MAX_PATH);
        for (size_t i = 0; i < MAX_PATH; ++i) {
            if (lpPath[i] == L'\0') {
                path_w.resize(i);
                break;
            }
        }
        size_t start = 0;
        size_t end = path_w.find(L';');
        while (end != std::wstring::npos) {
            search_paths.emplace_back(path_w.substr(start, end - start));
            start = end + 1;
            end = path_w.find(L';', start);
        }
        search_paths.emplace_back(path_w.substr(start));
    } else {
        search_paths.push_back(std::filesystem::current_path());
        if (const char* path_env = std::getenv("PATH"); path_env) {
            std::string path_env_str(path_env);
            size_t start = 0;
            size_t end = path_env_str.find(':');
            while (end != std::string::npos) {
                search_paths.emplace_back(path_env_str.substr(start, end - start));
                start = end + 1;
                end = path_env_str.find(':', start);
            }
            search_paths.emplace_back(path_env_str.substr(start));
        }
    }

    std::wstring file_name_w('\0', MAX_PATH);
    for (size_t i = 0; i < MAX_PATH; ++i) {
        if (lpFileName[i] == L'\0') {
            file_name_w.resize(i);
            break;
        }
        file_name_w[i] = lpFileName[i];
    }
    std::wstring extension_w('\0', MAX_PATH);
    if (lpExtension) {
        for (size_t i = 0; i < MAX_PATH; ++i) {
            if (lpExtension[i] == L'\0') {
                extension_w.resize(i);
                break;
            }
            extension_w[i] = lpExtension[i];
        }
    }

    for (const auto& dir : search_paths) {
        std::filesystem::path full_path = dir / file_name_w;
        if (!extension_w.empty() && full_path.extension() != extension_w) {
            full_path += extension_w;
        }
        if (std::filesystem::exists(full_path)) {
            const std::wstring full_path_w = full_path.wstring();
            const size_t path_length = full_path_w.length();
            if (nBufferLength <= path_length) {
                if (nBufferLength > 0) {
                    for (size_t i = 0; i < nBufferLength - 1; ++i) {
                        lpBuffer[i] = full_path_w[i];
                    }
                    lpBuffer[nBufferLength - 1] = L'\0';
                }
                SetLastError(ERROR_INSUFFICIENT_BUFFER);
                ret("Error set to: ERROR_INSUFFICIENT_BUFFER, Return value: <DWORD>[", path_length, "]");
                return path_length;
            }
            for (size_t i = 0; i < full_path_w.length(); ++i) {
                lpBuffer[i] = full_path_w[i];
            }
            lpBuffer[full_path_w.length()] = L'\0';
            if (lpFilePart) {
                *lpFilePart = lpBuffer + full_path_w.find_last_of(L"\\/") + 1;
            }
            SetLastError(ERROR_SUCCESS);
            ret("Error set to: ERROR_SUCCESS, Return value: <DWORD>[", path_length, "]");
            return path_length;
        }
    }
    SetLastError(ERROR_FILE_NOT_FOUND);
    ret("Error set to: ERROR_FILE_NOT_FOUND, Return value: <DWORD>[0]");
    return 0;
}

HANDLE Kernel32::GetStdHandle(DWORD nStdHandle) {
    trace("GetStdHandle implementation called. Arguments: nStdHandle=<DWORD>[", nStdHandle, "]");

    const HANDLE handle = process_info[tls.process].std_handles[nStdHandle];
    SetLastError(ERROR_SUCCESS);
    ret("Error set to: ERROR_SUCCESS, Return value: <HANDLE>[", handle, "]");
    return handle;
}

BOOL Kernel32::SetStdHandle(DWORD nStdHandle, HANDLE hHandle) {
    trace("SetStdHandle implementation called. Arguments: nStdHandle=<DWORD>[", nStdHandle,
          "], hHandle=<HANDLE>[", hHandle, "]");

    process_info[tls.process].std_handles[nStdHandle] = hHandle;
    ret("Error set to: ERROR_SUCCESS, Return value: <BOOL>[TRUE]");
    return TRUE;
}

BOOL Kernel32::IsDebuggerPresent() {
    trace("IsDebuggerPresent diserror-stub called. No arguments.");
    ret("Return value: <BOOL>[FALSE]");
    return FALSE; // Always return FALSE for simplicity
}

void Kernel32::RtlCaptureContext(LPCONTEXT ContextRecord) {
    trace("RtlCaptureContext implementation called. Arguments: ContextRecord=<LPCONTEXT>[", ContextRecord, "]");
    if (!ContextRecord) {
        return;
    }
    // Simplified context capture
    memset(ContextRecord, 0, sizeof(CONTEXT));
    ContextRecord->ContextFlags = CONTEXT_FULL;
    // Note: Actual register values are not captured in this simplified implementation
    ret("Return value: <void>");
}

std::vector<RUNTIME_FUNCTION> Kernel32::extract_exception_table(const LIEF::PE::Binary &pe,
    const uintptr_t base_address) {

    std::vector<RUNTIME_FUNCTION> functions;

    try {
        // Get the exception directory (directory entry 3)
        if (!pe.data_directory(LIEF::PE::DataDirectory::TYPES::EXCEPTION_TABLE)) {
            return functions; // No exception table
        }

        const auto& exception_dir = pe.data_directory(LIEF::PE::DataDirectory::TYPES::EXCEPTION_TABLE);
        if (exception_dir->RVA() == 0 || exception_dir->size() == 0) {
            return functions;
        }

        // Find section containing exception table
        const auto* section = pe.section_from_rva(exception_dir->RVA());
        if (!section) {
            warn("Exception table RVA not found in any section");
            return functions;
        }

        // Calculate offset within a section
        const auto section_data = section->content();
        const uint32_t offset_in_section = exception_dir->RVA() - section->virtual_address();

        if (offset_in_section + exception_dir->size() > section_data.size()) {
            warn("Exception table extends beyond section bounds");
            return functions;
        }

        // Parse RUNTIME_FUNCTION entries
        const size_t entry_count = exception_dir->size() / sizeof(RUNTIME_FUNCTION);
        const auto* runtime_functions = reinterpret_cast<const RUNTIME_FUNCTION*>(
            section_data.data() + offset_in_section
        );

        functions.reserve(entry_count);
        for (size_t i = 0; i < entry_count; ++i) {
            // Validate function entry
            if (const auto& func = runtime_functions[i]; func.BeginAddress < func.EndAddress &&
                                                         func.EndAddress <= pe.optional_header().sizeof_image()) {
                functions.push_back(func);
            } else {
                warn("Invalid function entry detected at index " + std::to_string(i));
            }
        }

        // Sort by BeginAddress for binary search
        std::ranges::sort(functions,
                          [](const RUNTIME_FUNCTION& a, const RUNTIME_FUNCTION& b) {
                              return a.BeginAddress < b.BeginAddress;
                          });

        trace("Extracted ", std::to_wstring(functions.size()), " exception entries for module at 0x",
              std::to_wstring(base_address));

    } catch (const std::exception& e) {
        warn("Failed to extract exception table: " + std::string(e.what()));
    }

    return functions;
}

uintptr_t Kernel32::find_module_base(uintptr_t control_pc) {
    // Check the main executable first
    for (const auto &proc_info: process_info | std::views::values) {
        if (proc_info.process_hmodule) {
            const auto base = reinterpret_cast<uintptr_t>(proc_info.process_hmodule);
            if (const uintptr_t end = base + proc_info.image_size; control_pc >= base && control_pc < end) {
                return base;
            }
        }
    }

    // Check loaded DLLs through process module info
    for (const auto &proc_info: process_info | std::views::values) {
        for (const auto &module_info: proc_info.modules | std::views::values) {
            const uintptr_t base = module_info.base_address;
            if (const uintptr_t end = base + module_info.size; control_pc >= base && control_pc < end) {
                return base;
            }
        }
    }

    return 0;
}

bool Kernel32::validate_function_entry(const RUNTIME_FUNCTION &func, uintptr_t image_size) {
    return func.BeginAddress < func.EndAddress &&
           func.EndAddress <= image_size &&
           func.BeginAddress < image_size;
}

PRUNTIME_FUNCTION Kernel32::RtlLookupFunctionEntry(DWORD64 ControlPc, PDWORD64 ImageBase,
    PUNWIND_HISTORY_TABLE HistoryTable) {

    trace("RtlLookupFunctionEntry: Looking up function entry for PC 0x",
          std::to_wstring(ControlPc));

    const auto control_pc = static_cast<uintptr_t>(ControlPc);

    // Find which module contains this address
    const uintptr_t module_base = find_module_base(control_pc);
    if (module_base == 0) {
        trace("RtlLookupFunctionEntry: No module found containing PC 0x",
              std::to_wstring(ControlPc));
        return nullptr;
    }

    if (ImageBase) {
        *ImageBase = module_base;
    }

    // Check the history table first for optimization (as Windows does)
    if (HistoryTable) {
        // Update search bounds
        if (HistoryTable->Count == 0) {
            HistoryTable->LowAddress = control_pc;
            HistoryTable->HighAddress = control_pc;
        } else {
            if (control_pc < HistoryTable->LowAddress) {
                HistoryTable->LowAddress = control_pc;
            }
            if (control_pc > HistoryTable->HighAddress) {
                HistoryTable->HighAddress = control_pc;
            }
        }

        // Check recent entries in the history table
        for (DWORD i = 0; i < HistoryTable->Count && i < 12; ++i) {
            const auto& entry = HistoryTable->Entry[i];
            if (entry.ImageBase == module_base && entry.FunctionEntry) {
                const auto* func = entry.FunctionEntry;
                const uintptr_t func_start = module_base + func->BeginAddress;
                const uintptr_t func_end = module_base + func->EndAddress;

                if (control_pc >= func_start && control_pc < func_end) {
                    trace("RtlLookupFunctionEntry: Found in history table");
                    return entry.FunctionEntry;
                }
            }
        }
    }

    // Check if we have cached exception table for this module
    std::lock_guard<std::mutex> lock(process_info[tls.process].exception_registry.registry_mutex);

    auto it = process_info[tls.process].exception_registry.exception_tables.begin();
    if (it == process_info[tls.process].exception_registry.exception_tables.end()) {
        // Check if module info has an exception table
        for (const auto &proc_info: process_info | std::views::values) {
            for (const auto &module_info: proc_info.modules | std::views::values) {
                if (module_info.base_address == module_base) {
                    if (module_info.has_exception_table && !module_info.exception_table.empty()) {
                        // Use the module's exception table
                        process_info[tls.process].exception_registry.exception_tables[module_base] = module_info.exception_table;
                        it = process_info[tls.process].exception_registry.exception_tables.find(module_base);
                        break;
                    }
                }
            }
            if (it != process_info[tls.process].exception_registry.exception_tables.end()) break;
        }

        if (it == process_info[tls.process].exception_registry.exception_tables.end()) {
            trace("RtlLookupFunctionEntry: No exception table found for module 0x",
                  std::to_wstring(module_base));
            return nullptr;
        }
    }

    const auto& functions = it->second;
    if (functions.empty()) {
        return nullptr;
    }

    // Convert absolute PC to RVA
    const auto rva = static_cast<uint32_t>(control_pc - module_base);

    // Binary search for a function containing this RVA
    const auto lower = std::lower_bound(functions.begin(), functions.end(), rva,
                                        [](const RUNTIME_FUNCTION& func, uint32_t target_rva) {
                                            return func.EndAddress <= target_rva;
                                        });

    if (lower != functions.end() &&
        rva >= lower->BeginAddress &&
        rva < lower->EndAddress &&
        validate_function_entry(*lower, SIZE_MAX)) {

        trace("RtlLookupFunctionEntry: Found function entry [0x",
              std::to_wstring(lower->BeginAddress), " - 0x",
              std::to_wstring(lower->EndAddress), "]");

        // Update the history table if provided
        if (HistoryTable && HistoryTable->Count < 12) {
            auto &[ImageBase, FunctionEntry] = HistoryTable->Entry[HistoryTable->Count];
            ImageBase = module_base;
            FunctionEntry = const_cast<PRUNTIME_FUNCTION>(&(*lower));
            HistoryTable->Count++;

            // Set hint for the next search
            if (HistoryTable->Count == 1) {
                HistoryTable->LocalHint = 0;
                HistoryTable->GlobalHint = 0;
            }
        }

        return const_cast<PRUNTIME_FUNCTION>(&(*lower));
    }

    trace("RtlLookupFunctionEntry: No function entry found for RVA 0x",
          std::to_wstring(rva));
    return nullptr;
}

void Kernel32::register_exception_table(uintptr_t base_address, const LIEF::PE::Binary &pe) {
    std::lock_guard<std::mutex> lock(process_info[tls.process].exception_registry.registry_mutex);
    process_info[tls.process].exception_registry.exception_tables[base_address] = extract_exception_table(pe, base_address);

    // Also update the global process info
    for (auto &proc_info: process_info | std::views::values) {
        for (auto &module_info: proc_info.modules | std::views::values) {
            if (module_info.base_address == base_address) {
                module_info.exception_table = process_info[tls.process].exception_registry.exception_tables[base_address];
                module_info.has_exception_table = !module_info.exception_table.empty();

                // Sort for binary search
                std::ranges::sort(module_info.exception_table,
                                  [](const RUNTIME_FUNCTION& a, const RUNTIME_FUNCTION& b) {
                                      return a.BeginAddress < b.BeginAddress;
                                  });
                break;
            }
        }
    }
}

void Kernel32::register_exception_table_raw(const uintptr_t base_address, const RUNTIME_FUNCTION *functions,
    const size_t count) {
    std::lock_guard<std::mutex> lock(process_info[tls.process].exception_registry.registry_mutex);

    std::vector<RUNTIME_FUNCTION> func_vec(functions, functions + count);
    std::ranges::sort(func_vec,
                      [](const RUNTIME_FUNCTION& a, const RUNTIME_FUNCTION& b) {
                          return a.BeginAddress < b.BeginAddress;
                      });

    process_info[tls.process].exception_registry.exception_tables[base_address] = std::move(func_vec);
}

void Kernel32::unregister_exception_table(const uintptr_t base_address) {
    std::lock_guard<std::mutex> lock(process_info[tls.process].exception_registry.registry_mutex);
    process_info[tls.process].exception_registry.exception_tables.erase(base_address);
}

PEXCEPTION_ROUTINE Kernel32::RtlVirtualUnwind(DWORD HandlerType, DWORD64 ImageBase, DWORD64 ControlPc,
    PRUNTIME_FUNCTION FunctionEntry, PCONTEXT ContextRecord, PVOID*HandlerData, PDWORD64 EstablisherFrame,
    PULONG64 TargetGp) {
    trace("RtlVirtualUnwind diserror-stub called. Arguments: HandlerType=<DWORD>[", HandlerType,
          "], ImageBase=<DWORD64>[", ImageBase,
          "], ControlPc=<DWORD64>[", ControlPc,
          "], FunctionEntry=<PRUNTIME_FUNCTION>[", FunctionEntry,
          "], ContextRecord=<PCONTEXT>[", ContextRecord,
          "], HandlerData=<PVOID*>[", HandlerData,
          "], EstablisherFrame=<PDWORD64>[", EstablisherFrame,
          "], TargetGp=<PULONG64>[", TargetGp, "]");
    // Simplified: No unwinding is performed
    if (HandlerData) {
        *HandlerData = nullptr;
    }
    if (EstablisherFrame) {
        *EstablisherFrame = 0;
    }
    if (TargetGp) {
        *TargetGp = 0;
    }
    SetLastError(ERROR_SUCCESS);
    ret("Error set to: ERROR_SUCCESS, Return value: <PEXCEPTION_ROUTINE>[NULL]");
    return nullptr;
}

LONG Kernel32::UnhandledExceptionFilter(EXCEPTION_POINTERS *ExceptionInfo) {
    trace("UnhandledExceptionFilter diserror-stub called. Arguments: ExceptionInfo=<struct _EXCEPTION_POINTERS*>[", ExceptionInfo, "]");
    // Simplified: Always continue search
    ret("Return value: <LONG>[EXCEPTION_CONTINUE_SEARCH]");
    return EXCEPTION_CONTINUE_SEARCH;
}

LPTOP_LEVEL_EXCEPTION_FILTER Kernel32::SetUnhandledExceptionFilter(
    LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter) {
    trace("SetUnhandledExceptionFilter diserror-stub called. Arguments: lpTopLevelExceptionFilter=<LPTOP_LEVEL_EXCEPTION_FILTER>[", lpTopLevelExceptionFilter, "]");
    // Simplified: No filter is actually set
    ret("Return value: <LPTOP_LEVEL_EXCEPTION_FILTER>[NULL]");
    return nullptr;
}

BOOL Kernel32::WriteConsoleW(HANDLE hConsoleOutput, const void *lpBuffer, DWORD nNumberOfCharsToWrite,
    const LPDWORD lpNumberOfCharsWritten, LPVOID lpReserved) {
    trace("WriteConsoleW implementation called. Arguments: hConsoleOutput=<HANDLE>[", hConsoleOutput,
          "], lpBuffer=<const VOID*>[", lpBuffer,
          "], nNumberOfCharsToWrite=<DWORD>[", nNumberOfCharsToWrite,
          "], lpNumberOfCharsWritten=<LPDWORD>[", lpNumberOfCharsWritten,
          "], lpReserved=<LPVOID>[", lpReserved, "]");

    if (!lpBuffer || !lpNumberOfCharsWritten) {
        SetLastError(ERROR_INVALID_PARAMETER);
        ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <BOOL>[FALSE]");
        return FALSE;
    }

    const auto buffer = static_cast<LPCWSTR>(lpBuffer);
    // since _wchar_t is unsigned short, we need to convert to wchar_t
    std::wstringstream ss;
    for (DWORD i = 0; i < nNumberOfCharsToWrite; ++i) {
        if (buffer[i] == _WEOF) { // stop at WEOF (0xFFFF is _WEOF so direct comparison with WEOF (0xFFFFFFFF) is not possible)
            ss << static_cast<wchar_t>(WEOF);
        }
        else {
            ss << static_cast<wchar_t>(buffer[i]);
        }
    }
    FILE *stream = fdopen(reinterpret_cast<intptr_t>(hConsoleOutput), "w");
    if (!stream) {
        SetLastError(ERROR_INVALID_HANDLE);
        ret("Error set to: ERROR_INVALID_HANDLE, Return value: <BOOL>[FALSE]");
        return FALSE;
    }
    std::fputws(ss.str().c_str(), stream);
    std::fflush(stream);
    *lpNumberOfCharsWritten = nNumberOfCharsToWrite;

    SetLastError(ERROR_SUCCESS);
    ret("Error set to: ERROR_SUCCESS, Return value: <BOOL>[TRUE]");
    return TRUE;
}

HANDLE Kernel32::GetProcessHeap() {
    trace("GetProcessHeap implementation called. No arguments.");
    const auto heap_handle = reinterpret_cast<HANDLE>(0x1); // Placeholder heap handle
    ret("Return value: <HANDLE>[", heap_handle, "]");
    return heap_handle;
}

LPVOID Kernel32::HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes) {
    trace("HeapAlloc implementation called. Arguments: hHeap=<HANDLE>[", hHeap,
          "], dwFlags=<DWORD>[", dwFlags,
          "], dwBytes=<SIZE_T>[", dwBytes, "]");

    if (hHeap != GetProcessHeap() && process_info[tls.process].heaps.contains(hHeap))
    {
        SetLastError(ERROR_INVALID_HANDLE);
        ret("Error set to: ERROR_INVALID_HANDLE, Return value: <LPVOID>[NULL]");
        return nullptr;
    }

    void* mem = malloc(dwBytes);
    if (!mem) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        ret("Error set to: ERROR_NOT_ENOUGH_MEMORY, Return value: <LPVOID>[NULL]");
        return nullptr;
    }

    if (dwFlags & HEAP_ZERO_MEMORY) {
        memset(mem, 0, dwBytes);
    }

    if (dwFlags & HEAP_CREATE_ENABLE_EXECUTE) {
        mprotect(mem, dwBytes, PROT_READ | PROT_WRITE | PROT_EXEC);
    }

    process_info[tls.process].heaps[hHeap].alloc_info[mem] = {
        .size = dwBytes,
        .flags = dwFlags
    };

    SetLastError(ERROR_SUCCESS);
    ret("Error set to: ERROR_SUCCESS, Return value: <LPVOID>[", mem, "]");
    return mem;
}

BOOL Kernel32::HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem) {
    trace("HeapFree implementation called. Arguments: hHeap=<HANDLE>[", hHeap,
          "], dwFlags=<DWORD>[", dwFlags,
          "], lpMem=<LPVOID>[", lpMem, "]");

    if (hHeap != GetProcessHeap() && process_info[tls.process].heaps.contains(hHeap))
    {
        SetLastError(ERROR_INVALID_HANDLE);
        ret("Error set to: ERROR_INVALID_HANDLE, Return value: <BOOL>[FALSE]");
        return FALSE;
    }

    if (!lpMem) {
        SetLastError(ERROR_INVALID_PARAMETER);
        ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <BOOL>[FALSE]");
        return FALSE;
    }

    auto &[alloc_info, flags] = process_info[tls.process].heaps[hHeap];
    const auto it = alloc_info.find(lpMem);
    if (it == alloc_info.end()) {
        SetLastError(ERROR_INVALID_PARAMETER);
        ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <BOOL>[FALSE]");
        return FALSE;
    }

    free(lpMem);
    alloc_info.erase(it);

    SetLastError(ERROR_SUCCESS);
    ret("Error set to: ERROR_SUCCESS, Return value: <BOOL>[TRUE]");
    return TRUE;
}

SIZE_T Kernel32::HeapSize(HANDLE hHeap, DWORD dwFlags, LPCVOID lpMem) {
    trace("HeapSize implementation called. Arguments: hHeap=<HANDLE>[", hHeap,
          "], dwFlags=<DWORD>[", dwFlags,
          "], lpMem=<LPCVOID>[", lpMem, "]");

    if (hHeap != GetProcessHeap() && process_info[tls.process].heaps.contains(hHeap))
    {
        SetLastError(ERROR_INVALID_HANDLE);
        ret("Error set to: ERROR_INVALID_HANDLE, Return value: <SIZE_T>[0]");
        return 0;
    }

    if (!lpMem) {
        SetLastError(ERROR_INVALID_PARAMETER);
        ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <SIZE_T>[0]");
        return 0;
    }

    const auto &alloc_info = process_info[tls.process].heaps[hHeap].alloc_info;
    const auto it = alloc_info.find(const_cast<LPVOID>(lpMem));
    if (it == alloc_info.end()) {
        SetLastError(ERROR_INVALID_PARAMETER);
        ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <SIZE_T>[0]");
        return 0;
    }

    SetLastError(ERROR_SUCCESS);
    ret("Error set to: ERROR_SUCCESS, Return value: <SIZE_T>[", it->second.size, "]");
    return it->second.size;
}

HANDLE Kernel32::HeapCreate(DWORD flOptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize) {
    trace("HeapCreate implementation called. Arguments: flOptions=<DWORD>[", flOptions,
          "], dwInitialSize=<SIZE_T>[", dwInitialSize,
          "], dwMaximumSize=<SIZE_T>[", dwMaximumSize, "]");

    HANDLE heap_handle = next_handle;
    next_handle = static_cast<HANDLE>(static_cast<char*>(next_handle) + 1);
    process_info[tls.process].heaps[heap_handle] = {
        .alloc_info = {},
        .flags = flOptions
    };

    SetLastError(ERROR_SUCCESS);
    ret("Error set to: ERROR_SUCCESS, Return value: <HANDLE>[", heap_handle, "]");
    return heap_handle;
}

BOOL Kernel32::HeapDestroy(HANDLE hHeap) {
    trace("HeapDestroy implementation called. Arguments: hHeap=<HANDLE>[", hHeap, "]");

    if (hHeap != GetProcessHeap() && process_info[tls.process].heaps.contains(hHeap))
    {
        SetLastError(ERROR_INVALID_HANDLE);
        ret("Error set to: ERROR_INVALID_HANDLE, Return value: <BOOL>[FALSE]");
        return FALSE;
    }

    for (auto &heap = process_info[tls.process].heaps[hHeap]; const auto &mem: heap.alloc_info | std::views::keys) {
        free(mem);
    }
    process_info[tls.process].heaps.erase(hHeap);

    SetLastError(ERROR_SUCCESS);
    ret("Error set to: ERROR_SUCCESS, Return value: <BOOL>[TRUE]");
    return TRUE;
}

LPVOID Kernel32::HeapReAlloc(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes) {
    trace("HeapReAlloc implementation called. Arguments: hHeap=<HANDLE>[", hHeap,
          "], dwFlags=<DWORD>[", dwFlags,
          "], lpMem=<LPVOID>[", lpMem,
          "], dwBytes=<SIZE_T>[", dwBytes, "]");

    if (hHeap != GetProcessHeap() && process_info[tls.process].heaps.contains(hHeap))
    {
        SetLastError(ERROR_INVALID_HANDLE);
        ret("Error set to: ERROR_INVALID_HANDLE, Return value: <LPVOID>[NULL]");
        return nullptr;
    }

    if (!lpMem) {
        SetLastError(ERROR_INVALID_PARAMETER);
        ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <LPVOID>[NULL]");
        return nullptr;
    }

    if (dwFlags & HEAP_REALLOC_IN_PLACE_ONLY) {
        // supported flag

    }

    auto &[alloc_info, flags] = process_info[tls.process].heaps[hHeap];
    const auto it = alloc_info.find(lpMem);
    if (it == alloc_info.end()) {
        SetLastError(ERROR_INVALID_PARAMETER);
        ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <LPVOID>[NULL]");
        return nullptr;
    }

    void* new_mem = realloc(lpMem, dwBytes);
    if (!new_mem) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        ret("Error set to: ERROR_NOT_ENOUGH_MEMORY, Return value: <LPVOID>[NULL]");
        return nullptr;
    }

    if (dwFlags & HEAP_ZERO_MEMORY && dwBytes > it->second.size) {
        memset(static_cast<char*>(new_mem) + it->second.size, 0, dwBytes - it->second.size);
    }

    if (dwFlags & HEAP_CREATE_ENABLE_EXECUTE) {
        mprotect(new_mem, dwBytes, PROT_READ | PROT_WRITE | PROT_EXEC);
    }

    alloc_info.erase(it);
    alloc_info[new_mem] = {
        .size = dwBytes,
        .flags = flags
    };

    SetLastError(ERROR_SUCCESS);
    ret("Error set to: ERROR_SUCCESS, Return value: <LPVOID>[", new_mem, "]");
    return new_mem;
}

DWORD Kernel32::GetProcessId() {
    trace("GetProcessId implementation called. No arguments.");
    const DWORD current_process_id = reinterpret_cast<uintptr_t>(tls.process);
    ret("Return value: <DWORD>[", current_process_id, "]");
    return current_process_id;
}

DWORD Kernel32::GetThreadId() {
    trace("GetThreadId implementation called. No arguments.");
    const DWORD current_thread_id = reinterpret_cast<uintptr_t>(tls.thread);
    ret("Return value: <DWORD>[", current_thread_id, "]");
    return current_thread_id;
}

void Kernel32::GetStartupInfoW(LPSTARTUPINFOW lpStartupInfo) {
    trace("GetStartupInfoW diserror-stub called. Arguments: lpStartupInfo=<LPSTARTUPINFOW>[", lpStartupInfo, "]");
    if (!lpStartupInfo) {
        return;
    }
    memset(lpStartupInfo, 0, sizeof(STARTUPINFOW));
    lpStartupInfo->cb = sizeof(STARTUPINFOW);
    ret("Return value: <void>");
}

void Kernel32::InitializeSListHead(PSLIST_HEADER ListHead) {
    trace("InitializeSListHead implementation called. Arguments: ListHead=<PSLIST_HEADER>[", ListHead, "]");
    if (!ListHead) {
        return;
    }
    ListHead->Alignment = 0;
    ListHead->Next = nullptr;
    ListHead->Depth = 0;
    ListHead->Sequence = 0;
    ListHead->Padding = 0;
    ret("Return value: <void>");
}

PSLIST_ENTRY Kernel32::InterlockedPushEntrySList(PSLIST_HEADER ListHead, PSLIST_ENTRY ListEntry) {
    trace("InterlockedPushEntrySList implementation called. Arguments: ListHead=<PSLIST_HEADER>[", ListHead,
          "], ListEntry=<PSLIST_ENTRY>[", ListEntry, "]");

    if (!ListHead || !ListEntry) {
        ret("Return value: <PSLIST_ENTRY>[NULL]");
        return nullptr;
    }

    ListEntry->Next = ListHead->Next;
    ListHead->Next = ListEntry;
    ListHead->Depth++;
    ListHead->Sequence++;

    ret("Return value: <PSLIST_ENTRY>[", ListEntry, "]");
    return ListEntry;
}

PSLIST_ENTRY Kernel32::InterlockedPopEntrySList(PSLIST_HEADER ListHead) {
    trace("InterlockedPopEntrySList implementation called. Arguments: ListHead=<PSLIST_HEADER>[", ListHead, "]");

    if (!ListHead || !ListHead->Next) {
        ret("Return value: <PSLIST_ENTRY>[NULL]");
        return nullptr;
    }

    PSLIST_ENTRY entry = ListHead->Next;
    ListHead->Next = entry->Next;
    ListHead->Depth--;
    ListHead->Sequence++;

    ret("Return value: <PSLIST_ENTRY>[", entry, "]");
    return entry;
}

PSLIST_ENTRY Kernel32::InterlockedFlushSList(PSLIST_HEADER ListHead) {
    trace("InterlockedFlushSList implementation called. Arguments: ListHead=<PSLIST_HEADER>[", ListHead, "]");

    if (!ListHead) {
        ret("Return value: <PSLIST_ENTRY>[NULL]");
        return nullptr;
    }

    PSLIST_ENTRY entry = ListHead->Next;
    ListHead->Next = nullptr;
    ListHead->Depth = 0;
    ListHead->Sequence++;

    ret("Return value: <PSLIST_ENTRY>[", entry, "]");
    return entry;
}

PSLIST_ENTRY Kernel32::InterlockedPushListSList(PSLIST_HEADER ListHead, PSLIST_ENTRY List, PSLIST_ENTRY ListEnd,
    ULONG Count) {
    trace("InterlockedPushListSList implementation called. Arguments: ListHead=<PSLIST_HEADER>[", ListHead,
          "], List=<PSLIST_ENTRY>[", List,
          "], ListEnd=<PSLIST_ENTRY>[", ListEnd,
          "], Count=<ULONG>[", Count, "]");

    if (!ListHead || !List || !ListEnd || Count == 0) {
        ret("Return value: <PSLIST_ENTRY>[NULL]");
        return nullptr;
    }

    ListEnd->Next = ListHead->Next;
    ListHead->Next = List;
    ListHead->Depth += Count;
    ListHead->Sequence++;

    ret("Return value: <PSLIST_ENTRY>[", List, "]");
    return List;
}

PSLIST_ENTRY Kernel32::RtlFirstEntrySList(PSLIST_HEADER ListHead) {
    trace("RtlFirstEntrySList implementation called. Arguments: ListHead=<PSLIST_HEADER>[", ListHead, "]");

    if (!ListHead) {
        ret("Return value: <PSLIST_ENTRY>[NULL]");
        return nullptr;
    }

    ret("Return value: <PSLIST_ENTRY>[", ListHead->Next, "]");
    return ListHead->Next;
}

USHORT Kernel32::QueryDepthSList(PSLIST_HEADER ListHead) {
    trace("RtlQueryDepthSList implementation called. Arguments: ListHead=<PSLIST_HEADER>[", ListHead, "]");

    if (!ListHead) {
        ret("Return value: <USHORT>[0]");
        return 0;
    }

    ret("Return value: <USHORT>[", ListHead->Depth, "]");
    return ListHead->Depth;
}

BOOL Kernel32::QueryPerformanceCounter(LARGE_INTEGER *lpPerformanceCount) {
    trace("QueryPerformanceCounter implementation called. Arguments: lpPerformanceCount=<LARGE_INTEGER*>[", lpPerformanceCount, "]");

    if (!lpPerformanceCount) {
        SetLastError(ERROR_INVALID_PARAMETER);
        ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <BOOL>[FALSE]");
        return FALSE;
    }

    timespec ts{};
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        SetLastError(ERROR_INVALID_PARAMETER);
        ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <BOOL>[FALSE]");
        return FALSE;
    }

    lpPerformanceCount->QuadPart = static_cast<LONGLONG>(ts.tv_sec) * 10000000 + static_cast<LONGLONG>(ts.tv_nsec) / 100;

    SetLastError(ERROR_SUCCESS);
    ret("Error set to: ERROR_SUCCESS, Return value: <BOOL>[TRUE]");
    return TRUE;
}

BOOL Kernel32::QueryPerformanceFrequency(LARGE_INTEGER *lpFrequency) {
    trace("QueryPerformanceFrequency implementation called. Arguments: lpFrequency=<LARGE_INTEGER*>[", lpFrequency, "]");

    if (!lpFrequency) {
        SetLastError(ERROR_INVALID_PARAMETER);
        ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <BOOL>[FALSE]");
        return FALSE;
    }

    lpFrequency->QuadPart = 10000000; // 10 million ticks per second

    SetLastError(ERROR_SUCCESS);
    ret("Error set to: ERROR_SUCCESS, Return value: <BOOL>[TRUE]");
    return TRUE;
}

void Kernel32::GetSystemTimeAsFileTime(LPFILETIME lpSystemTimeAsFileTime) {
    trace("GetSystemTimeAsFileTime implementation called. Arguments: lpSystemTimeAsFileTime=<LPFILETIME>[", lpSystemTimeAsFileTime, "]");

    if (!lpSystemTimeAsFileTime) {
        return;
    }

    timespec ts{};
    clock_gettime(CLOCK_REALTIME, &ts);
    constexpr ULONGLONG epoch_diff = 11644473600ULL; // Difference between 1601 and 1970 in seconds
    const ULONGLONG total_100ns = (static_cast<ULONGLONG>(ts.tv_sec) + epoch_diff) * 10000000 + static_cast<ULONGLONG>(ts.tv_nsec) / 100;

    lpSystemTimeAsFileTime->dwLowDateTime = static_cast<DWORD>(total_100ns & 0xFFFFFFFF);
    lpSystemTimeAsFileTime->dwHighDateTime = static_cast<DWORD>((total_100ns >> 32) & 0xFFFFFFFF);

    ret("Return value: <void>");
}

BOOL Kernel32::IsProcessorFeaturePresent(DWORD ProcessorFeature) {
    trace("IsProcessorFeaturePresent diserror-stub called. Arguments: ProcessorFeature=<DWORD>[", ProcessorFeature, "]");
    // Simplified: Assume all features are present (features include PF_FLOATING_POINT_PRECISION_ERRATA, PF_MMX_INSTRUCTIONS_AVAILABLE, etc.)
    ret("Return value: <BOOL>[TRUE]");
    return TRUE;
}

BOOL Kernel32::TerminateProcess(HANDLE hProcess, UINT uExitCode) {
    trace("TerminateProcess implementation called. Arguments: hProcess=<HANDLE>[", hProcess,
          "], uExitCode=<UINT>[", uExitCode, "]");

    if (hProcess == GetCurrentProcess()) {
        // Terminate current process
        exit(static_cast<int>(uExitCode));
    }
    // Terminate another process
    // kill all of it's threads
    if (!process_info.contains(hProcess)) {
        SetLastError(ERROR_INVALID_HANDLE);
        ret("Error set to: ERROR_INVALID_HANDLE, Return value: <BOOL>[FALSE]");
        return FALSE;
    }
    for (const auto &thread: process_info[hProcess].threads | std::views::values) {
        pthread_cancel(thread.thread);
        pthread_join(thread.thread, nullptr);
    }
    SetLastError(ERROR_INVALID_HANDLE);
    ret("Error set to: ERROR_INVALID_HANDLE, Return value: <BOOL>[FALSE]");
    return FALSE;
}

void Kernel32::RtlUnwindEx(LPCONTEXT ContextRecord, PVOID TargetFrame, PVOID TargetIp,
    PEXCEPTION_RECORD ExceptionRecord, LPVOID ReturnValue, PCONTEXT OriginalContext, LPVOID HistoryTable) {
    trace("RtlUnwind diserror-stub called. Arguments: ContextRecord=<LPCONTEXT>[", ContextRecord,
          "], TargetFrame=<PVOID>[", TargetFrame,
          "], TargetIp=<PVOID>[", TargetIp,
          "], ExceptionRecord=<PEXCEPTION_RECORD>[", ExceptionRecord,
          "], ReturnValue=<LPVOID>[", ReturnValue,
          "], OriginalContext=<PCONTEXT>[", OriginalContext,
          "], HistoryTable=<LPVOID>[", HistoryTable, "]");
    // Simplified: No unwinding is performed
    ret("Return value: <void>");
}

void Kernel32::RtlUnwind(LPCONTEXT ContextRecord, PVOID TargetFrame, PVOID TargetIp,
    PEXCEPTION_RECORD ExceptionRecord, LPVOID ReturnValue) {
    trace("RtlUnwind diserror-stub called. Arguments: ContextRecord=<LPCONTEXT>[", ContextRecord,
          "], TargetFrame=<PVOID>[", TargetFrame,
          "], TargetIp=<PVOID>[", TargetIp,
          "], ExceptionRecord=<PEXCEPTION_RECORD>[", ExceptionRecord,
          "], ReturnValue=<LPVOID>[", ReturnValue, "]");
    // Simplified: No unwinding is performed
    ret("Return value: <void>");
}

LPVOID Kernel32::EncodePointer(LPVOID Ptr) {
    trace("EncodePointer diserror-stub called. Arguments: Ptr=<LPVOID>[", Ptr, "]");
    // Simplified: No actual encoding is performed
    ret("Return value: <LPVOID>[", Ptr, "]");
    return Ptr;
}

LPVOID Kernel32::DecodePointer(LPVOID Ptr) {
    trace("DecodePointer diserror-stub called. Arguments: Ptr=<LPVOID>[", Ptr, "]");
    // Simplified: No actual decoding is performed
    ret("Return value: <LPVOID>[", Ptr, "]");
    return Ptr;
}

PVOID Kernel32::RtlPcToFileHeader(PVOID PcValue, PVOID*BaseOfImage) {
    if (!PcValue || !BaseOfImage) {
        trace("RtlPcToFileHeader: Invalid parameters - PcValue:", PcValue, " BaseOfImage:", BaseOfImage);
        if (BaseOfImage) {
            *BaseOfImage = nullptr;
        }
        return nullptr;
    }

    const auto pc_addr = reinterpret_cast<uintptr_t>(PcValue);
    trace("RtlPcToFileHeader: Looking up PC address 0x", std::to_wstring(pc_addr));

    //std::lock_guard<std::mutex> lock(g_modules_mutex);

    // Search through all loaded modules
    for (const auto& [module_name, module_info] : process_info[tls.process].modules) {
        const uintptr_t module_start = module_info.base_address;

        // Check if the PC address falls within this module's address range
        if (const uintptr_t module_end = module_start + module_info.size; pc_addr >= module_start && pc_addr < module_end) {
            trace("RtlPcToFileHeader: Found PC 0x", std::to_wstring(pc_addr),
                  " in module ", module_name, " (base: 0x", std::to_wstring(module_start), ")");
            *BaseOfImage = reinterpret_cast<PVOID>(module_info.base_address);
            return PcValue; // Return the input PcValue to indicate success
        }
    }

    // Also check the main executable if it's loaded
    if (process_info.contains(tls.process)) {
        if (HMODULE main_module = process_info[tls.process].process_hmodule) {
            const auto main_base = reinterpret_cast<uintptr_t>(main_module);

            if (const auto main_size = process_info[tls.process].image_size; pc_addr >= main_base && pc_addr < main_base + main_size) {
                trace("RtlPcToFileHeader: Found PC 0x", std::to_wstring(pc_addr),
                      " in main executable (base: 0x", std::to_wstring(main_base), ")");
                *BaseOfImage = main_module;
                return PcValue; // Return the input PcValue to indicate success
            }
        }
    }

    warn("RtlPcToFileHeader: No module found containing PC address 0x", std::to_wstring(pc_addr));
    *BaseOfImage = nullptr;
    return nullptr;
}

DWORD Kernel32::TlsAlloc() {
    trace("TlsAlloc implementation called. No arguments.");
    tls.tls_data.push_back(nullptr);
    const DWORD index = tls.tls_data.size();
    ret("Return value: <DWORD>[", index, "]");
    return index;
}

BOOL Kernel32::TlsFree(DWORD dwTlsIndex) {
    trace("TlsFree implementation called. Arguments: dwTlsIndex=<DWORD>[", dwTlsIndex, "]");

    if (dwTlsIndex == 0 || dwTlsIndex > tls.tls_data.size()) {
        SetLastError(ERROR_INVALID_PARAMETER);
        ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <BOOL>[FALSE]");
        return FALSE;
    }

    tls.tls_data[dwTlsIndex - 1] = nullptr;

    SetLastError(ERROR_SUCCESS);
    ret("Error set to: ERROR_SUCCESS, Return value: <BOOL>[TRUE]");
    return TRUE;
}

LPVOID Kernel32::TlsGetValue(DWORD dwTlsIndex) {
    trace("TlsGetValue implementation called. Arguments: dwTlsIndex=<DWORD>[", dwTlsIndex, "]");

    if (dwTlsIndex == 0 || dwTlsIndex > tls.tls_data.size()) {
        SetLastError(ERROR_INVALID_PARAMETER);
        ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <LPVOID>[NULL]");
        return nullptr;
    }

    LPVOID value = tls.tls_data[dwTlsIndex - 1];

    SetLastError(ERROR_SUCCESS);
    ret("Error set to: ERROR_SUCCESS, Return value: <LPVOID>[", value, "]");
    return value;
}

BOOL Kernel32::TlsSetValue(DWORD dwTlsIndex, LPVOID lpTlsValue) {
    trace("TlsSetValue implementation called. Arguments: dwTlsIndex=<DWORD>[", dwTlsIndex,
          "], lpTlsValue=<LPVOID>[", lpTlsValue, "]");

    if (dwTlsIndex == 0 || dwTlsIndex > tls.tls_data.size()) {
        SetLastError(ERROR_INVALID_PARAMETER);
        ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <BOOL>[FALSE]");
        return FALSE;
    }

    tls.tls_data[dwTlsIndex - 1] = lpTlsValue;

    SetLastError(ERROR_SUCCESS);
    ret("Error set to: ERROR_SUCCESS, Return value: <BOOL>[TRUE]");
    return TRUE;
}

bool Kernel32::is_wchar_surrogate_high(WCHAR wc) { return (wc >= 0xD800 && wc <= 0xDBFF); }

bool Kernel32::is_wchar_surrogate_low(WCHAR wc) { return (wc >= 0xDC00 && wc <= 0xDFFF); }

WORD Kernel32::map_category_to_C1(int8_t cat, UChar32 codepoint) {
    WORD flags = 0;

    switch (cat) {
        case U_UPPERCASE_LETTER:
        case U_TITLECASE_LETTER:
            flags |= C1_UPPER | C1_ALPHA;
            break;
        case U_LOWERCASE_LETTER:
            flags |= C1_LOWER | C1_ALPHA;
            break;
        case U_DECIMAL_DIGIT_NUMBER:
            flags |= C1_DIGIT;
            break;
        case U_LETTER_NUMBER:
        case U_OTHER_LETTER:
        case U_MODIFIER_LETTER:
            // letterlike
            flags |= C1_ALPHA;
            break;
        case U_SPACE_SEPARATOR:
        case U_LINE_SEPARATOR:
        case U_PARAGRAPH_SEPARATOR:
            flags |= C1_SPACE;
            break;
        case U_CONTROL_CHAR:
            flags |= C1_CNTRL;
            break;
        case U_CONNECTOR_PUNCTUATION:
        case U_DASH_PUNCTUATION:
        case U_START_PUNCTUATION:
        case U_END_PUNCTUATION:
        case U_OTHER_PUNCTUATION:
        case U_INITIAL_PUNCTUATION:
        case U_FINAL_PUNCTUATION:
            flags |= C1_PUNCT;
            break;
        case U_OTHER_SYMBOL:
        case U_CURRENCY_SYMBOL:
        case U_MATH_SYMBOL:
        case U_MODIFIER_SYMBOL:
            // Symbols are not C1_PUNCT but do want C3_SYMBOL set; for C1 we generally don't set anything except maybe XDIGIT
            break;
        default:
            break;
    }

    // Hex digit: Unicode provides property for ASCII hex digits and many fullwidth hex digits.
    // We check ASCII range and Unicode property ASCII_HEX_DIGIT
    if (u_hasBinaryProperty(codepoint, UCHAR_ASCII_HEX_DIGIT) || u_hasBinaryProperty(codepoint, UCHAR_HEX_DIGIT)) {
        flags |= C1_XDIGIT;
    } else {
        // fallback: treat ASCII hex letters and digits as hex
        if ((codepoint >= '0' && codepoint <= '9') ||
            (codepoint >= 'A' && codepoint <= 'F') ||
            (codepoint >= 'a' && codepoint <= 'f')) {
            flags |= C1_XDIGIT;
        }
    }

    // Blank (space or tab) — Windows C1_BLANK is 'space or tab' typically.
    // Use Unicode White_Space property but restrict to HTAB and SPACE and no other spaces?
    // Windows BLANK historically is only ' ' and '\t'. We'll set BLANK for U+0009 and U+0020 and their fullwidth/tab equivalents.
    if (codepoint == 0x0009 || codepoint == 0x0020) {
        flags |= C1_BLANK;
    }

    // iswalpha-like duplication for C1_ALPHA if not already set
    if (!(flags & C1_ALPHA)) {
        // categories that are letters or other letterlike categories
        if (cat == U_UPPERCASE_LETTER || cat == U_LOWERCASE_LETTER ||
            cat == U_TITLECASE_LETTER || cat == U_MODIFIER_LETTER ||
            cat == U_OTHER_LETTER) {
            flags |= C1_ALPHA;
        }
    }

    return flags;
}

WORD Kernel32::map_bidi_to_C2(UCharDirection dir, UChar32 c) {
    switch (dir) {
        case U_LEFT_TO_RIGHT:
            return C2_LEFTTORIGHT;
        case U_RIGHT_TO_LEFT:
        case U_RIGHT_TO_LEFT_ARABIC:
            return C2_RIGHTTOLEFT;
        case U_EUROPEAN_NUMBER:
        case U_EUROPEAN_NUMBER_SEPARATOR:
        case U_EUROPEAN_NUMBER_TERMINATOR:
            // map specific ones
            if (dir == U_EUROPEAN_NUMBER) return C2_EUROPENUMBER;
            if (dir == U_EUROPEAN_NUMBER_SEPARATOR) return C2_EUROPESEPARATOR;
            if (dir == U_EUROPEAN_NUMBER_TERMINATOR) return C2_EUROPETERMINATOR;
            break;
        case U_ARABIC_NUMBER:
            return C2_ARABICNUMBER;
        case U_COMMON_NUMBER_SEPARATOR:
        case U_OTHER_NEUTRAL:
        default:
            // whitespace detection (space separators)
            if (u_hasBinaryProperty(c, UCHAR_WHITE_SPACE)) return C2_WHITESPACE;
            return C2_OTHERNEUTRAL;
    }
    return C2_OTHERNEUTRAL;
}

WORD Kernel32::map_to_C3(UChar32 c) {
    WORD flags = 0;

    // Nonspacing: combining class != 0 typically -> nonspacing/combining mark
    uint8_t comb = u_getCombiningClass(c);
    if (comb != 0) flags |= C3_NONSPACING;

    // Diacritic: Unicode has DIACRITIC binary property
    if (u_hasBinaryProperty(c, UCHAR_DIACRITIC)) flags |= C3_DIACRITIC;

    // Vowel mark: ICU exposes Indic categories (INDIC_SYLLABIC_CATEGORY or INDIC_POS). We'll heuristically set VOWELMARK
    // when UCHAR_INDIC_SYLLABIC_CATEGORY is a vowel sign (INSC_VowelSign etc).
    // Use u_getIntPropertyValue with UCHAR_INDIC_SYLLABIC_CATEGORY (if available).
#if U_HAVE_BIG_ENDIAN
    // fallback: leave out if old ICU; but normally UCHAR_INDIC_SYLLABIC_CATEGORY exists in modern ICU
#endif
    int32_t isc = u_getIntPropertyValue(c, UCHAR_INDIC_SYLLABIC_CATEGORY);
    // ICU enum values for Indic syllabic category: UISC_Vowel_Independent, UISC_Vowel_Dependent etc.
    // Any 'vowel' dependent/independent set -> mark VOWELMARK
    // SYMBOL: Unicode general categories Sm Sc Sk So -> mark SYMBOL
    const int8_t cat = u_charType(c);
    if (cat == U_MATH_SYMBOL || cat == U_CURRENCY_SYMBOL || cat == U_MODIFIER_SYMBOL || cat == U_OTHER_SYMBOL) {
        flags |= C3_SYMBOL;
    }

    // Katakana / Hiragana: use uscript_getScript
    UErrorCode err = U_ZERO_ERROR;
    const UScriptCode sc = uscript_getScript(c, &err);
    if (U_SUCCESS(err)) {
        if (sc == USCRIPT_KATAKANA) flags |= C3_KATAKANA;
        if (sc == USCRIPT_HIRAGANA) flags |= C3_HIRAGANA;
        if (sc == USCRIPT_HAN) flags |= C3_IDEOGRAPH;
    }

    // Fullwidth / Halfwidth: use East Asian Width property
    const int32_t eaw = u_getIntPropertyValue(c, UCHAR_EAST_ASIAN_WIDTH);
    // ICU enumerants: U_EA_FULLWIDTH, U_EA_HALFWIDTH
    if (eaw == U_EA_FULLWIDTH) flags |= C3_FULLWIDTH;
    if (eaw == U_EA_HALFWIDTH) flags |= C3_HALFWIDTH;

    // Ideograph: use Unicode property IDEOGRAPHIC if available OR script Han
    if (u_hasBinaryProperty(c, UCHAR_IDEOGRAPHIC) || (uscript_getScript(c, &err) == USCRIPT_HAN)) {
        flags |= C3_IDEOGRAPH;
    }

    // Kashida: U+0640 ARABIC TATWEEL (Kashida)
    if (c == 0x0640) flags |= C3_KASHIDA;

    // Lexical: Windows sometimes sets this for characters that participate in word boundaries; we set heuristically for dash/connector punctuation
    if (cat == U_DASH_PUNCTUATION || cat == U_CONNECTOR_PUNCTUATION) flags |= C3_LEXICAL;

    // Alpha (C3_ALPHA): mark for letters (Unicode Alphabetic property)
    if (u_hasBinaryProperty(c, UCHAR_ALPHABETIC)) flags |= C3_ALPHA;

    return flags;
}

BOOL Kernel32::GetStringTypeW(DWORD dwInfoType, LPCWCH lpSrcStr, int cchSrc, LPWORD lpCharType) {
    if (lpSrcStr == nullptr || lpCharType == nullptr) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (cchSrc == -1) {
        // compute length until NUL (counts wchar_t units)
        cchSrc = static_cast<int>(UCRTBase::wcslen_(lpSrcStr));
    } else if (cchSrc < 0) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    // iterate code points correctly across surrogates using ICU macro U16_NEXT
    // input is UTF-16 (WCHAR is 16-bit on Windows; on Unix use wchar_t, but here we assume 16-bit or UTF-16 input provided)
    // We'll treat LPCWCH as 16-bit code units; cast to UChar*
    const auto u16 = reinterpret_cast<const UChar *>(lpSrcStr);
    int32_t idx = 0;
    const int32_t length = cchSrc;

    for (int out_i = 0; idx < length; ++out_i) {
        UChar32 codepoint = 0;
        U16_NEXT(u16, idx, length, codepoint); // updates idx to the next code unit position; codepoint is UTF-32 value

        WORD outFlags = 0;

        if (dwInfoType == CT_CTYPE1) {
            // Map Unicode general category + properties to C1_* flags
            const int8_t cat = u_charType(codepoint);
            outFlags = map_category_to_C1(cat, codepoint);

            // Control characters: Unicode Cc -> C1_CNTRL
            if (cat == U_CONTROL_CHAR) outFlags |= C1_CNTRL;

            // space: include characters with Unicode White_Space
            if (u_hasBinaryProperty(codepoint, UCHAR_WHITE_SPACE)) outFlags |= C1_SPACE;

            // ensure digits map
            if (cat == U_DECIMAL_DIGIT_NUMBER) outFlags |= C1_DIGIT;

            // Historically, MS C runtime also marks ASCII letters as ALPHA/UPPER/LOWER; ICU covers that via categories.
        }
        else if (dwInfoType == CT_CTYPE2) {
            // Map bidi class to C2_* flags
            const UCharDirection dir = u_charDirection(codepoint);
            outFlags = map_bidi_to_C2(dir, codepoint);

            // whitespace explicit
            if (u_hasBinaryProperty(codepoint, UCHAR_WHITE_SPACE)) outFlags = C2_WHITESPACE;
        }
        else if (dwInfoType == CT_CTYPE3) {
            // Aggregate many C3 attributes
            outFlags = map_to_C3(codepoint);
        }
        else {
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
        }

        lpCharType[out_i] = outFlags;
    }

    return TRUE;
}