// kernel32.hpp
// Description: Emulation of selected kernel32.dll functions for a custom Windows-like environment.
#pragma once
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


class Kernel32 {
public:
    std::unordered_map<std::string, void*> exports;

    Kernel32() = default;

    static std::unordered_map<std::string, void*> get_exports() {
        return {
                    {"ExitProcess", reinterpret_cast<void*>(ExitProcess)},
                    {"SetLastError", reinterpret_cast<void*>(SetLastError)},
                    {"GetLastError", reinterpret_cast<void*>(GetLastError)},
                    {"Sleep", reinterpret_cast<void*>(Sleep)},
                    {"GetTickCount", reinterpret_cast<void*>(GetTickCount)},
                    {"GetTickCount64", reinterpret_cast<void*>(GetTickCount64)},
                    {"GetCurrentThreadId", reinterpret_cast<void*>(GetCurrentThreadId)},
                    {"CreateFileW", reinterpret_cast<void*>(CreateFileW)},
                    {"ReadFile", reinterpret_cast<void*>(ReadFile)},
                    {"WriteFile", reinterpret_cast<void*>(WriteFile)},
                    {"DeleteFileW", reinterpret_cast<void*>(DeleteFileW)},
                    {"CloseHandle", reinterpret_cast<void*>(CloseHandle)},
                    {"WaitForSingleObject", reinterpret_cast<void*>(WaitForSingleObject)},
                    {"WaitForSingleObjectEx", reinterpret_cast<void*>(WaitForSingleObjectEx)},
                    {"WaitForMultipleObjects", reinterpret_cast<void*>(WaitForMultipleObjects)},
                    {"WaitForMultipleObjectsEx", reinterpret_cast<void*>(WaitForMultipleObjectsEx)},
                    {"QueueUserAPC", reinterpret_cast<void*>(QueueUserAPC)},
                    {"GetFileSize", reinterpret_cast<void*>(GetFileSize)},
                    {"SetFilePointer", reinterpret_cast<void*>(SetFilePointer)},
                    {"SetFilePointerEx", reinterpret_cast<void*>(SetFilePointerEx)},
                    {"FlushFileBuffers", reinterpret_cast<void*>(FlushFileBuffers)},
                    {"WideCharToMultiByte", reinterpret_cast<void*>(WideCharToMultiByte)},
                    {"MultiByteToWideChar", reinterpret_cast<void*>(MultiByteToWideChar)},
                    {"FindFirstFileW", reinterpret_cast<void*>(FindFirstFileW)},
                    {"FindNextFileW", reinterpret_cast<void*>(FindNextFileW)},
                    {"FindClose", reinterpret_cast<void*>(FindClose)},
                    {"FindFirstFileExW", reinterpret_cast<void*>(FindFirstFileExW)},
                    {"LoadLibraryW", reinterpret_cast<void*>(LoadLibraryW)},
                    {"GetProcAddress", reinterpret_cast<void*>(GetProcAddress)},
                    {"FreeLibrary", reinterpret_cast<void*>(FreeLibrary)},
                    {"GetModuleFileNameW", reinterpret_cast<void*>(GetModuleFileNameW)},
                };
    }

    static void WINAPI ExitProcess(UINT exit_code)  {
        trace("ExitProcess implementation called. Arguments: exit_code=<UINT>[", exit_code, "]");
        std::exit(static_cast<int>(exit_code));
    }

    static void WINAPI SetLastError(DWORD error_code) {
        trace("SetLastError implementation called. Arguments: error_code=<DWORD>[", error_code, "]");
        tls.last_error = error_code;
        ret("Error set to: ", error_code, ", Return value: <VOID>[]");
    }

    static DWORD GetLastError() {
        trace("GetLastError implementation called. Arguments:");
        ret("Error unset, Return Value: <DWORD>[", tls.last_error, "]");
        return tls.last_error;
    }

    static void WINAPI Sleep(DWORD milliseconds) {
        trace("Sleep implementation called. Arguments: milliseconds=<DWORD>[", milliseconds, "]");
        std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
        SetLastError(ERROR_SUCCESS);
        ret("Error set to: ERROR_SUCCESS, Return value: <VOID>[]");
    }

    static DWORD WINAPI GetTickCount() {
        trace("GetTickCount implementation called. Arguments:");
        SetLastError(ERROR_SUCCESS);
        ret("Error set to: ERROR_SUCCESS, Return value: <DWORD>[", static_cast<DWORD>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count()), "]");
        return static_cast<DWORD>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    }

    static ULONGLONG WINAPI GetTickCount64() {
        trace("GetTickCount64 implementation called. Arguments:");
        SetLastError(ERROR_SUCCESS);
        ret("Error set to: ERROR_SUCCESS, Return value: <ULONGLONG>[", static_cast<ULONGLONG>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count()), "]");
        return static_cast<ULONGLONG>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    }

    static DWORD WINAPI GetCurrentThreadId() {
        trace("GetCurrentThreadId implementation called. Arguments:");
        SetLastError(ERROR_SUCCESS);
        ret("Error set to: ERROR_SUCCESS, Return value: <DWORD>[", tls.thread, "]");
        return reinterpret_cast<DWORD>(tls.thread);
    }

    static HANDLE WINAPI CreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
                                      LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
                                      DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
        std::wstring file_name(lpFileName ? lpFileName : L"");
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

        const int fd = open(std::string(file_name.begin(), file_name.end()).c_str(), flags, mode);
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

    static BOOL WINAPI ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead,
                                LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped) {
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

    static BOOL WINAPI WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite,
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

    static BOOL WINAPI DeleteFileW(LPCWSTR lpFileName) {
        std::wstring file_name(lpFileName ? lpFileName : L"");
        trace("DeleteFileW implementation called. Arguments: lpFileName=<LPCWSTR>[", lpFileName, "]");

        if (file_name.empty()) {
            SetLastError(ERROR_INVALID_PARAMETER);
            ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <BOOL>[FALSE]");
            return FALSE;
        }

        if (remove(std::string(file_name.begin(), file_name.end()).c_str()) != 0) {
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

    static BOOL WINAPI CloseHandle(HANDLE hObject) {
        trace("CloseHandle implementation called. Arguments: hObject=<HANDLE>[", hObject, "]");
        if (const auto handle = reinterpret_cast<ULONG_PTR>(hObject); handle > process_info.size()) {
            SetLastError(ERROR_INVALID_HANDLE);
            ret("Error set to: ERROR_INVALID_HANDLE, Return value: <BOOL>[FALSE]");
            return FALSE;
        }

        // check if is a process handle
        if (process_info.contains(hObject)) {
            // kill all the threads
            for (const auto &thread_info: process_info[hObject].threads | std::views::values) {
                pthread_kill(thread_info, SIGKILL);
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
            pthread_kill(process_info[tls.process].threads[hObject], SIGKILL);
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

    static DWORD WINAPI WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds) {
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
            if (process_info[tls.process].threads[hHandle]) {
                if (timeout == -1) {
                    pthread_join(process_info[tls.process].threads[hHandle], nullptr);
                    SetLastError(ERROR_SUCCESS);
                    ret("Error set to: ERROR_SUCCESS, Return value: <DWORD>[", WAIT_OBJECT_0, "]");
                    return WAIT_OBJECT_0;
                }
                while (std::chrono::steady_clock::now() < timeout_time) {
                    // Check if the thread is still alive
                    if (pthread_kill(process_info[tls.process].threads[hHandle], 0) != 0) {
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
            } else {
                const auto now = std::chrono::steady_clock::now();
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
                const auto now = std::chrono::steady_clock::now();
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

    static DWORD WINAPI WaitForSingleObjectEx(HANDLE hHandle, DWORD dwMilliseconds, BOOL bAlertable)
    {
        trace("WaitForSingleObjectEx implementation called. Arguments: hHandle=<HANDLE>[", hHandle, "], dwMilliseconds=<DWORD>[", dwMilliseconds, "], bAlertable=<BOOL>[", bAlertable, "]");
        if (bAlertable) {
            // basically the same as WaitForSingleObject but with checkings of apc queue
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

    static DWORD WINAPI WaitForMultipleObjects(DWORD nCount, const HANDLE* lpHandles, BOOL bWaitAll, DWORD dwMilliseconds) {
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

    static DWORD WINAPI WaitForMultipleObjectsEx(DWORD nCount, const HANDLE* lpHandles, BOOL bWaitAll, DWORD dwMilliseconds, BOOL bAlertable) {
        trace("WaitForMultipleObjectsEx implementation called. Arguments: nCount=<DWORD>[", nCount,
              "], lpHandles=<const HANDLE*>[", lpHandles, "], bWaitAll=<BOOL>[", bWaitAll,
              "], dwMilliseconds=<DWORD>[", dwMilliseconds, "], bAlertable=<BOOL>[", bAlertable, "]");
        if (bAlertable) {
            // basically the same as WaitForMultipleObjects but with checkings of apc queue
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

    static BOOL QueueUserAPC(PAPCFUNC pfnAPC, HANDLE hThread, ULONG_PTR dwData) {
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

    static DWORD GetFileSize(HANDLE hFile, LPDWORD lpFileSizeHigh) {
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
    static DWORD SetFilePointer(HANDLE hFile, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod) {
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

    static DWORD SetFilePointerEx(HANDLE hFile, LARGE_INTEGER liDistanceToMove, PLARGE_INTEGER lpNewFilePointer, DWORD dwMoveMethod) {
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

    static BOOL FlushFileBuffers(HANDLE hFile) {
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

    static INT WideCharToMultiByte(UINT CodePage, DWORD dwFlags, LPCWCH lpWideCharStr, int cchWideChar,
                                     LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar,
                                     LPBOOL lpUsedDefaultChar) {
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

        const int required_size = std::wcstombs(nullptr, lpWideCharStr, 0);
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

        int converted_size = std::wcstombs(lpMultiByteStr, lpWideCharStr, cbMultiByte);
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

    static INT MultiByteToWideChar(UINT CodePage, DWORD dwFlags, LPCCH lpMultiByteStr, int cbMultiByte,
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

        const int required_size = std::mbstowcs(nullptr, lpMultiByteStr, 0);
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

        int converted_size = std::mbstowcs(lpWideCharStr, lpMultiByteStr, cchWideChar);
        if (converted_size == -1) {
            SetLastError(ERROR_INVALID_PARAMETER);
            ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <INT>[-1]");
            return -1;
        }

        SetLastError(ERROR_SUCCESS);
        ret("Error set to: ERROR_SUCCESS, Return value: <INT>[", converted_size, "]");
        return converted_size;
    }

private:
    // Helper function for pattern matching
    static bool match_pattern(const std::string& filename, const std::string& pattern, bool case_sensitive = false) {
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

    // Convert Unix file attributes to Windows file attributes
    static DWORD get_windows_attributes(const struct stat& file_stat, const std::string& filename) {
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

    // Convert Unix timestamp to Windows FILETIME
    static FILETIME unix_to_filetime(time_t unix_time) {
        FILETIME ft{};
        constexpr uint64_t EPOCH_DIFF = 116444736000000000ULL;
        const uint64_t file_time = (static_cast<uint64_t>(unix_time) * 10000000ULL) + EPOCH_DIFF;

        ft.dwLowDateTime = static_cast<DWORD>(file_time & 0xFFFFFFFF);
        ft.dwHighDateTime = static_cast<DWORD>((file_time >> 32) & 0xFFFFFFFF);
        return ft;
    }

    static bool fill_find_data(WIN32_FIND_DATAW* find_data, const std::string& filename,
                              const std::string& full_path, bool basic_info = false) {
        struct stat file_stat{};
        if (stat(full_path.c_str(), &file_stat) != 0) {
            return false;
        }

        memset(find_data, 0, sizeof(WIN32_FIND_DATAW));

        std::wstring wide_filename(filename.begin(), filename.end());
        wcsncpy(find_data->cFileName, wide_filename.c_str(),
               std::min(wide_filename.length(), static_cast<size_t>(MAX_PATH - 1)));
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

public:
    static HANDLE WINAPI FindFirstFileW(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData) {
        trace("FindFirstFileW implementation called. Arguments: lpFileName=<LPCWSTR>[", lpFileName,
              "], lpFindFileData=<LPWIN32_FIND_DATAW>[", lpFindFileData, "]");

        if (!lpFileName || !lpFindFileData) {
            SetLastError(ERROR_INVALID_PARAMETER);
            ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <HANDLE>[INVALID_HANDLE_VALUE]");
            return INVALID_HANDLE_VALUE;
        }

        std::wstring search_pattern_w(lpFileName);
        std::string search_pattern(search_pattern_w.begin(), search_pattern_w.end());

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

    static HANDLE WINAPI FindFirstFileExW(LPCWSTR lpFileName, FINDEX_INFO_LEVELS fInfoLevelId,
                                          LPVOID lpFindFileData, FINDEX_SEARCH_OPS fSearchOp,
                                          LPVOID lpSearchFilter, DWORD dwAdditionalFlags) {
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

        std::wstring search_pattern_w(lpFileName);
        std::string search_pattern(search_pattern_w.begin(), search_pattern_w.end());

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

    static BOOL WINAPI FindNextFileW(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData) {
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

    static BOOL WINAPI FindClose(HANDLE hFindFile) {
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

    static LPCWSTR GetCommandLineW() {
        trace("GetCommandLineW implementation called. No arguments.");
        return process_info[tls.process].command_line.c_str();
    }

    static HANDLE GetCurrentProcess() {
        trace("GetCurrentProcess implementation called. No arguments.");
        return reinterpret_cast<HANDLE>(-1); // Pseudo-handle for the current process
    }

    static HMODULE GetModuleHandleW(LPCWSTR lpModuleName) {
        trace("GetModuleHandleW implementation called. Arguments: lpModuleName=<LPCWSTR>[", lpModuleName, "]");

        if (!lpModuleName) {
            // means current module
            SetLastError(ERROR_SUCCESS);
            ret("Error set to: ERROR_SUCCESS, Return value: <HMODULE>[", process_info[tls.process].process_hmodule, "]");
            return process_info[tls.process].process_hmodule;
        }

        std::wstring module_name_w(lpModuleName);
        std::string module_name(module_name_w.begin(), module_name_w.end());
        std::ranges::transform(module_name, module_name.begin(), ::tolower);
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

    static HMODULE WINAPI LoadLibraryW(LPCWSTR lpLibFileName) {
        trace("LoadLibraryW implementation called. Arguments: lpLibFileName=<LPCWSTR>[", lpLibFileName, "]");

        if (!lpLibFileName) {
            SetLastError(ERROR_INVALID_PARAMETER);
            ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <HMODULE>[NULL]");
            return nullptr;
        }

        std::wstring lib_name_w(lpLibFileName);
        std::string lib_name(lib_name_w.begin(), lib_name_w.end());
        std::ranges::transform(lib_name, lib_name.begin(), ::tolower);

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
                lib_name + ".dll",
                lib_name.substr(0, lib_name.find_last_of('.')) + ".so",
                "lib" + lib_name.substr(0, lib_name.find_last_of('.')) + ".so"
            };

            for (const auto& variation : name_variations) {
                auto candidate = search_path / variation;
                if (std::filesystem::exists(candidate)) {
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
                // Not a PE file, create a stub module
                HMODULE hModule = next_handle;
                next_handle = static_cast<HANDLE>(static_cast<char*>(next_handle) + 1);

                ProcessModuleInfo mod_info;
                strncpy(mod_info.name, lib_name.c_str(), sizeof(mod_info.name) - 1);
                strncpy(mod_info.path, lib_path.string().c_str(), sizeof(mod_info.path) - 1);
                mod_info.base_address = reinterpret_cast<uintptr_t>(hModule);

                process_info[tls.process].modules[hModule] = mod_info;

                SetLastError(ERROR_SUCCESS);
                ret("Error set to: ERROR_SUCCESS, Return value: <HMODULE>[", hModule, "] (stub)");
                return hModule;
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

    static FARPROC WINAPI GetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
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
        if (auto kernel32_exports = get_exports(); kernel32_exports.contains(proc_name)) {
            SetLastError(ERROR_SUCCESS);
            ret("Error set to: ERROR_SUCCESS, Return value: <FARPROC>[",
                kernel32_exports[proc_name], "] (emulated)");
            return reinterpret_cast<FARPROC>(kernel32_exports[proc_name]);
        }

        // Check loaded modules
        if (process_info[tls.process].modules.contains(hModule)) {
            const auto& mod_info = process_info[tls.process].modules[hModule];
            if (mod_info.exports.contains(proc_name)) {
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

    static BOOL WINAPI FreeLibrary(HMODULE hLibModule) {
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
                munmap(reinterpret_cast<void*>(mod_info.base_address), 4096);
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

    static DWORD WINAPI GetModuleFileNameW(HMODULE hModule, LPWSTR lpFilename, DWORD nSize) {
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
        std::string path = mod_info.path;
        std::wstring path_w(path.begin(), path.end());

        if (path_w.length() >= nSize) {
            // Buffer too small
            wcsncpy(lpFilename, path_w.c_str(), nSize - 1);
            lpFilename[nSize - 1] = L'\0';
            SetLastError(ERROR_INSUFFICIENT_BUFFER);
            ret("Error set to: ERROR_INSUFFICIENT_BUFFER, Return value: <DWORD>[", nSize - 1, "]");
            return nSize - 1;
        } else {
            wcscpy(lpFilename, path_w.c_str());
            SetLastError(ERROR_SUCCESS);
            ret("Error set to: ERROR_SUCCESS, Return value: <DWORD>[", path_w.length(), "]");
            return static_cast<DWORD>(path_w.length());
        }
    }

    static BOOL SetEnvironmentVariableW(LPCWSTR lpName, LPCWSTR lpValue) {
        trace("SetEnvironmentVariableW implementation called. Arguments: lpName=<LPCWSTR>[", lpName,
              "], lpValue=<LPCWSTR>[", lpValue, "]");

        if (!lpName || wcslen(lpName) == 0 || wcscmp(lpName, L"=") == 0) {
            SetLastError(ERROR_INVALID_PARAMETER);
            ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <BOOL>[FALSE]");
            return FALSE;
        }

        std::wstring name_w(lpName);
        std::string name(name_w.begin(), name_w.end());

        if (lpValue) {
            std::wstring value_w(lpValue);
            const std::string value(value_w.begin(), value_w.end());
            environment[name] = value;
            trace("Environment variable set: ", std::wstring(name.begin(), name.end()));
        } else {
            environment.erase(name);
            trace("Environment variable removed: ", std::wstring(name.begin(), name.end()));
        }

        SetLastError(ERROR_SUCCESS);
        ret("Error set to: ERROR_SUCCESS, Return value: <BOOL>[TRUE]");
        return TRUE;
    }

    static DWORD WINAPI GetEnvironmentVariableW(LPCWSTR lpName, LPWSTR lpBuffer, DWORD nSize) {
        trace("GetEnvironmentVariableW implementation called. Arguments: lpName=<LPCWSTR>[", lpName,
              "], lpBuffer=<LPWSTR>[", lpBuffer, "], nSize=<DWORD>[", nSize, "]");

        if (!lpName || wcslen(lpName) == 0 || wcscmp(lpName, L"=") == 0) {
            SetLastError(ERROR_INVALID_PARAMETER);
            ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <DWORD>[0]");
            return 0;
        }

        std::wstring name_w(lpName);
        std::string name(name_w.begin(), name_w.end());

        if (!environment.contains(name)) {
            SetLastError(ERROR_ENVVAR_NOT_FOUND);
            ret("Error set to: ERROR_ENVVAR_NOT_FOUND, Return value: <DWORD>[0]");
            return 0;
        }

        const std::string& value = environment[name];
        const std::wstring value_w(value.begin(), value.end());
        const size_t required_size = value_w.length();

        if (nSize == 0) {
            SetLastError(ERROR_SUCCESS);
            ret("Error set to: ERROR_SUCCESS, Return value: <DWORD>[", required_size, "] (buffer size query)");
            return required_size;
        }
        if (nSize <= required_size) {
            if (nSize > 0) {
                wcsncpy(lpBuffer, value_w.c_str(), nSize - 1);
                lpBuffer[nSize - 1] = L'\0';
            }
            SetLastError(ERROR_INSUFFICIENT_BUFFER);
            ret("Error set to: ERROR_INSUFFICIENT_BUFFER, Return value: <DWORD>[", required_size, "]");
            return required_size;
        }
        wcscpy(lpBuffer, value_w.c_str());
        SetLastError(ERROR_SUCCESS);
        ret("Error set to: ERROR_SUCCESS, Return value: <DWORD>[", required_size, "]");
        return required_size;
    }

    // <idonotcare>
    static void InitializeCriticalSection(LPCRITICAL_SECTION lpCriticalSection) {
        trace("InitializeCriticalSection implementation called. Arguments: lpCriticalSection=<CRITICAL_SECTION*>[", lpCriticalSection, "]");
        ret("Return value: <void>");
    }

    static void InitializeCriticalSectionEx(LPCRITICAL_SECTION lpCriticalSection, DWORD dwSpinCount, DWORD Flags) {
        trace("InitializeCriticalSectionEx implementation called. Arguments: lpCriticalSection=<CRITICAL_SECTION*>[", lpCriticalSection,
              "], dwSpinCount=<DWORD>[", dwSpinCount, "], Flags=<DWORD>[", Flags, "]");
        ret("Return value: <void>");
    }

    static void InitializeCriticalSectionAndSpinCount(LPCRITICAL_SECTION lpCriticalSection, DWORD dwSpinCount) {
        trace("InitializeCriticalSectionAndSpinCount implementation called. Arguments: lpCriticalSection=<CRITICAL_SECTION*>[", lpCriticalSection,
              "], dwSpinCount=<DWORD>[", dwSpinCount, "]");
        ret("Return value: <void>");
    }

    // </idonotcare>

    static void EnterCriticalSection(LPCRITICAL_SECTION lpCriticalSection) {
        trace("EnterCriticalSection implementation called. Arguments: lpCriticalSection=<CRITICAL_SECTION*>[", lpCriticalSection, "]");
        lpCriticalSection->enter();
        ret("Return value: <void>");
    }

    static BOOL TryEnterCriticalSection(LPCRITICAL_SECTION lpCriticalSection) {
        trace("TryEnterCriticalSection implementation called. Arguments: lpCriticalSection=<CRITICAL_SECTION*>[", lpCriticalSection, "]");
        const BOOL result = lpCriticalSection->try_enter() ? TRUE : FALSE;
        ret("Return value: <BOOL>[", result, "]");
        return result;
    }

    static void LeaveCriticalSection(LPCRITICAL_SECTION lpCriticalSection) {
        trace("LeaveCriticalSection implementation called. Arguments: lpCriticalSection=<CRITICAL_SECTION*>[", lpCriticalSection, "]");
        lpCriticalSection->leave();
        ret("Return value: <void>");
    }

    static void DeleteCriticalSection(LPCRITICAL_SECTION lpCriticalSection) {
        trace("DeleteCriticalSection implementation called. Arguments: lpCriticalSection=<CRITICAL_SECTION*>[", lpCriticalSection, "]");
        lpCriticalSection->remove();
        ret("Return value: <void>");
    }

    static UINT SetErrorMode(UINT uMode) {
        trace("SetErrorMode diserror-stub called. Arguments: uMode=<UINT>[", uMode, "]");
        return 0;
    }

    static UINT GetErrorMode() {
        trace("GetErrorMode diserror-stub called.");
        return 0;
    }

    static HANDLE CreateEventW(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset,
                                 BOOL bInitialState, LPCWSTR lpName) {
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

    static BOOL SetEvent(HANDLE hEvent) {
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

    static BOOL ResetEvent(HANDLE hEvent) {
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

    static HANDLE CreateSemaphoreW(LPSECURITY_ATTRIBUTES lpSemaphoreAttributes, LONG lInitialCount,
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

    static BOOL ReleaseSemaphore(HANDLE hSemaphore, LONG lReleaseCount, LPLONG lpPreviousCount) {
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

    static HANDLE CreateMutexW(LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner,
                                 LPCWSTR lpName) {
        trace("CreateMutexW implementation called. Arguments: lpMutexAttributes=<LPSECURITY_ATTRIBUTES>[", lpMutexAttributes,
              "], bInitialOwner=<BOOL>[", bInitialOwner, "], lpName=<LPCWSTR>[", lpName, "]");

        std::mutex new_mutex;
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

    static BOOL ReleaseMutex(HANDLE hMutex) {
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

    static LPCWSTR GetEnvironmentStringsW() {
        trace("GetEnvironmentStringsW implementation called. No arguments.");

        // Calculate the total size needed
        size_t total_size = 1; // For the final null terminator
        for (const auto& [key, value] : environment) {
            std::wstring entry = std::wstring(key.begin(), key.end()) + L"=" + std::wstring(value.begin(), value.end());
            total_size += entry.length() + 1; // +1 for null terminator
        }

        // Allocate buffer
        const auto buffer = new wchar_t[total_size];
        wchar_t* ptr = buffer;

        // Fill buffer
        for (const auto& [key, value] : environment) {
            std::wstring entry = std::wstring(key.begin(), key.end()) + L"=" + std::wstring(value.begin(), value.end());
            wcscpy(ptr, entry.c_str());
            ptr += entry.length() + 1;
        }
        *ptr = L'\0'; // Final null terminator

        ret("Return value: <LPCWSTR>[", static_cast<void*>(buffer), "]");
        return buffer; // Caller is responsible for freeing this memory
    }

    static BOOL FreeEnvironmentStringsW(LPCWSTR penv) {
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

    static void RaiseException(DWORD dwExceptionCode, DWORD dwExceptionFlags, DWORD nNumberOfArguments, const ULONG_PTR* lpArguments) {
        trace("RaiseException implementation called. Arguments: dwExceptionCode=<DWORD>[", dwExceptionCode,
              "], dwExceptionFlags=<DWORD>[", dwExceptionFlags, "], nNumberOfArguments=<DWORD>[", nNumberOfArguments,
              "], lpArguments=<const ULONG_PTR*>[", lpArguments, "]");
        throw std::runtime_error("RaiseException called with code " + std::to_string(dwExceptionCode) + " and flags " + std::to_string(dwExceptionFlags));
    }

    static void GetSystemInfo(LPSYSTEM_INFO lpSystemInfo) {
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

    static DWORD GetCurrentDirectoryW(DWORD nBufferLength, LPWSTR lpBuffer) {
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
                wcsncpy(lpBuffer, current_path_w.c_str(), nBufferLength - 1);
                lpBuffer[nBufferLength - 1] = L'\0';
            }
            SetLastError(ERROR_INSUFFICIENT_BUFFER);
            ret("Error set to: ERROR_INSUFFICIENT_BUFFER, Return value: <DWORD>[", path_length, "]");
            return path_length;
        }

        wcscpy(lpBuffer, current_path_w.c_str());
        SetLastError(ERROR_SUCCESS);
        ret("Error set to: ERROR_SUCCESS, Return value: <DWORD>[", path_length, "]");
        return path_length;
    }

    static bool SwitchToThread(DWORD thread_id) {
        trace("SwitchToThread implementation called. Arguments: thread_id=<DWORD>[", thread_id, "]");
        // <idontcare> just yield the CPU (real implementation would switch to another thread) </idontcare>
        std::this_thread::yield();
        ret("Return value: <bool>[true]");
        return true;
    }

    static LPVOID VirtualAllocEx(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect, HANDLE hProcess) {
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

    static BOOL VirtualFreeEx(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType, HANDLE hProcess) {
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

    static BOOL VirtualProtectEx(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect, HANDLE hProcess) {
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

    static SIZE_T VirtualQueryEx(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength, HANDLE hProcess) {
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

    static HANDLE VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
        trace("VirtualAlloc implementation called. Arguments: lpAddress=<LPVOID>[", lpAddress,
              "], dwSize=<SIZE_T>[", dwSize, "], flAllocationType=<DWORD>[", flAllocationType,
              "], flProtect=<DWORD>[", flProtect, "]");

        return VirtualAllocEx(lpAddress, dwSize, flAllocationType, flProtect, GetCurrentProcess());
    }

    static BOOL VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) {
        trace("VirtualFree implementation called. Arguments: lpAddress=<LPVOID>[", lpAddress,
              "], dwSize=<SIZE_T>[", dwSize, "], dwFreeType=<DWORD>[", dwFreeType, "]");

        return VirtualFreeEx(lpAddress, dwSize, dwFreeType, GetCurrentProcess());
    }

    static BOOL VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) {
        trace("VirtualProtect implementation called. Arguments: lpAddress=<LPVOID>[", lpAddress,
              "], dwSize=<SIZE_T>[", dwSize, "], flNewProtect=<DWORD>[", flNewProtect,
              "], lpflOldProtect=<PDWORD>[", lpflOldProtect, "]");

        return VirtualProtectEx(lpAddress, dwSize, flNewProtect, lpflOldProtect, GetCurrentProcess());
    }

    static SIZE_T VirtualQuery(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength) {
        trace("VirtualQuery implementation called. Arguments: lpAddress=<LPCVOID>[", lpAddress,
              "], lpBuffer=<PMEMORY_BASIC_INFORMATION>[", lpBuffer, "], dwLength=<SIZE_T>[", dwLength, "]");

        return VirtualQueryEx(lpAddress, lpBuffer, dwLength, GetCurrentProcess());
    }

    static DWORD GetFullPathNameW(LPCWSTR lpFileName, DWORD nBufferLength, LPWSTR lpBuffer, LPWSTR* lpFilePart) {
        trace("GetFullPathNameW implementation called. Arguments: lpFileName=<LPCWSTR>[", lpFileName,
              "], nBufferLength=<DWORD>[", nBufferLength, "], lpBuffer=<LPWSTR>[", lpBuffer,
              "], lpFilePart=<LPWSTR*>[", lpFilePart, "]");

        if (!lpFileName || nBufferLength == 0) {
            SetLastError(ERROR_INVALID_PARAMETER);
            ret("Error set to: ERROR_INVALID_PARAMETER, Return value: <DWORD>[0]");
            return 0;
        }

        const std::wstring input_path(lpFileName);
        const std::filesystem::path full_path = std::filesystem::absolute(input_path);
        const std::wstring full_path_w = full_path.wstring();
        const size_t path_length = full_path_w.length();

        if (nBufferLength <= path_length) {
            if (nBufferLength > 0) {
                wcsncpy(lpBuffer, full_path_w.c_str(), nBufferLength - 1);
                lpBuffer[nBufferLength - 1] = L'\0';
            }
            SetLastError(ERROR_INSUFFICIENT_BUFFER);
            ret("Error set to: ERROR_INSUFFICIENT_BUFFER, Return value: <DWORD>[", path_length, "]");
            return path_length;
        }

        wcscpy(lpBuffer, full_path_w.c_str());
        if (lpFilePart) {
            *lpFilePart = lpBuffer + full_path_w.find_last_of(L"\\/") + 1;
        }

        SetLastError(ERROR_SUCCESS);
        ret("Error set to: ERROR_SUCCESS, Return value: <DWORD>[", path_length, "]");
        return path_length;
    }

    static DWORD GetTempPathW(DWORD nBufferLength, LPWSTR lpBuffer) {
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
                wcsncpy(lpBuffer, temp_path_w.c_str(), nBufferLength - 1);
                lpBuffer[nBufferLength - 1] = L'\0';
            }
            SetLastError(ERROR_INSUFFICIENT_BUFFER);
            ret("Error set to: ERROR_INSUFFICIENT_BUFFER, Return value: <DWORD>[", path_length, "]");
            return path_length;
        }

        wcscpy(lpBuffer, temp_path_w.c_str());
        SetLastError(ERROR_SUCCESS);
        ret("Error set to: ERROR_SUCCESS, Return value: <DWORD>[", path_length, "]");
        return path_length;
    }

    static BOOL GetExitCodeThread(HANDLE hThread, LPDWORD lpExitCode) {
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

        if (const auto& thread = process_info[tls.process].threads[hThread]; pthread_tryjoin_np(thread, nullptr) == EBUSY) {
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

    static BOOL GetExitCodeProcess(HANDLE hProcess, LPDWORD lpExitCode) {
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

    static DWORD GetFreeDiskSpaceExW(LPCWSTR lpDirectoryName, PULARGE_INTEGER lpFreeBytesAvailableToCaller,
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

        std::wstring path_w(lpDirectoryName);
        std::string path(path_w.begin(), path_w.end());

        struct statvfs stat;
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

    static DWORD GetFreeDiskSpaceW(LPCWSTR lpDirectoryName, LPDWORD lpSectorsPerCluster,
                                 LPDWORD lpBytesPerSector, LPDWORD lpNumberOfFreeClusters,
                                 LPDWORD lpTotalNumberOfClusters) {
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

        std::wstring path_w(lpDirectoryName);
        const std::string path(path_w.begin(), path_w.end());

        struct statvfs stat;
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

    static HANDLE CreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize,
                           LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter,
                           DWORD dwCreationFlags, LPDWORD lpThreadId) {
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
        auto thread_func = [](void* arg) -> void* {
            auto [start_routine, param] = *static_cast<std::pair<LPTHREAD_START_ROUTINE, LPVOID>*>(arg);
            delete static_cast<std::pair<LPTHREAD_START_ROUTINE, LPVOID>*>(arg);
            const DWORD exit_code = start_routine(param);
            return reinterpret_cast<void*>(static_cast<uintptr_t>(exit_code));
        };

        if (auto* arg = new std::pair<LPTHREAD_START_ROUTINE, LPVOID>(lpStartAddress, lpParameter); pthread_create(&thread, nullptr, thread_func, arg) != 0) {
            delete arg;
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            ret("Error set to: ERROR_NOT_ENOUGH_MEMORY, Return value: <HANDLE>[NULL]");
            return nullptr;
        }

        HANDLE thread_handle = next_handle;
        next_handle = static_cast<HANDLE>(static_cast<char*>(next_handle) + 1);
        process_info[tls.process].threads[thread_handle] = thread;

        if (lpThreadId) {
            *lpThreadId = reinterpret_cast<DWORD>(thread_handle);
        }

        SetLastError(ERROR_SUCCESS);
        ret("Error set to: ERROR_SUCCESS, Return value: <HANDLE>[", thread_handle, "]");
        return thread_handle;
    }

    static HANDLE GetCurrentThread() {
        trace("GetCurrentThread implementation called. No arguments.");
        const auto current_thread_handle = reinterpret_cast<HANDLE>(pthread_self());
        ret("Return value: <HANDLE>[", current_thread_handle, "]");
        return current_thread_handle;
    }

    static DWORD GetCurrentProcessId() {
        trace("GetCurrentProcessId implementation called. No arguments.");
        DWORD current_process_id = reinterpret_cast<uintptr_t>(tls.process);
        ret("Return value: <DWORD>[", current_process_id, "]");
        return current_process_id;
    }

    static BOOL TerminateThread(HANDLE hThread, DWORD dwExitCode) {
        trace("TerminateThread implementation called. Arguments: hThread=<HANDLE>[", hThread,
              "], dwExitCode=<DWORD>[", dwExitCode, "]");
        if (!process_info[tls.process].threads.contains(hThread)) {
            SetLastError(ERROR_INVALID_HANDLE);
            ret("Error set to: ERROR_INVALID_HANDLE, Return value: <BOOL>[FALSE]");
            return FALSE;
        }
        pthread_cancel(process_info[tls.process].threads[hThread]);
        pthread_join(process_info[tls.process].threads[hThread], nullptr);
        process_info[tls.process].threads.erase(hThread);
        SetLastError(ERROR_SUCCESS);
        ret("Error set to: ERROR_SUCCESS, Return value: <BOOL>[TRUE]");
        return TRUE;
    }

    static BOOL SetConsoleCtrlHandler(PHANDLER_ROUTINE HandlerRoutine, BOOL Add) {
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

    static DWORD SearchPathW(LPCWSTR lpPath, LPCWSTR lpFileName, LPCWSTR lpExtension, DWORD nBufferLength,
                               LPWSTR lpBuffer, LPWSTR* lpFilePart) {
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
            std::wstring path_w(lpPath);
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

        const std::wstring file_name_w(lpFileName);
        const std::wstring extension_w = lpExtension ? std::wstring(lpExtension) : L"";

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
                        wcsncpy(lpBuffer, full_path_w.c_str(), nBufferLength - 1);
                        lpBuffer[nBufferLength - 1] = L'\0';
                    }
                    SetLastError(ERROR_INSUFFICIENT_BUFFER);
                    ret("Error set to: ERROR_INSUFFICIENT_BUFFER, Return value: <DWORD>[", path_length, "]");
                    return path_length;
                }
                wcscpy(lpBuffer, full_path_w.c_str());
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

    static HANDLE GetStdHandle(DWORD nStdHandle) {
        trace("GetStdHandle implementation called. Arguments: nStdHandle=<DWORD>[", nStdHandle, "]");

        HANDLE handle = nullptr;
        switch (nStdHandle) {
            case STD_INPUT_HANDLE:
                handle = process_info[tls.process].std_handles[0];
                break;
            case STD_OUTPUT_HANDLE:
                handle = process_info[tls.process].std_handles[1];
                break;
            case STD_ERROR_HANDLE:
                handle = process_info[tls.process].std_handles[2];
                break;
            default:
                SetLastError(ERROR_INVALID_HANDLE);
                ret("Error set to: ERROR_INVALID_HANDLE, Return value: <HANDLE>[NULL]");
                return nullptr;
        }
        SetLastError(ERROR_SUCCESS);
        ret("Error set to: ERROR_SUCCESS, Return value: <HANDLE>[", handle, "]");
        return handle;
    }

    static BOOL SetStdHandle(DWORD nStdHandle, HANDLE hHandle) {
        trace("SetStdHandle implementation called. Arguments: nStdHandle=<DWORD>[", nStdHandle,
              "], hHandle=<HANDLE>[", hHandle, "]");

        switch (nStdHandle) {
            case STD_INPUT_HANDLE:
                process_info[tls.process].std_handles[0] = hHandle;
                break;
            case STD_OUTPUT_HANDLE:
                process_info[tls.process].std_handles[1] = hHandle;
                break;
            case STD_ERROR_HANDLE:
                process_info[tls.process].std_handles[2] = hHandle;
                break;
            default:
                SetLastError(ERROR_INVALID_HANDLE);
                ret("Error set to: ERROR_INVALID_HANDLE, Return value: <BOOL>[FALSE]");
                return FALSE;
        }
        SetLastError(ERROR_SUCCESS);
        ret("Error set to: ERROR_SUCCESS, Return value: <BOOL>[TRUE]");
        return TRUE;
    }

    static BOOL IsDebuggerPresent() {
        trace("IsDebuggerPresent diserror-stub called. No arguments.");
        ret("Return value: <BOOL>[FALSE]");
        return FALSE; // Always return FALSE for simplicity
    }

    static void RtlCaptureContext(LPCONTEXT ContextRecord) {
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

    static PRUNTIME_FUNCTION RtlLookupFunctionEntry(DWORD64 ControlPc, PDWORD64 ImageBase, PULONG64 TargetGp) {
        trace("RtlLookupFunctionEntry diserror-stub called. Arguments: ControlPc=<DWORD64>[", ControlPc,
              "], ImageBase=<PDWORD64>[", ImageBase, "], TargetGp=<PULONG64>[", TargetGp, "]");
        // Simplified: No function entries are available
        if (ImageBase) {
            *ImageBase = 0;
        }
        if (TargetGp) {
            *TargetGp = 0;
        }
        SetLastError(ERROR_SUCCESS);
        ret("Error set to: ERROR_SUCCESS, Return value: <PRUNTIME_FUNCTION>[NULL]");
        return nullptr;
    }

    static PEXCEPTION_ROUTINE RtlVirtualUnwind(DWORD HandlerType, DWORD64 ImageBase, DWORD64 ControlPc,
                                        PRUNTIME_FUNCTION FunctionEntry, PCONTEXT ContextRecord,
                                        PVOID* HandlerData, PDWORD64 EstablisherFrame, PULONG64 TargetGp) {
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

    static LONG UnhandledExceptionFilter(EXCEPTION_POINTERS* ExceptionInfo) {
        trace("UnhandledExceptionFilter diserror-stub called. Arguments: ExceptionInfo=<struct _EXCEPTION_POINTERS*>[", ExceptionInfo, "]");
        // Simplified: Always continue search
        ret("Return value: <LONG>[EXCEPTION_CONTINUE_SEARCH]");
        return EXCEPTION_CONTINUE_SEARCH;
    }

    static LPTOP_LEVEL_EXCEPTION_FILTER SetUnhandledExceptionFilter(LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter) {
        trace("SetUnhandledExceptionFilter diserror-stub called. Arguments: lpTopLevelExceptionFilter=<LPTOP_LEVEL_EXCEPTION_FILTER>[", lpTopLevelExceptionFilter, "]");
        // Simplified: No filter is actually set
        ret("Return value: <LPTOP_LEVEL_EXCEPTION_FILTER>[NULL]");
        return nullptr;
    }

    static BOOL WriteConsoleW(HANDLE hConsoleOutput, const void* lpBuffer, DWORD nNumberOfCharsToWrite,
                            LPDWORD lpNumberOfCharsWritten, LPVOID lpReserved) {
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

        std::wstring output(static_cast<const wchar_t*>(lpBuffer), nNumberOfCharsToWrite);
        std::wcout << output;
        *lpNumberOfCharsWritten = nNumberOfCharsToWrite;

        SetLastError(ERROR_SUCCESS);
        ret("Error set to: ERROR_SUCCESS, Return value: <BOOL>[TRUE]");
        return TRUE;
    }

    static HANDLE GetProcessHeap() {
        trace("GetProcessHeap implementation called. No arguments.");
        const auto heap_handle = reinterpret_cast<HANDLE>(0x1); // Placeholder heap handle
        ret("Return value: <HANDLE>[", heap_handle, "]");
        return heap_handle;
    }

    static LPVOID HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes) {
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

    static BOOL HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem) {
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

    static SIZE_T HeapSize(HANDLE hHeap, DWORD dwFlags, LPCVOID lpMem) {
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

    static HANDLE HeapCreate(DWORD flOptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize) {
        trace("HeapCreate implementation called. Arguments: flOptions=<DWORD>[", flOptions,
              "], dwInitialSize=<SIZE_T>[", dwInitialSize,
              "], dwMaximumSize=<SIZE_T>[", dwMaximumSize, "]");

        const HANDLE heap_handle = next_handle;
        next_handle = static_cast<HANDLE>(static_cast<char*>(next_handle) + 1);
        process_info[tls.process].heaps[heap_handle] = {
            .alloc_info = {},
            .flags = flOptions
        };

        SetLastError(ERROR_SUCCESS);
        ret("Error set to: ERROR_SUCCESS, Return value: <HANDLE>[", heap_handle, "]");
        return heap_handle;
    }

    static BOOL HeapDestroy(HANDLE hHeap) {
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

    static LPVOID HeapReAlloc(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes) {
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

    static DWORD GetProcessId() {
        trace("GetProcessId implementation called. No arguments.");
        const DWORD current_process_id = reinterpret_cast<uintptr_t>(tls.process);
        ret("Return value: <DWORD>[", current_process_id, "]");
        return current_process_id;
    }

    static DWORD GetThreadId() {
        trace("GetThreadId implementation called. No arguments.");
        const DWORD current_thread_id = reinterpret_cast<uintptr_t>(tls.thread);
        ret("Return value: <DWORD>[", current_thread_id, "]");
        return current_thread_id;
    }

    static void GetStartupInfoW(LPSTARTUPINFOW lpStartupInfo) {
        trace("GetStartupInfoW diserror-stub called. Arguments: lpStartupInfo=<LPSTARTUPINFOW>[", lpStartupInfo, "]");
        if (!lpStartupInfo) {
            return;
        }
        memset(lpStartupInfo, 0, sizeof(STARTUPINFOW));
        lpStartupInfo->cb = sizeof(STARTUPINFOW);
        ret("Return value: <void>");
    }
};