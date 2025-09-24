#kernel32.py
from globals import *

def _save_env():
    with open("environment.json", "w") as f:
        f.write(jn.dumps(global_env, indent=4))

def _get_current_apc_queue():
    global processes
    tid = th.get_ident()
    if tid not in processes[tls.process_id]["apc_queue"]:
        processes[tls.process_id]["apc_queue"][tid] = cl.deque()
    return processes[tls.process_id]["apc_queue"][tid]

# Helper: normalize module name per Windows rules
def _normalize_module_name(mod_name: str) -> str:
    # trailing dot => no extension
    if mod_name.endswith('.'):
        mod_name = mod_name[:-1]
    # add .DLL if no extension
    if not os.path.splitext(mod_name)[1]:
        mod_name = mod_name + ".DLL"
    return os.path.basename(mod_name).lower()

class Kernel32:
    def __init__(self):
        self.exports = {
            "ExitProcess": self.ExitProcess,
            "GetLastError": self.GetLastError,
            "SetLastError": self.SetLastError,
            "Sleep": self.Sleep,
            "GetTickCount": self.GetTickCount,
            "GetCurrentThreadId": self.GetCurrentThreadId,
            "CreateFileW": self.CreateFileW,
            "ReadFile": self.ReadFile,
            "WriteFile": self.WriteFile,
            "DeleteFileW": self.DeleteFileW,
            "CloseHandle": self.CloseHandle,
            "GetFileSize": self.GetFileSize,
            "SetFilePointer": self.SetFilePointer,
            "SetFilePointerEx": self.SetFilePointerEx,
            "FlushFileBuffers": self.FlushFileBuffers,
            "FindFirstFileW": self.FindFirstFileW,
            "FindNextFileW": self.FindNextFileW,
            "FindClose": self.FindClose,
            "GetCommandLineW": self.GetCommandLineW,
            "GetCurrentProcess": self.GetCurrentProcess,
            "GetModuleHandleW": self.GetModuleHandleW,
            "LoadLibraryW": self.LoadLibraryW,
            "FreeLibrary": self.FreeLibrary,
            "WaitForSingleObject": self.WaitForSingleObject,
            "WaitForSingleObjectEx": self.WaitForSingleObjectEx,
            "WaitForMultipleObjects": self.WaitForMultipleObjects,
            "WaitForMultipleObjectsEx": self.WaitForMultipleObjectsEx,
            "GetModuleFileNameW": self.GetModuleFileNameW,
            "SetEnvironmentVariableW": self.SetEnvironmentVariableW,
            "GetEnvironmentVariableW": self.GetEnvironmentVariableW,
            "InitializeCriticalSection": self.InitializeCriticalSection,
            "InitializeCriticalSectionEx": self.InitializeCriticalSectionEx,
            "TryEnterCriticalSection": self.TryEnterCriticalSection,
            "InitializeCriticalSectionAndSpinCount": self.InitializeCriticalSectionAndSpinCount,
            "EnterCriticalSection": self.EnterCriticalSection,
            "LeaveCriticalSection": self.LeaveCriticalSection,
            "DeleteCriticalSection": self.DeleteCriticalSection,
            "SetErrorMode": self.SetErrorMode,
            "GetErrorMode": self.GetErrorMode,
            "CreateEventW": self.CreateEventW,
            "SetEvent": self.SetEvent,
            "ResetEvent": self.ResetEvent,
            "CreateSemaphoreW": self.CreateSemaphoreW,
            "ReleaseSemaphore": self.ReleaseSemaphore,
            "CreateMutexW": self.CreateMutexW,
            "ReleaseMutex": self.ReleaseMutex,
            "QueueUserAPC": self.QueueUserAPC,
            "GetEnvironmentStringsW": self.GetEnvironmentStringsW,
            "FreeEnvironmentStringsW": self.FreeEnvironmentStringsW,
            "GetProcAddress": self.GetProcAddress,
            "RaiseException": self.RaiseException,
            "GetSystemInfo": self.GetSystemInfo,
            "GetCurrentDirectoryW": self.GetCurrentDirectoryW,
            "SwitchToThread": self.SwitchToThread,
            "virtualAlloc": self.VirtualAlloc,
            "VirtualFree": self.VirtualFree,
            "VirtualProtect": self.VirtualProtect,
            "VirtualQuery": self.VirtualQuery,
            "LoadLibraryExW": self.LoadLibraryExW,
            "SetStdHandle": self.SetStdHandle,
            "IsDebuggerPresent": self.IsDebuggerPresent,
            "MultiByteToWideChar": self.MultiByteToWideChar,
            "WideCharToMultiByte": self.WideCharToMultiByte,
            "RtlVirtualUnwind": self.RtlVirtualUnwind,
            "RtlCaptureContext": self.RtlCaptureContext,
            "UnhandledExceptionFilter": self.UnhandledExceptionFilter,
            "RtlLookupFunctionEntry": self.RtlLookupFunctionEntry,
            "SetUnhandledExceptionFilter": self.SetUnhandledExceptionFilter,
            "GetStdHandle": self.GetStdHandle,
            "WriteConsoleW": self.WriteConsoleW,
            "GetProcessHeap": self.GetProcessHeap,
            "HeapAlloc": self.HeapAlloc,
            "HeapFree": self.HeapFree,
            "HeapReAlloc": self.HeapReAlloc,
            "HeapSize": self.HeapSize,
            "HeapCreate": self.HeapCreate,
            "HeapDestroy": self.HeapDestroy,
            "GetProcessId": self.GetProcessId,
            "GetThreadId": self.GetThreadId,
            "CreateThread": self.CreateThread,
            "TerminateThread": self.TerminateThread,
            "GetExitCodeThread": self.GetExitCodeThread,
            "GetStartupInfoW": self.GetStartupInfoW,
            "GetCurrentProcessId": self.GetCurrentProcessId,
            "InitializeSListHead": self.InitializeSListHead,
            "InterlockedPushEntrySList": self.InterlockedPushEntrySList,
            "InterlockedPopEntrySList": self.InterlockedPopEntrySList,
            "InterlockedFlushSList": self.InterlockedFlushSList,
            "InterlockedPushListSList": self.InterlockedPushListSList,
            "RtlFirstEntrySList": self.RtlFirstEntrySList,
            "QueryDepthSList": self.QueryDepthSList,
            "QueryPerformanceCounter": self.QueryPerformanceCounter,
            "QueryPerformanceFrequency": self.QueryPerformanceFrequency,
            "GetSystemTimeAsFileTime": self.GetSystemTimeAsFileTime,
            "IsProcessorFeaturePresent": self.IsProcessorFeaturePresent,
            "TerminateProcess": self.TerminateProcess,
            "GetTickCount64": self.GetTickCount64,
            "EncodePointer": self.EncodePointer,
            "DecodePointer": self.DecodePointer,
            "RtlPcToFileHeader": self.RtlPcToFileHeader,
            "TlsAlloc": self.TlsAlloc,
            "TlsFree": self.TlsFree,
            "TlsGetValue": self.TlsGetValue,
            "TlsSetValue": self.TlsSetValue,
            "RtlUnwindEx": self.RtlUnwindEx,
            "RtlUnwind": self.RtlUnwind,
        }

    @staticmethod
    def ExitProcess(uExitCode: wt.UINT) -> tp.NoReturn:
        trace(f"ExitProcess impl. [{uExitCode=}]")
        Kernel32.SetLastError(wt.DWORD(0))
        ret(f"ExitProcess impl. [Error=ERROR_SUCCESS, Value={tp.NoReturn}]")
        ss.exit(uExitCode.value)

    @staticmethod
    def GetLastError() -> wt.DWORD:
        trace(f"GetLastError impl. []")
        ret(f"GetLastError impl. [Error=-, Value={tls.last_error}]")
        return tls.last_error

    @staticmethod
    def SetLastError(err: wt.DWORD) -> None:
        trace(f"SetLastError impl. [{err=}]")
        ret(f"SetLastError impl. [Error=-, Value=None]")
        tls.last_error = err

    @staticmethod
    def Sleep(dwMilliseconds: wt.DWORD) -> None:
        trace(f"Sleep impl. [{dwMilliseconds=}]")
        tm.sleep(dwMilliseconds.value / 1000.0)1
        Kernel32.SetLastError(wt.DWORD(0))
        ret(f"Sleep impl. [Error=ERROR_SUCCESS, Value=None]")

    @staticmethod
    def GetTickCount():
        elapsed = int((tm.time() - system_start_time) * 1000) & 0xFFFFFFFF
        trace(f"GetTickCount impl. []")
        Kernel32.SetLastError(wt.DWORD(0))34
        ret(f"GetTickCount impl. [Error=ERROR_SUCCESS, Value={elapsed}]")
        return wt.DWORD(elapsed)

    @staticmethod
    def GetCurrentThreadId():
        tid = th.get_ident() & 0xFFFFFFFF
        tls.thread_id = wt.DWORD(tid)
        trace(f"GetCurrentThreadId impl. []")
        Kernel32.SetLastError(wt.DWORD(0))
        ret(f"GetCurrentThreadId impl. [Error=ERROR_SUCCESS, Value={tid}]")
        return wt.DWORD(tid)

    # ------------------ File Handling ------------------
    @staticmethod
    def CreateFileW(lpFileName: wt.LPCWSTR, dwDesiredAccess: wt.DWORD, dwShareMode: wt.DWORD,
                    lpSecurityAttributes: wt.LPVOID, dwCreationDisposition: wt.DWORD,
                    dwFlagsAndAttributes: wt.DWORD, hTemplateFile: wt.HANDLE) -> wt.HANDLE:
        trace(f"CreateFileW impl. [{lpFileName=}, {dwDesiredAccess=}, {dwCreationDisposition=}]")

        filename = lpFileName.value if hasattr(lpFileName, 'value') else str(lpFileName)

        # Map Windows file creation dispositions to Python modes
        global processes
        mode_map = {
            1: 'r',  # CREATE_NEW (fail if exists)
            2: 'w',  # CREATE_ALWAYS (overwrite)
            3: 'r',  # OPEN_EXISTING (fail if doesn't exist)
            4: 'a',  # OPEN_ALWAYS (create if doesn't exist)
            5: 'w'   # TRUNCATE_EXISTING (fail if doesn't exist, truncate)
        }

        disposition = dwCreationDisposition.value
        if disposition not in mode_map:
            Kernel32.SetLastError(wt.DWORD(87))  # ERROR_INVALID_PARAMETER
            return wt.HANDLE(-1)

        try:
            mode = mode_map[disposition]
            if dwDesiredAccess.value & 0x40000000:  # GENERIC_WRITE
                if 'r' in mode:
                    mode = 'r+'
                elif 'a' in mode:
                    mode = 'a+'

            file_obj = open(filename, mode)
            handle = processes[tls.process_id]["next_file_handle"]
            processes[tls.process_id]["next_file_handle"] += 1

            processes[tls.process_id]["file_handles"][handle] = {
                'file': file_obj,
                'filename': filename,
                'mode': mode
            }

            Kernel32.SetLastError(wt.DWORD(0))
            ret(f"CreateFileW impl. [Error=ERROR_SUCCESS, Value={handle}]")
            return wt.HANDLE(handle)

        except FileNotFoundError:
            Kernel32.SetLastError(wt.DWORD(2))  # ERROR_FILE_NOT_FOUND
            ret(f"CreateFileW impl. [Error=ERROR_FILE_NOT_FOUND, Value={wt.HANDLE(-1)}]")
            return wt.HANDLE(-1)
        except FileExistsError:
            Kernel32.SetLastError(wt.DWORD(80))  # ERROR_FILE_EXISTS
            ret(f"CreateFileW impl. [Error=ERROR_FILE_EXISTS, Value={wt.HANDLE(-1)}]")
            return wt.HANDLE(-1)
        except Exception as e:
            error(f"CreateFileW impl. {e}")
            Kernel32.SetLastError(wt.DWORD(5))  # ERROR_ACCESS_DENIED
            ret(f"CreateFileW impl. [Error=ERROR_ACCESS_DENIED, Value={wt.HANDLE(-1)}]")
            return wt.HANDLE(-1)

    @staticmethod
    def ReadFile(hFile: wt.HANDLE, lpBuffer: wt.LPVOID, nNumberOfBytesToRead: wt.DWORD,
                 lpNumberOfBytesRead: wt.LPDWORD, lpOverlapped: wt.LPVOID) -> wt.BOOL:
        global processes
        trace(f"ReadFile impl. [{hFile=}, {nNumberOfBytesToRead=}]")

        handle = hFile.value if hasattr(hFile, 'value') else hFile
        if handle not in processes[tls.process_id]["file_handles"]:
            Kernel32.SetLastError(wt.DWORD(6))  # ERROR_INVALID_HANDLE
            return wt.BOOL(0)

        try:
            file_obj = processes[tls.process_id]["file_handles"][handle]['file']
            data = file_obj.read(nNumberOfBytesToRead.value)
            bytes_read = len(data)

            # Copy data to buffer
            if isinstance(data, str):
                data = data.encode('utf-8')
            ct.memmove(lpBuffer, data, bytes_read)

            if lpNumberOfBytesRead:
                lpNumberOfBytesRead[0] = wt.DWORD(bytes_read)

            Kernel32.SetLastError(wt.DWORD(0))
            ret(f"ReadFile impl. [Error=ERROR_SUCCESS, Value={wt.BOOL(1)}]")
            return wt.BOOL(1)

        except Exception as e:
            error(f"ReadFile impl. {e}")
            Kernel32.SetLastError(wt.DWORD(5))  # ERROR_ACCESS_DENIED
            ret(f"ReadFile impl. [Error=ERROR_ACCESS_DENIED, Value={wt.BOOL(0)}]")
            return wt.BOOL(0)

    @staticmethod
    def WriteFile(hFile: wt.HANDLE, lpBuffer: wt.LPCVOID, nNumberOfBytesToWrite: wt.DWORD,
                  lpNumberOfBytesWritten: wt.LPDWORD, lpOverlapped: wt.LPVOID) -> wt.BOOL:
        global processes
        trace(f"WriteFile impl. [{hFile=}, {nNumberOfBytesToWrite=}]")

        handle = hFile.value if hasattr(hFile, 'value') else hFile
        if handle not in processes[tls.process_id]["file_handles"]:
            Kernel32.SetLastError(wt.DWORD(6))  # ERROR_INVALID_HANDLE
            return wt.BOOL(0)

        try:
            file_obj = processes[tls.process_id]["file_handles"][handle]['file']
            data = ct.string_at(lpBuffer, nNumberOfBytesToWrite.value)

            if hasattr(file_obj, 'buffer'):  # Handle text mode files
                bytes_written = file_obj.buffer.write(data)
            else:
                bytes_written = file_obj.write(data)

            if lpNumberOfBytesWritten:
                lpNumberOfBytesWritten[0] = wt.DWORD(bytes_written)

            Kernel32.SetLastError(wt.DWORD(0))
            ret(f"WriteFile impl. [Error=ERROR_SUCCESS, Value={wt.BOOL(1)}]")
            return wt.BOOL(1)

        except Exception as e:
            error(f"WriteFile impl. {e}")
            Kernel32.SetLastError(wt.DWORD(5))  # ERROR_ACCESS_DENIED
            ret(f"WriteFile impl. [Error=ERROR_ACCESS_DENIED, Value={wt.BOOL(0)}]")
            return wt.BOOL(0)

    @staticmethod
    def DeleteFileW(lpFileName: wt.LPCWSTR) -> wt.BOOL:
        """
        Deletes the specified file.
        Returns TRUE on success, FALSE on failure (check GetLastError).
        """
        trace(f"DeleteFileW impl. [{lpFileName=}]")

        # Convert LPCWSTR to Python string
        filename = lpFileName.value if hasattr(lpFileName, 'value') else str(lpFileName)

        try:
            if not os.path.exists(filename):
                Kernel32.SetLastError(wt.DWORD(2))  # ERROR_FILE_NOT_FOUND
                ret(f"DeleteFileW impl. [Error=ERROR_FILE_NOT_FOUND, Value={wt.BOOL(0)}]")
                return wt.BOOL(0)

            os.remove(filename)
            Kernel32.SetLastError(wt.DWORD(0))
            ret(f"DeleteFileW impl. TRUE")
            return wt.BOOL(1)

        except PermissionError:
            Kernel32.SetLastError(wt.DWORD(5))  # ERROR_ACCESS_DENIED
            ret(f"DeleteFileW impl. [Error=ERROR_ACCESS_DENIED, Value={wt.BOOL(0)}]")
            return wt.BOOL(0)
        except Exception as e:
            error(f"DeleteFileW impl. {e}")
            Kernel32.SetLastError(wt.DWORD(1))  # ERROR_INVALID_FUNCTION
            ret(f"DeleteFileW impl. [Error=ERROR_INVALID_FUNCTION, Value={wt.BOOL(0)}]")
            return wt.BOOL(0)

    @staticmethod
    def CloseHandle(hObject: wt.HANDLE) -> wt.BOOL:
        """
        Closes a handle of any type (file, thread, module, event, semaphore, mutex, process, etc.)
        Works per-process for thread handles.
        """
        global processes
        handle = hObject.value if hasattr(hObject, "value") else hObject
        trace(f"CloseHandle impl. [{handle=}]")

        # --- Everything except process handles is per-process ---
        for pid, proc in processes.items():
            if "threads" in proc and handle in proc["threads"]:
                del proc["threads"][handle]
                Kernel32.SetLastError(wt.DWORD(0))
                ret(f"CloseHandle impl. {wt.BOOL(1)}")
                return wt.BOOL(1)
            # --- File handles ---
            if "file_handles" in proc and handle in proc["file_handles"]:
                file_info = proc["file_handles"][handle]
                try:
                    file_info['file'].close()
                except Exception as e:
                    error(f"CloseHandle file close error: {e}")
                del proc["file_handles"][handle]
                Kernel32.SetLastError(wt.DWORD(0))
                ret(f"CloseHandle impl. [Error=ERROR_SUCCESS, Value={wt.BOOL(1)}]")
                return wt.BOOL(1)

            # --- Registry handles ---
            if "registry_handles" in proc and handle in proc["registry_handles"]:
                del proc["registry_handles"][handle]
                Kernel32.SetLastError(wt.DWORD(0))
                ret(f"CloseHandle impl. [Error=ERROR_SUCCESS, Value={wt.BOOL(1)}]")
                return wt.BOOL(1)
            # --- Find handles ---
            if "find_handles" in proc and handle in proc["find_handles"]:
                del proc["find_handles"][handle]
                Kernel32.SetLastError(wt.DWORD(0))
                ret(f"CloseHandle impl. [Error=ERROR_SUCCESS, Value={wt.BOOL(1)}]")
                return wt.BOOL(1)
            # --- Module handles ---
            if "modules" in proc and handle in proc["modules"]:
                del proc["modules"][handle]
                Kernel32.SetLastError(wt.DWORD(0))
                ret(f"CloseHandle impl. [Error=ERROR_SUCCESS, Value={wt.BOOL(1)}]")
                return wt.BOOL(1)
            # --- Events ---
            if "event_handles" in proc and handle in proc["event_handles"]:
                del proc["event_handles"][handle]
                Kernel32.SetLastError(wt.DWORD(0))
                ret(f"CloseHandle impl. [Error=ERROR_SUCCESS, Value={wt.BOOL(1)}]")
                return wt.BOOL(1)
            # --- Semaphores ---
            if "semaphore_handles" in proc and handle in proc["semaphore_handles"]:
                del proc["semaphore_handles"][handle]
                Kernel32.SetLastError(wt.DWORD(0))
                ret(f"CloseHandle impl. [Error=ERROR_SUCCESS, Value={wt.BOOL(1)}]")
                return wt.BOOL(1)

            # --- Mutexes ---
            if "mutex_handles" in proc and handle in proc["mutex_handles"]:
                del proc["mutex_handles"][handle]
                Kernel32.SetLastError(wt.DWORD(0))
                ret(f"CloseHandle impl. [Error=ERROR_SUCCESS, Value={wt.BOOL(1)}]")
                return wt.BOOL(1)

        # --- Processes ---
        if handle in process_handles:
            # Kill the process.
            if handle in processes:
                proc = processes[handle]
                # Terminate all threads
                if "threads" in proc:
                    for th_handle, th_info in list(proc["threads"].items()):
                        th_obj = th_info["thread"]
                        if th_obj.is_alive():
                            # No direct way to kill threads in Python; just remove references
                            del proc["threads"][th_handle]
                # Close all open file handles owned by this process
                # (In this simplified model, files are global, so we skip this)
                # Remove from processes dict below

            # Remove entire process state
            pid = process_handles[handle]["pid"]
            if pid in processes:
                del processes[pid]
            del process_handles[handle]
            Kernel32.SetLastError(wt.DWORD(0))
            ret(f"CloseHandle impl. [Error=ERROR_SUCCESS, Value={wt.BOOL(1)}]")
            return wt.BOOL(1)

        # --- Invalid handle ---
        Kernel32.SetLastError(wt.DWORD(6))  # ERROR_INVALID_HANDLE
        ret(f"CloseHandle impl. {wt.BOOL(0)}")
        return wt.BOOL(0)

    @staticmethod
    def WaitForSingleObject(hHandle: wt.HANDLE, dwMilliseconds: wt.DWORD) -> wt.DWORD:
        """
        Wait for a single object to become signaled.
        """
        trace(f"WaitForSingleObject impl. [{hHandle=}, {dwMilliseconds=}]")

        handle = hHandle.value if hasattr(hHandle, 'value') else hHandle
        timeout = dwMilliseconds.value if dwMilliseconds.value != INFINITE else None
        timeout_seconds = timeout / 1000.0 if timeout is not None else None

        # Check for thread handles
        for pid, proc in processes.items():
            if "threads" in proc and handle in proc["threads"]:
                thread_obj = proc["threads"][handle]["thread"]
                try:
                    if timeout_seconds is None:
                        thread_obj.join()
                        result = WAIT_OBJECT_0
                    else:
                        thread_obj.join(timeout_seconds)
                        result = WAIT_OBJECT_0 if not thread_obj.is_alive() else WAIT_TIMEOUT
                except Exception as e:
                    error(f"WaitForSingleObject impl. thread wait failed: {e}")
                    result = WAIT_FAILED
                Kernel32.SetLastError(wt.DWORD(0) if result != WAIT_FAILED else wt.DWORD(6))
                ret(f"WaitForSingleObject impl. [Error={'ERROR_SUCCESS' if result != WAIT_FAILED else 'ERROR_INVALID_HANDLE'}, Value={result}]")
                return wt.DWORD(result)

        # Check for event handles
        if handle in processes[tls.process_id]["event_handles"]:
            event_state = processes[tls.process_id]["event_handles"][handle]
            try:
                if event_state['event'].wait(timeout_seconds):
                    # If manual reset, keep signaled; if auto reset, clear it
                    if not event_state.get('manual_reset', False):
                        event_state['event'].clear()
                    result = WAIT_OBJECT_0
                else:
                    result = WAIT_TIMEOUT
            except Exception as e:
                error(f"WaitForSingleObject impl. event wait failed: {e}")
                result = WAIT_FAILED

        # Check for semaphore handles
        elif handle in processes[tls.process_id]["semaphore_handles"]:
            sem_state = processes[tls.process_id]["semaphore_handles"][handle]
            try:
                if sem_state['semaphore'].acquire(timeout=timeout_seconds):
                    result = WAIT_OBJECT_0
                else:
                    result = WAIT_TIMEOUT
            except Exception as e:
                error(f"WaitForSingleObject impl. semaphore wait failed: {e}")
                result = WAIT_FAILED

        # Check for mutex handles
        elif handle in processes[tls.process_id]["mutex_handles"]:
            mutex_state = processes[tls.process_id]["mutex_handles"][handle]
            try:
                if mutex_state['lock'].acquire(timeout=timeout_seconds):
                    mutex_state['owner'] = th.get_ident()
                    result = WAIT_OBJECT_0
                else:
                    result = WAIT_TIMEOUT
            except Exception as e:
                error(f"WaitForSingleObject impl. mutex wait failed: {e}")
                result = WAIT_FAILED

        # Check for process handles
        elif handle in process_handles:
            process_state = process_handles[handle]
            # For simplicity, assume process is always signaled
            result = WAIT_OBJECT_0

        else:
            error(f"WaitForSingleObject impl. invalid handle")
            Kernel32.SetLastError(wt.DWORD(6))  # ERROR_INVALID_HANDLE
            result = WAIT_FAILED

        Kernel32.SetLastError(wt.DWORD(0) if result != WAIT_FAILED else wt.DWORD(6))
        ret(f"WaitForSingleObject impl. [Error={'ERROR_SUCCESS' if result != WAIT_FAILED else 'ERROR_INVALID_HANDLE'}, Value={result}]")
        return wt.DWORD(result)

    @staticmethod
    def WaitForMultipleObjects(nCount: wt.DWORD, lpHandles: wt.LPHANDLE,
                               bWaitAll: wt.BOOL, dwMilliseconds: wt.DWORD) -> wt.DWORD:
        """
        Wait for multiple objects.
        """
        trace(f"WaitForMultipleObjects impl. [{nCount=}, {bWaitAll=}, {dwMilliseconds=}]")

        count = nCount.value
        wait_all = bWaitAll.value
        timeout = dwMilliseconds.value if dwMilliseconds.value != INFINITE else None
        timeout_seconds = timeout / 1000.0 if timeout is not None else None

        if count == 0 or count > 64:  # Windows limit is 64 objects
            Kernel32.SetLastError(wt.DWORD(87))  # ERROR_INVALID_PARAMETER
            return wt.DWORD(WAIT_FAILED)

        handles = []
        for i in range(count):
            handle = lpHandles[i].value if hasattr(lpHandles[i], 'value') else lpHandles[i]
            handles.append(handle)

        start_time = tm.time()
        signaled_objects = []

        while True:
            current_time = tm.time()
            if timeout_seconds and (current_time - start_time) >= timeout_seconds:
                Kernel32.SetLastError(wt.DWORD(0))
                ret(f"WaitForMultipleObjects impl. [Error=ERROR_SUCCESS, Value=WAIT_TIMEOUT]")
                return wt.DWORD(WAIT_TIMEOUT)

            signaled_objects.clear()

            for i, handle in enumerate(handles):
                is_signaled = False

                # Check different handle types
                for pid, proc in processes.items():
                    if "threads" in proc and handle in proc["threads"]:
                        thread_obj = proc["threads"][handle]["thread"]
                        is_signaled = not thread_obj.is_alive()
                        break
                if handle in processes[tls.process_id]["event_handles"]:
                    is_signaled = processes[tls.process_id]["event_handles"][handle]['event'].is_set()
                elif handle in processes[tls.process_id]["semaphore_handles"]:
                    # Try to acquire without blocking
                    try:
                        if processes[tls.process_id]["semaphore_handles"][handle]['semaphore'].acquire(blocking=False):
                            is_signaled = True
                    except Exception:
                        pass
                elif handle in processes[tls.process_id]["mutex_handles"]:
                    # Try to acquire without blocking
                    try:
                        if processes[tls.process_id]["mutex_handles"][handle]['lock'].acquire(blocking=False):
                            processes[tls.process_id]["mutex_handles"][handle]['owner'] = th.get_ident()
                            is_signaled = True
                    except Exception:
                        pass
                elif handle in process_handles:
                    is_signaled = True  # Processes always signaled for simplicity

                if is_signaled:
                    signaled_objects.append(i)

            if wait_all:
                if len(signaled_objects) == count:
                    Kernel32.SetLastError(wt.DWORD(0))
                    ret(f"WaitForMultipleObjects impl. [Error=ERROR_SUCCESS, Value=WAIT_OBJECT_0]")
                    return wt.DWORD(WAIT_OBJECT_0)
            else:
                if signaled_objects:
                    result = WAIT_OBJECT_0 + signaled_objects[0]
                    Kernel32.SetLastError(wt.DWORD(0))
                    ret(f"WaitForMultipleObjects impl. [Error=ERROR_SUCCESS, Value={result}]")
                    return wt.DWORD(result)

            # Small sleep to avoid busy waiting
            tm.sleep(0.001)

    @staticmethod
    def WaitForSingleObjectEx(hHandle: wt.HANDLE, dwMilliseconds: wt.DWORD,
                              bAlertable: wt.BOOL) -> wt.DWORD:
        """
        Wait for a single object with alertable wait support.
        """
        trace(f"WaitForSingleObjectEx impl. [{hHandle=}, {dwMilliseconds=}, {bAlertable=}]")

        if bAlertable.value:
            apc_queue = _get_current_apc_queue()
            processed = False

            # Process queued APCs
            while apc_queue:
                apc_callback = apc_queue.popleft()
                try:
                    apc_callback()
                    processed = True
                except Exception as e:
                    error(f"APC callback failed: {e}")

            # If we executed at least one APC, return WAIT_IO_COMPLETION
            if processed:
                Kernel32.SetLastError(wt.DWORD(0))
                ret(f"WaitForSingleObjectEx impl. [Error=ERROR_SUCCESS, Value=WAIT_IO_COMPLETION]")
                return wt.DWORD(0x000000C0)  # WAIT_IO_COMPLETION

        # Fall back to regular wait
        return Kernel32.WaitForSingleObject(hHandle, dwMilliseconds)


    @staticmethod
    def WaitForMultipleObjectsEx(nCount: wt.DWORD, lpHandles: wt.LPHANDLE,
                                 bWaitAll: wt.BOOL, dwMilliseconds: wt.DWORD,
                                 bAlertable: wt.BOOL) -> wt.DWORD:
        """
        Wait for multiple objects with alertable wait support.
        """
        trace(f"WaitForMultipleObjectsEx impl. [{nCount=}, {bWaitAll=}, {dwMilliseconds=}, {bAlertable=}]")

        if bAlertable.value:
            apc_queue = _get_current_apc_queue()
            processed = False

            # Process queued APCs
            while apc_queue:
                apc_callback = apc_queue.popleft()
                try:
                    apc_callback()
                    processed = True
                except Exception as e:
                    error(f"WaitForMultipleObjectsEx APC callback failed: {e}")

            # If we executed at least one APC, return WAIT_IO_COMPLETION
            if processed:
                Kernel32.SetLastError(wt.DWORD(0))
                ret(f"WaitForMultipleObjectsEx impl. [Error=ERROR_SUCCESS, Value=WAIT_IO_COMPLETION]")
                return wt.DWORD(0x000000C0)  # WAIT_IO_COMPLETION

        # Fall back to regular wait
        return Kernel32.WaitForMultipleObjects(nCount, lpHandles, bWaitAll, dwMilliseconds)

    @staticmethod
    def QueueUserAPC(pfnAPC: wt.LPVOID, hThread: wt.HANDLE, dwData: ULONG_PTR) -> wt.BOOL:
        """
        Queue an APC (Asynchronous Procedure Call) to a thread.
        """
        global processes
        trace(f"QueueUserAPC impl. [{pfnAPC=}, {hThread=}, {dwData=}]")

        handle = hThread.value if hasattr(hThread, 'value') else hThread

        # Find the thread ID for this handle
        target_tid = None
        for pid, proc in processes.items():
            if "threads" in proc and handle in proc["threads"]:
                target_tid = proc["threads"][handle]["thread_id"].value
                break

        if target_tid is None:
            error("QueueUserAPC: invalid thread handle")
            Kernel32.SetLastError(wt.DWORD(6))  # ERROR_INVALID_HANDLE
            ret(f"QueueUserAPC impl. [Error=ERROR_INVALID_HANDLE, Value=FALSE]")
            return wt.BOOL(0)

        # Create APC queue for target thread if it doesn't exist
        if target_tid not in processes[tls.process_id]["apc_queue"]:
            processes[tls.process_id]["apc_queue"][target_tid] = cl.deque()

        # Queue the APC callback
        def apc_wrapper():
            try:
                # Call the APC function with dwData parameter
                callback_func = ct.CFUNCTYPE(None, ULONG_PTR)(pfnAPC)
                callback_func(dwData)
            except Exception as e:
                error(f"APC execution failed: {e}")

        processes[tls.process_id]["apc_queue"][target_tid].append(apc_wrapper)

        Kernel32.SetLastError(wt.DWORD(0))
        ret(f"QueueUserAPC impl. [Error=ERROR_SUCCESS, Value=TRUE]")
        return wt.BOOL(1)

    @staticmethod
    def GetFileSize(hFile: wt.HANDLE, lpFileSizeHigh: wt.LPDWORD) -> wt.DWORD:
        trace(f"GetFileSize impl. [{hFile=}]")
        global processes

        handle = hFile.value if hasattr(hFile, 'value') else hFile
        if handle not in processes[tls.process_id]["file_handles"]:
            Kernel32.SetLastError(wt.DWORD(6))  # ERROR_INVALID_HANDLE
            ret(f"GetFileSize impl. {0xFFFFFFFF}")
            return wt.DWORD(0xFFFFFFFF)  # INVALID_FILE_SIZE

        try:
            file_obj = processes[tls.process_id]["file_handles"][handle]['file']
            current_pos = file_obj.tell()
            file_obj.seek(0, 2)  # Seek to end
            file_size = file_obj.tell()
            file_obj.seek(current_pos)  # Restore position

            # Split into low and high parts
            size_low = file_size & 0xFFFFFFFF
            size_high = (file_size >> 32) & 0xFFFFFFFF

            if lpFileSizeHigh:
                lpFileSizeHigh[0] = wt.DWORD(size_high)

            Kernel32.SetLastError(wt.DWORD(0))
            ret(f"GetFileSize impl. [Error=ERROR_SUCCESS, Value={size_low}]")
            return wt.DWORD(size_low)

        except Exception as e:
            error(f"GetFileSize impl. {e}")
            Kernel32.SetLastError(wt.DWORD(5))  # ERROR_ACCESS_DENIED
            ret(f"GetFileSize impl. [Error=ERROR_ACCESS_DENIED, Value={0xFFFFFFFF}]")
            return wt.DWORD(0xFFFFFFFF)

    @staticmethod
    def SetFilePointer(hFile: wt.HANDLE, lDistanceToMove: wt.LONG, lpDistanceToMoveHigh: wt.PLONG,
                       dwMoveMethod: wt.DWORD) -> wt.DWORD:
        global processes
        trace(f"SetFilePointer impl. [{hFile=}, {lDistanceToMove=}, {dwMoveMethod=}]")

        handle = hFile.value if hasattr(hFile, 'value') else hFile
        if handle not in processes[tls.process_id]["file_handles"]:
            Kernel32.SetLastError(wt.DWORD(6))  # ERROR_INVALID_HANDLE
            ret(f"SetFilePointer impl. [Error=ERROR_INVALID_HANDLE, Value={0xFFFFFFFF}]")
            return wt.DWORD(0xFFFFFFFF)

        try:
            file_obj = processes[tls.process_id]["file_handles"][handle]['file']

            # Calculate 64-bit offset
            offset = lDistanceToMove.value
            if lpDistanceToMoveHigh:
                offset |= (lpDistanceToMoveHigh[0] << 32)

            # Map Windows seek methods to Python
            whence_map = {0: 0, 1: 1, 2: 2}  # FILE_BEGIN, FILE_CURRENT, FILE_END
            whence = whence_map.get(dwMoveMethod.value, 0)

            new_pos = file_obj.seek(offset, whence)

            Kernel32.SetLastError(wt.DWORD(0))
            ret(f"SetFilePointer impl. [Error=ERROR_SUCCESS, Value={new_pos & 0xFFFFFFFF}]")
            return wt.DWORD(new_pos & 0xFFFFFFFF)

        except Exception as e:
            error(f"SetFilePointer impl. {e}")
            Kernel32.SetLastError(wt.DWORD(5))  # ERROR_ACCESS_DENIED
            ret(f"SetFilePointer impl. [Error=ERROR_ACCESS_DENIED, Value={0xFFFFFFFF}]")
            return wt.DWORD(0xFFFFFFFF)

    @staticmethod
    def SetFilePointerEx(hFile: wt.HANDLE, liDistanceToMove: wt.LARGE_INTEGER,
                         lpNewFilePointer: wt.PULARGE_INTEGER, dwMoveMethod: wt.DWORD) -> wt.BOOL:
        """
        Move the file pointer of an open file handle (64-bit version).
        """
        global processes
        trace(f"SetFilePointerEx impl. [{hFile=}, {liDistanceToMove=}, {lpNewFilePointer=}, {dwMoveMethod=}]")

        handle = hFile.value if hasattr(hFile, 'value') else hFile
        if handle not in processes[tls.process_id]["file_handles"]:
            Kernel32.SetLastError(wt.DWORD(6))  # ERROR_INVALID_HANDLE
            return wt.BOOL(0)
        file_obj = processes[tls.process_id]["file_handles"][handle]['file']
        try:
            distance = liDistanceToMove.value

            if dwMoveMethod.value == 0:  # FILE_BEGIN
                file_obj.seek(distance, os.SEEK_SET)
            elif dwMoveMethod.value == 1:  # FILE_CURRENT
                file_obj.seek(distance, os.SEEK_CUR)
            elif dwMoveMethod.value == 2:  # FILE_END
                file_obj.seek(distance, os.SEEK_END)
            else:
                Kernel32.SetLastError(wt.DWORD(87))  # ERROR_INVALID_PARAMETER
                return wt.BOOL(0)

            new_pos = file_obj.tell()
            if lpNewFilePointer:
                lpNewFilePointer.contents.value = new_pos

            Kernel32.SetLastError(wt.DWORD(0))
            ret(f"SetFilePointerEx impl. [Error=ERROR_SUCCESS, Value={wt.BOOL(1)}]")
            return wt.BOOL(1)
        except Exception as e:
            error(f"SetFilePointerEx impl. {e}")
            Kernel32.SetLastError(wt.DWORD(5))  # ERROR_ACCESS_DENIED
            ret(f"SetFilePointerEx impl. [Error=ERROR_ACCESS_DENIED, Value={wt.BOOL(0)}]")
            return wt.BOOL(0)


    @staticmethod
    def FlushFileBuffers(hFile: wt.HANDLE) -> wt.BOOL:
        global processes
        trace(f"FlushFileBuffers impl. [{hFile=}]")

        handle = hFile.value if hasattr(hFile, 'value') else hFile
        if handle not in processes[tls.process_id]["file_handles"]:
            Kernel32.SetLastError(wt.DWORD(6))  # ERROR_INVALID_HANDLE
            return wt.BOOL(0)

        try:
            file_obj = processes[tls.process_id]["file_handles"][handle]['file']
            file_obj.flush()

            Kernel32.SetLastError(wt.DWORD(0))
            ret(f"FlushFileBuffers impl. [Error=ERROR_SUCCESS, Value={wt.BOOL(1)}]")
            return wt.BOOL(1)

        except Exception as e:
            error(f"FlushFileBuffers impl. {e}")
            Kernel32.SetLastError(wt.DWORD(5))  # ERROR_ACCESS_DENIED
            ret(f"FlushFileBuffers impl. [Error=ERROR_ACCESS_DENIED, Value={wt.BOOL(0)}]")
            return wt.BOOL(0)

    @staticmethod
    def FindFirstFileW(lpFileName: wt.LPCWSTR, lpFindFileData: wt.LPVOID) -> wt.HANDLE:
        global processes

        trace(f"FindFirstFileW impl. [{lpFileName=}]")

        pattern = lpFileName.value if hasattr(lpFileName, 'value') else str(lpFileName)

        try:
            files = gb.glob(pattern)
            if not files:
                Kernel32.SetLastError(wt.DWORD(2))  # ERROR_FILE_NOT_FOUND
                return wt.HANDLE(-1)

            iterator = iter(files)
            first_file = next(iterator)

            # Fill WIN32_FIND_DATAW
            fd = WIN32_FIND_DATAW()
            fd.dwFileAttributes = 0  # can expand with more attributes if needed
            fd.nFileSizeLow = os.path.getsize(first_file) & 0xFFFFFFFF
            fd.nFileSizeHigh = (os.path.getsize(first_file) >> 32) & 0xFFFFFFFF
            fd.cFileName = first_file

            ct.memmove(lpFindFileData, ct.byref(fd), ct.sizeof(fd))

            handle = processes[tls.process_id]["next_find_handle"]
            processes[tls.process_id]["next_find_handle"] += 1
            processes[tls.process_id]["find_handles"][handle] = iterator

            Kernel32.SetLastError(wt.DWORD(0))
            ret(f"FindFirstFileW impl. [Error=ERROR_SUCCESS, Value={handle}]")
            return wt.HANDLE(handle)

        except Exception as e:
            error(f"FindFirstFileW impl. {e}")
            Kernel32.SetLastError(wt.DWORD(5))  # ERROR_ACCESS_DENIED
            ret(f"FindFirstFileW impl. [Error=ERROR_ACCESS_DENIED, Value={wt.HANDLE(-1)}]")
            return wt.HANDLE(-1)

    @staticmethod
    def FindNextFileW(hFindFile: wt.HANDLE, lpFindFileData: wt.LPVOID) -> wt.BOOL:
        global processes
        handle = hFindFile.value if hasattr(hFindFile, 'value') else hFindFile

        trace(f"FindNextFileW impl. [{hFindFile=}]")

        if handle not in processes[tls.process_id]["find_handles"]:
            Kernel32.SetLastError(wt.DWORD(6))  # ERROR_INVALID_HANDLE
            return wt.BOOL(0)

        try:
            next_file = next(processes[tls.process_id]["find_handles"][handle])

            fd = WIN32_FIND_DATAW()
            fd.dwFileAttributes = 0
            fd.nFileSizeLow = os.path.getsize(next_file) & 0xFFFFFFFF
            fd.nFileSizeHigh = (os.path.getsize(next_file) >> 32) & 0xFFFFFFFF
            fd.cFileName = next_file

            ct.memmove(lpFindFileData, ct.byref(fd), ct.sizeof(fd))

            Kernel32.SetLastError(wt.DWORD(0))
            ret(f"FindNextFileW impl. [Error=ERROR_SUCCESS, Value={wt.BOOL(1)}]")
            return wt.BOOL(1)

        except StopIteration:
            Kernel32.SetLastError(wt.DWORD(18))  # ERROR_NO_MORE_FILES
            ret(f"FindNextFileW impl. [Error=ERROR_NO_MORE_FILES, Value={wt.BOOL(0)}]")
            return wt.BOOL(0)

    @staticmethod
    def FindClose(hFindFile: wt.HANDLE) -> wt.BOOL:
        handle = hFindFile.value if hasattr(hFindFile, 'value') else hFindFile

        trace(f"FindClose impl. [{hFindFile=}]")

        if handle in processes[tls.process_id]["find_handles"]:
            del processes[tls.process_id]["find_handles"][handle]
            Kernel32.SetLastError(wt.DWORD(0))
            ret(f"FindClose impl. [Error=ERROR_SUCCESS, Value={wt.BOOL(1)}]")
            return wt.BOOL(1)

        Kernel32.SetLastError(wt.DWORD(6))  # ERROR_INVALID_HANDLE
        return wt.BOOL(0)

    @staticmethod
    def GetCommandLineW() -> wt.LPCWSTR:
        trace(f"GetCommandLineW impl. []")
        Kernel32.SetLastError(wt.DWORD(0))
        cmdline_buffer = processes[tls.process_id]["cmdline_buffer"]
        ret(f"GetCommandLineW impl. [Error=ERROR_SUCCESS, Value={cmdline_buffer}]")
        return cmdline_buffer

    @staticmethod
    def GetCurrentProcess() -> wt.HANDLE:
        trace(f"GetCurrentProcess impl. []")
        Kernel32.SetLastError(wt.DWORD(0))
        ret(f"GetCurrentProcess impl. [Error=ERROR_SUCCESS, Value={wt.HANDLE(-1)}]")
        return wt.HANDLE(-1)

    @staticmethod
    def GetModuleHandleW(lpModuleName: wt.LPCWSTR) -> wt.HMODULE:
        """
        Get a handle to a loaded module (Unicode version).
        """
        trace(f"GetModuleHandleW impl. [{lpModuleName=}]")

        try:
            if not lpModuleName:
                # Return handle to the executable module of the current process
                exe_module = processes[tls.process_id]["exe_module"]
                handle = wt.HMODULE(exe_module)
                Kernel32.SetLastError(wt.DWORD(0))
                ret(f"GetModuleHandleW impl. {handle}")
                return handle

            mod_name = ct.wstring_at(lpModuleName).lower()
            for mod_base, mod_info in processes[tls.process_id]["modules"].items():
                if mod_info["name"].lower() == mod_name:
                    handle = wt.HMODULE(mod_base)
                    Kernel32.SetLastError(wt.DWORD(0))
                    ret(f"GetModuleHandleW impl. {handle}")
                    return handle

            # Not found
            Kernel32.SetLastError(wt.DWORD(126))  # ERROR_MOD_NOT_FOUND
            return wt.HMODULE(0)

        except Exception as e:
            error(f"GetModuleHandleW impl. {e}")
            Kernel32.SetLastError(wt.DWORD(5))
            return wt.HMODULE(0)

    # LoadLibraryW (keeps your earlier behavior but fixed to register properly)
    @staticmethod
    def LoadLibraryW(lpLibFileName: wt.LPCWSTR) -> wt.HMODULE:
        global processes
        trace(f"LoadLibraryW impl. [{lpLibFileName=}]")

        lib_name = lpLibFileName.value if hasattr(lpLibFileName, "value") else str(lpLibFileName)
        if not lib_name:
            Kernel32.SetLastError(wt.DWORD(87))  # ERROR_INVALID_PARAMETER
            ret(f"LoadLibraryW impl. [Error=ERROR_INVALID_PARAMETER, Value={wt.HMODULE(0)}]")
            return wt.HMODULE(0)

        lib_path = os.path.abspath(lib_name)
        dll_name = os.path.basename(lib_path).lower()
        dll_name = _normalize_module_name(dll_name)

        # Already loaded?
        if dll_name in processes[tls.process_id]["modules"]:
            info = processes[tls.process_id]["modules"][dll_name]
            Kernel32.SetLastError(wt.DWORD(0))
            trace(f"LoadLibraryW impl.: already loaded {dll_name} -> {info['hModule']}")
            ret(f"LoadLibraryW impl. [Error=ERROR_SUCCESS, Value={info['hModule']}]")
            return info["hModule"]

        # Load and map PE
        try:
            pe = pf.PE(lib_path)
        except FileNotFoundError:
            error(f"LoadLibraryW impl.: DLL not found {lib_path}")
            Kernel32.SetLastError(wt.DWORD(2))  # ERROR_FILE_NOT_FOUND
            ret(f"LoadLibraryW impl. [Error=ERROR_FILE_NOT_FOUND, Value={wt.HMODULE(0)}]")
            return wt.HMODULE(0)
        except Exception as e:
            error(f"LoadLibraryW impl.: failed to parse PE {lib_path}: {e}")
            Kernel32.SetLastError(wt.DWORD(1))  # ERROR_INVALID_FUNCTION (fallback)
            ret(f"LoadLibraryW impl. [Error=ERROR_INVALID_FUNCTION, Value={wt.HMODULE(0)}]")
            return wt.HMODULE(0)

        size = pe.OPTIONAL_HEADER.SizeOfImage
        mem = mm.mmap(-1, size, prot=mm.PROT_READ | mm.PROT_WRITE | mm.PROT_EXEC)
        base_addr = ct.addressof(ct.c_char.from_buffer(mem))
        trace(f"LoadLibraryW impl.: mapping {dll_name} -> base {hex(base_addr)} size {size}")

        # Copy sections
        for section in pe.sections:
            sect_va = base_addr + section.VirtualAddress
            raw = section.get_data()
            ct.memmove(sect_va, raw, len(raw))

        # Apply relocations, resolve imports, init TLS
        from idk import WineLikeLoader
        loader = WineLikeLoader()  # or use existing loader instance
        loader.apply_relocs(pe, mem, base_addr)
        loader.resolve_imports(pe, base_addr)
        loader.init_tls(pe, mem, base_addr)

        # Build exports
        exports = {}
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.address is not None:
                    addr = base_addr + (exp.address if isinstance(exp.address, int) else int(exp.address))
                    if exp.name:
                        exports[exp.name.decode(errors="ignore")] = addr
                    else:
                        exports[f"Ordinal_{exp.ordinal}"] = addr

        # Call DllMain with DLL_PROCESS_ATTACH
        entry_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        if entry_rva != 0:
            entry_va = base_addr + entry_rva
            DllMainProto = ct.CFUNCTYPE(wt.BOOL, wt.HMODULE, wt.DWORD, wt.LPVOID)
            dll_main = DllMainProto(entry_va)
            try:
                ret_val = dll_main(base_addr, 1, None)  # 1 = DLL_PROCESS_ATTACH
                trace(f"LoadLibraryW impl.: DllMain called for {dll_name}, returned {ret_val}")
            except Exception as e:
                error(f"LoadLibraryW impl.: DllMain execution failed for {dll_name}: {e}")

        # Register module
        info = {
            "hModule": wt.HMODULE(base_addr),
            "base_addr": base_addr,
            "exports": exports,
            "pe": pe,
            "mem": mem,
            "dll_info": None,
        }
        modules[dll_name] = info

        Kernel32.SetLastError(wt.DWORD(0))
        ret(f"LoadLibraryW impl. [Error=ERROR_SUCCESS, Value={info['hModule']}]")
        return info["hModule"]

    @staticmethod
    def LoadLibraryExW(lpLibFileName: wt.LPCWSTR, hFile: wt.HANDLE = None, dwFlags: wt.DWORD = 0) -> wt.HMODULE:
        """
        LoadLibraryExW implementation for Wine-like loader supporting all flags.

        Flags:
          0x00000001 DONT_RESOLVE_DLL_REFERENCES
          0x00000002 LOAD_LIBRARY_AS_DATAFILE
          0x00000008 LOAD_WITH_ALTERED_SEARCH_PATH
          0x00000010 LOAD_IGNORE_CODE_AUTHZ_LEVEL
          0x00000020 LOAD_LIBRARY_AS_IMAGE_RESOURCE
          0x00000040 LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE
          0x00000100 LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR
          0x00000200 LOAD_LIBRARY_SEARCH_APPLICATION_DIR
          0x00000400 LOAD_LIBRARY_SEARCH_USER_DIRS
          0x00000800 LOAD_LIBRARY_SEARCH_SYSTEM32
          0x00001000 LOAD_LIBRARY_SEARCH_DEFAULT_DIRS
          0x00002000 LOAD_LIBRARY_SAFE_CURRENT_DIRS
          0x00000080 LOAD_LIBRARY_REQUIRE_SIGNED_TARGET
        """
        global modules
        trace(f"LoadLibraryExW impl. [{lpLibFileName=}, {dwFlags=}]")

        lib_name = lpLibFileName.value if hasattr(lpLibFileName, "value") else str(lpLibFileName)
        if not lib_name:
            Kernel32.SetLastError(wt.DWORD(87))  # ERROR_INVALID_PARAMETER
            return wt.HMODULE(0)

        lib_path = os.path.abspath(lib_name)
        dll_name = os.path.basename(lib_path).lower()
        dll_name = _normalize_module_name(dll_name)

        # Already loaded?
        if dll_name in modules:
            info = modules[dll_name]
            Kernel32.SetLastError(wt.DWORD(0))
            trace(f"LoadLibraryExW impl.: already loaded {dll_name} -> {info['hModule']}")
            ret(f"LoadLibraryExW impl. [Error=ERROR_SUCCESS, Value={info['hModule']}]")
            return info["hModule"]

        # Load PE file
        try:
            pe = pf.PE(lib_path)
        except FileNotFoundError:
            error(f"LoadLibraryExW impl.: DLL not found {lib_path}")
            Kernel32.SetLastError(wt.DWORD(2))  # ERROR_FILE_NOT_FOUND
            ret(f"LoadLibraryExW impl. [Error=ERROR_FILE_NOT_FOUND, Value={wt.HMODULE(0)}]")
            return wt.HMODULE(0)
        except Exception as e:
            error(f"LoadLibraryExW impl.: failed to parse PE {lib_path}: {e}")
            Kernel32.SetLastError(wt.DWORD(1))  # ERROR_INVALID_FUNCTION
            ret(f"LoadLibraryExW impl. [Error=ERROR_INVALID_FUNCTION, Value={wt.HMODULE(0)}]")
            return wt.HMODULE(0)

        size = pe.OPTIONAL_HEADER.SizeOfImage
        mem = mm.mmap(-1, size, prot=mm.PROT_READ | mm.PROT_WRITE | mm.PROT_EXEC)
        base_addr = ct.addressof(ct.c_char.from_buffer(mem))
        trace(f"LoadLibraryExW impl.: mapping {dll_name} -> base {hex(base_addr)} size {size}")

        # Copy sections
        for section in pe.sections:
            sect_va = base_addr + section.VirtualAddress
            raw = section.get_data()
            ct.memmove(sect_va, raw, len(raw))

        from idk import WineLikeLoader
        loader = WineLikeLoader()  # or use existing loader instance

        # Apply relocations & imports only if NOT loading as datafile/resource
        if not (dwFlags.value & 0x00000002 or dwFlags.value & 0x00000001):
            loader.apply_relocs(pe, mem, base_addr)
            loader.resolve_imports(pe, base_addr)
            loader.init_tls(pe, mem, base_addr)
        else:
            trace("LoadLibraryExW impl.: skipping relocations/imports/TLS due to DATAFILE/IMAGE_RESOURCE flags")

        # Build exports table
        exports = {}
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.address is not None:
                    addr = base_addr + (exp.address if isinstance(exp.address, int) else int(exp.address))
                    if exp.name:
                        exports[exp.name.decode(errors="ignore")] = addr
                    else:
                        exports[f"Ordinal_{exp.ordinal}"] = addr

        # Call DllMain with DLL_PROCESS_ATTACH
        entry_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        if entry_rva != 0:
            entry_va = base_addr + entry_rva
            DllMainProto = ct.CFUNCTYPE(wt.BOOL, wt.HMODULE, wt.DWORD, wt.LPVOID)
            dll_main = DllMainProto(entry_va)
            try:
                ret_val = dll_main(base_addr, 1, None)  # 1 = DLL_PROCESS_ATTACH
                trace(f"LoadLibraryExW impl.: DllMain called for {dll_name}, returned {ret_val}")
            except Exception as e:
                error(f"LoadLibraryExW impl.: DllMain execution failed for {dll_name}: {e}")

        # Register module
        info = {
            "hModule": wt.HMODULE(base_addr),
            "base_addr": base_addr,
            "exports": exports,
            "pe": pe,
            "mem": mem,
            "dll_info": None,
        }
        modules[dll_name] = info

        Kernel32.SetLastError(wt.DWORD(0))
        ret(f"LoadLibraryExW impl. [Error=ERROR_SUCCESS, Value={info['hModule']}]")
        return info["hModule"]

    # FreeLibrary
    @staticmethod
    def FreeLibrary(hModule: wt.HANDLE) -> wt.BOOL:
        global modules
        trace(f"FreeLibrary impl. [{hModule=}]")

        if hModule is None:
            Kernel32.SetLastError(wt.DWORD(87))  # ERROR_INVALID_PARAMETER
            return wt.BOOL(0)

        handle_val = hModule.value if hasattr(hModule, "value") else int(hModule)

        # find module by base_addr/hModule value
        found_key = None
        for name, info in modules.items():
            if info.get("hModule") and info["hModule"].value == handle_val:
                found_key = name
                break

        if not found_key:
            Kernel32.SetLastError(wt.DWORD(6))  # ERROR_INVALID_HANDLE
            ret("FreeLibrary impl. [Error=ERROR_INVALID_HANDLE, Value=FALSE]")
            return wt.BOOL(0)

        info = modules.pop(found_key)

        # Call DllMain with DLL_PROCESS_DETACH
        pe = info.get("pe")
        base_addr = info.get("base_addr")
        if pe and base_addr:
            entry_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            if entry_rva != 0:
                entry_va = base_addr + entry_rva
                DllMainProto = ct.CFUNCTYPE(wt.BOOL, wt.HMODULE, wt.DWORD, wt.LPVOID)
                dll_main = DllMainProto(entry_va)
                try:
                    ret_val = dll_main(base_addr, 0, None)  # 0 = DLL_PROCESS_DETACH
                    trace(f"FreeLibrary impl.: DllMain DLL_PROCESS_DETACH called for {found_key}, returned {ret_val}")
                except Exception as e:
                    error(f"FreeLibrary impl.: DllMain DLL_PROCESS_DETACH execution failed for {found_key}: {e}")

        # close/unmap memory if present
        try:
            mem = info.get("mem")
            if mem is not None:
                try:
                    mem.close()
                except Exception:
                    pass
        except Exception:
            pass

        Kernel32.SetLastError(wt.DWORD(0))
        ret(f"FreeLibrary impl. [Error=ERROR_SUCCESS, Value=TRUE]")
        return wt.BOOL(1)

    @staticmethod
    def GetCurrentProcessId() -> wt.DWORD:
        trace(f"GetCurrentProcessId impl. []")
        Kernel32.SetLastError(wt.DWORD(0))
        ret(f"GetCurrentProcessId impl. [Error=ERROR_SUCCESS, Value={tls.process_id}]")
        return wt.DWORD(tls.process_id)

    # GetModuleFileNameW
    @staticmethod
    def GetModuleFileNameW(hModule: wt.HANDLE, lpFilename: wt.LPWSTR, nSize: wt.DWORD) -> wt.DWORD:
        global module_filename_buffer, modules, process_hmodule
        trace(f"GetModuleFileNameW impl. [{hModule=}, {nSize=}]")
        cmdline = processes[tls.process_id]["cmdline"]
        process_hmodule = processes[tls.process_id].get(cmdline.split(os.sep)[0].lower())
        # determine path
        try:
            if hModule is None or (hasattr(hModule, "value") and hModule.value == 0):
                # current executable
                if process_hmodule:
                    # find the registered module with is_main flag or match process_hmodule
                    # fallback to first module with base_addr == process_hmodule.value
                    for name, info in modules.items():
                        m = info.get("hModule")
                        if m and process_hmodule and m.value == process_hmodule.value:
                            path = info.get("pe").__data__ if info.get("pe") else cmdline[0]
                            break
                    else:
                        path = cmdline[0]
                else:
                    path = cmdline[0]
            else:
                handle_val = hModule.value if hasattr(hModule, "value") else int(hModule)
                # find module by handle/base_addr
                for name, info in modules.items():
                    if info.get("hModule") and info["hModule"].value == handle_val:
                        peobj = info.get("pe")
                        if peobj and hasattr(peobj, 'name') and peobj.name:
                            path = getattr(peobj, 'name', None) or info.get("dll_info", {}).get("path") or ""
                        else:
                            # try to recover path from dll_info if present
                            di = info.get("dll_info")
                            path = di.path if di and getattr(di, "path", None) else ""
                        if not path:
                            # fallback to file on disk if available
                            path = info.get("dll_info").path if di and getattr(di, "path", None) else ""
                        break
                else:
                    Kernel32.SetLastError(wt.DWORD(6))  # ERROR_INVALID_HANDLE
                    return wt.DWORD(0)

            # ensure str and truncate to nSize - 1
            path_str = str(path)
            if nSize.value and len(path_str) >= nSize.value:
                path_str = path_str[: nSize.value - 1]

            module_filename_buffer = ct.create_unicode_buffer(path_str, nSize.value)
            # copy into caller buffer
            ct.memmove(lpFilename, module_filename_buffer, ct.sizeof(module_filename_buffer))

            Kernel32.SetLastError(wt.DWORD(0))
            ret(f"GetModuleFileNameW impl. [Error=ERROR_SUCCESS, Value={len(path_str)}]")
            return wt.DWORD(len(path_str))
        except Exception as e:
            error(f"GetModuleFileNameW impl. {e}")
            Kernel32.SetLastError(wt.DWORD(5))
            ret(f"GetModuleFileNameW impl. [Error=ERROR_ACCESS_DENIED, Value={wt.DWORD(5)}")
            return wt.DWORD(0)

    @staticmethod
    def SetEnvironmentVariableW(lpName: wt.LPCWSTR, lpValue: wt.LPCWSTR) -> wt.BOOL:
        trace(f"SetEnvironmentVariableW impl. [{lpName=}, {lpValue=}]")

        name = lpName.value if hasattr(lpName, "value") else str(lpName)
        value = lpValue.value if hasattr(lpValue, "value") else str(lpValue)

        try:
            if value is None:
                if name in global_env:
                    del global_env[name]
            else:
                global_env[name] = value
            _save_env()
            Kernel32.SetLastError(wt.DWORD(0))
            ret(f"SetEnvironmentVariableW impl. [Error=ERROR_SUCCESS, Value={wt.BOOL(1)}]")
            return wt.BOOL(1)
        except Exception as e:
            error(f"SetEnvironmentVariableW impl. {e}")
            Kernel32.SetLastError(wt.DWORD(5))
            ret(f"SetEnvironmentVariableW impl. [Error=ERROR_ACCESS_DENIED, Value={wt.BOOL(0)}]")
            return wt.BOOL(0)

    @staticmethod
    def GetEnvironmentVariableW(lpName: wt.LPCWSTR, lpBuffer: wt.LPWSTR, nSize: wt.DWORD) -> wt.DWORD:
        trace(f"GetEnvironmentVariableW impl. [{lpName=}, {nSize=}]")
        name = lpName.value if hasattr(lpName, "value") else str(lpName)
        value = global_env.get(name, "")
        if len(value) >= nSize.value:
            value = value[: nSize.value - 1]
        if lpBuffer and nSize.value > 0:
            ct.memmove(lpBuffer, ct.create_unicode_buffer(value), (len(value) + 1) * ct.sizeof(ct.c_wchar))
        Kernel32.SetLastError(wt.DWORD(0))
        ret(f"GetEnvironmentVariableW impl. [Error=ERROR_SUCCESS, Value={len(value)}]")
        return wt.DWORD(len(value))

    @staticmethod
    def InitializeCriticalSection(lpCriticalSection: LPCRITICAL_SECTION) -> None:
        """
        Properly initialize CRITICAL_SECTION.
        """
        global processes
        trace(f"InitializeCriticalSection impl. [{lpCriticalSection=}]")

        cs = lpCriticalSection.contents
        cs.LockCount = -1
        cs.RecursionCount = 0
        cs.OwningThread = wt.HANDLE(0)
        cs.LockSemaphore = wt.HANDLE(processes[tls.process_id]["next_file_handle"])  # fake handle for semaphore
        processes[tls.process_id]["next_file_handle"] += 1
        cs.SpinCount = 0x400  # arbitrary spin count

        # Python internal state
        sem = th.Semaphore(0)
        lock_state = {
            "lock": th.Lock(),
            "semaphore": sem,
            "owner": None,
            "recursion": 0,
            "waiters": cl.deque(),
        }
        processes[tls.process_id].setdefault("critical_sections", {})
        processes[tls.process_id]["critical_sections"][id(cs)] = lock_state

        Kernel32.SetLastError(wt.DWORD(0))
        ret(f"InitializeCriticalSection impl. [Error=ERROR_SUCCESS, Value=-]")

    @staticmethod
    def InitializeCriticalSectionEx(
            lpCriticalSection: PCRITICAL_SECTION,
            dwSpinCount: wt.DWORD,
            Flags: wt.DWORD
    ) -> wt.BOOL:
        """
        Initialize a critical section with spin count and optional flags.
        """
        global processes
        trace(f"InitializeCriticalSectionEx impl. [{lpCriticalSection=}, {dwSpinCount=}, {Flags=}]")

        cs = lpCriticalSection.contents
        cs.LockCount = -1
        cs.RecursionCount = 0
        cs.OwningThread = wt.HANDLE(0)
        cs.LockSemaphore = wt.HANDLE(processes[tls.process_id]["next_file_handle"])  # fake handle for semaphore
        processes[tls.process_id]["next_file_handle"] += 1
        cs.SpinCount = dwSpinCount.value

        # Python internal state
        sem = th.Semaphore(0)
        lock_state = {
            "lock": th.Lock(),
            "semaphore": sem,
            "owner": None,
            "recursion": 0,
            "waiters": cl.deque(),
            "flags": Flags.value,
        }
        processes[tls.process_id].setdefault("critical_sections", {})
        processes[tls.process_id]["critical_sections"][id(cs)] = lock_state

        Kernel32.SetLastError(wt.DWORD(0))
        ret(f"InitializeCriticalSectionEx impl. {cs}")
        return wt.BOOL(1)

    @staticmethod
    def TryEnterCriticalSection(lpCriticalSection: LPCRITICAL_SECTION) -> wt.BOOL:
        global processes
        cs = lpCriticalSection.contents
        state = processes[tls.process_id]["critical_sections"].get(id(cs))
        tid = th.get_ident()
        trace(f"TryEnterCriticalSection impl. [{cs}, tid={tid}]")
        if state is None:
            error("TryEnterCriticalSection invalid handle")
            Kernel32.SetLastError(wt.DWORD(6))
            return wt.BOOL(0)

        # Reentrant check
        if cs.OwningThread.value == tid:
            cs.RecursionCount += 1
            Kernel32.SetLastError(wt.DWORD(0))
            ret(f"TryEnterCriticalSection impl. [Error=ERROR_SUCCESS, Value=TRUE]")
            return wt.BOOL(1)

        # Try to acquire lock
        with state["lock"]:
            if cs.LockCount == -1:
                # acquired
                cs.LockCount = 0
                cs.RecursionCount = 1
                cs.OwningThread = wt.HANDLE(tid)
                Kernel32.SetLastError(wt.DWORD(0))
                ret(f"TryEnterCriticalSection impl. [Error=ERROR_SUCCESS, Value=TRUE]")
                return wt.BOOL(1)
            else:
                # already locked
                Kernel32.SetLastError(wt.DWORD(0))
                ret(f"TryEnterCriticalSection impl. [Error=ERROR_SUCCESS, Value=FALSE]")
                return wt.BOOL(0)
    @staticmethod
    def InitializeCriticalSectionAndSpinCount(
            lpCriticalSection: PCRITICAL_SECTION,
            dwSpinCount: wt.DWORD
    ) -> wt.DWORD:
        """
        Initialize a critical section with a specified spin count.
        """
        global processes
        trace(f"InitializeCriticalSectionAndSpinCount impl. [{lpCriticalSection=}, {dwSpinCount=}]")

        cs = lpCriticalSection.contents
        cs.LockCount = -1
        cs.RecursionCount = 0
        cs.OwningThread = wt.HANDLE(0)
        cs.LockSemaphore = wt.HANDLE(processes[tls.process_id]["next_file_handle"])  # fake handle for semaphore
        processes[tls.process_id]["next_file_handle"] += 1
        cs.SpinCount = dwSpinCount.value

        # Python internal state
        sem = th.Semaphore(0)
        lock_state = {
            "lock": th.Lock(),
            "semaphore": sem,
            "owner": None,
            "recursion": 0,
            "waiters": cl.deque(),
        }

        processes[tls.process_id].setdefault("critical_sections", {})
        processes[tls.process_id]["critical_sections"][id(cs)] = lock_state

        Kernel32.SetLastError(wt.DWORD(0))
        ret(f"InitializeCriticalSectionAndSpinCount impl. {cs}")
        return wt.DWORD(1)

    @staticmethod
    def EnterCriticalSection(lpCriticalSection: LPCRITICAL_SECTION) -> None:
        global processes
        cs = lpCriticalSection.contents
        state = processes[tls.process_id]["critical_sections"].get(id(cs))
        tid = th.get_ident()
        trace(f"EnterCriticalSection impl. [{cs}, tid={tid}]")

        if state is None:
            error("EnterCriticalSection invalid handle")
            Kernel32.SetLastError(wt.DWORD(6))
            return

        # Reentrant check
        if cs.OwningThread.value == tid:
            cs.RecursionCount += 1
            Kernel32.SetLastError(wt.DWORD(0))
            ret(f"EnterCriticalSection impl. [Error=ERROR_SUCCESS, Value=-]")
            return

        # Acquire lock
        with state["lock"]:
            while cs.LockCount != -1:
                # block waiting
                waiter = th.Semaphore(0)
                state["waiters"].append(waiter)
                state["lock"].release()
                waiter.acquire()
                state["lock"].acquire()

            # acquired
            cs.LockCount = 0
            cs.RecursionCount = 1
            cs.OwningThread = wt.HANDLE(tid)

        Kernel32.SetLastError(wt.DWORD(0))
        ret(f"EnterCriticalSection impl. [Error=ERROR_SUCCESS, Value=-]")

    @staticmethod
    def LeaveCriticalSection(lpCriticalSection: LPCRITICAL_SECTION) -> None:
        global processes
        cs = lpCriticalSection.contents
        state = processes[tls.process_id]["critical_sections"].get(id(cs))
        tid = th.get_ident()
        trace(f"LeaveCriticalSection impl. [{cs}, tid={tid}]")

        if state is None or cs.OwningThread.value != tid:
            error("LeaveCriticalSection invalid handle or wrong owner")
            Kernel32.SetLastError(wt.DWORD(6))
            return

        cs.RecursionCount -= 1
        if cs.RecursionCount > 0:
            Kernel32.SetLastError(wt.DWORD(0))
            ret(f"LeaveCriticalSection decremented RecursionCount={cs.RecursionCount}")
            return

        # Fully release
        cs.OwningThread = wt.HANDLE(0)
        cs.LockCount = -1

        # Wake up one waiter if exists
        with state["lock"]:
            if state["waiters"]:
                waiter = state["waiters"].popleft()
                waiter.release()

        Kernel32.SetLastError(wt.DWORD(0))
        ret(f"LeaveCriticalSection fully released by {tid}")

    @staticmethod
    def DeleteCriticalSection(lpCriticalSection: LPCRITICAL_SECTION) -> None:
        global processes
        critical_sections = processes[tls.process_id].get("critical_sections", {})
        cs = lpCriticalSection.contents
        trace(f"DeleteCriticalSection impl. [{cs}]")

        if id(cs) in critical_sections:
            del critical_sections[id(cs)]
            Kernel32.SetLastError(wt.DWORD(0))
            ret(f"DeleteCriticalSection deleted {cs}")
        else:
            error("DeleteCriticalSection invalid handle")
            Kernel32.SetLastError(wt.DWORD(6))

    @staticmethod
    def SetErrorMode(uMode: wt.UINT) -> wt.UINT:
        global error_mode
        trace(f"SetErrorMode impl. [{uMode=}]")
        old_mode = error_mode
        error_mode = uMode.value
        Kernel32.SetLastError(wt.DWORD(0))
        ret(f"SetErrorMode impl. {old_mode}")
        return wt.UINT(old_mode)
    
    @staticmethod
    def GetErrorMode() -> wt.UINT:
        global error_mode
        trace(f"GetErrorMode impl. []")
        Kernel32.SetLastError(wt.DWORD(0))
        ret(f"GetErrorMode impl. {error_mode}")
        return wt.UINT(error_mode)

    @staticmethod
    def CreateEventW(lpEventAttributes: wt.LPVOID, bManualReset: wt.BOOL,
                     bInitialState: wt.BOOL, lpName: wt.LPCWSTR) -> wt.HANDLE:
        """
        Create an event object (Unicode version).
        """
        trace(f"CreateEventW impl. [{bManualReset=}, {bInitialState=}, {lpName=}]")
        return Kernel32._create_event_impl(bManualReset, bInitialState, lpName)

    @staticmethod
    def _create_event_impl(bManualReset: wt.BOOL, bInitialState: wt.BOOL, lpName) -> wt.HANDLE:
        global processes

        try:
            event = th.Event()
            if bInitialState.value:
                event.set()

            handle = processes[tls.process_id]["next_file_handle"]
            processes[tls.process_id]["next_file_handle"] += 1

            processes[tls.process_id].setdefault("event_handles", {})
            processes[tls.process_id]["event_handles"][handle] = {
                'event': event,
                'manual_reset': bool(bManualReset.value),
                'name': lpName.value if hasattr(lpName, 'value') else str(lpName) if lpName else None
            }


            Kernel32.SetLastError(wt.DWORD(0))
            ret(f"CreateEvent impl. {handle}")
            return wt.HANDLE(handle)

        except Exception as e:
            error(f"CreateEvent impl. {e}")
            Kernel32.SetLastError(wt.DWORD(5))  # ERROR_ACCESS_DENIED
            return wt.HANDLE(-1)

    @staticmethod
    def SetEvent(hEvent: wt.HANDLE) -> wt.BOOL:
        """
        Set an event to signaled state.
        """
        global processes
        trace(f"SetEvent impl. [{hEvent=}]")

        handle = hEvent.value if hasattr(hEvent, 'value') else hEvent

        if handle not in processes[tls.process_id].get("event_handles", {}):
            Kernel32.SetLastError(wt.DWORD(6))  # ERROR_INVALID_HANDLE
            return wt.BOOL(0)

        try:
            processes[tls.process_id]["event_handles"][handle].set()
            Kernel32.SetLastError(wt.DWORD(0))
            ret(f"SetEvent impl. True")
            return wt.BOOL(1)

        except Exception as e:
            error(f"SetEvent impl. {e}")
            Kernel32.SetLastError(wt.DWORD(5))  # ERROR_ACCESS_DENIED
            return wt.BOOL(0)

    @staticmethod
    def ResetEvent(hEvent: wt.HANDLE) -> wt.BOOL:
        """
        Reset an event to non-signaled state.
        """
        global processes
        trace(f"ResetEvent impl. [{hEvent=}]")

        handle = hEvent.value if hasattr(hEvent, 'value') else hEvent

        if handle not in processes[tls.process_id].get("event_handles", {}):
            Kernel32.SetLastError(wt.DWORD(6))  # ERROR_INVALID_HANDLE
            return wt.BOOL(0)

        try:
            processes[tls.process_id]["event_handles"][handle].clear()
            Kernel32.SetLastError(wt.DWORD(0))
            ret(f"ResetEvent impl. True")
            return wt.BOOL(1)

        except Exception as e:
            error(f"ResetEvent impl. {e}")
            Kernel32.SetLastError(wt.DWORD(5))  # ERROR_ACCESS_DENIED
            return wt.BOOL(0)

    @staticmethod
    def CreateSemaphoreA(lpSemaphoreAttributes: wt.LPVOID, lInitialCount: wt.LONG,
                         lMaximumCount: wt.LONG, lpName: wt.LPCSTR) -> wt.HANDLE:
        """
        Create a semaphore object (ANSI version).
        """
        trace(f"CreateSemaphoreA impl. [{lInitialCount=}, {lMaximumCount=}, {lpName=}]")
        return Kernel32._create_semaphore_impl(lInitialCount, lMaximumCount, lpName)

    @staticmethod
    def CreateSemaphoreW(lpSemaphoreAttributes: wt.LPVOID, lInitialCount: wt.LONG,
                         lMaximumCount: wt.LONG, lpName: wt.LPCWSTR) -> wt.HANDLE:
        """
        Create a semaphore object (Unicode version).
        """
        trace(f"CreateSemaphoreW impl. [{lInitialCount=}, {lMaximumCount=}, {lpName=}]")
        return Kernel32._create_semaphore_impl(lInitialCount, lMaximumCount, lpName)

    @staticmethod
    def _create_semaphore_impl(lInitialCount: wt.LONG, lMaximumCount: wt.LONG, lpName) -> wt.HANDLE:
        global processes

        try:
            initial = lInitialCount.value
            maximum = lMaximumCount.value

            if initial < 0 or maximum <= 0 or initial > maximum:
                Kernel32.SetLastError(wt.DWORD(87))  # ERROR_INVALID_PARAMETER
                return wt.HANDLE(-1)

            semaphore = th.Semaphore(initial)

            handle = processes[tls.process_id]["next_file_handle"]
            processes[tls.process_id]["next_file_handle"] += 1
            processes[tls.process_id].setdefault("semaphore_handles", {})
            processes[tls.process_id]["semaphore_handles"][handle] = {
                'semaphore': semaphore,
                'count': initial,
                'max_count': maximum,
                'name': lpName.value if hasattr(lpName, 'value') else str(lpName) if lpName else None
            }

            Kernel32.SetLastError(wt.DWORD(0))
            ret(f"CreateSemaphore impl. {handle}")
            return wt.HANDLE(handle)

        except Exception as e:
            error(f"CreateSemaphore impl. {e}")
            Kernel32.SetLastError(wt.DWORD(5))  # ERROR_ACCESS_DENIED
            return wt.HANDLE(-1)

    @staticmethod
    def ReleaseSemaphore(hSemaphore: wt.HANDLE, lReleaseCount: wt.LONG,
                         lpPreviousCount: wt.PLONG) -> wt.BOOL:
        """
        Release a semaphore.
        """
        global processes
        trace(f"ReleaseSemaphore impl. [{hSemaphore=}, {lReleaseCount=}]")

        handle = hSemaphore.value if hasattr(hSemaphore, 'value') else hSemaphore
        release_count = lReleaseCount.value

        if handle not in processes[tls.process_id].get("semaphore_handles", {}):
            Kernel32.SetLastError(wt.DWORD(6))  # ERROR_INVALID_HANDLE
            return wt.BOOL(0)

        sem_state = processes[tls.process_id]["semaphore_handles"][handle]

        try:
            previous_count = sem_state['count']

            # Check if release would exceed maximum
            if sem_state['count'] + release_count > sem_state['max_count']:
                Kernel32.SetLastError(wt.DWORD(298))  # ERROR_TOO_MANY_POSTS
                return wt.BOOL(0)

            # Release the semaphore
            for _ in range(release_count):
                sem_state['semaphore'].release()
                sem_state['count'] += 1

            if lpPreviousCount:
                lpPreviousCount[0] = wt.LONG(previous_count)

            Kernel32.SetLastError(wt.DWORD(0))
            ret(f"ReleaseSemaphore impl. True")
            return wt.BOOL(1)

        except Exception as e:
            error(f"ReleaseSemaphore impl. {e}")
            Kernel32.SetLastError(wt.DWORD(5))  # ERROR_ACCESS_DENIED
            return wt.BOOL(0)

    @staticmethod
    def CreateMutexA(lpMutexAttributes: wt.LPVOID, bInitialOwner: wt.BOOL,
                     lpName: wt.LPCSTR) -> wt.HANDLE:
        """
        Create a mutex object (ANSI version).
        """
        trace(f"CreateMutexA impl. [{bInitialOwner=}, {lpName=}]")
        return Kernel32._create_mutex_impl(bInitialOwner, lpName)

    @staticmethod
    def CreateMutexW(lpMutexAttributes: wt.LPVOID, bInitialOwner: wt.BOOL,
                     lpName: wt.LPCWSTR) -> wt.HANDLE:
        """
        Create a mutex object (Unicode version).
        """
        trace(f"CreateMutexW impl. [{bInitialOwner=}, {lpName=}]")
        return Kernel32._create_mutex_impl(bInitialOwner, lpName)

    @staticmethod
    def _create_mutex_impl(bInitialOwner: wt.BOOL, lpName) -> wt.HANDLE:
        global processes

        try:
            lock = th.RLock()  # Reentrant lock for mutex behavior

            handle = processes[tls.process_id]["next_file_handle"]
            processes[tls.process_id]["next_file_handle"] += 1

            owner = None
            if bInitialOwner.value:
                lock.acquire()
                owner = th.get_ident()

            processes[tls.process_id].setdefault("mutex_handles", {})
            processes[tls.process_id]["mutex_handles"][handle] = {
                'lock': lock,
                'owner': owner,
                'name': lpName.value if hasattr(lpName, 'value') else str(lpName) if lpName else None
            }

            Kernel32.SetLastError(wt.DWORD(0))
            ret(f"CreateMutex impl. {handle}")
            return wt.HANDLE(handle)

        except Exception as e:
            error(f"CreateMutex impl. {e}")
            Kernel32.SetLastError(wt.DWORD(5))  # ERROR_ACCESS_DENIED
            return wt.HANDLE(-1)

    @staticmethod
    def ReleaseMutex(hMutex: wt.HANDLE) -> wt.BOOL:
        """
        Release a mutex.
        """
        global processes
        trace(f"ReleaseMutex impl. [{hMutex=}]")

        handle = hMutex.value if hasattr(hMutex, 'value') else hMutex

        if handle not in processes[tls.process_id].get("mutex_handles", {}):
            Kernel32.SetLastError(wt.DWORD(6))  # ERROR_INVALID_HANDLE
            return wt.BOOL(0)

        mutex_state = processes[tls.process_id]["mutex_handles"][handle]
        current_thread = th.get_ident()

        try:
            if mutex_state['owner'] != current_thread:
                Kernel32.SetLastError(wt.DWORD(288))  # ERROR_NOT_OWNER
                return wt.BOOL(0)

            mutex_state['lock'].release()
            mutex_state['owner'] = None

            Kernel32.SetLastError(wt.DWORD(0))
            ret(f"ReleaseMutex impl. True")
            return wt.BOOL(1)

        except Exception as e:
            error(f"ReleaseMutex impl. {e}")
            Kernel32.SetLastError(wt.DWORD(5))  # ERROR_ACCESS_DENIED
            return wt.BOOL(0)

    @staticmethod
    def GetEnvironmentStringsW() -> wt.LPCWSTR:
        """
        Return a pointer to a double-null-terminated UTF-16 string block of environment variables.
        """
        global env_strings_buffer
        trace("GetEnvironmentStringsW impl. []")

        # Build double-null terminated block
        block = "\0".join(f"{k}={v}" for k, v in os.environ.items()) + "\0\0"

        # Store as ctypes array (UTF-16)
        arr = (wt.WCHAR * len(block))()
        arr[:] = block
        env_strings_buffer = arr

        Kernel32.SetLastError(wt.DWORD(0))
        ret(f"GetEnvironmentStringsW impl. {arr}")
        return ct.cast(arr, wt.LPCWSTR)

    @staticmethod
    def FreeEnvironmentStringsW(lpszEnvironmentBlock: wt.LPCWSTR) -> wt.BOOL:
        """
        Free the environment block previously returned by GetEnvironmentStringsW.
        """
        global env_strings_buffer
        trace(f"FreeEnvironmentStringsW impl. [{lpszEnvironmentBlock=}]")

        # In ctypes, LPCWSTR is just a pointer to WCHAR array
        # Compare addresses of the stored buffer
        if env_strings_buffer is not None and ct.addressof(env_strings_buffer) == ct.addressof(
                ct.cast(lpszEnvironmentBlock, ct.POINTER(wt.WCHAR)).contents):
            env_strings_buffer = None
            Kernel32.SetLastError(wt.DWORD(0))
            ret("FreeEnvironmentStringsW impl. TRUE")
            return wt.BOOL(1)
        else:
            error("FreeEnvironmentStringsW: invalid block")
            Kernel32.SetLastError(wt.DWORD(6))  # ERROR_INVALID_HANDLE
            return wt.BOOL(0)

    @staticmethod
    def RaiseException(dwExceptionCode: wt.DWORD, dwExceptionFlags: wt.DWORD, nNumberOfArguments: wt.DWORD,
                       lpArguments: wt.LPVOID) -> None:
        """
        Raise a software exception.
        """
        trace(f"RaiseException impl. [{dwExceptionCode=}, {dwExceptionFlags=}, {nNumberOfArguments=}, {lpArguments=}]")
        Kernel32.SetLastError(dwExceptionCode)
        args = []
        if nNumberOfArguments.value > 0 and lpArguments:
            arg_array_type = ULONG_PTR * nNumberOfArguments.value
            arg_array = ct.cast(lpArguments, ct.POINTER(arg_array_type)).contents
            args = [arg_array[i] for i in range(nNumberOfArguments.value)]

        error(f"RaiseException impl. [code={dwExceptionCode.value}, flags={dwExceptionFlags.value}, args={args}]")
        raise Exception(f"RaiseException impl. code={dwExceptionCode.value}, flags={dwExceptionFlags.value}, args={args}")

    @staticmethod
    def GetSystemInfo(lpSystemInfo: LPSYSTEM_INFO) -> None:
        """
        Fill SYSTEM_INFO structure with basic system information.
        """
        trace(f"GetSystemInfo impl. [{lpSystemInfo=}]")

        sys_info = lpSystemInfo.contents
        sys_info.wProcessorArchitecture = 9  # PROCESSOR_ARCHITECTURE_AMD64
        sys_info.wReserved = 0
        sys_info.dwPageSize = 0x1000  # 4KB
        sys_info.lpMinimumApplicationAddress = wt.LPVOID(0x0000000000400000)
        sys_info.lpMaximumApplicationAddress = wt.LPVOID(0x00007FFFFFFFFFFF)
        sys_info.dwActiveProcessorMask = DWORD_PTR(0xFFFFFFFF)
        sys_info.dwNumberOfProcessors = os.cpu_count() or 1
        sys_info.dwProcessorType = 8664  # PROCESSOR_INTEL_PENTIUM
        sys_info.dwAllocationGranularity = 0x10000  # 64KB
        sys_info.wProcessorLevel = 0
        sys_info.wProcessorRevision = 0

    @staticmethod
    def GetCurrentDirectoryW(nBufferLength: wt.DWORD, lpBuffer: wt.LPWSTR) -> wt.DWORD:
        """
        Get the current directory as a UTF-16 string.
        """
        trace(f"GetCurrentDirectoryW impl. [{nBufferLength=}]")

        try:
            cwd = os.getcwd()
            if len(cwd) >= nBufferLength.value:
                cwd = cwd[: nBufferLength.value - 1]

            if lpBuffer and nBufferLength.value > 0:
                ct.memmove(lpBuffer, ct.create_unicode_buffer(cwd), (len(cwd) + 1) * ct.sizeof(ct.c_wchar))

            Kernel32.SetLastError(wt.DWORD(0))
            ret(f"GetCurrentDirectoryW impl. {len(cwd)}")
            return wt.DWORD(len(cwd))
        except Exception as e:
            error(f"GetCurrentDirectoryW impl. {e}")
            Kernel32.SetLastError(wt.DWORD(5))  # ERROR_ACCESS_DENIED
            return wt.DWORD(0)

    @staticmethod
    def SwitchToThread() -> wt.BOOL:
        """
        Yield execution to another thread.
        """
        trace("SwitchToThread impl. []")
        tm.sleep(0)  # Yield to other threads
        Kernel32.SetLastError(wt.DWORD(0))
        ret("SwitchToThread impl. True")
        return wt.BOOL(1)

    @staticmethod
    def GetProcAddress(hModule: wt.HANDLE, lpProcName: wt.LPCSTR) -> ct.c_void_p:
        # Normalize func name
        if isinstance(lpProcName, bytes):
            func_name = lpProcName.decode("ascii")
        elif isinstance(lpProcName, str):
            func_name = lpProcName
        elif isinstance(lpProcName, int):
            func_name = f"Ordinal_{lpProcName}"
        else:
            Kernel32.SetLastError(wt.DWORD(87))  # ERROR_INVALID_PARAMETER
            return ct.c_void_p(0)

        # Find module by handle
        target_mod = None
        for mod in modules.values():
            if mod["hModule"].value == hModule.value:
                target_mod = mod
                break

        if not target_mod:
            Kernel32.SetLastError(wt.DWORD(126))  # ERROR_MOD_NOT_FOUND
            return ct.c_void_p(0)

        exports = target_mod["exports"]
        if func_name in exports:
            addr = exports[func_name]
            Kernel32.SetLastError(wt.DWORD(0))
            return ct.c_void_p(addr)

        Kernel32.SetLastError(wt.DWORD(127))  # ERROR_PROC_NOT_FOUND
        return ct.c_void_p(0)

    @staticmethod
    def VirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect) -> wt.LPVOID:
        pid = hProcess.value if hasattr(hProcess, "value") else hProcess
        trace(f"VirtualAllocEx impl. [{hProcess=}, {lpAddress=}, {dwSize=}, {flAllocationType=}, {flProtect=}]")
        global processes

        if pid not in processes:
            Kernel32.SetLastError(wt.DWORD(87))  # ERROR_INVALID_PARAMETER
            return wt.LPVOID(0)

        try:
            mem = mm.mmap(-1, dwSize, prot=mm.PROT_READ | mm.PROT_WRITE | mm.PROT_EXEC)
        except Exception as e:
            error(f"VirtualAllocEx failed: {e}")
            Kernel32.SetLastError(wt.DWORD(8))
            return wt.LPVOID(0)

        base_addr = ct.addressof(ct.c_char.from_buffer(mem))
        processes[pid]["memory"][base_addr] = {
            "mem": mem,
            "size": dwSize,
            "protect": flProtect,
            "state": MEM_COMMIT,
            "type": MEM_PRIVATE,
        }

        Kernel32.SetLastError(wt.DWORD(0))
        ret(f"VirtualAllocEx impl. {hex(base_addr)}")
        return wt.LPVOID(base_addr)

    @staticmethod
    def VirtualFreeEx(hProcess, lpAddress, dwSize, dwFreeType) -> wt.BOOL:
        pid = hProcess.value if hasattr(hProcess, "value") else hProcess
        addr = ct.cast(lpAddress, ct.c_void_p).value
        trace(f"VirtualFreeEx impl. [{hProcess=}, {lpAddress=}, {dwSize=}, {dwFreeType=}]")
        global processes

        if pid not in processes:
            Kernel32.SetLastError(wt.DWORD(87))  # ERROR_INVALID_PARAMETER
            return wt.BOOL(0)

        memmap = processes[pid]["memory"]
        if addr not in memmap:
            Kernel32.SetLastError(wt.DWORD(487))  # ERROR_INVALID_ADDRESS
            return wt.BOOL(0)

        if dwFreeType == MEM_RELEASE:
            memmap[addr]["mem"].close()
            del memmap[addr]
            Kernel32.SetLastError(wt.DWORD(0))
            ret("VirtualFreeEx impl. MEM_RELEASE -> True")
            return wt.BOOL(1)

        elif dwFreeType == MEM_DECOMMIT:
            memmap[addr]["state"] = MEM_RESERVE
            Kernel32.SetLastError(wt.DWORD(0))
            ret("VirtualFreeEx impl. MEM_DECOMMIT -> True")
            return wt.BOOL(1)

        else:
            Kernel32.SetLastError(wt.DWORD(87))  # ERROR_INVALID_PARAMETER
            ret("VirtualFreeEx impl. unsupported FreeType -> False")
            return wt.BOOL(0)


    @staticmethod
    def VirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect) -> wt.BOOL:
        pid = hProcess.value if hasattr(hProcess, "value") else hProcess
        addr = ct.cast(lpAddress, ct.c_void_p).value
        trace(f"VirtualProtectEx impl. [{hProcess=}, {lpAddress=}, {dwSize=}, {flNewProtect=}]")
        global processes

        if pid not in processes:
            Kernel32.SetLastError(wt.DWORD(87))
            return wt.BOOL(0)

        memmap = processes[pid]["memory"]
        if addr not in memmap:
            Kernel32.SetLastError(wt.DWORD(487))  # ERROR_INVALID_ADDRESS
            return wt.BOOL(0)

        old_protect = memmap[addr]["protect"]
        if lpflOldProtect:
            lpflOldProtect[0] = old_protect

        memmap[addr]["protect"] = flNewProtect
        Kernel32.SetLastError(wt.DWORD(0))
        ret(f"VirtualProtectEx impl. {hex(addr)} old={old_protect} new={flNewProtect}")
        return wt.BOOL(1)


    @staticmethod
    def VirtualQueryEx(hProcess, lpAddress, lpBuffer, dwLength) -> SIZE_T:
        pid = hProcess.value if hasattr(hProcess, "value") else hProcess
        addr = ct.cast(lpAddress, ct.c_void_p).value
        trace(f"VirtualQueryEx impl. [{hProcess=}, {lpAddress=}, {dwLength=}]")
        global processes

        if pid not in processes:
            Kernel32.SetLastError(wt.DWORD(87))
            return SIZE_T(0)

        memmap = processes[pid]["memory"]
        for base, info in memmap.items():
            if base <= addr < base + info["size"]:
                mbi = MEMORY_BASIC_INFORMATION()
                mbi.BaseAddress       = wt.LPVOID(base)
                mbi.AllocationBase    = wt.LPVOID(base)
                mbi.AllocationProtect = info["protect"]
                mbi.RegionSize        = info["size"]
                mbi.State             = info["state"]
                mbi.Protect           = info["protect"]
                mbi.Type              = info["type"]

                # copy out
                ct.memmove(lpBuffer, ct.byref(mbi), min(dwLength, ct.sizeof(mbi)))
                Kernel32.SetLastError(wt.DWORD(0))
                ret(f"VirtualQueryEx impl. {hex(addr)} -> size={info['size']} state={info['state']}")
                return SIZE_T(ct.sizeof(mbi))

        Kernel32.SetLastError(wt.DWORD(487))  # ERROR_INVALID_ADDRESS
        ret("VirtualQueryEx impl. invalid address -> 0")
        return SIZE_T(0)

    @staticmethod
    def VirtualAlloc(lpAddress: wt.LPVOID, dwSize: SIZE_T, flAllocationType: wt.DWORD, flProtect: wt.DWORD) -> wt.LPVOID:
        return Kernel32.VirtualAllocEx(Kernel32.GetCurrentProcess(), lpAddress, dwSize, flAllocationType, flProtect)

    @staticmethod
    def VirtualFree(lpAddress: wt.LPVOID, dwSize: SIZE_T, dwFreeType: wt.DWORD) -> wt.BOOL:
        return Kernel32.VirtualFreeEx(Kernel32.GetCurrentProcess(), lpAddress, dwSize, dwFreeType)

    @staticmethod
    def VirtualProtect(lpAddress: wt.LPVOID, dwSize: SIZE_T, flNewProtect: wt.DWORD, lpflOldProtect: wt.LPDWORD) -> wt.BOOL:
        return Kernel32.VirtualProtectEx(Kernel32.GetCurrentProcess(), lpAddress, dwSize, flNewProtect, lpflOldProtect)

    @staticmethod
    def VirtualQuery(lpAddress: wt.LPVOID, lpBuffer: PMEMORY_BASIC_INFORMATION, dwLength: SIZE_T) -> SIZE_T:
        return Kernel32.VirtualQueryEx(Kernel32.GetCurrentProcess(), lpAddress, lpBuffer, dwLength)

    @staticmethod
    def GetFullPathNameW(lpFileName: wt.LPCWSTR, nBufferLength: wt.DWORD,
                         lpBuffer: wt.LPWSTR, lpFilePart: ct.POINTER(wt.LPWSTR)) -> wt.DWORD:
        """
        Get the full path of a file (Unicode version).
        """
        trace(f"GetFullPathNameW impl. [{lpFileName=}, {nBufferLength=}]")

        try:
            filename = lpFileName.value if hasattr(lpFileName, "value") else str(lpFileName)
            full_path = os.path.abspath(filename)
            if len(full_path) >= nBufferLength.value:
                full_path = full_path[: nBufferLength.value - 1]

            if lpBuffer and nBufferLength.value > 0:
                ct.memmove(lpBuffer, ct.create_unicode_buffer(full_path), (len(full_path) + 1) * ct.sizeof(ct.c_wchar))

            if lpFilePart:
                # Find the file part (after last backslash or slash)
                file_part_str = os.path.basename(full_path)
                file_part_buf = ct.create_unicode_buffer(file_part_str)
                lpFilePart[0] = ct.cast(file_part_buf, wt.LPWSTR)

            Kernel32.SetLastError(wt.DWORD(0))
            ret(f"GetFullPathNameW impl. {len(full_path)}")
            return wt.DWORD(len(full_path))
        except Exception as e:
            error(f"GetFullPathNameW impl. {e}")
            Kernel32.SetLastError(wt.DWORD(5))  # ERROR_ACCESS_DENIED
            return wt.DWORD(0)

    @staticmethod
    def GetTempPathW(nBufferLength: wt.DWORD, lpBuffer: wt.LPWSTR) -> wt.DWORD:
        """
        Get the path of the temporary directory (Unicode version).
        """
        trace(f"GetTempPathW impl. [{nBufferLength=}]")

        try:
            temp_path = "C\\Temp"  # Default temp path
            if len(temp_path) >= nBufferLength.value:
                temp_path = temp_path[: nBufferLength.value - 1]

            if lpBuffer and nBufferLength.value > 0:
                ct.memmove(lpBuffer, ct.create_unicode_buffer(temp_path), (len(temp_path) + 1) * ct.sizeof(ct.c_wchar))

            Kernel32.SetLastError(wt.DWORD(0))
            ret(f"GetTempPathW impl. {len(temp_path)}")
            return wt.DWORD(len(temp_path))
        except Exception as e:
            error(f"GetTempPathW impl. {e}")
            Kernel32.SetLastError(wt.DWORD(5))  # ERROR_ACCESS_DENIED
            return wt.DWORD(0)

    @staticmethod
    def GetExitCodeThread(hThread: wt.HANDLE, lpExitCode: wt.LPDWORD) -> wt.BOOL:
        """
        Get the exit code of a thread.
        """
        trace(f"GetExitCodeThread impl. [{hThread=}]")

        handle = hThread.value if hasattr(hThread, 'value') else hThread

        threads = processes[tls.process_id]["threads"]

        if handle not in threads:
            Kernel32.SetLastError(wt.DWORD(6)) # ERROR_INVALID_HANDLE
            return wt.BOOL(0)

        thread_info = threads[handle]
        if thread_info["thread"].is_alive():
            lpExitCode[0] = wt.DWORD(259) # STILL_ACTIVE
        else:
            lpExitCode[0] = wt.DWORD(thread_info["exit_code"])

        Kernel32.SetLastError(wt.DWORD(0))
        ret(f"GetExitCodeThread impl. {lpExitCode[0].value}")
        return wt.BOOL(1)

    @staticmethod
    def GetDiskFreeSpaceExW(
            lpDirectoryName: wt.LPCWSTR,
            lpFreeBytesAvailableToCaller: wt.PULARGE_INTEGER,
            lpTotalNumberOfBytes: wt.PULARGE_INTEGER,
            lpTotalNumberOfFreeBytes: wt.PULARGE_INTEGER
    ) -> wt.BOOL:
        """
        Get disk free space information (Unicode version).
        """
        trace(f"GetDiskFreeSpaceExW impl. [{lpDirectoryName=}]")

        try:
            stats = su.disk_usage(lpDirectoryName.value)
            if lpFreeBytesAvailableToCaller:
                lpFreeBytesAvailableToCaller[0] = wt.ULARGE_INTEGER(stats.free)
            if lpTotalNumberOfBytes:
                lpTotalNumberOfBytes[0] = wt.ULARGE_INTEGER(stats.total)
            if lpTotalNumberOfFreeBytes:
                lpTotalNumberOfFreeBytes[0] = wt.ULARGE_INTEGER(stats.free)
            Kernel32.SetLastError(wt.DWORD(0))
            ret("GetDiskFreeSpaceExW impl. True")
            return wt.BOOL(1)
        except Exception as e:
            error(f"GetDiskFreeSpaceExW impl. {e}")
            Kernel32.SetLastError(wt.DWORD(5))  # ERROR_ACCESS_DENIED
            return wt.BOOL(0)

    @staticmethod
    def CreateThread(lpThreadAttributes: LPSECURITY_ATTRIBUTES, dwStackSize: SIZE_T,
                     lpStartAddress: LPTHREAD_START_ROUTINE, lpParameter: wt.LPVOID,
                     dwCreationFlags: wt.DWORD, lpThreadId: wt.LPDWORD) -> wt.HANDLE:
        """
        Create a new thread.
        """
        trace(f"CreateThread impl. [{dwStackSize=}, {lpStartAddress=}, {lpParameter=}, {dwCreationFlags=}]")

        def thread_func(start_addr, param, thread_handle, parent_tls_data=tls.__dict__.copy()):
            for k, v in parent_tls_data.items():
                setattr(tls, k, v)

            try:
                func_type = ct.CFUNCTYPE(wt.DWORD, wt.LPVOID)
                func = func_type(start_addr)
                ret_code = func(param)
            except Exception as e:
                error(f"Thread function raised exception: {e}")
                ret_code = 1
            finally:
                # Mark thread as exited
                threads = processes[tls.process_id]["threads"]
                if thread_handle in threads:
                    threads[thread_handle]["exit_code"] = ret_code

        handle = processes[tls.process_id]["next_thread_handle"]
        processes[tls.process_id]["next_thread_handle"] += 1

        thread = th.Thread(target=thread_func, args=(lpStartAddress, lpParameter, handle))
        thread.start()

        # Store thread info
        processes[tls.process_id]["threads"][handle] = {
            "thread": thread,
            "exit_code": 0
        }

        if lpThreadId:
            lpThreadId[0] = wt.DWORD(handle)

        Kernel32.SetLastError(wt.DWORD(0))
        ret(f"CreateThread impl. {handle}")
        return wt.HANDLE(handle)

    @staticmethod
    def GetCurrentThread() -> wt.HANDLE:
        """
        Get a pseudo-handle for the current thread.
        """
        trace("GetCurrentThread impl. []")
        # Return a pseudo-handle (constant value)
        Kernel32.SetLastError(wt.DWORD(0))
        ret("GetCurrentThread impl. -2")
        return wt.HANDLE(-2)


    @staticmethod
    def TerminateThread(hThread: wt.HANDLE, dwExitCode: wt.DWORD) -> wt.BOOL:
        """
        Terminate a thread.
        """
        trace(f"TerminateThread impl. [{hThread=}, {dwExitCode=}]")

        handle = hThread.value if hasattr(hThread, 'value') else hThread

        if handle not in processes[tls.process_id]["threads"]:
            Kernel32.SetLastError(wt.DWORD(6)) # ERROR_INVALID_HANDLE
            return wt.BOOL(0)

        thread_info = processes[tls.process_id]["threads"][handle]
        if not thread_info["thread"].is_alive():
            Kernel32.SetLastError(wt.DWORD(288)) # ERROR_NOT_OWNER
            return wt.BOOL(0)

        # just delete the thread info, can't really kill threads in Python
        del processes[tls.process_id]["threads"][handle]
        Kernel32.SetLastError(wt.DWORD(0))
        ret("TerminateThread impl. True")
        return wt.BOOL(1)

    @staticmethod
    def SetConsoleCtrlHandler(
            HandlerRoutine: PHANDLER_ROUTINE,
            Add: wt.BOOL
    ) -> wt.BOOL:
        """
        Set a console control handler.
        """
        trace(f"SetConsoleCtrlHandler impl. [{HandlerRoutine=}, {Add=}]")

        if Add.value:
            processes[tls.process_id]["console_ctrl_handlers"].add(HandlerRoutine)
        else:
            if HandlerRoutine in processes[tls.process_id]["console_ctrl_handlers"]:
                processes[tls.process_id]["console_ctrl_handlers"].remove(HandlerRoutine)

        Kernel32.SetLastError(wt.DWORD(0))
        ret("SetConsoleCtrlHandler impl. True")
        return wt.BOOL(1)

    @staticmethod
    def SearchPathW(lpPath: wt.LPCWSTR, lpFileName: wt.LPCWSTR,
                    lpExtension: wt.LPCWSTR, nBufferLength: wt.DWORD,
                    lpBuffer: wt.LPWSTR, lpFilePart: ct.POINTER(wt.LPWSTR)) -> wt.DWORD:
        """
        Searches for a file in the specified path and standard system directories.
        """
        trace(f"SearchPathW impl. [{lpPath=}, {lpFileName=}, {lpExtension=}, {nBufferLength=}]")

        # Determine directories to search
        search_dirs = []
        if lpPath and lpPath != "":
            search_dirs.extend(lpPath.value.split(';'))
        else:
            # default: current directory + PATH environment
            search_dirs.append(os.getcwd())
            search_dirs.extend(os.environ.get("PATH", "").split(os.pathsep))

        found_path = None
        extensions = [lpExtension] if lpExtension else [""]

        for dir_ in search_dirs:
            for ext in extensions:
                candidate = os.path.join(dir_, lpFileName.value)
                if ext and not candidate.endswith(ext.value):
                    candidate += ext
                if os.path.isfile(candidate):
                    found_path = os.path.abspath(candidate)
                    break
            if found_path:
                break

        if found_path:
            # Copy path to lpBuffer
            if nBufferLength.value < len(found_path) + 1:
                Kernel32.SetLastError(wt.DWORD(87))  # ERROR_INVALID_PARAMETER
                return wt.DWORD(0)
            ct.memmove(lpBuffer, found_path.encode('utf-16le'), (len(found_path) + 1) * 2)
            if lpFilePart:
                # Set pointer to file part (basename)
                file_part_ptr = ct.create_unicode_buffer(os.path.basename(found_path))
                lpFilePart[0] = ct.cast(file_part_ptr, wt.LPWSTR)
            Kernel32.SetLastError(wt.DWORD(0))
            ret(f"SearchPathW found: {found_path}")
            return wt.DWORD(len(found_path))
        else:
            Kernel32.SetLastError(wt.DWORD(2))  # ERROR_FILE_NOT_FOUND
            ret("SearchPathW did not find file")
            return wt.DWORD(0)
        
    @staticmethod
    def GetStdHandle(nStdHandle: wt.DWORD) -> wt.HANDLE:
        """
        Get a standard device handle (stdin, stdout, stderr).
        """
        global processes
        trace(f"GetStdHandle impl. [{nStdHandle=}]")

        if nStdHandle == -10:
            handle = processes[tls.process_id].device_handles["CONIN$"]
        elif nStdHandle == -11:
            handle = processes[tls.process_id].device_handles["CONOUT$"]
        elif nStdHandle == -12:
            handle = processes[tls.process_id].device_handles["CONERR$"]
        else:
            Kernel32.SetLastError(wt.DWORD(87))
            ret(f"GetStdHandle impl. {wt.HANDLE(0)}")
            return wt.HANDLE(0)

        Kernel32.SetLastError(wt.DWORD(0))
        ret(f"GetStdHandle impl. {handle}")
        return handle
            
    @staticmethod
    def SetStdHandle(nStdHandle: wt.DWORD, hHandle: wt.HANDLE) -> wt.BOOL:
        """
        Set a standard device handle (stdin, stdout, stderr).
        """
        trace(f"SetStdHandle impl. [{nStdHandle=}, {hHandle=}]")

        if nStdHandle == -10:
            processes[tls.process_id].device_handles["CONIN$"] = hHandle
        elif nStdHandle == -11:
            processes[tls.process_id].device_handles["CONOUT$"] = hHandle
        elif nStdHandle == -12:
            processes[tls.process_id].device_handles["CONERR$"] = hHandle
        else:
            Kernel32.SetLastError(wt.DWORD(87))  # ERROR_INVALID_PARAMETER
            ret(f"SetStdHandle impl. {wt.BOOL(0)}") 
            return wt.BOOL(0)
        
        Kernel32.SetLastError(wt.DWORD(0))
        ret(f"SetStdHandle impl. {wt.BOOL(1)}")
        return wt.BOOL(1)
    
    @staticmethod
    def IsDebuggerPresent() -> wt.BOOL:
        """
        Check if the current process is being debugged.
        """
        trace("IsDebuggerPresent diserror-stub. []")
        # For simplicity, always return False
        Kernel32.SetLastError(wt.DWORD(0))
        ret("IsDebuggerPresent impl. False")
        return wt.BOOL(0)
    
    @staticmethod
    def MultiByteToWideChar(CodePage: wt.UINT,
                            dwFlags: wt.DWORD,
                            lpMultiByteStr: wt.LPCSTR,
                            cbMultiByte: wt.INT,
                            lpWideCharStr: wt.LPWSTR,
                            cchWideChar: wt.INT) -> wt.INT:
        """
        Convert a multibyte string (e.g. UTF-8, CP_ACP) to wide char (UTF-16LE).
        If lpWideCharStr == NULL, returns required buffer size.
        """
        trace(f"MultiByteToWideChar impl. [{CodePage=}, {dwFlags=}, {cbMultiByte=}, {cchWideChar=}]")

        try:
            # Get input string
            if cbMultiByte == -1:
                # Null-terminated
                in_bytes = ct.string_at(lpMultiByteStr)
            else:
                in_bytes = ct.string_at(lpMultiByteStr, cbMultiByte.value)

            # Pick encoding based on CodePage
            if CodePage == 65001:  # CP_UTF8
                encoding = "utf-8"
            elif CodePage == 0:  # CP_ACP (system default)
                encoding = ss.getdefaultencoding()
            else:
                # Fallback: pretend utf-8
                encoding = "utf-8"

            # Decode to Python str (which is Unicode)
            decoded = in_bytes.decode(encoding, errors="replace")

            # Required size
            needed = len(decoded) + 1  # include null terminator

            if not lpWideCharStr or cchWideChar == 0:
                # Caller only wants required length
                Kernel32.SetLastError(wt.DWORD(0))
                ret(f"MultiByteToWideChar impl. need {needed}")
                return wt.INT(needed)

            # Truncate if buffer is too small
            out_str = decoded
            if len(out_str) >= cchWideChar.value:
                out_str = out_str[:cchWideChar.value - 1]

            # Write to output buffer
            lpWideCharStr_mutable = ct.cast(lpWideCharStr, ct.POINTER(wt.WCHAR))

            for i, ch in enumerate(out_str):
                lpWideCharStr_mutable[i] = ch
            lpWideCharStr_mutable[len(out_str)] = '\0'  # Null-terminate

            Kernel32.SetLastError(wt.DWORD(0))
            ret(f"MultiByteToWideChar impl. wrote {len(out_str)+1}")
            return wt.INT(len(out_str) + 1)

        except Exception as e:
            error(f"MultiByteToWideChar impl. {e}")
            Kernel32.SetLastError(wt.DWORD(87))  # ERROR_INVALID_PARAMETER
            ret(f"MultiByteToWideChar impl. {wt.INT(0)}")
            return wt.INT(0)
        
    @staticmethod
    def WideCharToMultiByte(CodePage: wt.UINT,
                            dwFlags: wt.DWORD,
                            lpWideCharStr: wt.LPCWSTR,
                            cchWideChar: wt.INT,
                            lpMultiByteStr: wt.LPSTR,
                            cbMultiByte: wt.INT,
                            lpDefaultChar: wt.LPCSTR,
                            lpUsedDefaultChar: wt.LPBOOL) -> wt.INT:
        """
        Convert wide char (UTF-16LE) string to multibyte (e.g. UTF-8, CP_ACP).
        If lpMultiByteStr == NULL, returns required buffer size.
        """
        trace(f"WideCharToMultiByte impl. [{CodePage=}, {dwFlags=}, {cchWideChar=}, {cbMultiByte=}]")

        try:
            # Read input string
            if cchWideChar == -1:
                # Null-terminated
                in_str = ct.wstring_at(lpWideCharStr)
            else:
                in_str = ct.wstring_at(lpWideCharStr, cchWideChar.value)

            # Pick encoding based on CodePage
            if CodePage == 65001:  # CP_UTF8
                encoding = "utf-8"
            elif CodePage == 0:  # CP_ACP
                encoding = ss.getdefaultencoding()
            else:
                # Fallback
                encoding = "utf-8"

            # Encode to bytes
            encoded = in_str.encode(encoding, errors="replace")

            needed = len(encoded)  # No null terminator in return length

            if not lpMultiByteStr or cbMultiByte == 0:
                # Caller just wants required length
                Kernel32.SetLastError(wt.DWORD(0))
                ret(f"WideCharToMultiByte impl. need {needed}")
                return wt.INT(needed)

            # Truncate if buffer is too small
            out_bytes = encoded
            if len(out_bytes) > cbMultiByte.value:
                out_bytes = out_bytes[:cbMultiByte]

            # Write bytes
            ct.memmove(lpMultiByteStr, out_bytes, len(out_bytes))

            lpMultiByteStr_mutable = ct.cast(lpMultiByteStr, ct.POINTER(wt.CHAR))

            # Null-terminate if space
            if len(out_bytes) < cbMultiByte.value:
                lpMultiByteStr_mutable[len(out_bytes)] = b'\0'

            # Set lpUsedDefaultChar if passed
            if lpUsedDefaultChar:
                lpUsedDefaultChar[0] = wt.BOOL(False)

            Kernel32.SetLastError(wt.DWORD(0))
            ret(f"WideCharToMultiByte impl. wrote {len(out_bytes)}")
            return wt.INT(len(out_bytes))

        except Exception as e:
            error(f"WideCharToMultiByte impl. {e}")
            Kernel32.SetLastError(wt.DWORD(87))  # ERROR_INVALID_PARAMETER
            return wt.INT(0)

    @staticmethod
    def RtlCaptureContext(ContextRecord: PCONTEXT) -> None:
        """
        Capture the current CPU context into a CONTEXT structure.
        """
        trace(f"RtlCaptureContext impl. [{ContextRecord=}]")

        try:
            # For simplicity, zero out the context
            ct.memset(ContextRecord, 0, ct.sizeof(CONTEXT))

            Kernel32.SetLastError(wt.DWORD(0))
            ret("RtlCaptureContext impl. success")
        except Exception as e:
            error(f"RtlCaptureContext impl. {e}")
            Kernel32.SetLastError(wt.DWORD(5))  # ERROR_ACCESS_DENIED

    @staticmethod
    def RtlLookupFunctionEntry(ControlPc: DWORD64, ImageBase: PDWORD64,
                            HistoryTable: wt.LPVOID) -> wt.LPVOID:
        """
        Look up function entry in the runtime function table.
        """
        trace(f"RtlLookupFunctionEntry diserror-stub. [{ControlPc=}, {ImageBase=}]")

        try:
            # For simplicity, return NULL (no function entry found)
            if ImageBase:
                ImageBase[0] = DWORD64(0)

            Kernel32.SetLastError(wt.DWORD(0))
            ret("RtlLookupFunctionEntry diserror-stub. NULL")
            return wt.LPVOID(0)

        except Exception as e:
            error(f"RtlLookupFunctionEntry diserror-stub. {e}")
            Kernel32.SetLastError(wt.DWORD(5))  # ERROR_ACCESS_DENIED
            return wt.LPVOID(0)

    @staticmethod
    def RtlVirtualUnwind(HandlerType: wt.DWORD, ImageBase: DWORD64,
                         ControlPc: DWORD64, FunctionEntry: wt.LPVOID,
                         ContextRecord: PCONTEXT,
                         HandlerData: wt.LPVOID, EstablisherFrame: PDWORD64,
                         ContextPointers: PDWORD64) -> PEXCEPTION_ROUTINE:
        """
        Perform a virtual unwind of the stack.
        """
        trace(f"RtlVirtualUnwind diserror-stub. [{HandlerType=}, {ImageBase=}, {ControlPc=}]")

        try:
            EstablisherFrame[0] = 0
            ContextPointers.contents = wt.LPVOID(0)  # Set context pointer to NULL
            # For simplicity, return NULL (no exception routine)
            Kernel32.SetLastError(wt.DWORD(0))
            ret("RtlVirtualUnwind diserror-stub. NULL")
            return PEXCEPTION_ROUTINE(0)
        except Exception as e:
            error(f"RtlVirtualUnwind diserror-stub. {e}")
            Kernel32.SetLastError(wt.DWORD(5))
            return PEXCEPTION_ROUTINE(0)

    @staticmethod
    def UnhandledExceptionFilter(ExceptionInfo: PEXCEPTION_POINTERS) -> wt.LONG:
        """
        Unhandled exception filter.
        """
        trace(f"UnhandledExceptionFilter diserror-stub. [{ExceptionInfo=}]")
        # For simplicity, always return EXCEPTION_CONTINUE_SEARCH
        Kernel32.SetLastError(wt.DWORD(0))
        ret("UnhandledExceptionFilter diserror-stub. EXCEPTION_CONTINUE_SEARCH")
        return wt.LONG(0)

    @staticmethod
    def SetUnhandledExceptionFilter(
            lpTopLevelExceptionFilter: LPTOP_LEVEL_EXCEPTION_FILTER
    ) -> LPTOP_LEVEL_EXCEPTION_FILTER:
        """
        Set the unhandled exception filter.
        """
        trace(f"SetUnhandledExceptionFilter diserror-stub. [{lpTopLevelExceptionFilter=}]")
        # For simplicity, do nothing and return NULL
        Kernel32.SetLastError(wt.DWORD(0))
        ret("SetUnhandledExceptionFilter diserror-stub. NULL")
        return LPTOP_LEVEL_EXCEPTION_FILTER(0)

    @staticmethod
    def WriteConsoleW(hConsoleOutput: wt.HANDLE, lpBuffer: wt.LPCVOID,
                             nNumberOfCharsToWrite: wt.DWORD,
                             lpNumberOfCharsWritten: wt.LPDWORD,
                             lpReserved: wt.LPVOID) -> wt.BOOL:
        """
        Write characters to a console screen buffer (Unicode version).
        """
        trace(f"WriteConsoleW impl. [{hConsoleOutput=}, {nNumberOfCharsToWrite=}]")

        handle = hConsoleOutput.value if hasattr(hConsoleOutput, 'value') else hConsoleOutput

        try:
            # Read input string
            in_str = ct.wstring_at(lpBuffer, nNumberOfCharsToWrite.value)

            # Write to appropriate stream
            if handle == processes[tls.process_id].device_handles["CONOUT$"].value:
                os.write(1, in_str.encode('utf-8', errors='replace'))
            elif handle == processes[tls.process_id].device_handles["CONERR$"].value:
                os.write(2, in_str.encode('utf-8', errors='replace'))
            else:
                os.write(0, in_str.encode('utf-8', errors='replace'))

            if lpNumberOfCharsWritten:
                lpNumberOfCharsWritten[0] = wt.DWORD(len(in_str))

            Kernel32.SetLastError(wt.DWORD(0))
            ret(f"WriteConsoleW impl. wrote {len(in_str)} chars")
            return wt.BOOL(1)

        except Exception as e:
            error(f"WriteConsoleW impl. {e}")
            Kernel32.SetLastError(wt.DWORD(5))  # ERROR_ACCESS_DENIED
            return wt.BOOL(0)

    @staticmethod
    def GetProcessHeap() -> wt.HANDLE:
        """
        Get a handle to the default process heap.
        """
        trace("GetProcessHeap impl. []")

        handle = wt.HANDLE(0x8000)

        Kernel32.SetLastError(wt.DWORD(0))
        ret(f"GetProcessHeap impl. {handle}")
        return handle

    @staticmethod
    def HeapFree(hHeap: wt.HANDLE, dwFlags: wt.DWORD, lpMem: wt.LPVOID) -> wt.BOOL:
        """
        Free a memory block allocated from a heap.
        """
        trace(f"HeapFree impl. [{hHeap=}, {dwFlags=}, {lpMem=}]")

        handle = hHeap.value if hasattr(hHeap, 'value') else hHeap
        addr = ct.cast(lpMem, ct.c_void_p).value

        if handle not in processes[tls.process_id]["heap_handles"]:
            Kernel32.SetLastError(wt.DWORD(6)) # ERROR_INVALID_HANDLE
            return wt.BOOL(0)

        heap_info = processes[tls.process_id]["heap_handles"][handle]
        if addr not in heap_info["allocations"]:
            Kernel32.SetLastError(wt.DWORD(487))  # ERROR_INVALID_ADDRESS
            return wt.BOOL(0)

        try:
            heap_info["allocations"][addr]["mem"].close()
            del heap_info["allocations"][addr]

            Kernel32.SetLastError(wt.DWORD(0))
            ret("HeapFree impl. success")
            return wt.BOOL(1)
        except Exception as e:
            error(f"HeapFree impl. {e}")
            Kernel32.SetLastError(wt.DWORD(5))  # ERROR_ACCESS_DENIED
            return wt.BOOL(0)

    @staticmethod
    def HeapAlloc(hHeap: wt.HANDLE, dwFlags: wt.DWORD, dwBytes: SIZE_T) -> wt.LPVOID:
        """
        Allocate a memory block from a heap.
        """
        trace(f"HeapAlloc impl. [{hHeap=}, {dwFlags=}, {dwBytes=}]")

        handle = hHeap.value if hasattr(hHeap, 'value') else hHeap

        if handle not in processes[tls.process_id]["heap_handles"]:
            Kernel32.SetLastError(wt.DWORD(6)) # ERROR_INVALID_HANDLE
            return wt.LPVOID(0)
        heap_info = processes[tls.process_id]["heap_handles"][handle]

        try:
            mem = mm.mmap(-1, dwBytes, prot=mm.PROT_READ | mm.PROT_WRITE)
        except Exception as e:
            error(f"HeapAlloc failed: {e}")
            Kernel32.SetLastError(wt.DWORD(8))
            return wt.LPVOID(0)

        base_addr = ct.addressof(ct.c_char.from_buffer(mem))
        heap_info["allocations"][base_addr] = {
            "mem": mem,
            "size": dwBytes,
            "flags": dwFlags,
        }

        Kernel32.SetLastError(wt.DWORD(0))
        ret(f"HeapAlloc impl. {hex(base_addr)}")
        return wt.LPVOID(base_addr)

    @staticmethod
    def HeapCreate(flOptions: wt.DWORD, dwInitialSize: SIZE_T, dwMaximumSize: SIZE_T) -> wt.HANDLE:
        """
        Create a private heap object.
        """
        trace(f"HeapCreate impl. [{flOptions=}, {dwInitialSize=}, {dwMaximumSize=}]")

        handle = processes[tls.process_id]["next_heap_handle"]
        processes[tls.process_id]["next_heap_handle"] += 1

        processes[tls.process_id]["heap_handles"][handle] = {
            "options": flOptions,
            "initial_size": dwInitialSize,
            "maximum_size": dwMaximumSize,
            "allocations": {}
        }

        Kernel32.SetLastError(wt.DWORD(0))
        ret(f"HeapCreate impl. {handle}")
        return wt.HANDLE(handle)

    @staticmethod
    def HeapDestroy(hHeap: wt.HANDLE) -> wt.BOOL:
        """
        Destroy a heap object.
        """
        trace(f"HeapDestroy impl. [{hHeap=}]")

        handle = hHeap.value if hasattr(hHeap, 'value') else hHeap

        if handle not in processes[tls.process_id]["heap_handles"]:
            Kernel32.SetLastError(wt.DWORD(6)) # ERROR_INVALID_HANDLE
            return wt.BOOL(0)

        heap_info = processes[tls.process_id]["heap_handles"][handle]
        # Free all allocations
        for alloc in list(heap_info["allocations"].values()):
            alloc["mem"].close()
        del processes[tls.process_id]["heap_handles"][handle]
        Kernel32.SetLastError(wt.DWORD(0))
        ret("HeapDestroy impl. success")
        return wt.BOOL(1)

    @staticmethod
    def HeapReAlloc(hHeap: wt.HANDLE, dwFlags: wt.DWORD, lpMem: wt.LPVOID, dwBytes: SIZE_T) -> wt.LPVOID:
        """
        Reallocate a memory block from a heap.
        """
        trace(f"HeapReAlloc impl. [{hHeap=}, {dwFlags=}, {lpMem=}, {dwBytes=}]")

        handle = hHeap.value if hasattr(hHeap, 'value') else hHeap
        addr = ct.cast(lpMem, ct.c_void_p).value

        if handle not in processes[tls.process_id]["heap_handles"]:
            Kernel32.SetLastError(wt.DWORD(6)) # ERROR_INVALID_HANDLE
            return wt.LPVOID(0)

        heap_info = processes[tls.process_id]["heap_handles"][handle]
        if addr not in heap_info["allocations"]:
            Kernel32.SetLastError(wt.DWORD(487))  # ERROR_INVALID_ADDRESS
            return wt.LPVOID(0)

        old_alloc = heap_info["allocations"][addr]
        old_size = old_alloc["size"]
        old_mem = old_alloc["mem"]

        try:
            new_mem = mm.mmap(-1, dwBytes, prot=mm.PROT_READ | mm.PROT_WRITE)
            # Copy old data
            ct.memmove(ct.addressof(ct.c_char.from_buffer(new_mem)),
                       ct.addressof(ct.c_char.from_buffer(old_mem)),
                       min(old_size, dwBytes))
            # Free old memory
            old_mem.close()
        except Exception as e:
            error(f"HeapReAlloc failed: {e}")
            Kernel32.SetLastError(wt.DWORD(8))
            return wt.LPVOID(0)

        new_addr = ct.addressof(ct.c_char.from_buffer(new_mem))
        # Update allocation record
        del heap_info["allocations"][addr]
        heap_info["allocations"][new_addr] = {
            "mem": new_mem,
            "size": dwBytes,
            "flags": dwFlags
        }
        Kernel32.SetLastError(wt.DWORD(0))
        ret(f"HeapReAlloc impl. {hex(new_addr)}")
        return wt.LPVOID(new_addr)

    @staticmethod
    def HeapSize(hHeap: wt.HANDLE, dwFlags: wt.DWORD, lpMem: wt.LPCVOID) -> SIZE_T:
        """
        Get the size of a memory block allocated from a heap.
        """
        trace(f"HeapSize impl. [{hHeap=}, {dwFlags=}, {lpMem=}]")

        handle = hHeap.value if hasattr(hHeap, 'value') else hHeap
        addr = ct.cast(lpMem, ct.c_void_p).value

        if handle not in processes[tls.process_id]["heap_handles"]:
            Kernel32.SetLastError(wt.DWORD(6)) # ERROR_INVALID_HANDLE
            return SIZE_T(-1)

        heap_info = processes[tls.process_id]["heap_handles"][handle]
        if addr not in heap_info["allocations"]:
            Kernel32.SetLastError(wt.DWORD(487))  # ERROR_INVALID_ADDRESS
            return SIZE_T(-1)

        size = heap_info["allocations"][addr]["size"]
        Kernel32.SetLastError(wt.DWORD(0))
        ret(f"HeapSize impl. {size}")
        return SIZE_T(size)

    @staticmethod
    def GetProcessId(hProcess: wt.HANDLE) -> wt.DWORD:
        """
        Get the process ID for a given process handle.
        """
        trace(f"GetProcessId impl. [{hProcess=}]")

        handle = hProcess.value if hasattr(hProcess, 'value') else hProcess

        if handle == wt.HANDLE(-1).value:
            # Current process
            pid = tls.process_id
            Kernel32.SetLastError(wt.DWORD(0))
            ret(f"GetProcessId impl. {pid}")
            return wt.DWORD(pid)

        if handle not in processes:
            Kernel32.SetLastError(wt.DWORD(6)) # ERROR_INVALID_HANDLE
            return wt.DWORD(0)

        pid = handle
        Kernel32.SetLastError(wt.DWORD(0))
        ret(f"GetProcessId impl. {pid}")
        return wt.DWORD(pid)

    @staticmethod
    def GetThreadId(hThread: wt.HANDLE) -> wt.DWORD:
        """
        Get the thread ID for a given thread handle.
        """
        trace(f"GetThreadId impl. [{hThread=}]")

        handle = hThread.value if hasattr(hThread, 'value') else hThread

        threads = processes[tls.process_id]["threads"]

        tid = tls.thread_id

        return wt.DWORD(tid)

    @staticmethod
    def GetStartupInfoW(lpStartupInfo: LPSTARTUPINFOW) -> None:
        """
        Get the startup information for the current process (Unicode version).
        """
        global processes
        trace(f"GetStartupInfoW impl. [{lpStartupInfo=}]")

        try:
            si = processes[tls.process_id]["startup_info"]
            lpStartupInfo.contents = si
            Kernel32.SetLastError(wt.DWORD(0))
            ret("GetStartupInfoW impl. success")
        except Exception as e:
            error(f"GetStartupInfoW impl. {e}")
            Kernel32.SetLastError(wt.DWORD(5))
            return

    @staticmethod
    def InitializeSListHead(ListHead: PSLIST_HEADER):
        """
        Initialize a singly linked list header.
        """
        trace(f"InitializeSListHead impl. [{ListHead=}]")

        try:
            ListHead.contents.Alignment = 0
            ListHead.contents.Next = wt.LPVOID(0)
            Kernel32.SetLastError(wt.DWORD(0))
            ret("InitializeSListHead impl. success")
        except Exception as e:
            error(f"InitializeSListHead impl. {e}")
            Kernel32.SetLastError(wt.DWORD(5))
            return

    @staticmethod
    def InterlockedPushEntrySList(ListHead: PSLIST_HEADER, ListEntry: PSLIST_ENTRY) -> PSLIST_ENTRY:
        """
        Push an entry onto a singly linked list.
        """
        trace(f"InterlockedPushEntrySList impl. [{ListHead=}, {ListEntry=}]")

        try:
            # Push entry
            ListEntry.contents.Next = ListHead.contents.Next
            ListHead.contents.Next = ct.cast(ListEntry, wt.LPVOID)

            Kernel32.SetLastError(wt.DWORD(0))
            ret("InterlockedPushEntrySList impl. success")
            return ListEntry
        except Exception as e:
            error(f"InterlockedPushEntrySList impl. {e}")
            Kernel32.SetLastError(wt.DWORD(5))
            return PSLIST_ENTRY(0)

    @staticmethod
    def InterlockedPopEntrySList(ListHead: PSLIST_HEADER) -> PSLIST_ENTRY:
        """
        Pop an entry from a singly linked list.
        """
        trace(f"InterlockedPopEntrySList impl. [{ListHead=}]")

        try:
            entry_ptr = ListHead.contents.Next
            if not entry_ptr:
                Kernel32.SetLastError(wt.DWORD(0))
                ret("InterlockedPopEntrySList impl. empty list")
                return PSLIST_ENTRY(0)

            entry = ct.cast(entry_ptr, PSLIST_ENTRY)
            ListHead.contents.Next = entry.contents.Next

            Kernel32.SetLastError(wt.DWORD(0))
            ret("InterlockedPopEntrySList impl. success")
            return entry
        except Exception as e:
            error(f"InterlockedPopEntrySList impl. {e}")
            Kernel32.SetLastError(wt.DWORD(5))
            return PSLIST_ENTRY(0)

    @staticmethod
    def InterlockedFlushSList(ListHead: PSLIST_HEADER) -> PSLIST_ENTRY:
        """
        Flush a singly linked list, returning the head of the list.
        """
        trace(f"InterlockedFlushSList impl. [{ListHead=}]")

        try:
            entry_ptr = ListHead.contents.Next
            ListHead.contents.Next = wt.LPVOID(0)

            if not entry_ptr:
                Kernel32.SetLastError(wt.DWORD(0))
                ret("InterlockedFlushSList impl. empty list")
                return PSLIST_ENTRY(0)

            entry = ct.cast(entry_ptr, PSLIST_ENTRY)

            Kernel32.SetLastError(wt.DWORD(0))
            ret("InterlockedFlushSList impl. success")
            return entry
        except Exception as e:
            error(f"InterlockedFlushSList impl. {e}")
            Kernel32.SetLastError(wt.DWORD(5))
            return PSLIST_ENTRY(0)

    @staticmethod
    def InterlockedPushListSList(ListHead: PSLIST_HEADER, List: PSLIST_ENTRY, ListEnd: PSLIST_ENTRY, Count: wt.ULONG) -> PSLIST_ENTRY:
        """
        Push a list of entries onto a singly linked list.
        """
        trace(f"InterlockedPushListSList impl. [{ListHead=}, {List=}, {ListEnd=}, {Count=}]")

        try:
            ListEnd.contents.Next = ListHead.contents.Next
            ListHead.contents.Next = ct.cast(List, wt.LPVOID)

            Kernel32.SetLastError(wt.DWORD(0))
            ret("InterlockedPushListSList impl. success")
            return List
        except Exception as e:
            error(f"InterlockedPushListSList impl. {e}")
            Kernel32.SetLastError(wt.DWORD(5))
            return PSLIST_ENTRY(0)

    @staticmethod
    def RtlFirstEntrySList(ListHead: PSLIST_HEADER) -> PSLIST_ENTRY:
        """
        Get the first entry in a singly linked list.
        """
        trace(f"RtlFirstEntrySList impl. [{ListHead=}]")

        try:
            entry_ptr = ListHead.contents.Next
            if not entry_ptr:
                Kernel32.SetLastError(wt.DWORD(0))
                ret("RtlFirstEntrySList impl. empty list")
                return PSLIST_ENTRY(0)

            entry = ct.cast(entry_ptr, PSLIST_ENTRY)

            Kernel32.SetLastError(wt.DWORD(0))
            ret("RtlFirstEntrySList impl. success")
            return entry
        except Exception as e:
            error(f"RtlFirstEntrySList impl. {e}")
            Kernel32.SetLastError(wt.DWORD(5))
            return PSLIST_ENTRY(0)

    @staticmethod
    def QueryDepthSList(ListHead: PSLIST_HEADER) -> wt.USHORT:
        """
        Get the depth of a singly linked list.
        """
        trace(f"QueryDepthSList impl. [{ListHead=}]")

        try:
            count = 0
            entry_ptr = ListHead.contents.Next
            while entry_ptr:
                count += 1
                entry = ct.cast(entry_ptr, PSLIST_ENTRY)
                entry_ptr = entry.contents.Next

            Kernel32.SetLastError(wt.DWORD(0))
            ret(f"QueryDepthSList impl. depth {count}")
            return wt.USHORT(count)
        except Exception as e:
            error(f"QueryDepthSList impl. {e}")
            Kernel32.SetLastError(wt.DWORD(5))
            return wt.USHORT(0)

    @staticmethod
    def QueryPerformanceFrequency(lpFrequency: wt.PLARGE_INTEGER) -> wt.BOOL:
        """
        Retrieve the frequency of the high-resolution performance counter.
        """
        trace(f"QueryPerformanceFrequency impl. [{lpFrequency=}]")

        try:
            frequency = 1_000_000  # 1 MHz for microsecond resolution
            lpFrequency[0] = wt.LARGE_INTEGER(frequency)
            Kernel32.SetLastError(wt.DWORD(0))
            ret(f"QueryPerformanceFrequency impl. {frequency}")
            return wt.BOOL(1)
        except Exception as e:
            error(f"QueryPerformanceFrequency impl. {e}")
            Kernel32.SetLastError(wt.DWORD(5))
            return wt.BOOL(0)

    @staticmethod
    def QueryPerformanceCounter(lpPerformanceCount: wt.PLARGE_INTEGER) -> wt.BOOL:
        """
        Retrieve the current value of the high-resolution performance counter.
        """
        trace(f"QueryPerformanceCounter impl. [{lpPerformanceCount=}]")

        try:
            counter = int(tm.perf_counter() * 1_000_000)  # microseconds
            lpPerformanceCount[0] = wt.LARGE_INTEGER(counter)
            Kernel32.SetLastError(wt.DWORD(0))
            ret(f"QueryPerformanceCounter impl. {counter}")
            return wt.BOOL(1)
        except Exception as e:
            error(f"QueryPerformanceCounter impl. {e}")
            Kernel32.SetLastError(wt.DWORD(5))
            return wt.BOOL(0)

    @staticmethod
    def GetSystemTimeAsFileTime(lpSystemTimeAsFileTime: wt.LPFILETIME) -> None:
        """
        Retrieve the current system time as a FILETIME structure.
        """
        trace(f"GetSystemTimeAsFileTime impl. [{lpSystemTimeAsFileTime=}]")

        try:
            # Get current time in 100-nanosecond intervals since January 1, 1601 (UTC)
            epoch_as_filetime = 116444736000000000  # January 1, 1970 as FILETIME
            hundreds_of_ns = int(tm.time() * 10_000_000) + epoch_as_filetime

            lpSystemTimeAsFileTime.contents.dwLowDateTime = hundreds_of_ns & 0xFFFFFFFF
            lpSystemTimeAsFileTime.contents.dwHighDateTime = (hundreds_of_ns >> 32) & 0xFFFFFFFF

            Kernel32.SetLastError(wt.DWORD(0))
            ret("GetSystemTimeAsFileTime impl. success")
        except Exception as e:
            error(f"GetSystemTimeAsFileTime impl. {e}")
            Kernel32.SetLastError(wt.DWORD(5))
            return

    @staticmethod
    def GetTickCount64() -> ULONGLONG:
        """
        Retrieve the number of milliseconds that have elapsed since the system was started.
        """
        trace("GetTickCount64 impl. []")

        try:
            # Use time since process start as a proxy for system uptime
            uptime_ms = int((tm.time() - processes[tls.process_id]["start_time"]) * 1000)
            Kernel32.SetLastError(wt.DWORD(0))
            ret(f"GetTickCount64 impl. {uptime_ms}")
            return ULONGLONG(uptime_ms)
        except Exception as e:
            error(f"GetTickCount64 impl. {e}")
            Kernel32.SetLastError(wt.DWORD(5))
            return ULONGLONG(0)

    @staticmethod
    def IsProcessorFeaturePresent(ProcessorFeature: wt.DWORD) -> wt.BOOL:
        """
        Determine if a specified processor feature is present.
        """
        trace(f"IsProcessorFeaturePresent impl. [{ProcessorFeature=}]")

        # For simplicity, assume all features are present
        Kernel32.SetLastError(wt.DWORD(0))
        ret("IsProcessorFeaturePresent impl. True")
        return wt.BOOL(1)

    @staticmethod
    def TerminateProcess(hProcess: wt.HANDLE, uExitCode: wt.UINT) -> wt.BOOL:
        """
        Terminate a process and all of its threads.
        """
        global processes
        trace(f"TerminateProcess impl. [{hProcess=}, {uExitCode=}]")

        handle = hProcess.value if hasattr(hProcess, 'value') else hProcess

        if handle not in processes:
            Kernel32.SetLastError(wt.DWORD(6))
            return wt.BOOL(0)
        try:
            # For simplicity, just remove the process from the table
            del processes[handle]
            Kernel32.SetLastError(wt.DWORD(0))
            ret("TerminateProcess impl. success")
            return wt.BOOL(1)
        except Exception as e:
            error(f"TerminateProcess impl. {e}")
            Kernel32.SetLastError(wt.DWORD(5))
            return wt.BOOL(0)

    @staticmethod
    def RtlUnwindEx(TargetFrame: wt.LPVOID,
                     TargetIp: DWORD64,
                     ExceptionRecord: PEXCEPTION_RECORD,
                     ReturnValue: wt.LPVOID,
                     OriginalContext: PCONTEXT,
                     HistoryTable: wt.LPVOID) -> None:
        """
        Unwind the stack to a specified frame.
        """
        trace(f"RtlUnwindEx diserror-stub. [{TargetFrame=}, {TargetIp=}]")

        try:
            # For simplicity, do nothing
            Kernel32.SetLastError(wt.DWORD(0))
            ret("RtlUnwindEx diserror-stub. success")
        except Exception as e:
            error(f"RtlUnwindEx diserror-stub. {e}")
            Kernel32.SetLastError(wt.DWORD(5))
            return

    @staticmethod
    def RtlUnwind(TargetFrame: wt.LPVOID,
                     TargetIp: DWORD64,
                     ExceptionRecord: PEXCEPTION_RECORD,
                     ReturnValue: wt.LPVOID) -> None:
        """
        Unwind the stack to a specified frame.
        """
        trace(f"RtlUnwind diserror-stub. [{TargetFrame=}, {TargetIp=}]")

        try:
            # For simplicity, do nothing
            Kernel32.SetLastError(wt.DWORD(0))
            ret("RtlUnwind diserror-stub. success")
        except Exception as e:
            error(f"RtlUnwind diserror-stub. {e}")
            Kernel32.SetLastError(wt.DWORD(5))
            return

    @staticmethod
    def EncodePointer(Ptr: wt.LPVOID) -> wt.LPVOID:
        """
        Encode a pointer for security purposes.
        """
        trace(f"EncodePointer impl. [{Ptr=}]")

        try:
            # Simple XOR encoding with a fixed key
            key = 0x5A5A5A5A
            addr = ct.cast(Ptr, ct.c_void_p).value
            encoded_addr = addr ^ key
            encoded_ptr = wt.LPVOID(encoded_addr)

            Kernel32.SetLastError(wt.DWORD(0))
            ret(f"EncodePointer impl. {encoded_ptr}")
            return encoded_ptr
        except Exception as e:
            error(f"EncodePointer impl. {e}")
            Kernel32.SetLastError(wt.DWORD(5))
            return wt.LPVOID(0)

    @staticmethod
    def DecodePointer(Ptr: wt.LPVOID) -> wt.LPVOID:
        """
        Decode a pointer that was encoded with EncodePointer.
        """
        trace(f"DecodePointer impl. [{Ptr=}]")

        try:
            # Simple XOR decoding with the same fixed key
            key = 0x5A5A5A5A
            addr = ct.cast(Ptr, ct.c_void_p).value
            decoded_addr = addr ^ key
            decoded_ptr = wt.LPVOID(decoded_addr)

            Kernel32.SetLastError(wt.DWORD(0))
            ret(f"DecodePointer impl. {decoded_ptr}")
            return decoded_ptr
        except Exception as e:
            error(f"DecodePointer impl. {e}")
            Kernel32.SetLastError(wt.DWORD(5))
            return wt.LPVOID(0)

    @staticmethod
    def RtlPcToFileHeader(ControlPc: DWORD64, ImageBase: PDWORD64) -> wt.LPVOID:
        """
        Retrieve the base address of the module containing the specified address.
        """
        trace(f"RtlPcToFileHeader impl. [{ControlPc=}, {ImageBase=}]")
        # full implementation.
        try:
            for mod_base, mod_info in processes[tls.process_id]["modules"].items():
                mod_size = mod_info["size"]
                if mod_base <= ControlPc < (mod_base + mod_size):
                    ImageBase[0] = DWORD64(mod_base)
                    Kernel32.SetLastError(wt.DWORD(0))
                    ret(f"RtlPcToFileHeader impl. found module at {hex(mod_base)}")
                    return wt.LPVOID(mod_base)
            # Not found
            ImageBase[0] = DWORD64(0)
            Kernel32.SetLastError(wt.DWORD(0))
            ret("RtlPcToFileHeader impl. no module found")
            return wt.LPVOID(0)
        except Exception as e:
            error(f"RtlPcToFileHeader impl. {e}")
            Kernel32.SetLastError(wt.DWORD(5))
            return wt.LPVOID(0)

    @staticmethod
    def TlsAlloc() -> wt.DWORD:
        """
        Allocate a thread local storage (TLS) index.
        """
        trace("TlsAlloc impl. []")

        try:
            index = processes[tls.process_id]["next_tls_index"]
            processes[tls.process_id]["next_tls_index"] += 1
            processes[tls.process_id]["tls_data"][index] = {}

            Kernel32.SetLastError(wt.DWORD(0))
            ret(f"TlsAlloc impl. {index}")
            return wt.DWORD(index)
        except Exception as e:
            error(f"TlsAlloc impl. {e}")
            Kernel32.SetLastError(wt.DWORD(5))
            return wt.DWORD(0xFFFFFFFF)

    @staticmethod
    def TlsFree(dwTlsIndex: wt.DWORD) -> wt.BOOL:
        """
        Free a thread local storage (TLS) index.
        """
        trace(f"TlsFree impl. [{dwTlsIndex=}]")

        try:
            index = dwTlsIndex.value if hasattr(dwTlsIndex, 'value') else dwTlsIndex

            if index not in processes[tls.process_id]["tls_data"]:
                Kernel32.SetLastError(wt.DWORD(87))  # ERROR_INVALID_PARAMETER
                return wt.BOOL(0)

            del processes[tls.process_id]["tls_data"][index]

            Kernel32.SetLastError(wt.DWORD(0))
            ret("TlsFree impl. success")
            return wt.BOOL(1)
        except Exception as e:
            error(f"TlsFree impl. {e}")
            Kernel32.SetLastError(wt.DWORD(5))
            return wt.BOOL(0)

    @staticmethod
    def TlsSetValue(dwTlsIndex: wt.DWORD, lpTlsValue: wt.LPVOID) -> wt.BOOL:
        """
        Set the value in a thread local storage (TLS) slot for the current thread.
        """
        trace(f"TlsSetValue impl. [{dwTlsIndex=}, {lpTlsValue=}]")

        try:
            index = dwTlsIndex.value if hasattr(dwTlsIndex, 'value') else dwTlsIndex

            if index not in processes[tls.process_id]["tls_data"]:
                Kernel32.SetLastError(wt.DWORD(87))  # ERROR_INVALID_PARAMETER
                return wt.BOOL(0)

            tid = tls.thread_id
            processes[tls.process_id]["tls_data"][index][tid] = lpTlsValue

            Kernel32.SetLastError(wt.DWORD(0))
            ret("TlsSetValue impl. success")
            return wt.BOOL(1)
        except Exception as e:
            error(f"TlsSetValue impl. {e}")
            Kernel32.SetLastError(wt.DWORD(5))
            return wt.BOOL(0)

    @staticmethod
    def TlsGetValue(dwTlsIndex: wt.DWORD) -> wt.LPVOID:
        """
        Retrieve the value in a thread local storage (TLS) slot for the current thread.
        """
        trace(f"TlsGetValue impl. [{dwTlsIndex=}]")

        try:
            index = dwTlsIndex.value if hasattr(dwTlsIndex, 'value') else dwTlsIndex

            if index not in processes[tls.process_id]["tls_data"]:
                Kernel32.SetLastError(wt.DWORD(87))  # ERROR_INVALID_PARAMETER
                return wt.LPVOID(0)

            tid = tls.thread_id
            value = processes[tls.process_id]["tls_data"][index].get(tid, wt.LPVOID(0))

            Kernel32.SetLastError(wt.DWORD(0))
            ret(f"TlsGetValue impl. {value}")
            return value
        except Exception as e:
            error(f"TlsGetValue impl. {e}")
            Kernel32.SetLastError(wt.DWORD(5))
            return wt.LPVOID(0)
