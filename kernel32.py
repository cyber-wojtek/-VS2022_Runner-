from win_types import *
from log import *
import os
from advapi32 import _handle_map
from pathlib import Path
import glob
import threading

# File search state tracking
_next_search_handle = 0x2000
_search_handles = {}  # handle -> {'pattern': str, 'files': list, 'index': int}
cmdline: str | None = None
# Environment variables
env_vars = {
    # System paths
    "SYSTEMROOT": "C:\\Windows",
    "WINDIR": "C:\\Windows",
    "SYSTEMDRIVE": "C:",
    "PROGRAMFILES": "C:\\Program Files",
    "PROGRAMFILES(X86)": "C:\\Program Files (x86)",
    "PROGRAMDATA": "C:\\ProgramData",
    "COMMONPROGRAMFILES": "C:\\Program Files\\Common Files",
    "COMMONPROGRAMFILES(X86)": "C:\\Program Files (x86)\\Common Files",

    # User paths
    "USERPROFILE": "C:\\Users\\User",
    "HOMEDRIVE": "C:",
    "HOMEPATH": "\\Users\\User",
    "APPDATA": "C:\\Users\\User\\AppData\\Roaming",
    "LOCALAPPDATA": "C:\\Users\\User\\AppData\\Local",
    "TEMP": "C:\\Users\\User\\AppData\\Local\\Temp",
    "TMP": "C:\\Users\\User\\AppData\\Local\\Temp",

    # System info
    "COMPUTERNAME": "EMULATED-PC",
    "USERNAME": "User",
    "USERDOMAIN": "WORKGROUP",
    "OS": "Windows_NT",
    "PROCESSOR_ARCHITECTURE": "AMD64",
    "PROCESSOR_IDENTIFIER": "Intel64 Family 6 Model 158 Stepping 10, GenuineIntel",
    "NUMBER_OF_PROCESSORS": "8",

    # Path and execution
    "PATH": "C:\\Windows\\system32;C:\\Windows;C:\\Windows\\System32\\Wbem;C:\\Windows\\System32\\WindowsPowerShell\\v1.0",
    "PATHEXT": ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC",
    "COMSPEC": "C:\\Windows\\system32\\cmd.exe",

    # Session and display
    "SESSIONNAME": "Console",
    "LOGONSERVER": "\\\\EMULATED-PC",
    "ALLUSERSPROFILE": "C:\\ProgramData",
    "PUBLIC": "C:\\Users\\Public"
}
error_mode = 0

# File handle management
_next_file_handle = 0x3000
_file_handles = {}  # handle -> file object

_tls = threading.local()
_tls.last_error = 0

_next_critical_section = 0x4000
_critical_sections = {} # addr -> threading.RLock()


def _alloc_file_handle(file_obj) -> int:
    """Allocate a new file handle"""
    global _next_file_handle
    handle = _next_file_handle
    _next_file_handle += 1
    _file_handles[handle] = file_obj
    return handle


def CreateFileW(
        lpFileName: wt.LPCWSTR,
        dwDesiredAccess: wt.DWORD,
        dwShareMode: wt.DWORD,
        lpSecurityAttributes: wt.LPVOID,
        dwCreationDisposition: wt.DWORD,
        dwFlagsAndAttributes: wt.DWORD,
        hTemplateFile: wt.HANDLE
) -> wt.HANDLE:
    trace(
        f"CreateFileW impl. lpFileName: {lpFileName}, dwDesiredAccess: {dwDesiredAccess}, dwCreationDisposition: {dwCreationDisposition}")

    try:
        filename = lpFileName

        # Map Windows access flags to Python mode
        mode = ""

        # Handle creation disposition
        if dwCreationDisposition.value == 1:  # CREATE_NEW
            if os.path.exists(filename.value):
                SetLastError(wt.DWORD(183))  # ERROR_ALREADY_EXISTS
                ret(f"  {wt.HANDLE(-1)}")  # File exists, fail
                return wt.HANDLE(-1)
            mode = "w+b" if dwDesiredAccess.value & 0x40000000 else "rb"  # GENERIC_WRITE
        elif dwCreationDisposition.value == 2:  # CREATE_ALWAYS
            mode = "w+b" if dwDesiredAccess.value & 0x40000000 else "rb"
        elif dwCreationDisposition.value == 3:  # OPEN_EXISTING
            if not os.path.exists(filename.value):
                SetLastError(wt.DWORD(2))  # ERROR_FILE_NOT_FOUND
                ret(f"  {wt.HANDLE(-1)}")  # File doesn't exist, fail
                return wt.HANDLE(-1)
            if dwDesiredAccess.value & 0x40000000:  # GENERIC_WRITE
                mode = "r+b"
            else:
                mode = "rb"
        elif dwCreationDisposition.value == 4:  # OPEN_ALWAYS
            if os.path.exists(filename.value):
                mode = "r+b" if dwDesiredAccess.value & 0x40000000 else "rb"
            else:
                mode = "w+b" if dwDesiredAccess.value & 0x40000000 else "rb"
        elif dwCreationDisposition.value == 5:  # TRUNCATE_EXISTING
            if not os.path.exists(filename.value):
                SetLastError(wt.DWORD(2))  # ERROR_FILE_NOT_FOUND
                ret(f"  {wt.HANDLE(-1)}")  # File doesn't exist, fail
                return wt.HANDLE(-1)
            mode = "w+b"

        # Open the file
        file_obj = open(filename.value, mode)
        handle = _alloc_file_handle(file_obj)

        SetLastError(wt.DWORD(0))  # NO_ERROR
        ret(f"  {wt.HANDLE(handle)}")
        return wt.HANDLE(handle)

    except Exception as e:
        trace(f"CreateFileW error: {e}")
        ret(f"  {wt.HANDLE(-1)}")  # INVALID_HANDLE_VALUE
        return wt.HANDLE(-1)

def ReadFile(
        hFile: wt.HANDLE,
        lpBuffer: wt.LPVOID,
        nNumberOfBytesToRead: wt.DWORD,
        lpNumberOfBytesRead: wt.LPDWORD,
        lpOverlapped: wt.LPVOID
) -> wt.BOOL:
    trace(f"ReadFile impl. hFile: {hFile}, nNumberOfBytesToRead: {nNumberOfBytesToRead}")

    if hFile.value not in _file_handles:
        SetLastError(wt.DWORD(6))  # ERROR_INVALID_HANDLE
        ret(f"  {wt.BOOL(0)}")  # FALSE
        return wt.BOOL(0)

    try:
        file_obj = _file_handles[hFile.value]
        data = file_obj.read(nNumberOfBytesToRead)
        bytes_read = len(data)

        # Copy data to buffer
        if bytes_read > 0:
            ct.memmove(lpBuffer, data, bytes_read)

        # Set bytes read
        if lpNumberOfBytesRead:
            lpNumberOfBytesRead[0] = wt.DWORD(bytes_read)

        SetLastError(wt.DWORD(0))  # NO_ERROR
        ret(f"  {wt.BOOL(1)}")  # TRUE
        return wt.BOOL(1)

    except Exception as e:
        error(f"  ReadFile error: {e}")
        SetLastError(wt.DWORD(1))  # ERROR_INVALID_FUNCTION (as a generic error)
        ret(f"  {wt.BOOL(0)}")
        return wt.BOOL(0)


def WriteFile(
        hFile: wt.HANDLE,
        lpBuffer: wt.LPCVOID,
        nNumberOfBytesToWrite: wt.DWORD,
        lpNumberOfBytesWritten: wt.LPDWORD,
        lpOverlapped: wt.LPVOID
) -> wt.BOOL:
    trace(f"WriteFile impl. hFile: {hFile}, nNumberOfBytesToWrite: {nNumberOfBytesToWrite}")

    if hFile.value not in _file_handles:
        SetLastError(wt.DWORD(6))  # ERROR_INVALID_HANDLE
        ret(f"  {wt.BOOL(0)}")  # FALSE
        return wt.BOOL(0)

    try:
        file_obj = _file_handles[hFile.value]

        # Extract data from buffer
        data = ct.string_at(lpBuffer, nNumberOfBytesToWrite.value)
        bytes_written = file_obj.write(data)
        file_obj.flush()  # Ensure data is written

        # Set bytes written
        if lpNumberOfBytesWritten:
            lpNumberOfBytesWritten[0] = wt.DWORD(bytes_written)

        SetLastError(wt.DWORD(0))  # NO_ERROR
        ret(f"  {wt.BOOL(1)}")  # TRUE
        return wt.BOOL(1)

    except Exception as e:
        error(f"  WriteFile error: {e}")
        SetLastError(wt.DWORD(1))  # ERROR_INVALID_FUNCTION (as a generic error)
        ret(f"  {wt.BOOL(0)}")
        return wt.BOOL(0)


def CloseHandle(
        hObject: wt.HANDLE
) -> wt.BOOL:
    trace(f"CloseHandle impl. hObject: {hObject}")

    # Handle file handles
    if hObject.value in _file_handles:
        try:
            _file_handles[hObject.value].close()
            del _file_handles[hObject.value]
            SetLastError(wt.DWORD(0))  # NO_ERROR
            ret(f"  {wt.BOOL(1)}")  # TRUE
            return wt.BOOL(1)
        except Exception as e:
            trace(f"CloseHandle file error: {e}")
            SetLastError(wt.DWORD(1))  # ERROR_INVALID_FUNCTION (as a generic error)
            ret(f"  {wt.BOOL(0)}")
            return wt.BOOL(0)

    # Handle search handles
    if hObject.value in _search_handles:
        del _search_handles[hObject.value]
        SetLastError(wt.DWORD(0))  # NO_ERROR
        ret(f"  {wt.BOOL(1)}")  # TRUE
        return wt.BOOL(1)

    # Handle registry handles
    if hObject.value in _handle_map:
        del _handle_map[hObject.value]
        ret(f"  {wt.BOOL(1)}")  # TRUE
        SetLastError(wt.DWORD(0))  # NO_ERROR
        return wt.BOOL(1)

    # For other handles, just return success (stub)
    # TODO: Implement other handle types as needed !!!!!!

    SetLastError(wt.DWORD(0))  # NO_ERROR
    ret(f"  {wt.BOOL(1)}")  # TRUE
    return wt.BOOL(1)


def DeleteFileW(
        lpFileName: wt.LPCWSTR
) -> wt.BOOL:
    trace(f"DeleteFileW impl. lpFileName: {lpFileName}")

    try:
        if os.path.exists(lpFileName.value):
            if os.path.isfile(lpFileName.value):
                os.remove(lpFileName.value)
                SetLastError(wt.DWORD(0)) # NO_ERROR
                ret(f"  {wt.BOOL(1)}")  # TRUE
                return wt.BOOL(1)
            else:
                # It's a directory, can't delete with DeleteFileW
                SetLastError(wt.DWORD(5))  # ERROR_ACCESS_DENIED
                ret(f"  {wt.BOOL(0)}")  # FALSE
                return wt.BOOL(0)
        else:
            # File doesn't exist
            SetLastError(wt.DWORD(2))  # ERROR_FILE_NOT_FOUND
            ret(f"  {wt.BOOL(0)}")  # FALSE
            return wt.BOOL(0)

    except Exception as e:
        error(f"  DeleteFileW error: {e}")
        SetLastError(wt.DWORD(1))  # ERROR_INVALID_FUNCTION (as a generic error)
        ret(f"  {wt.BOOL(0)}")
        return wt.BOOL(0)


def GetFileSize(
        hFile: wt.HANDLE,
        lpFileSizeHigh: wt.LPDWORD
) -> wt.DWORD:
    trace(f"GetFileSize impl. hFile: {hFile}")

    if hFile.value not in _file_handles:
        SetLastError(wt.DWORD(6))  # ERROR_INVALID_HANDLE
        
        if lpFileSizeHigh:
            lpFileSizeHigh[0] = wt.DWORD(0)

        ret(f"  {wt.DWORD(0xFFFFFFFF)}")  # INVALID_FILE_SIZE
        return wt.DWORD(0xFFFFFFFF)

    try:
        file_obj = _file_handles[hFile.value]
        current_pos = file_obj.tell()
        file_obj.seek(0, 2)  # Seek to end
        size = file_obj.tell()
        file_obj.seek(current_pos)  # Restore position

        # Split 64-bit size into high and low parts
        size_low = size & 0xFFFFFFFF
        size_high = (size >> 32) & 0xFFFFFFFF

        if lpFileSizeHigh:
            lpFileSizeHigh[0] = wt.DWORD(size_high)

        SetLastError(wt.DWORD(0))  # NO_ERROR
        ret(f"  {wt.DWORD(size_low)}")
        return wt.DWORD(size_low)

    except Exception as e:
        error(f"  GetFileSize error: {e}")
        SetLastError(wt.DWORD(1))  # ERROR_INVALID_FUNCTION (as a generic error)
        ret(f"  {wt.DWORD(0xFFFFFFFF)}")
        return wt.DWORD(0xFFFFFFFF)


def SetFilePointer(
        hFile: wt.HANDLE,
        lDistanceToMove: wt.LONG,
        lpDistanceToMoveHigh: wt.PLONG,
        dwMoveMethod: wt.DWORD
) -> wt.DWORD:
    trace(f"SetFilePointer impl. hFile: {hFile}, lDistanceToMove: {lDistanceToMove}, dwMoveMethod: {dwMoveMethod}")

    if hFile.value not in _file_handles:
        ret(f"  {wt.DWORD(0xFFFFFFFF)}")  # INVALID_SET_FILE_POINTER
        return wt.DWORD(0xFFFFFFFF)

    try:
        file_obj = _file_handles[hFile.value]

        # Construct 64-bit offset
        offset = lDistanceToMove
        if lpDistanceToMoveHigh:
            offset |= (lpDistanceToMoveHigh[0] << 32)

        # Map Windows seek method to Python
        whence = 0  # os.SEEK_SET
        if dwMoveMethod.value == 1:  # FILE_CURRENT
            whence = 1  # os.SEEK_CUR
        elif dwMoveMethod.value == 2:  # FILE_END
            whence = 2  # os.SEEK_END

        new_pos = file_obj.seek(offset, whence)

        # Return low 32 bits of new position
        pos_low = new_pos & 0xFFFFFFFF
        pos_high = (new_pos >> 32) & 0xFFFFFFFF

        if lpDistanceToMoveHigh:
            lpDistanceToMoveHigh[0] = wt.LONG(pos_high)

        SetLastError(wt.DWORD(0))  # NO_ERROR
        ret(f"  {wt.DWORD(pos_low)}")
        return wt.DWORD(pos_low)

    except Exception as e:
        error(f"  SetFilePointer error: {e}")
        SetLastError(wt.DWORD(1))  # ERROR_INVALID_FUNCTION (as a generic error)
        ret(f"  {wt.DWORD(0xFFFFFFFF)}")
        return wt.DWORD(0xFFFFFFFF)

def _alloc_search_handle(pattern: str, files: list) -> int:
    """Allocate a new search handle"""
    global _next_search_handle
    handle = _next_search_handle
    _next_search_handle += 1
    _search_handles[handle] = {
        'pattern': pattern,
        'files': files,
        'index': 0
    }
    return handle


def _fill_find_data(file_path: str, find_data: LPWIN32_FIND_DATAW):
    """Fill WIN32_FIND_DATAW structure with file information"""
    try:
        path_obj = Path(file_path)
        stat = path_obj.stat()

        # Clear the structure
        ct.memset(find_data, 0, ct.sizeof(wt.WIN32_FIND_DATAW))

        # File attributes
        attrs = 0
        if path_obj.is_dir():
            attrs |= 0x10  # FILE_ATTRIBUTE_DIRECTORY
        if path_obj.name.startswith('.'):
            attrs |= 0x02  # FILE_ATTRIBUTE_HIDDEN
        # read-only attribute
        if not os.access(file_path, os.W_OK):
            attrs |= 0x01  # FILE_ATTRIBUTE_READONLY
        if attrs == 0:
            attrs = 0x80  # FILE_ATTRIBUTE_NORMAL
        find_data.contents.dwFileAttributes = wt.DWORD(attrs)

        # File times (simplified - just use modification time for all)
        # Windows FILETIME is 100-nanosecond intervals since Jan 1, 1601
        # Python time is seconds since Jan 1, 1970
        # Difference is 11644473600 seconds
        win_time = int((stat.st_mtime + 11644473600) * 10000000)
        find_data.contents.ftCreationTime.dwLowDateTime = wt.DWORD(win_time & 0xFFFFFFFF)
        find_data.contents.ftCreationTime.dwHighDateTime = wt.DWORD(win_time >> 32)
        find_data.contents.ftLastAccessTime = find_data.contents.ftCreationTime
        find_data.contents.ftLastWriteTime = find_data.contents.ftCreationTime

        # File size
        if not path_obj.is_dir():
            find_data.contents.nFileSizeLow = wt.DWORD(stat.st_size & 0xFFFFFFFF)
            find_data.contents.nFileSizeHigh = wt.DWORD(stat.st_size >> 32)

        # File name (convert to wide string)
        filename = path_obj.name
        if len(filename) >= 260:  # MAX_PATH
            filename = filename[:259]
        filename_bytes = filename.encode('utf-16le')
        ct.memmove(find_data.contents.cFileName, filename_bytes, len(filename_bytes))

        # Alternate name (8.3 format) - simplified
        alt_name = filename[:8] + "~1"
        if '.' in filename:
            ext = filename.split('.')[-1][:3]
            alt_name = filename[:6] + "~1." + ext
        alt_name_bytes = alt_name.encode('utf-16le')
        ct.memmove(find_data.contents.cAlternateFileName, alt_name_bytes, len(alt_name_bytes))

        return True

    except Exception as e:
        trace(f"Error filling find data for {file_path}: {e}")
        return False


def FindFirstFileW(
        lpFileName: wt.LPCWSTR,
        lpFindFileData: LPWIN32_FIND_DATAW
) -> wt.HANDLE:
    trace(f"FindFirstFileW impl. lpFileName: {lpFileName}, lpFindFileData: {lpFindFileData}")

    try:
        # Normalize path for glob
        pattern = lpFileName.value.replace('\\', '/')

        if ':' in pattern and pattern[1] == '/':
            # convert "C:/..." → "C/..."
            pattern = pattern[0] + pattern[2:]

        # Handle wildcards
        files = []
        if '*' in pattern or '?' in pattern:
            files = glob.glob(pattern, recursive=False)
        else:
            if os.path.exists(pattern):
                files = [pattern]

        if not files:
            SetLastError(wt.DWORD(2))  # ERROR_FILE_NOT_FOUND
            ret(f"  {wt.HANDLE(-1)}")  # INVALID_HANDLE_VALUE
            return wt.HANDLE(-1)

        files.sort()

        # Fill data for first file
        if not _fill_find_data(files[0], lpFindFileData):
            SetLastError(wt.DWORD(1))  # ERROR_INVALID_FUNCTION (as a generic error)
            ret(f"  {wt.HANDLE(-1)}")
            return wt.HANDLE(-1)

        # Allocate search handle
        handle = _alloc_search_handle(pattern, files)

        SetLastError(wt.DWORD(0))  # NO_ERROR
        ret(f"  {wt.HANDLE(handle)}")
        return wt.HANDLE(handle)

    except Exception as e:
        error(f"  FindFirstFileW error: {e}")
        SetLastError(wt.DWORD(1))  # ERROR_INVALID_FUNCTION (as a generic error)
        ret(f"  {wt.HANDLE(-1)}")
        return wt.HANDLE(-1)


def FindNextFileW(
        hFindFile: wt.HANDLE,
        lpFindFileData: LPWIN32_FIND_DATAW
) -> wt.BOOL:
    trace(f"FindNextFileW impl. hFindFile: {hFindFile}, lpFindFileData: {lpFindFileData}")

    if hFindFile.value not in _search_handles:
        SetLastError(wt.DWORD(6))  # ERROR_INVALID_HANDLE
        ret(f"  {wt.BOOL(0)}")     # FALSE
        return wt.BOOL(0)

    search_info = _search_handles[hFindFile.value]
    search_info['index'] += 1

    if search_info['index'] >= len(search_info['files']):
        SetLastError(wt.DWORD(18))  # ERROR_NO_MORE_FILES
        ret(f"  {wt.BOOL(0)}")      # FALSE
        return wt.BOOL(0)

    # Fill data for next file
    next_file = search_info['files'][search_info['index']]
    if not _fill_find_data(next_file, lpFindFileData):
        SetLastError(wt.DWORD(1))  # ERROR_INVALID_FUNCTION (generic error)
        ret(f"  {wt.BOOL(0)}")
        return wt.BOOL(0)

    SetLastError(wt.DWORD(0))      # NO_ERROR
    ret(f"  {wt.BOOL(1)}")         # TRUE
    return wt.BOOL(1)

def FindClose(
        hFindFile: wt.HANDLE
) -> wt.BOOL:
    trace(f"FindClose impl. hFindFile: {hFindFile}")

    if hFindFile.value in _search_handles:
        del _search_handles[hFindFile.value]
        SetLastError(wt.DWORD(0))  # NO_ERROR
        ret(f"  {wt.BOOL(1)}")  # TRUE
        return wt.BOOL(1)

    SetLastError(wt.DWORD(6))  # ERROR_INVALID_HANDLE
    ret(f"  {wt.BOOL(0)}")  # FALSE
    return wt.BOOL(0)

def GetCommandLineW() -> wt.LPWSTR:
    global cmdline
    trace(f"GetCommandLineW impl. cmdline: {cmdline}")
    SetLastError(wt.DWORD(0)) # NO_ERROR
    ret(f"  {wt.LPWSTR(cmdline)}")
    return wt.LPWSTR(cmdline)

def GetCurrentProcess() -> wt.HANDLE:
    trace("GetCurrentProcess impl.")
    SetLastError(wt.DWORD(0)) # NO_ERROR
    ret(f"  {wt.HANDLE(0xFFFFFFFF)}")  # Pseudo-handle for current process
    return wt.HANDLE(0xFFFFFFFF)

def GetModuleFileNameW(
        hModule: wt.HANDLE,
        lpFilename: wt.LPWSTR,
        nSize: wt.DWORD
) -> wt.DWORD:
    trace(f"GetModuleFileNameW semi-stub. hModule: {hModule}, lpFilename: {lpFilename}, nSize: {nSize}")

    try:
        # Only support "current executable" (hModule == NULL or a pseudo-handle)
        if hModule.value not in (0, None):
            # Simulate "module not found" for any non-current module
            SetLastError(wt.DWORD(126))  # ERROR_MOD_NOT_FOUND
            ret(f"  {wt.DWORD(0)}")
            return wt.DWORD(0)

        # Decide what the emulated executable path should be
        exe_path = cmdline.split(' ')[0]

        # Encode to UTF-16 LE with null terminator
        path_w = exe_path.encode('utf-16le') + b'\x00\x00'

        # Max buffer in bytes
        max_bytes = nSize.value * 2

        if len(path_w) > max_bytes:
            # Truncate to fit and add null terminator
            truncated = path_w[:max_bytes - 2] + b'\x00\x00'
            ct.memmove(lpFilename, truncated, len(truncated))
            SetLastError(wt.DWORD(0))  # NO_ERROR, truncated is still a valid return
            ret(f"  {wt.DWORD(nSize.value - 1)}")
            return wt.DWORD(nSize.value - 1)

        # Copy full path
        ct.memmove(lpFilename, path_w, len(path_w))
        length = len(path_w) // 2 - 1
        SetLastError(wt.DWORD(0))  # NO_ERROR
        ret(f"  {wt.DWORD(length)}")
        return wt.DWORD(length)

    except Exception as e:
        error(f"  GetModuleFileNameW error: {e}")
        SetLastError(wt.DWORD(1))  # ERROR_INVALID_FUNCTION as generic error
        ret(f"  {wt.DWORD(0)}")
        return wt.DWORD(0)

def SetEnvironmentVariableW(
        lpName: wt.LPCWSTR,
        lpValue: wt.LPCWSTR
) -> wt.BOOL:
    global env_vars
    trace(f"SetEnvironmentVariableW impl. lpName: {lpName}, lpValue: {lpValue}")
    try:
        name = lpName.value
        value = lpValue.value if lpValue else None
        if value is None:
            if name in env_vars:
                del env_vars[name]
        else:
            env_vars[name] = value
        SetLastError(wt.DWORD(0))  # NO_ERROR
        ret(f"  {wt.BOOL(1)}")  # TRUE
        return wt.BOOL(1)
    except Exception as e:
        error(f"  SetEnvironmentVariableW error: {e}")
        SetLastError(wt.DWORD(1))
        ret(f"  {wt.BOOL(0)}")  # FALSE
        return wt.BOOL(0)

def GetEnvironmentVariableW(
        lpName: wt.LPCWSTR,
        lpBuffer: wt.LPWSTR,
        nSize: wt.DWORD
) -> wt.DWORD:
    global env_vars
    trace(f"GetEnvironmentVariableW impl. lpName: {lpName}, lpBuffer: {lpBuffer}, nSize: {nSize}")
    try:
        name = lpName.value
        if name not in env_vars:
            ret(f"  {wt.DWORD(0)}")  # Variable not found
            return wt.DWORD(0)
        value = env_vars[name]
        value_w = value.encode('utf-16le') + b'\x00\x00'  # Null-terminated
        required_size = len(value_w) // 2  # In WCHARs
        if nSize.value < required_size:
            ret(f"  {wt.DWORD(required_size)}")  # Buffer too small
            return wt.DWORD(required_size)
        ct.memmove(lpBuffer, value_w, len(value_w))
        SetLastError(wt.DWORD(0))  # NO_ERROR
        ret(f"  {wt.DWORD(required_size - 1)}")  # Exclude null terminator
        return wt.DWORD(required_size - 1)
    except Exception as e:
        error(f"  GetEnvironmentVariableW error: {e}")
        SetLastError(wt.DWORD(1))  # ERROR_INVALID_FUNCTION as generic error
        ret(f"  {wt.DWORD(0)}")
        return wt.DWORD(0)

def SetErrorMode(
        uMode: wt.UINT
) -> wt.UINT:
    global error_mode
    trace(f"SetErrorMode impl. uMode: {uMode}")
    previous_mode = error_mode
    error_mode = uMode.value
    SetLastError(wt.DWORD(0)) # NO_ERROR
    ret(f"  {wt.UINT(previous_mode)}")
    return wt.UINT(previous_mode)

def GetErrorMode() -> wt.UINT:
    global error_mode
    trace("GetErrorMode impl.")
    SetLastError(wt.DWORD(0)) # NO_ERROR
    ret(f"  {wt.UINT(error_mode)}")
    return wt.UINT(error_mode)

def SetLastError(
        dwErrCode: wt.DWORD
) -> None:
    trace(f"SetLastError impl. dwErrCode: {dwErrCode}")
    _tls.last_error = dwErrCode.value
    ret("  <void>")

def GetLastError() -> wt.DWORD:
    trace("GetLastError impl.")
    err = getattr(_tls, 'last_error', 0)
    ret(f"  {wt.DWORD(err)}")
    return wt.DWORD(err)

def _addr_of_cs_ptr(lpCriticalSection) -> int | None:
    """Return integer address for a PCRITICAL_SECTION or None if invalid."""
    if not lpCriticalSection:
        return None
    try:
        return ct.addressof(lpCriticalSection.contents)
    except Exception:
        return None

def InitializeCriticalSectionEx(
        lpCriticalSection: LPCRITICAL_SECTION,
        dwSpinCount: wt.DWORD,
        Flags: wt.DWORD
) -> wt.BOOL:
    """
    BOOL InitializeCriticalSectionEx(LPCRITICAL_SECTION lpCriticalSection, DWORD dwSpinCount, DWORD Flags)
    We ignore spin count and flags; create an RLock for the CRITICAL_SECTION pointer.
    """
    global _critical_sections, _next_critical_section_handle
    trace(f"InitializeCriticalSectionEx impl. lpCriticalSection: {lpCriticalSection}, dwSpinCount: {dwSpinCount}, Flags: {Flags}")

    addr = _addr_of_cs_ptr(lpCriticalSection)
    if addr is None:
        # In real Windows passing NULL is undefined; fail gracefully.
        SetLastError(wt.DWORD(87))  # ERROR_INVALID_PARAMETER
        ret(f"  {wt.BOOL(0)}")
        return wt.BOOL(0)

    # Create a re-entrant lock for the CRITICAL_SECTION
    lock = threading.RLock()
    _critical_sections[addr] = lock

    # Optionally store the spin count value inside the structure if you want (ignored here)
    try:
        # Best-effort: store SpinCount field if present (safe no-op if not)
        try:
            lpCriticalSection.contents.SpinCount = dwSpinCount.value
        except Exception:
            # Some callers won't expect the structure to be mutated; ignore failures.
            pass
    except Exception:
        pass

    SetLastError(wt.DWORD(0))  # NO_ERROR
    ret(f"  {wt.BOOL(1)}")
    return wt.BOOL(1)


def InitializeCriticalSection(
        lpCriticalSection: LPCRITICAL_SECTION
) -> None:
    """
    VOID InitializeCriticalSection(LPCRITICAL_SECTION lpCriticalSection)
    Just call the Ex variant with defaults.
    """
    trace(f"InitializeCriticalSection impl. lpCriticalSection: {lpCriticalSection}")
    InitializeCriticalSectionEx(lpCriticalSection, wt.DWORD(0), wt.DWORD(0))
    ret("  <void>")
    return None


def InitializeCriticalSectionAndSpinCount(
        lpCriticalSection: LPCRITICAL_SECTION,
        dwSpinCount: wt.DWORD
) -> wt.BOOL:
    """
    DWORD InitializeCriticalSectionAndSpinCount(LPCRITICAL_SECTION, DWORD dwSpinCount)
    Return nonzero on success.
    """
    trace(f"InitializeCriticalSectionAndSpinCount impl. lpCriticalSection: {lpCriticalSection}, dwSpinCount: {dwSpinCount}")
    return InitializeCriticalSectionEx(lpCriticalSection, dwSpinCount, wt.DWORD(0))


def EnterCriticalSection(
        lpCriticalSection: LPCRITICAL_SECTION
) -> None:
    """
    VOID EnterCriticalSection(LPCRITICAL_SECTION)
    Blocks until the RLock is acquired.
    """
    trace(f"EnterCriticalSection impl. lpCriticalSection: {lpCriticalSection}")
    addr = _addr_of_cs_ptr(lpCriticalSection)
    if addr is None:
        # undefined in real Windows; just return
        SetLastError(wt.DWORD(87))  # ERROR_INVALID_PARAMETER
        ret("  <void>")
        return None

    lock = _critical_sections.get(addr)
    if lock is None:
        # If not initialized, create one (Windows implicitly allows this in some cases)
        lock = threading.RLock()
        _critical_sections[addr] = lock

    lock.acquire()
    SetLastError(wt.DWORD(0))  # NO_ERROR
    ret("  <void>")
    return None


def LeaveCriticalSection(
        lpCriticalSection: LPCRITICAL_SECTION
) -> None:
    """
    VOID LeaveCriticalSection(LPCRITICAL_SECTION)
    Releases the RLock.
    """
    trace(f"LeaveCriticalSection impl. lpCriticalSection: {lpCriticalSection}")
    addr = _addr_of_cs_ptr(lpCriticalSection)
    if addr is None:
        # undefined in real Windows; just return
        SetLastError(wt.DWORD(87))  # ERROR_INVALID_PARAMETER
        ret("  <void>")
        return None

    lock = _critical_sections.get(addr)
    if lock is None:
        # Nothing to release; log and return
        SetLastError(wt.DWORD(0))  # NO_ERROR
        warn("LeaveCriticalSection: no lock found for pointer")
        ret("  <void>")
        return None

    try:
        lock.release()
    except RuntimeError:
        # Release called more times than acquire — ignore for emulator
        warn("LeaveCriticalSection: release called on unlocked RLock")
    SetLastError(wt.DWORD(0))  # NO_ERROR
    ret("  <void>")
    return None


def TryEnterCriticalSection(
        lpCriticalSection: LPCRITICAL_SECTION
) -> wt.BOOL:
    """
    BOOL TryEnterCriticalSection(LPCRITICAL_SECTION)
    Non-blocking attempt to acquire; returns nonzero on success.
    """
    trace(f"TryEnterCriticalSection impl. lpCriticalSection: {lpCriticalSection}")
    addr = _addr_of_cs_ptr(lpCriticalSection)
    if addr is None:
        # undefined in real Windows; just fail
        SetLastError(wt.DWORD(87))  # ERROR_INVALID_PARAMETER
        ret(f"  {wt.BOOL(0)}")
        return wt.BOOL(0)

    lock = _critical_sections.get(addr)
    if lock is None:
        # Create one and acquire immediately (match Windows behavior: initialize implicitly)
        lock = threading.RLock()
        _critical_sections[addr] = lock

    ok = lock.acquire(blocking=False)
    SetLastError(wt.DWORD(0))  # NO_ERROR
    ret(f"  {wt.BOOL(1 if ok else 0)}")
    return wt.BOOL(1 if ok else 0)


def DeleteCriticalSection(
        lpCriticalSection: LPCRITICAL_SECTION
) -> None:
    """
    VOID DeleteCriticalSection(LPCRITICAL_SECTION)
    Remove our mapping; the Python RLock will be garbage-collected.
    """
    trace(f"DeleteCriticalSection impl. lpCriticalSection: {lpCriticalSection}")
    addr = _addr_of_cs_ptr(lpCriticalSection)
    if addr is None:
        # undefined in real Windows; just return
        SetLastError(wt.DWORD(87))  # ERROR_INVALID_PARAMETER
        ret("  <void>")
        return None

    if addr in _critical_sections:
        try:
            del _critical_sections[addr]
        except Exception:
            pass

    SetLastError(wt.DWORD(0))  # NO_ERROR
    ret("  <void>")
    return None

def WaitForSingleObject(
        hHandle: wt.HANDLE,
        dwMilliseconds: wt.DWORD
) -> wt.DWORD:
    """
    DWORD WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds)

    In this emulation:
    - If hHandle corresponds to a file, registry, or other non-waitable object, return WAIT_OBJECT_0 immediately.
    - Critical sections are not handles, so WaitForSingleObject on them is a noop.
    - Timeout handling is ignored in this stub; returns WAIT_OBJECT_0.
    """
    trace(f"WaitForSingleObject impl. hHandle: {hHandle}, dwMilliseconds: {dwMilliseconds}")

    # If hHandle is invalid, return WAIT_FAILED
    if hHandle.value == 0 or hHandle.value == -1:
        SetLastError(wt.DWORD(6))  # ERROR_INVALID_HANDLE
        ret(f"  {wt.DWORD(0xFFFFFFFF)}")  # WAIT_FAILED
        return wt.DWORD(0xFFFFFFFF)

    # Check if handle is in known handles that cannot be waited on
    if hHandle.value in _file_handles or hHandle.value in _handle_map or hHandle.value in _search_handles:
        SetLastError(wt.DWORD(0))  # NO_ERROR
        ret(f"  {wt.DWORD(0)}")  # WAIT_OBJECT_0
        return wt.DWORD(0)

    # All other handles — stubbed as immediately signaled bcz we dont have real waitable objects yet TODO: implement for real waitable objects if needed !!!!!
    SetLastError(wt.DWORD(0))  # NO_ERROR
    ret(f"  {wt.DWORD(0)}")  # WAIT_OBJECT_0
    return wt.DWORD(0)