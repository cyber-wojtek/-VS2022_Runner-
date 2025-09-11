import ctypes as ct
import ctypes.wintypes as wt
from typing import TYPE_CHECKING
import threading as th
from enum import Enum as En, IntEnum as IntEn
import time as tm
import queue as q

HCRYPTPROV = wt.ULONG
if TYPE_CHECKING:
    PHCRYPTPROV = ct._Pointer[HCRYPTPROV]
else:
    PHCRYPTPROV = ct.POINTER(HCRYPTPROV)

class GUID(ct.Structure):
    _fields_ = [
        ("Data1", ct.c_ulong),
        ("Data2", ct.c_ushort),
        ("Data3", ct.c_ushort),
        ("Data4", ct.c_ubyte * 8)
    ]

    def __repr__(self) -> str:
        return f"{{{self.Data1:08X}-{self.Data2:04X}-{self.Data3:04X}-" + \
               f"{''.join(f'{b:02X}' for b in self.Data4[:2])}-" + \
               f"{''.join(f'{b:02X}' for b in self.Data4[2:])}}}"

UUID = GUID

if TYPE_CHECKING:
    PGUID = ct._Pointer[GUID]
    LPGUID = ct._Pointer[GUID]
    LPCGUID = ct._Pointer[GUID]
else:
    PGUID = ct.POINTER(GUID)
    LPGUID = ct.POINTER(GUID)
    LPCGUID = ct.POINTER(GUID)

HRESULT = wt.LONG

ENABLECALLBACK = ct.CFUNCTYPE(HRESULT, wt.DWORD, wt.LPVOID)
PENABLECALLNBACK = ct.POINTER(ENABLECALLBACK)

REGHANDLE = wt.ULONG
PREGHANDLE = ct.POINTER(REGHANDLE)

class EVENT_DESCRIPTOR(ct.Structure):
    _fields_ = [
        ("Id", wt.USHORT),
        ("Version", wt.BYTE),
        ("Channel", wt.BYTE),
        ("Level", wt.BYTE),
        ("Opcode", wt.BYTE),
        ("Task", wt.USHORT),
        ("Keyword", ct.c_ulonglong)
    ]

    def __repr__(self) -> str:
        return (f"EVENT_DESCRIPTOR(Id={self.Id}, Version={self.Version}, Channel={self.Channel}, "
                f"Level={self.Level}, Opcode={self.Opcode}, Task={self.Task}, Keyword=0x{self.Keyword:X})")

if TYPE_CHECKING:
    PEVENT_DESCRIPTOR = ct._Pointer[EVENT_DESCRIPTOR]
else:
    PEVENT_DESCRIPTOR = ct.POINTER(EVENT_DESCRIPTOR)

class EVENT_DATA_DESCRIPTOR_UNION_STRUCT(ct.Structure):
    _fields_ = [
        ("Type", wt.BYTE),
        ("Reserved", wt.BYTE),
        ("Reserved2", wt.USHORT)
    ]

    def __repr__(self) -> str:
        return f"EVENT_DATA_DESCRIPTOR_UNION_STRUCT(Type={self.Type}, Reserved={self.Reserved}, Reserved2={self.Reserved2})"

class EVENT_DATA_DESCRIPTOR_UNION(ct.Union):
    _fields_ = [
        ("Reserved", wt.ULONG),
        ("u", EVENT_DATA_DESCRIPTOR_UNION_STRUCT)
    ]

    _anonymous_ = ("u",)

    def __repr__(self) -> str:
        return f"EVENT_DATA_DESCRIPTOR_UNION(Reserved={self.Reserved}, u={self.u})"

class EVENT_DATA_DESCRIPTOR(ct.Structure):
    _fields_ = [
        ("Ptr", ct.c_ulonglong),
        ("Size", wt.ULONG),
        ("u", EVENT_DATA_DESCRIPTOR_UNION)
    ]

    _anonymous_ = ("u",)

    def __repr__(self) -> str:
        return f"EVENT_DATA_DESCRIPTOR(Ptr=0x{self.Ptr:X}, Size={self.Size}, u={self.u})"

if TYPE_CHECKING:
    PEVENT_DATA_DESCRIPTOR = ct._Pointer[EVENT_DATA_DESCRIPTOR]
else:
    PEVENT_DATA_DESCRIPTOR = ct.POINTER(EVENT_DATA_DESCRIPTOR)

LSTATUS = wt.LONG

HKEY = wt.ULONG
if TYPE_CHECKING:
    PHKEY = ct._Pointer[HKEY]
else:
    PHKEY = ct.POINTER(HKEY)
REGSAM = wt.DWORD

class WIN32_FIND_DATAW(ct.Structure):
    _fields_ = [
        ("dwFileAttributes", wt.DWORD),
        ("ftCreationTime", wt.FILETIME),
        ("ftLastAccessTime", wt.FILETIME),
        ("ftLastWriteTime", wt.FILETIME),
        ("nFileSizeHigh", wt.DWORD),
        ("nFileSizeLow", wt.DWORD),
        ("dwReserved0", wt.DWORD),
        ("dwReserved1", wt.DWORD),
        ("cFileName", wt.WCHAR * 260),  # MAX_PATH
        ("cAlternateFileName", wt.WCHAR * 14)
    ]

    def __repr__(self) -> str:
        return (f"WIN32_FIND_DATAW(dwFileAttributes=0x{self.dwFileAttributes:X}, "
                f"ftCreationTime=({self.ftCreationTime.dwLowDateTime}, {self.ftCreationTime.dwHighDateTime}), "
                f"ftLastAccessTime=({self.ftLastAccessTime.dwLowDateTime}, {self.ftLastAccessTime.dwHighDateTime}), "
                f"ftLastWriteTime=({self.ftLastWriteTime.dwLowDateTime}, {self.ftLastWriteTime.dwHighDateTime}), "
                f"nFileSizeHigh={self.nFileSizeHigh}, nFileSizeLow={self.nFileSizeLow}, "
                f"dwReserved0={self.dwReserved0}, dwReserved1={self.dwReserved1}, "
                f"cFileName='{self.cFileName}', cAlternateFileName='{self.cAlternateFileName}')")

if TYPE_CHECKING:
    PWIN32_FIND_DATAW = ct._Pointer[WIN32_FIND_DATAW]
else:
    PWIN32_FIND_DATAW = ct.POINTER(WIN32_FIND_DATAW)
LPWIN32_FIND_DATAW = PWIN32_FIND_DATAW

class CRITIAL_SECTION(ct.Structure):
    _fields_ = [
        ("DebugInfo", wt.LPVOID),
        ("LockCount", wt.LONG),
        ("RecursionCount", wt.LONG),
        ("OwningThread", wt.HANDLE),
        ("LockSemaphore", wt.HANDLE),
        ("SpinCount", ct.c_ulonglong)
    ]

    def __repr__(self) -> str:
        return (f"CRITICAL_SECTION(DebugInfo={self.DebugInfo}, LockCount={self.LockCount}, "
                f"RecursionCount={self.RecursionCount}, OwningThread={self.OwningThread}, "
                f"LockSemaphore={self.LockSemaphore}, SpinCount={self.SpinCount})")

if TYPE_CHECKING:
    PCRITICAL_SECTION = ct._Pointer[CRITIAL_SECTION]
else:
    PCRITICAL_SECTION = ct.POINTER(CRITIAL_SECTION)
LPCRITICAL_SECTION = PCRITICAL_SECTION

class SRWLock(ct.Structure):
    _fields_ = [
        ("Ptr", ct.c_ulonglong),
    ]

    def __repr__(self) -> str:
        return f"SRWLOCK(Ptr=0x{self.Ptr:X})"

class _SRWLockData:
    def __init__(self):
        self.lock = th.RLock()          # for exclusive
        self.readers = 0
        self.readers_cond = th.Condition(th.Lock())
        self.exclusive_locked = False

if TYPE_CHECKING:
    PSRWLOCK = ct._Pointer[SRWLock]
else:
    PSRWLOCK = ct.POINTER(SRWLock)

SIZE_T = ct.c_size_t

if TYPE_CHECKING:
    PSIZE_T = ct._Pointer[SIZE_T]
else:
    PSIZE_T = ct.POINTER(SIZE_T)

class HEAP_INFORMATION_CLASS(IntEn):
    HeapCompatibilityInformation = 0
    HeapEnableTerminationOnCorruption = 1
    HeapOptimizeResources = 3

class SYSTEMTIME(ct.Structure):
    _fields_ = [
        ("wYear", wt.WORD),
        ("wMonth", wt.WORD),
        ("wDayOfWeek", wt.WORD),
        ("wDay", wt.WORD),
        ("wHour", wt.WORD),
        ("wMinute", wt.WORD),
        ("wSecond", wt.WORD),
        ("wMilliseconds", wt.WORD)
    ]

    def __repr__(self) -> str:
        return (f"SYSTEMTIME(Year={self.wYear}, Month={self.wMonth}, DayOfWeek={self.wDayOfWeek}, "
                f"Day={self.wDay}, Hour={self.wHour}, Minute={self.wMinute}, "
                f"Second={self.wSecond}, Milliseconds={self.wMilliseconds})")

if TYPE_CHECKING:
    PSYSTEMTIME = ct._Pointer[SYSTEMTIME]
else:
    PSYSTEMTIME = ct.POINTER(SYSTEMTIME)
LPSYSTEMTIME = PSYSTEMTIME

GetFileExInfoStandard = 0
GetFileExMaxInfoLevel = 1

class WIN32_FILE_ATTRIBUTE_DATA(ct.Structure):
     _fields_ = [
         ("dwFileAttributes", wt.DWORD),
         ("ftCreationTime", wt.FILETIME),
         ("ftLastAccessTime", wt.FILETIME),
         ("ftLastWriteTime", wt.FILETIME),
         ("nFileSizeHigh", wt.DWORD),
         ("nFileSizeLow", wt.DWORD)
     ]

     def __repr__(self) -> str:
         return (f"WIN32_FILE_ATTRIBUTE_DATA(dwFileAttributes=0x{self.dwFileAttributes:X}, "
                 f"ftCreationTime=({self.ftCreationTime.dwLowDateTime}, {self.ftCreationTime.dwHighDateTime}), "
                 f"ftLastAccessTime=({self.ftLastAccessTime.dwLowDateTime}, {self.ftLastAccessTime.dwHighDateTime}), "
                 f"ftLastWriteTime=({self.ftLastWriteTime.dwLowDateTime}, {self.ftLastWriteTime.dwHighDateTime}), "
                 f"nFileSizeHigh={self.nFileSizeHigh}, nFileSizeLow={self.nFileSizeLow})")

if TYPE_CHECKING:
     PWIN32_FILE_ATTRIBUTE_DATA = ct._Pointer[WIN32_FILE_ATTRIBUTE_DATA]
else:
     PWIN32_FILE_ATTRIBUTE_DATA = ct.POINTER(WIN32_FILE_ATTRIBUTE_DATA)
LPWIN32_FILE_ATTRIBUTE_DATA = PWIN32_FILE_ATTRIBUTE_DATA

class GET_FILEEX_INFO_LEVELS(IntEn):
    GetFileExInfoStandard = 0
    GetFileExMaxInfoLevel = 1

class BY_HANDLE_FILE_INFORMATION(ct.Structure):
    _fields_ = [
         ("dwFileAttributes", wt.DWORD),
         ("ftCreationTime", wt.FILETIME),
         ("ftLastAccessTime", wt.FILETIME),
         ("ftLastWriteTime", wt.FILETIME),
         ("dwVolumeSerialNumber", wt.DWORD),
         ("nFileSizeHigh", wt.DWORD),
         ("nFileSizeLow", wt.DWORD),
         ("nNumberOfLinks", wt.DWORD),
         ("nFileIndexHigh", wt.DWORD),
         ("nFileIndexLow", wt.DWORD)
    ]

if TYPE_CHECKING:
    PBY_HANDLE_FILE_INFORMATION = ct._Pointer[BY_HANDLE_FILE_INFORMATION]
else:
    PBY_HANDLE_FILE_INFORMATION = ct.POINTER(BY_HANDLE_FILE_INFORMATION)
LPBY_HANDLE_FILE_INFORMATION = PBY_HANDLE_FILE_INFORMATION

class SECURITY_ATTRIBUTES(ct.Structure):
    _fields_ = [
        ("nLength", wt.DWORD),
        ("lpSecurityDescriptor", wt.LPVOID),
        ("bInheritHandle", wt.BOOL)
    ]

    def __repr__(self) -> str:
        return (f"SECURITY_ATTRIBUTES(nLength={self.nLength}, "
                f"lpSecurityDescriptor={self.lpSecurityDescriptor}, "
                f"bInheritHandle={self.bInheritHandle})")

if TYPE_CHECKING:
    PSECURITY_ATTRIBUTES = ct._Pointer[SECURITY_ATTRIBUTES]
else:
    PSECURITY_ATTRIBUTES = ct.POINTER(SECURITY_ATTRIBUTES)
LPSECURITY_ATTRIBUTES = PSECURITY_ATTRIBUTES

class STARTUPINFOW(ct.Structure):
    _fields_ = [
        ("cb", wt.DWORD),
        ("lpReserved", wt.LPWSTR),
        ("lpDesktop", wt.LPWSTR),
        ("lpTitle", wt.LPWSTR),
        ("dwX", wt.DWORD),
        ("dwY", wt.DWORD),
        ("dwXSize", wt.DWORD),
        ("dwYSize", wt.DWORD),
        ("dwXCountChars", wt.DWORD),
        ("dwYCountChars", wt.DWORD),
        ("dwFillAttribute", wt.DWORD),
        ("dwFlags", wt.DWORD),
        ("wShowWindow", wt.WORD),
        ("cbReserved2", wt.WORD),
        ("lpReserved2", ct.POINTER(ct.c_byte)),
        ("hStdInput", wt.HANDLE),
        ("hStdOutput", wt.HANDLE),
        ("hStdError", wt.HANDLE)
    ]

    def __repr__(self) -> str:
        return (f"STARTUPINFOW(cb={self.cb}, lpReserved={self.lpReserved}, lpDesktop={self.lpDesktop}, "
                f"lpTitle={self.lpTitle}, dwX={self.dwX}, dwY={self.dwY}, dwXSize={self.dwXSize}, "
                f"dwYSize={self.dwYSize}, dwXCountChars={self.dwXCountChars}, dwYCountChars={self.dwYCountChars}, "
                f"dwFillAttribute={self.dwFillAttribute}, dwFlags={self.dwFlags}, wShowWindow={self.wShowWindow}, "
                f"cbReserved2={self.cbReserved2}, lpReserved2={self.lpReserved2}, hStdInput={self.hStdInput}, "
                f"hStdOutput={self.hStdOutput}, hStdError={self.hStdError})")

if TYPE_CHECKING:
    PSTARTUPINFOW = ct._Pointer[STARTUPINFOW]
else:
    PSTARTUPINFOW = ct.POINTER(STARTUPINFOW)
LPSTARTUPINFOW = PSTARTUPINFOW

class FILETIME(ct.Structure):
    _fields_ = [
        ("dwLowDateTime", wt.DWORD),
        ("dwHighDateTime", wt.DWORD)
    ]

    def __repr__(self) -> str:
        return f"FILETIME(dwLowDateTime={self.dwLowDateTime}, dwHighDateTime={self.dwHighDateTime})"

if TYPE_CHECKING:
    PFILETIME = ct._Pointer[FILETIME]
else:
    PFILETIME = ct.POINTER(FILETIME)
LPFILETIME = PFILETIME

class _OVERLAPPED_UNION_STRUCT(ct.Structure):
    _fields_ = [
        ("Offset", wt.DWORD),
        ("OffsetHigh", wt.DWORD)
    ]

    def __repr__(self) -> str:
        return f"_OVERLAPPED_UNION_STRUCT(Offset={self.Offset}, OffsetHigh={self.OffsetHigh})"

class _OVERLAPPED_UNION(ct.Union):
    _fields_ = [
        ("Pointer", wt.LPVOID),
        ("s", _OVERLAPPED_UNION_STRUCT)
    ]

    _anonymous_ = ("s",)

    def __repr__(self) -> str:
        return f"_OVERLAPPED_UNION(Pointer={self.Pointer}, Offset={self.Offset}, OffsetHigh={self.OffsetHigh})"

class OVERLAPPED(ct.Structure):
    _fields_ = [
        ("Internal", ct.c_ulonglong),
        ("InternalHigh", ct.c_ulonglong),
        ("u", _OVERLAPPED_UNION),
        ("hEvent", wt.HANDLE)
    ]

    _anonymous_ = ("u",)

    def __repr__(self) -> str:
        return (f"OVERLAPPED(Internal={self.Internal}, InternalHigh={self.InternalHigh}, "
                f"Offset={self.Offset}, OffsetHigh={self.OffsetHigh}, hEvent={self.hEvent})")

if TYPE_CHECKING:
    LPOVERLAPPED = ct._Pointer[OVERLAPPED]
else:
    LPOVERLAPPED = ct.POINTER(OVERLAPPED)


class CRITICAL_SECTION(ct.Structure):
    """Opaque struct just for ctypes pointer passing"""
    _fields_ = [
        ("LockCount", wt.LONG),
        ("RecursionCount", wt.LONG),
        ("OwningThread", wt.HANDLE),
        ("LockSemaphore", wt.HANDLE),
        ("SpinCount", ct.c_ulonglong)
    ]

    def __repr__(self) -> str:
        return (f"CRITICAL_SECTION(LockCount={self.LockCount}, RecursionCount={self.RecursionCount}, "
                f"OwningThread={self.OwningThread}, LockSemaphore={self.LockSemaphore}, SpinCount={self.SpinCount})")

if TYPE_CHECKING:
    PCRITICAL_SECTION = ct._Pointer[CRITICAL_SECTION]
else:
    PCRITICAL_SECTION = ct.POINTER(CRITICAL_SECTION)
LPCRITICAL_SECTION = PCRITICAL_SECTION

ULONG_PTR = ct.c_ulonglong

class SYSTEM_INFO_UNION_STRUCT(ct.Structure):
    _fields_ = [
        ("wProcessorArchitecture", wt.WORD),
        ("wReserved", wt.WORD)
    ]

    def __repr__(self) -> str:
        return f"SYSTEM_INFO_UNION_STRUCT(wProcessorArchitecture={self.wProcessorArchitecture}, wReserved={self.wReserved})"

class SYSTEM_INFO_UNION(ct.Union):
    _fields_ = [
        ("dwOemId", wt.DWORD),
        ("s", SYSTEM_INFO_UNION_STRUCT)
    ]

    _anonymous_ = ("s",)

    def __repr__(self) -> str:
        return f"SYSTEM_INFO_UNION(dwOemId={self.dwOemId}, wProcessorArchitecture={self.wProcessorArchitecture}, wReserved={self.wReserved})"

class SYSTEM_INFO(ct.Structure):
    _fields_ = [
        ("u", SYSTEM_INFO_UNION),
        ("dwPageSize", wt.DWORD),
        ("lpMinimumApplicationAddress", wt.LPVOID),
        ("lpMaximumApplicationAddress", wt.LPVOID),
        ("dwActiveProcessorMask", ULONG_PTR),
        ("dwNumberOfProcessors", wt.DWORD),
        ("dwProcessorType", wt.DWORD),
        ("dwAllocationGranularity", wt.DWORD),
        ("wProcessorLevel", wt.WORD),
        ("wProcessorRevision", wt.WORD)
    ]

    _anonymous_ = ("u",)

    def __repr__(self) -> str:
        return (f"SYSTEM_INFO(dwOemId={self.dwOemId}, wProcessorArchitecture={self.wProcessorArchitecture}, "
                f"wReserved={self.wReserved}, dwPageSize={self.dwPageSize}, "
                f"lpMinimumApplicationAddress={self.lpMinimumApplicationAddress}, "
                f"lpMaximumApplicationAddress={self.lpMaximumApplicationAddress}, "
                f"dwActiveProcessorMask={self.dwActiveProcessorMask}, "
                f"dwNumberOfProcessors={self.dwNumberOfProcessors}, "
                f"dwProcessorType={self.dwProcessorType}, "
                f"dwAllocationGranularity={self.dwAllocationGranularity}, "
                f"wProcessorLevel={self.wProcessorLevel}, "
                f"wProcessorRevision={self.wProcessorRevision})")

if TYPE_CHECKING:
    LPSYSTEM_INFO = ct._Pointer[SYSTEM_INFO]
else:
    LPSYSTEM_INFO = ct.POINTER(SYSTEM_INFO)

FARPROC = wt.LPVOID

class MEMORY_BASIC_INFORMATION(ct.Structure):
    _fields_ = [
        ("BaseAddress",      wt.LPVOID),
        ("AllocationBase",   wt.LPVOID),
        ("AllocationProtect", wt.DWORD),
        ("RegionSize",       ct.c_size_t),
        ("State",            wt.DWORD),
        ("Protect",          wt.DWORD),
        ("Type",             wt.DWORD),
    ]

    def __repr__(self) -> str:
        return (f"MEMORY_BASIC_INFORMATION(BaseAddress={self.BaseAddress}, "
                f"AllocationBase={self.AllocationBase}, AllocationProtect=0x{self.AllocationProtect:X}, "
                f"RegionSize={self.RegionSize}, State=0x{self.State:X}, "
                f"Protect=0x{self.Protect:X}, Type=0x{self.Type:X})")

if TYPE_CHECKING:
    PMEMORY_BASIC_INFORMATION = ct._Pointer[MEMORY_BASIC_INFORMATION]
else:
    PMEMORY_BASIC_INFORMATION = ct.POINTER(MEMORY_BASIC_INFORMATION)
LPMEMORY_BASIC_INFORMATION = PMEMORY_BASIC_INFORMATION

class SECURITY_ATTRIBUTES(ct.Structure):
    _fields_ = [
        ("nLength", wt.DWORD),
        ("lpSecurityDescriptor", wt.LPVOID),
        ("bInheritHandle", wt.BOOL)
    ]

    def __repr__(self) -> str:
        return (f"SECURITY_ATTRIBUTES(nLength={self.nLength}, "
                f"lpSecurityDescriptor={self.lpSecurityDescriptor}, "
                f"bInheritHandle={self.bInheritHandle})")

if TYPE_CHECKING:
    PSECURITY_ATTRIBUTES = ct._Pointer[SECURITY_ATTRIBUTES]
else:
    PSECURITY_ATTRIBUTES = ct.POINTER(SECURITY_ATTRIBUTES)
LPSECURITY_ATTRIBUTES = PSECURITY_ATTRIBUTES

THREAD_START_ROUTINE = ct.CFUNCTYPE(wt.DWORD, wt.LPVOID)
if TYPE_CHECKING:
    PTHREAD_START_ROUTINE = ct._Pointer[THREAD_START_ROUTINE]
else:
    PTHREAD_START_ROUTINE = ct.POINTER(THREAD_START_ROUTINE)
LPTHREAD_START_ROUTINE = PTHREAD_START_ROUTINE

HANDLER_ROUTINE = ct.CFUNCTYPE(wt.BOOL, wt.DWORD)
if TYPE_CHECKING:
    PHANDLER_ROUTINE = ct._Pointer[HANDLER_ROUTINE]
else:
    PHANDLER_ROUTINE = ct.POINTER(HANDLER_ROUTINE)
LPHANDLER_ROUTINE = PHANDLER_ROUTINE

class CONTEXT(ct.Structure):
    _fields_ = [
        ("ContextFlags", wt.DWORD),
        ("Dr0", ct.c_ulonglong),
        ("Dr1", ct.c_ulonglong),
        ("Dr2", ct.c_ulonglong),
        ("Dr3", ct.c_ulonglong),
        ("Dr6", ct.c_ulonglong),
        ("Dr7", ct.c_ulonglong),
        ("Rax", ct.c_ulonglong),
        ("Rcx", ct.c_ulonglong),
        ("Rdx", ct.c_ulonglong),
        ("Rbx", ct.c_ulonglong),
        ("Rsp", ct.c_ulonglong),
        ("Rbp", ct.c_ulonglong),
        ("Rsi", ct.c_ulonglong),
        ("Rdi", ct.c_ulonglong),
        ("R8", ct.c_ulonglong),
        ("R9", ct.c_ulonglong),
        ("R10", ct.c_ulonglong),
        ("R11", ct.c_ulonglong),
        ("R12", ct.c_ulonglong),
        ("R13", ct.c_ulonglong),
        ("R14", ct.c_ulonglong),
        ("R15", ct.c_ulonglong),
        ("Rip", ct.c_ulonglong),
        # Skipping floating point and vector registers for brevity
    ]

    def __repr__(self) -> str:
        return (f"CONTEXT(ContextFlags=0x{self.ContextFlags:X}, Rax=0x{self.Rax:X}, Rcx=0x{self.Rcx:X}, "
                f"Rdx=0x{self.Rdx:X}, Rbx=0x{self.Rbx:X}, Rsp=0x{self.Rsp:X}, Rbp=0x{self.Rbp:X}, "
                f"Rsi=0x{self.Rsi:X}, Rdi=0x{self.Rdi:X}, R8=0x{self.R8:X}, R9=0x{self.R9:X}, "
                f"R10=0x{self.R10:X}, R11=0x{self.R11:X}, R12=0x{self.R12:X}, R13=0x{self.R13:X}, "
                f"R14=0x{self.R14:X}, R15=0x{self.R15:X}, Rip=0x{self.Rip:X})")
        
if TYPE_CHECKING:
    PCONTEXT = ct._Pointer[CONTEXT]
else:
    PCONTEXT = ct.POINTER(CONTEXT)
LPCONTEXT = PCONTEXT

DWORD64 = ct.c_ulonglong

if TYPE_CHECKING:
    PDWORD64 = ct._Pointer[DWORD64]
else:
    PDWORD64 = ct.POINTER(DWORD64)

EXCEPTION_ROUTINE = ct.CFUNCTYPE(
    wt.DWORD,  # Return type
    wt.LPVOID,  # Exception pointer
    wt.LPVOID   # Context pointer
)

if TYPE_CHECKING:
    PEXCEPTION_ROUTINE = ct._Pointer[EXCEPTION_ROUTINE]
else:
    PEXCEPTION_ROUTINE = ct.POINTER(EXCEPTION_ROUTINE)
LPPEXCEPTION_ROUTINE = PEXCEPTION_ROUTINE

class EXCEPTION_RECORD(ct.Structure):
    _fields_ = [
        ("ExceptionCode", wt.DWORD),
        ("ExceptionFlags", wt.DWORD),
        ("ExceptionRecord", ct.c_void_p),  # Pointer to another EXCEPTION_RECORD
        ("ExceptionAddress", wt.LPVOID),
        ("NumberParameters", wt.DWORD),
        ("ExceptionInformation", DWORD64 * 15)
    ]

    def __repr__(self) -> str:
        return (f"EXCEPTION_RECORD(ExceptionCode=0x{self.ExceptionCode:X}, ExceptionFlags=0x{self.ExceptionFlags:X}, "
                f"ExceptionRecord=0x{self.ExceptionRecord:X}, ExceptionAddress=0x{self.ExceptionAddress:X}, "
                f"NumberParameters={self.NumberParameters}, "
                f"ExceptionInformation={[self.ExceptionInformation[i] for i in range(self.NumberParameters)]})")

if TYPE_CHECKING:
    PEXCEPTION_RECORD = ct._Pointer[EXCEPTION_RECORD]
else:
    PEXCEPTION_RECORD = ct.POINTER(EXCEPTION_RECORD)

class EXCEPTION_POINTERS(ct.Structure):
    _fields_ = [
        ("ExceptionRecord", PEXCEPTION_RECORD),
        ("ContextRecord", PCONTEXT)
    ]

    def __repr__(self):
        return f"EXCEPTION_POINTERS(ExceptionRecord=0x{self.ExceptionRecord}, ContextRecord=0x{self.ContextRecord})"

if TYPE_CHECKING:
    PEXCEPTION_POINTERS = ct._Pointer[EXCEPTION_POINTERS]
else:
    PEXCEPTION_POINTERS = ct.POINTER(EXCEPTION_POINTERS)

DWORD_PTR = ct.c_ulonglong

TOP_LEVEL_EXCEPTION_FILTER = ct.CFUNCTYPE(
    wt.LONG,  # Return type
    PEXCEPTION_POINTERS  # Exception pointers
)
if TYPE_CHECKING:
    PEXCEPTION_FILTER = ct._Pointer[TOP_LEVEL_EXCEPTION_FILTER]
else:
    PEXCEPTION_FILTER = ct.POINTER(TOP_LEVEL_EXCEPTION_FILTER)
LPTOP_LEVEL_EXCEPTION_FILTER = PEXCEPTION_FILTER


class SLIST_ENTRY(ct.Structure):
    def __repr__(self) -> str:
        return f"SLIST_ENTRY(Next=0x{self.Next:X})"

if TYPE_CHECKING:
    PSLIST_ENTRY = ct._Pointer[SLIST_ENTRY]
else:
    PSLIST_ENTRY = ct.POINTER(SLIST_ENTRY)

SLIST_ENTRY._fields_ = [
    ("Next", PSLIST_ENTRY)
]

class SLIST_HEADER(ct.Structure):
    _fields_ = [
        ("Alignment", ct.c_ulonglong),
        ("Next", PSLIST_ENTRY)
    ]

    _pack_ = 8         # pack fields naturally
    _align_ = 16       # force 16-byte alignment

    def __repr__(self) -> str:
        return f"SLIST_HEADER(Alignment=0x{self.Alignment:X}, Next=0x{self.Next})"

if TYPE_CHECKING:
    PSLIST_HEADER = ct._Pointer[SLIST_HEADER]
else:
    PSLIST_HEADER = ct.POINTER(SLIST_HEADER)

ULONGLONG = ct.c_ulonglong
if TYPE_CHECKING:
    PULONGLONG = ct._Pointer[ULONGLONG]
else:
    PULONGLONG = ct.POINTER(ULONGLONG)