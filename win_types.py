import ctypes as ct
import ctypes.wintypes as wt
from typing import TYPE_CHECKING
import threading as th

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
        ("SpinCount", wt.ULONG_PTR)
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