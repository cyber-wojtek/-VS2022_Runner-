//
// Created by wojtek on 9/10/25.
//

#ifndef _VS2022_RUNNER__WIN_TYPES_H
#define _VS2022_RUNNER__WIN_TYPES_H

#include <cstddef>
#include <cstdint>
#include <type_traits>
#include <cstdlib>

using DWORD = unsigned long;
using HANDLE = void*;
using HMODULE = void*;
using LPVOID = void*;
using SIZE_T = size_t;
using BOOL = int;
using BYTE = unsigned char;
using WORD = unsigned short;
using WCHAR = wchar_t;
using LPWSTR = WCHAR*;
using LPCWSTR = const WCHAR*;
using CHAR = char;
using LPSTR = CHAR*;
using LPCSTR = const CHAR*;
using UINT = unsigned int;
using ULONG = unsigned int;
using ULONG_PTR = uintptr_t;
using LONG = int;
using LONGLONG = long long;
using ULONGLONG = unsigned long long;
using PVOID = void*;
using LPBYTE = BYTE*;
using LPWORD = WORD*;
using LPDWORD = DWORD*;
using SIZE_T = size_t;
using SSIZE_T = std::make_signed_t<SIZE_T>;
using DWORD_PTR = uintptr_t;
using PDWORD_PTR = DWORD_PTR*;
using HANDLE = void*;
using PHANDLE = HANDLE*;

using PHANDLER_ROUTINE = BOOL(*)(DWORD);
using LPTHREAD_START_ROUTINE = DWORD(*)(LPVOID);
using FARPROC = int(*)();
using TCHAR = WCHAR;
using LPTSTR = TCHAR*;
using LPCTSTR = const TCHAR*;

using DWORD64 = unsigned long long;
using DWORDLONG = unsigned long long;
using QWORD = unsigned long long;
using ULONGLONG = unsigned long long;
using LONGLONG = long long;

union LARGE_INTEGER {
    struct {
        DWORD LowPart;
        LONG HighPart;
    };
    LONGLONG QuadPart;
};

union ULARGE_INTEGER {
    struct {
        DWORD LowPart;
        DWORD HighPart;
    };
    ULONGLONG QuadPart;
};

using PULARGE_INTEGER = ULARGE_INTEGER*;
using PLARGE_INTEGER = LARGE_INTEGER*;
using PULONG_PTR = ULONG_PTR*;
using PULONG = ULONG*;
using PDWORD = DWORD*;
using PDWORD64 = DWORD64*;
using PDWORDLONG = DWORDLONG*;
using PQWORD = QWORD*;
using PULONG64 = ULONGLONG*;
using PSIZE_T = SIZE_T*;
using PSSIZE_T = SSIZE_T*;
using PDWORD_PTR = DWORD_PTR*;
using PHANDLE = HANDLE*;
using PVOID = void*;
using LPVOID = void*;
using PCHAR = char*;
using LPSTR = char*;

struct FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
};

using PFILETIME = FILETIME*;
using LPFILETIME = PFILETIME;

struct SYSTEMTIME {
    WORD wYear;
    WORD wMonth;
    WORD wDayOfWeek;
    WORD wDay;
    WORD wHour;
    WORD wMinute;
    WORD wSecond;
    WORD wMilliseconds;
};

using PSYSTEMTIME = SYSTEMTIME*;
using LPSYSTEMTIME = PSYSTEMTIME;

constexpr DWORD INFINITE = 0xFFFFFFFF;
constexpr DWORD WAIT_OBJECT_0 = 0x00000000;
constexpr DWORD WAIT_TIMEOUT = 0x00000102;
constexpr DWORD WAIT_FAILED = 0xFFFFFFFF;
constexpr DWORD WAIT_IO_COMPLETION = 0x000000C0;
constexpr DWORD WAIT_ABANDONED = 0x00000080;
constexpr DWORD MAXIMUM_WAIT_OBJECTS = 64;
constexpr DWORD ERROR_SUCCESS = 0;
constexpr DWORD ERROR_INVALID_HANDLE = 6;
constexpr DWORD ERROR_NOT_ENOUGH_MEMORY = 8;
constexpr DWORD ERROR_INVALID_PARAMETER = 87;
constexpr DWORD ERROR_NO_MORE_FILES = 18;
constexpr DWORD ERROR_ALREADY_EXISTS = 183;
constexpr DWORD ERROR_FILE_NOT_FOUND = 2;
constexpr DWORD ERROR_ACCESS_DENIED = 5;
constexpr DWORD ERROR_INVALID_ACCESS = 12;
constexpr DWORD ERROR_INVALID_DATA = 13;
constexpr DWORD ERROR_INVALID_FUNCTION = 1;
constexpr DWORD ERROR_NOT_SUPPORTED = 50;
constexpr DWORD ERROR_NOT_ENOUGH_QUOTA = 1816;
constexpr DWORD ERROR_INVALID_NAME = 123;
constexpr DWORD ERROR_BAD_PATHNAME = 161;
constexpr DWORD ERROR_BAD_NETPATH = 53;
constexpr DWORD ERROR_BAD_NET_NAME = 67;
constexpr DWORD ERROR_FILE_EXISTS = 80;
constexpr DWORD ERROR_INVALID_DRIVE = 15;
constexpr DWORD ERROR_CURRENT_DIRECTORY = 16;
constexpr DWORD ERROR_NOT_SAME_DEVICE = 17;
constexpr DWORD ERROR_NO_MORE_ITEMS = 259;
constexpr DWORD ERROR_MORE_DATA = 234;
constexpr DWORD ERROR_BAD_COMMAND = 220;
constexpr DWORD ERROR_BAD_LENGTH = 225;
constexpr DWORD ERROR_BAD_EXE_FORMAT = 193;
constexpr DWORD PAGE_NOACCESS = 0x01;
constexpr DWORD PAGE_READONLY = 0x02;
constexpr DWORD PAGE_READWRITE = 0x04;
constexpr DWORD PAGE_WRITECOPY = 0x08;
constexpr DWORD PAGE_EXECUTE = 0x10;
constexpr DWORD PAGE_EXECUTE_READ = 0x20;
constexpr DWORD PAGE_EXECUTE_READWRITE = 0x40;
constexpr DWORD PAGE_EXECUTE_WRITECOPY = 0x80;
constexpr DWORD PAGE_GUARD = 0x100;
constexpr DWORD PAGE_NOCACHE = 0x200;
constexpr DWORD PAGE_WRITECOMBINE = 0x400;
constexpr DWORD MEM_COMMIT = 0x1000;
constexpr DWORD MEM_RESERVE = 0x2000;
constexpr DWORD MEM_FREE = 0x10000;
constexpr DWORD MEM_PRIVATE = 0x20000;
constexpr DWORD MEM_MAPPED = 0x40000;
constexpr DWORD MEM_IMAGE = 0x1000000;
constexpr DWORD FILE_SHARE_READ = 0x00000001;
constexpr DWORD FILE_SHARE_WRITE = 0x00000002;
constexpr DWORD FILE_SHARE_DELETE = 0x00000004;
constexpr DWORD OPEN_EXISTING = 3;
constexpr DWORD CREATE_NEW = 1;
constexpr DWORD CREATE_ALWAYS = 2;
constexpr DWORD OPEN_ALWAYS = 4;
constexpr DWORD TRUNCATE_EXISTING = 5;
constexpr DWORD FILE_ATTRIBUTE_READONLY = 0x00000001;
constexpr DWORD FILE_ATTRIBUTE_HIDDEN = 0x00000002;
constexpr DWORD FILE_ATTRIBUTE_SYSTEM = 0x00000004;
constexpr DWORD FILE_ATTRIBUTE_DIRECTORY = 0x00000010;
constexpr DWORD FILE_ATTRIBUTE_ARCHIVE = 0x00000020;
constexpr DWORD FILE_ATTRIBUTE_NORMAL = 0x00000080;
constexpr DWORD FILE_ATTRIBUTE_TEMPORARY = 0x00000100;
constexpr DWORD FILE_ATTRIBUTE_OFFLINE = 0x00001000;
constexpr DWORD FILE_ATTRIBUTE_ENCRYPTED = 0x00004000;
constexpr DWORD FILE_ATTRIBUTE_VIRTUAL = 0x00010000;
constexpr DWORD FILE_BEGIN = 0;
constexpr DWORD FILE_CURRENT = 1;
constexpr DWORD FILE_END = 2;
constexpr DWORD STD_INPUT_HANDLE = (DWORD)-10;
constexpr DWORD STD_OUTPUT_HANDLE = (DWORD)-11;
constexpr DWORD STD_ERROR_HANDLE = (DWORD)-12;
constexpr DWORD CTRL_C_EVENT = 0;
constexpr DWORD CTRL_BREAK_EVENT = 1;
constexpr DWORD CTRL_CLOSE_EVENT = 2;
constexpr DWORD CTRL_LOGOFF_EVENT = 5;
constexpr DWORD CTRL_SHUTDOWN_EVENT = 6;
constexpr size_t MAX_PATH = 260;
constexpr BOOL TRUE = 1;
constexpr BOOL FALSE = 0;

struct SECURITY_DESCRIPTOR {
    BYTE Revision;
    BYTE Sbz1;
    WORD Control;
    PVOID Owner;
    PVOID Group;
    PVOID Sacl;
    PVOID Dacl;
};

using PSECURITY_DESCRIPTOR = SECURITY_DESCRIPTOR*;
using LPSECURITY_DESCRIPTOR = PSECURITY_DESCRIPTOR;

struct SECURITY_ATTRIBUTES {
    DWORD nLength;
    LPSECURITY_DESCRIPTOR lpSecurityDescriptor;
    BOOL bInheritHandle;
};

using PSECURITY_ATTRIBUTES = SECURITY_ATTRIBUTES*;
using LPSECURITY_ATTRIBUTES = PSECURITY_ATTRIBUTES;

struct OVERLAPPED {
    DWORD Internal;
    DWORD InternalHigh;
    union {
        struct {
            DWORD Offset;
            DWORD OffsetHigh;
        };
        PVOID Pointer;
    };
    HANDLE hEvent;
};

using LPOVERLAPPED = OVERLAPPED*;

#if /* x86 */ defined(_M_IX86)
#define STDCALL __stdcall
#define CALLBACK __stdcall
#else
#define WINAPI
#define CALLBACK
#endif

using LPCVOID = const void*;

inline const auto INVALID_HANDLE_VALUE = reinterpret_cast<HANDLE>(-1);

using PAPC_FUNC = void(*)(ULONG_PTR);

constexpr DWORD INVALID_FILE_SIZE = 0xFFFFFFFF;

struct WIN32_FIND_DATAW {
    DWORD dwFileAttributes;
    FILETIME ftCreationTime;
    FILETIME ftLastAccessTime;
    FILETIME ftLastWriteTime;
    DWORD nFileSizeHigh;
    DWORD nFileSizeLow;
    DWORD dwReserved0;
    DWORD dwReserved1;
    WCHAR cFileName[MAX_PATH];
    WCHAR cAlternateFileName[14];
};

using PWIN32_FIND_DATAW = WIN32_FIND_DATAW*;
using LPWIN32_FIND_DATAW = PWIN32_FIND_DATAW;

constexpr DWORD CP_UTF8 = 65001;

using INT = int;
using UINT = unsigned int;
using ULONG_PTR = uintptr_t;
using LONGLONG = long long;
using ULONGLONG = unsigned long long;
using PVOID = void*;
using LPVOID = void*;
using PCHAR = char*;

constexpr DWORD ERROR_DIRECTORY = 267;
constexpr DWORD ERROR_PATH_NOT_FOUND = 3;

constexpr DWORD FIND_FIRST_EX_CASE_SENSITIVE = 0x00000001;
constexpr DWORD FIND_FIRST_EX_LARGE_FETCH = 0x00000002;


// Find function enums
enum FINDEX_INFO_LEVELS {
    FindExInfoStandard,
    FindExInfoBasic,
    FindExInfoMaxInfoLevel
};

enum FINDEX_SEARCH_OPS {
    FindExSearchNameMatch,
    FindExSearchLimitToDirectories,
    FindExSearchLimitToDevices,
    FindExSearchMaxSearchOp
};

using PAPCFUNC = void(*)(ULONG_PTR);

using PLONG = int*;
using LPBOOL = BOOL*;

constexpr DWORD ERROR_INSUFFICIENT_BUFFER = 122;
constexpr DWORD ERROR_MOD_NOT_FOUND = 126;
constexpr DWORD ERROR_PROC_NOT_FOUND = 127;
constexpr DWORD ERROR_DLL_INIT_FAILED = 1114;
constexpr DWORD ERROR_INVALID_ORDINAL = 182;
constexpr DWORD ERROR_NOACCESS = 998;
constexpr DWORD ERROR_PARTIAL_COPY = 299;
constexpr DWORD ERROR_INVALID_BLOCK = 9;
constexpr DWORD ERROR_NOT_LOCKED = 158;
constexpr DWORD ERROR_LOCK_VIOLATION = 33;
constexpr DWORD ERROR_ALREADY_LOCKED = 193;
constexpr DWORD ERROR_LOCK_FAILED = 167;
constexpr DWORD ERROR_FILE_INVALID = 1006;
constexpr DWORD ERROR_NEGATIVE_SEEK = 131;
constexpr DWORD ERROR_SEEK_ON_DEVICE = 132;
constexpr DWORD ERROR_NOT_DOS_DISK = 26;
constexpr DWORD ERROR_SECTOR_NOT_FOUND = 27;
constexpr DWORD ERROR_WRITE_PROTECT = 19;
constexpr DWORD ERROR_READ_FAULT = 30;
constexpr DWORD ERROR_WRITE_FAULT = 29;
constexpr DWORD ERROR_GEN_FAILURE = 31;
constexpr DWORD ERROR_SHARING_VIOLATION = 32;
constexpr DWORD ERROR_HANDLE_EOF = 38;
constexpr DWORD ERROR_HANDLE_DISK_FULL = 39;
constexpr DWORD ERROR_REM_NOT_LIST = 51;
constexpr DWORD ERROR_DUP_NAME = 52;
constexpr DWORD ERROR_NETWORK_BUSY = 54;
constexpr DWORD ERROR_DEV_NOT_EXIST = 55;
constexpr DWORD ERROR_TOO_MANY_CMDS = 56;
constexpr DWORD ERROR_ADAP_HDW_ERR = 57;
constexpr DWORD ERROR_BAD_NET_RESP = 58;
constexpr DWORD ERROR_UNEXP_NET_ERR = 59;
constexpr DWORD ERROR_BAD_REM_ADAP = 60;
constexpr DWORD ERROR_PRINTQ_FULL = 61;
constexpr DWORD ERROR_NO_SPOOL_SPACE = 62;
constexpr DWORD ERROR_PRINT_CANCELLED = 63;
constexpr DWORD ERROR_NETNAME_DELETED = 64;
constexpr DWORD ERROR_NETWORK_ACCESS_DENIED = 65;
constexpr DWORD ERROR_BAD_DEV_TYPE = 66;
constexpr DWORD ERROR_TOO_MANY_NAMES = 68;
constexpr DWORD ERROR_TOO_MANY_SESS = 69;
constexpr DWORD ERROR_SHARING_PAUSED = 70;
constexpr DWORD ERROR_REQ_NOT_ACCEP = 71;
constexpr DWORD ERROR_REDIR_PAUSED = 72;
constexpr DWORD ERROR_CANNOT_MAKE = 82;
constexpr DWORD ERROR_FAIL_I24 = 83;
constexpr DWORD ERROR_OUT_OF_PAPER = 83;

using CCH = char;
using LPCCH = const char*;
using WCH = wchar_t;
using LPWCH = WCH*;
using LPCWCH = const LPWCH;

using UCH = unsigned char;
using PUCH = UCH*;

using BYTE = unsigned char;
using PBYTE = BYTE*;

#define DLL_PROCESS_ATTACH 1
#define DLL_PROCESS_DETACH 0

constexpr DWORD ERROR_ENVVAR_NOT_FOUND = 203;
constexpr DWORD ERROR_FILENAME_EXCED_RANGE = 206;
constexpr DWORD ERROR_NO_UNICODE_TRANSLATION = 1113;
constexpr DWORD ERROR_UNIDENTIFIED_ERROR = 0xE0000000;
constexpr DWORD ERROR_INVALID_TIME = 1901;
constexpr DWORD ERROR_INVALID_FORM_NAME = 1902;
constexpr DWORD ERROR_INVALID_FORM_SIZE = 1903;
constexpr DWORD ERROR_ALREADY_WAITING = 1904;
constexpr DWORD ERROR_PRINTER_DELETED = 1905;
constexpr DWORD ERROR_INVALID_PRINTER_STATE = 1906;
constexpr DWORD ERROR_PASSWORD_MUST_CHANGE = 1907;
constexpr DWORD ERROR_DOMAIN_CONTROLLER_NOT_FOUND = 1908;
constexpr DWORD ERROR_ACCOUNT_LOCKED_OUT = 1909;
constexpr DWORD ERROR_NO_SITENAME = 1910;
constexpr DWORD ERROR_CANT_ACCESS_FILE = 1920;
constexpr DWORD ERROR_CANT_RESOLVE_FILENAME = 1921;
constexpr DWORD ERROR_KM_DRIVER_BLOCKED = 1930;
constexpr DWORD ERROR_CONTEXT_EXPIRED = 1931;
constexpr DWORD ERROR_PER_USER_TRUST_QUOTA_EXCEEDED = 1932;

class SYSTEM_INFO {
public:
    union {
        DWORD dwOemId; // Obsolete field
        struct {
            WORD wProcessorArchitecture;
            WORD wReserved;
        };
    };
    DWORD dwPageSize;
    LPVOID lpMinimumApplicationAddress;
    LPVOID lpMaximumApplicationAddress;
    DWORD_PTR dwActiveProcessorMask;
    DWORD dwNumberOfProcessors;
    DWORD dwProcessorType;
    DWORD dwAllocationGranularity;
    WORD wProcessorLevel;
    WORD wProcessorRevision;
};

using LPSYSTEM_INFO = SYSTEM_INFO*;

constexpr DWORD ERROR_INVALID_ADDRESS = 487;

constexpr DWORD MEM_DECOMMIT = 0x4000;
constexpr DWORD MEM_RELEASE = 0x8000;

class MEMORY_BASIC_INFORMATION {
public:
    PVOID BaseAddress;
    PVOID AllocationBase;
    DWORD AllocationProtect;
    SIZE_T RegionSize;
    DWORD State;
    DWORD Protect;
    DWORD Type;
};

using PMEMORY_BASIC_INFORMATION = MEMORY_BASIC_INFORMATION*;
using LPMEMORY_BASIC_INFORMATION = PMEMORY_BASIC_INFORMATION;

constexpr DWORD MEMORY_ALLOCATION_ALIGNMENT = 0x10000;
constexpr DWORD PAGE_REVERT_TO_FILE_MAP = 0x80000000;
constexpr DWORD PAGE_TARGETS_NO_UPDATE = 0x40000000;
constexpr DWORD PAGE_ENCLAVE_THREAD_CONTROL = 0x80000000;
constexpr DWORD PAGE_ENCLAVE_UNVALIDATED = 0x20000000;
constexpr DWORD PAGE_ENCLAVE_DECOMMIT = 0x10000000;
constexpr DWORD SEC_FILE = 0x800000;
constexpr DWORD SEC_IMAGE = 0x1000000;
constexpr DWORD SEC_RESERVE = 0x4000000;
constexpr DWORD SEC_COMMIT = 0x8000000;
constexpr DWORD SEC_COMMIT_ZEROED = 0x20000000;
constexpr DWORD SEC_NOCACHE = 0x10000000;
constexpr DWORD SEC_WRITECOMBINE = 0x40000000;
constexpr DWORD SEC_LARGE_PAGES = 0x80000000;
constexpr DWORD SEC_IMAGE_NO_EXECUTE = 0x11000000;

using LPLONG = LONG*;

constexpr DWORD STILL_ACTIVE = 259;

using PHANDLER_ROUTINE = BOOL(*)(DWORD);

class FLOATING_SAVE_AREA {
public:
    DWORD ControlWord;
    DWORD StatusWord;
    DWORD TagWord;
    DWORD ErrorOffset;
    DWORD ErrorSelector;
    DWORD DataOffset;
    DWORD DataSelector;
    BYTE RegisterArea[80];
    DWORD Cr0NpxState;
};

class CONTEXT {
public:
    DWORD ContextFlags;
    DWORD Dr0;
    DWORD Dr1;
    DWORD Dr2;
    DWORD Dr3;
    DWORD Dr6;
    DWORD Dr7;
    FLOATING_SAVE_AREA FloatSave;
    DWORD SegGs;
    DWORD SegFs;
    DWORD SegEs;
    DWORD SegDs;
    DWORD Edi;
    DWORD Esi;
    DWORD Ebx;
    DWORD Edx;
    DWORD Ecx;
    DWORD Eax;
    DWORD Ebp;
    DWORD Eip;
    DWORD SegCs;
    DWORD EFlags;
    DWORD Esp;
    DWORD SegSs;
    BYTE ExtendedRegisters[512];
};

using PCONTEXT = CONTEXT*;
using LPCONTEXT = CONTEXT*;

constexpr DWORD CONTEXT_ALL = 0xFFFFFFFF;
constexpr DWORD CONTEXT_DEBUG = 0x00000002;
constexpr DWORD CONTEXT_FULL = 0x00010007;
constexpr DWORD CONTEXT_i386 = 0x00010000;
constexpr DWORD CONTEXT_CONTROL = CONTEXT_i386 | 0x00000001;
constexpr DWORD CONTEXT_INTEGER = CONTEXT_i386 | 0x00000002;
constexpr DWORD CONTEXT_SEGMENTS = CONTEXT_i386 | 0x00000004;
constexpr DWORD CONTEXT_FLOATING_POINT = CONTEXT_i386 | 0x00000008;
constexpr DWORD CONTEXT_EXTENDED_REGISTERS = CONTEXT_i386 | 0x00000020;
constexpr DWORD CONTEXT_XSTATE = CONTEXT_i386 | 0x00000040;

class EXCEPTION_RECORD {
public:
    DWORD ExceptionCode;
    DWORD ExceptionFlags;
    EXCEPTION_RECORD* ExceptionRecord;
    PVOID ExceptionAddress;
    DWORD NumberParameters;
    ULONG_PTR ExceptionInformation[15];
};

using PEXCEPTION_RECORD = EXCEPTION_RECORD*;
using LPEXCEPTION_RECORD = PEXCEPTION_RECORD*;

using PRUNTIME_FUNCTION = void*;
using PEXCEPTION_ROUTINE = DWORD(*)(PEXCEPTION_RECORD, PVOID, PCONTEXT, PVOID);

constexpr DWORD EXCEPTION_CONTINUE_EXECUTION = 0x0;
constexpr DWORD EXCEPTION_CONTINUE_SEARCH = 0x1;
constexpr DWORD EXCEPTION_NT_CONTINUE = 0x2;

using LPTOP_LEVEL_EXCEPTION_FILTER = DWORD(*)(PEXCEPTION_RECORD);

constexpr DWORD EXCEPTION_MAXIMUM_PARAMETERS = 15;

class EXCEPTION_POINTERS {
public:
    PEXCEPTION_RECORD ExceptionRecord;
    PCONTEXT ContextRecord;
};

constexpr DWORD HEAP_NO_SERIALIZE = 0x00000001;
constexpr DWORD HEAP_GENERATE_EXCEPTIONS = 0x00000004;
constexpr DWORD HEAP_ZERO_MEMORY = 0x00000008;
constexpr DWORD HEAP_REALLOC_IN_PLACE_ONLY = 0x00000010;
constexpr DWORD HEAP_TAIL_CHECKING_ENABLED = 0x00000020;
constexpr DWORD HEAP_FREE_CHECKING_ENABLED = 0x00000040;
constexpr DWORD HEAP_DISABLE_COALESCE_ON_FREE = 0x00000080;
constexpr DWORD HEAP_CREATE_ENABLE_EXECUTE = 0x00040000;
constexpr DWORD HEAP_CREATE_ENABLE_TRACING = 0x00080000;
constexpr DWORD HEAP_CREATE_SEGMENT_HEAP = 0x00100000;
constexpr DWORD HEAP_CREATE_HARDENED = 0x00200000;
constexpr DWORD HEAP_CREATE_ALIGN_16 = 0x00400000;
constexpr DWORD HEAP_CREATE_ENABLE_HOOKS = 0x00800000;
constexpr DWORD HEAP_CREATE_ENABLE_HARDENED_FLAGS = 0x01000000;
constexpr DWORD HEAP_CREATE_PROTECTED_HEAP = 0x02000000;
constexpr DWORD HEAP_CREATE_USE_EXECUTE_WRITECOPY = 0x04000000;
constexpr DWORD HEAP_CREATE_USE_ALLOCA = 0x08000000;
constexpr DWORD HEAP_CREATE_LEAK_DETECTION = 0x10000000;
constexpr DWORD HEAP_CREATE_TAG_MASK = 0xFFFF0000;
constexpr DWORD HEAP_TAG_SHIFT = 16;
constexpr DWORD HEAP_VALIDATE_PARAMETERS = 0x00000001;
constexpr DWORD HEAP_VALIDATE_ALL = 0x00000002;
constexpr DWORD HEAP_VALIDATE_RESERVE = 0x00000004;
constexpr DWORD HEAP_VALIDATE_EXECUTE = 0x00000008;
constexpr DWORD HEAP_VALIDATE_ALL_FLAGS = 0x0000000F;

class STARTUPINFOW {
public:
    DWORD cb;
    LPWSTR lpReserved;
    LPWSTR lpDesktop;
    LPWSTR lpTitle;
    DWORD dwX;
    DWORD dwY;
    DWORD dwXSize;
    DWORD dwYSize;
    DWORD dwXCountChars;
    DWORD dwYCountChars;
    DWORD dwFillAttribute;
    DWORD dwFlags;
    WORD wShowWindow;
    WORD cbReserved2;
    LPBYTE lpReserved2;
    HANDLE hStdInput;
    HANDLE hStdOutput;
    HANDLE hStdError;
};

using LPSTARTUPINFOW = STARTUPINFOW*;
using PSTARTUPINFOW = LPSTARTUPINFOW;

class SLIST_ENTRY {
public:
    SLIST_ENTRY* Next;
};

#endif //_VS2022_RUNNER__WIN_TYPES_H