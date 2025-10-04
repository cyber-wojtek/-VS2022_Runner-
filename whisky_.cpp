//
// Created by wojtek on 10/3/25.
//
#include <LIEF/PE.hpp>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <unistd.h>
#include <cstdio>
#include <cerrno>
#include <cstdlib>
#include <csignal>
#include <cstring>
#include <iostream>
#include <iomanip>
#include <filesystem>
#include <utility>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <cstdint>
#include <algorithm>
#include "log.h"
#include <random>
#include <codecvt>
#include <list>
#include <queue>
#include <chrono>
#include <thread>
#include <atomic>
#include <shared_mutex>
#include <fstream>
#include <mutex>
#include <optional>

#include <linux/hdreg.h>
#include <linux/cdrom.h>
#include <scsi/sg.h>
#include <condition_variable>
#define USE_WS_PREFIX
#include <nlohmann/json.hpp>
#include <future>


#include "winternl.h"
#include "winioctl.h"
#include "ws2def.h"
#include "ntstatus.h"
#include "ntddcdrm.h"
#include "ntddstor.h"
#include "afd.h"
#include "winbase.h"
#include "winreg.h"

#include <fcntl.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <netdb.h>
#include <execinfo.h>
#include <ucontext.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <asm/prctl.h>
#include <sys/shm.h>
#include <sys/ipc.h>
#include <sys/stat.h>
#include <capstone/capstone.h>
#include <sys/stat.h>
#include <sched.h>
#include <pthread.h>
#include <dirent.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/sysinfo.h>
#include <spawn.h>
#include <sys/eventfd.h>
#include <sys/signalfd.h>
#include <sys/timerfd.h>

#define KUSER_SHARED_DATA_ADDRESS 0x7FFE0000
#define KUSER_SHARED_DATA_SIZE 0x1000

// The ONE. True. Converter.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
std::wstring_convert<std::codecvt_utf8<char16_t>, char16_t> converter16;
#pragma GCC diagnostic pop

struct TLS {
    HANDLE thread{};
    HANDLE process{};
    std::vector<LPVOID> tls_data;
    DWORD last_error{0};
};

// Missing type definitions for AFD
namespace w32 {
    struct afd_poll_info {
        ULONG_PTR socket;
        ULONG flags;
        NTSTATUS status;
    };
}

struct poll_req {
    ULONG_PTR socket;
    ULONG flags;
    NTSTATUS status;
};

// Type definitions
typedef struct _KSYSTEM_TIME {
    ULONG LowPart;
    LONG High1Time;
    LONG High2Time;
} KSYSTEM_TIME, *PKSYSTEM_TIME;

typedef enum _NT_PRODUCT_TYPE {
    _NtProductWin_Nt = 1,
    _NtProductLanMan_Nt,
    _NtProductServer
} NT_PRODUCT_TYPE, *PNT_PRODUCT_TYPE;

typedef enum _ALTERNATIVE_ARCHITECTURE_TYPE {
    StandardDesign = 0,
    NEC98x86,
    EndAlternatives
} ALTERNATIVE_ARCHITECTURE_TYPE, *PALTERNATIVE_ARCHITECTURE_TYPE;

typedef struct _KUSER_SHARED_DATA {
    ULONG TickCountLowDeprecated;
    ULONG TickCountMultiplier;
    KSYSTEM_TIME InterruptTime;
    KSYSTEM_TIME SystemTime;
    KSYSTEM_TIME TimeZoneBias;
    USHORT ImageNumberLow;
    USHORT ImageNumberHigh;
    WCHAR _NtSystemRoot[260];
    ULONG MaxStackTraceDepth;
    ULONG CryptoExponent;
    ULONG TimeZoneId;
    ULONG LargePageMinimum;
    ULONG AitSamplingValue;
    ULONG AppCompatFlag;
    ULONGLONG RNGSeedVersion;
    ULONG GlobalValidationRunlevel;
    LONG TimeZoneBiasStamp;
    ULONG _NtBuildNumber;
    NT_PRODUCT_TYPE _NtProductType;
    BOOLEAN ProductTypeIsValid;
    BOOLEAN Reserved0[1];
    USHORT NativeProcessorArchitecture;
    ULONG _NtMajorVersion;
    ULONG _NtMinorVersion;
    BOOLEAN ProcessorFeatures[64];
    ULONG Reserved1;
    ULONG Reserved3;
    ULONG TimeSlip;
    ALTERNATIVE_ARCHITECTURE_TYPE AlternativeArchitecture;
    ULONG BootId;
    LARGE_INTEGER SystemExpirationDate;
    ULONG SuiteMask;
    BOOLEAN KdDebuggerEnabled;
    union {
        UCHAR MitigationPolicies;
        struct {
            UCHAR NXSupportPolicy : 2;
            UCHAR SEHValidationPolicy : 2;
            UCHAR CurDirDevicesSkippedForDlls : 2;
            UCHAR Reserved : 2;
        };
    };
    USHORT CyclesPerYield;
    ULONG ActiveConsoleId;
    ULONG DismountCount;
    ULONG ComPlusPackage;
    ULONG LastSystemRITEventTickCount;
    ULONG NumberOfPhysicalPages;
    BOOLEAN SafeBootMode;
    union {
        UCHAR VirtualizationFlags;
        struct {
            UCHAR ArchStartedInEl2 : 1;
            UCHAR QcSlIsSupported : 1;
        };
    };
    UCHAR Reserved12[2];
    union {
        ULONG SharedDataFlags;
        struct {
            ULONG DbgErrorPortPresent : 1;
            ULONG DbgElevationEnabled : 1;
            ULONG DbgVirtEnabled : 1;
            ULONG DbgInstallerDetectEnabled : 1;
            ULONG DbgLkgEnabled : 1;
            ULONG DbgDynProcessorEnabled : 1;
            ULONG DbgConsoleBrokerEnabled : 1;
            ULONG DbgSecureBootEnabled : 1;
            ULONG DbgMultiSessionSku : 1;
            ULONG DbgMultiUsersInSessionSku : 1;
            ULONG DbgStateSeparationEnabled : 1;
            ULONG SpareBits : 21;
        } DUMMYSTRUCTNAME2;
    } DUMMYUNIONNAME2;
    ULONG DataFlagsPad[1];
    ULONGLONG TestRetInstruction;
    LONGLONG QpcFrequency;
    ULONG SystemCall;
    ULONG Reserved2;
    ULONGLONG FullNumberOfPhysicalPages;
    ULONGLONG SystemCallPad[1];
    union {
        KSYSTEM_TIME TickCount;
        ULONG64 TickCountQuad;
        struct {
            ULONG ReservedTickCountOverlay[3];
            ULONG TickCountPad[1];
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME3;
    ULONG Cookie;
    ULONG CookiePad[1];
    LONGLONG ConsoleSessionForegroundProcessId;
    ULONGLONG TimeUpdateLock;
    ULONGLONG BaselineSystemTimeQpc;
    ULONGLONG BaselineInterruptTimeQpc;
    ULONGLONG QpcSystemTimeIncrement;
    ULONGLONG QpcInterruptTimeIncrement;
    UCHAR QpcSystemTimeIncrementShift;
    UCHAR QpcInterruptTimeIncrementShift;
    USHORT UnparkedProcessorCount;
    ULONG EnclaveFeatureMask[4];
    ULONG TelemetryCoverageRound;
    USHORT UserModeGlobalLogger[16];
    ULONG ImageFileExecutionOptions;
    ULONG LangGenerationCount;
    ULONGLONG Reserved4;
    ULONGLONG InterruptTimeBias;
    ULONGLONG QpcBias;
    ULONG ActiveProcessorCount;
    UCHAR ActiveGroupCount;
    UCHAR Reserved9;
    union {
        USHORT QpcData;
        struct {
            UCHAR QpcBypassEnabled;
            UCHAR QpcReserved;
        };
    };
    LARGE_INTEGER TimeZoneBiasEffectiveStart;
    LARGE_INTEGER TimeZoneBiasEffectiveEnd;
    XSTATE_CONFIGURATION XState;
    KSYSTEM_TIME FeatureConfigurationChangeStamp;
    ULONG Spare;
    ULONG64 UserPointerAuthMask;
    XSTATE_CONFIGURATION XStateArm64;
    ULONG Reserved10[210];
} KUSER_SHARED_DATA, *PKUSER_SHARED_DATA;

typedef struct _FIBER                                    /* Field offsets:    */
{                                                        /* i386  arm   x64   */
    PVOID FiberData;                                     /* 0x000 0x000 0x000 */
    _EXCEPTION_REGISTRATION_RECORD *ExceptionList;/* 0x004 0x004 0x008 */
    PVOID StackBase;                                     /* 0x008 0x008 0x010 */
    PVOID StackLimit;                                    /* 0x00C 0x00C 0x018 */
    PVOID DeallocationStack;                             /* 0x010 0x010 0x020 */
    CONTEXT FiberContext;                                /* 0x014 0x018 0x030 */
    PVOID Wx86Tib;                                       /* 0x2E0 0x1b8 0x500 */
    _ACTIVATION_CONTEXT_STACK *ActivationContextStackPointer; /* 0x2E4 0x1bc 0x508 */
    PVOID FlsData;                                       /* 0x2E8 0x1c0 0x510 */
    ULONG GuaranteedStackBytes;                          /* 0x2EC 0x1c4 0x518 */
    ULONG TebFlags;                                      /* 0x2F0 0x1c8 0x51C */
} FIBER, *PFIBER;

// KEEP: Thread-local variables
static thread_local TLS g_tls;
static thread_local TEB* g_current_teb = nullptr;
static thread_local PEB* g_current_peb = nullptr;
static KUSER_SHARED_DATA* g_kuser_shared_data = nullptr;
static std::shared_mutex g_kuser_update_mutex;

static NTSTATUS errno_to_ntstatus(int err) {
    switch (err) {
        case EAGAIN: return STATUS_SHARING_VIOLATION;
        case EBADF: return STATUS_INVALID_HANDLE;
        case EBUSY: return STATUS_DEVICE_BUSY;
        case ENOSPC: return STATUS_DISK_FULL;
        case EPERM: case EROFS: case EACCES: return STATUS_ACCESS_DENIED;
        case ENOTDIR: return STATUS_OBJECT_PATH_NOT_FOUND;
        case ENOENT: return STATUS_OBJECT_NAME_NOT_FOUND;
        case EISDIR: return STATUS_INVALID_DEVICE_REQUEST;
        case EMFILE: case ENFILE: return STATUS_TOO_MANY_OPENED_FILES;
        case EINVAL: return STATUS_INVALID_PARAMETER;
        case ENOTEMPTY: return STATUS_DIRECTORY_NOT_EMPTY;
        case EPIPE: return STATUS_PIPE_DISCONNECTED;
        case EIO: return STATUS_DEVICE_NOT_READY;
        case ENXIO: return STATUS_NO_SUCH_DEVICE;
        case ENOTTY: case EOPNOTSUPP: return STATUS_NOT_SUPPORTED;
        case ECONNRESET: return STATUS_PIPE_DISCONNECTED;
        case EFAULT: return STATUS_ACCESS_VIOLATION;
        case ESPIPE: return STATUS_ILLEGAL_FUNCTION;
        case ELOOP: return STATUS_REPARSE_POINT_NOT_RESOLVED;
        case EEXIST: return STATUS_OBJECT_NAME_COLLISION;
        default: return STATUS_UNSUCCESSFUL;
    }
}

static int ntstatus_to_errno(NTSTATUS status) {
    switch (status) {
        case STATUS_SHARING_VIOLATION: return EAGAIN;
        case STATUS_INVALID_HANDLE: return EBADF;
        case STATUS_DEVICE_BUSY: return EBUSY;
        case STATUS_DISK_FULL: return ENOSPC;
        case STATUS_ACCESS_DENIED: return EACCES;
        case STATUS_OBJECT_PATH_NOT_FOUND: return ENOTDIR;
        case STATUS_OBJECT_NAME_NOT_FOUND: return ENOENT;
        case STATUS_INVALID_DEVICE_REQUEST: return EISDIR;
        case STATUS_TOO_MANY_OPENED_FILES: return EMFILE;
        case STATUS_INVALID_PARAMETER: return EINVAL;
        case STATUS_DIRECTORY_NOT_EMPTY: return ENOTEMPTY;
        case STATUS_PIPE_DISCONNECTED: return EPIPE;
        case STATUS_DEVICE_NOT_READY: return EIO;
        case STATUS_NO_SUCH_DEVICE: return ENXIO;
        case STATUS_NOT_SUPPORTED: return ENOTTY;
        case STATUS_ACCESS_VIOLATION: return EFAULT;
        case STATUS_ILLEGAL_FUNCTION: return ESPIPE;
        case STATUS_REPARSE_POINT_NOT_RESOLVED: return ELOOP;
        case STATUS_OBJECT_NAME_COLLISION: return EEXIST;
        default: return EINVAL;
    }
}

static ULONGLONG get_system_time_as_file_time() {
    timespec ts{};
    clock_gettime(CLOCK_REALTIME, &ts);
    constexpr ULONGLONG EPOCH_DIFFERENCE = 116444736000000000ULL;
    return (static_cast<ULONGLONG>(ts.tv_sec) * 10000000ULL) +
           (static_cast<ULONGLONG>(ts.tv_nsec) / 100ULL) + EPOCH_DIFFERENCE;
}

static ULONGLONG get_interrupt_time() {
    timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (static_cast<ULONGLONG>(ts.tv_sec) * 10000000ULL) +
           (static_cast<ULONGLONG>(ts.tv_nsec) / 100ULL);
}

static ULONGLONG get_tick_count() {
    timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (ts.tv_sec * 1000) + ts.tv_nsec / 1000000;
}

ULONG_PTR g_next_handle_num = 0x10000;
HANDLE &g_next_handle = *reinterpret_cast<HANDLE*>(&g_next_handle_num);

class VirtualMemoryAllocation {
public:
    VirtualMemoryAllocation() = default;
    VirtualMemoryAllocation(void* addr, size_t size, DWORD protect)
        : address(addr), size(size), protection(protect) {}

    void* address = nullptr;
    size_t size = 0;
    DWORD protection = 0;
};

struct APC {
    PNTAPCFUNC apc_function{};
    ULONG_PTR apc_param_1{};
    ULONG_PTR apc_param_2{};
    ULONG_PTR apc_param_3{};
    BOOLEAN inserted{ false }; // Set when the APC is inserted into the queue
    BOOLEAN pending{ false }; // Set when the APC is pending execution
};

struct Thread {
    pthread_t tid{}; // POSIX thread ID
    pid_t pid{}; // POSIX parent process ID
    std::atomic<bool> is_suspended{ false }; // Used via ptrace to suspend/resume
    std::atomic<bool> is_exiting{ false }; // Set when the thread is exiting
    std::atomic<bool> is_terminated{ false }; // Set when the thread has terminated
    std::atomic<bool> is_alertable{ false }; // Set when the thread is in alertable wait state
    std::atomic<bool> is_in_wait{ false }; // Set when the thread is in a wait state
    std::atomic<bool> is_stopped{ false }; // Set when the thread is stopped (e.g., via debugger)
    std::atomic<bool> is_handling_exception{ false }; // Set when the thread is handling an exception
    std::atomic<bool> is_debugger_thread{ false }; // Set when the thread is a debugger thread
    int priority{ NORMAL_PRIORITY_CLASS }; // Current priority
    int base_priority{ NORMAL_PRIORITY_CLASS }; // Base priority (used to restore priority after boost)
    std::atomic<uint64_t> affinity_mask{ 0xFFFFFFFFFFFFFFFF }; // Default to all cores
    PVOID start_address{ nullptr }; // Start address of the thread
    CONTEXT context{}; // Thread context
    std::mutex context_lock; // To protect concurrent access to the context
    std::deque<APC> apc_queue; // Queue of APCs to be executed
    std::mutex apc_lock; // To protect concurrent access to the APC queue
    std::condition_variable apc_cv; // To signal when an APC is added
};

struct Event {
    std::mutex mutex;
    std::condition_variable cv;
    bool signaled{false};
    bool manual_reset{false};
};

struct Semaphore {
    std::mutex mutex;
    std::condition_variable cv;
    LONG count{0};
    LONG max_count{0};
};

struct Mutex {
    std::mutex mutex;
    HANDLE owner{};
    DWORD recursion_count{0};
};

struct CriticalSection {
    std::mutex mutex;
    HANDLE owner{};
    DWORD recursion_count{0};
};

struct Timer {
    HANDLE due_time_event{};
    bool periodic{false};
    LONG period{0};
};

struct WaitableTimer {
    HANDLE due_time_event{};
    bool periodic{false};
    LONG period{0};
    bool is_absolute{false};
};

struct Mapping {
    HANDLE file_handle{};
    size_t size{0};
    DWORD protect{0};
    std::unordered_map<HANDLE, VirtualMemoryAllocation> views; // key is the view's base address as HANDLE
};

struct Section {
    std::string name;
    DWORD characteristics{0};
    size_t size{0};
    off_t file_offset{0};
    LPVOID mapped_address{nullptr};
};

struct Module {
    std::string path;
    HMODULE base_address{};
    size_t size{0};
    std::vector<Section> sections;
};

struct HeapAllocation {
    LPVOID address{};
    size_t size{0};
    DWORD flags{0};
};

struct Heap {
    std::unordered_map<HANDLE, HeapAllocation> allocations;
    std::mutex lock; // To protect concurrent access to the heap
};

struct IoCompletionPort {
    std::mutex mutex; // To protect concurrent access to the queue
    std::condition_variable cv; // To signal when a new completion is added
    std::deque<std::tuple<LPOVERLAPPED, PVOID, /* num of bytes transferred */ ULONG_PTR>> queue; // (file handle, overlapped, completion key)
    NTSTATUS status{ STATUS_SUCCESS };
    ULONG_PTR key{};
    LONG concurrency{0};
};

struct File {
    int fd{-1};
    std::string path;
    DWORD access{0};
    DWORD share_mode{0};
    DWORD disposition{0};
    DWORD attributes{0};
    DWORD flags{0}; // e.g., FILE_FLAG_OVERLAPPED
    bool is_device{false};
    bool is_pipe{false};
    bool is_socket{false};
    bool is_console{false};
    bool is_directory{false};
    bool is_symlink{false};
    off_t file_pointer{0};
    HANDLE iocp{nullptr}; // Associated IOCP, if any
    ULONG_PTR completion_key{}; // Completion key for IOCP
    std::mutex lock; // To protect concurrent access to the file
};

// Page mapping for ntmapphysicalpages(scatter)
struct PageMapping {
    void* vaddr; // Virtual address
    uint64_t paddr; // Physical address
    size_t size; // Size of the mapping
};

enum class IPCCommand : uint32_t {
    SYSCALL_NTWORKERFACTORYWORKERREADY, // No-op on both sides
    SYSCALL_NTMAPUSERPHYSICALPAGESSCATTER, // Child scatters pages,
    SYSCALL_NTREMOVEIOCOMPLETION, // No-op on child side, handled in parent
    SYSCALL_NTSETINFORMATIONTHREAD, // No-op on child side, handled in parent
    SYSCALL_NTSETEVENT, // No-op on child side, handled in parent
    SYSCALL_NTQUERYINFORMATIONFILE, // No-op on child side, handled in parent
    SYSCALL_NTFINDATOM, // No-op on child side, handled in parent
    SYSCALL_NTADDATOM, // No-op on child side, handled in parent
    SYSCALL_NTQUERYINFORMATIONPROCESS, // No-op on child side, handled in parent
    SYSCALL_NTWRITEFILEGATHER, // Child gathers data(no-op), write handled in parent
    SYSCALL_NTSETINFORMATIONFILE, // No-op on child side, handled in parent
    SYSCALL_NTQUERYSYSTEMINFORMATION, // No-op on child side, handled in parent
    SYSCALL_NTQUERYSYSTEMINFORMATIONEX, // No-op on child side, handled in parent
    SYSCALL_NTCREATEPROCESSEX, // No-op on child side, handled in parent
    SYSCALL_NTCREATEPROCESS, // No-op on child side, handled in parent
    SYSCALL_NTRAISEEXCEPTION, // Child raises exception, parent stops further tracing/execution
    SYSCALL_NTFLUSHKEY, // No-op on child side, handled in parent
    SYSCALL_NTCREATETHREAD, // Handled in child, handled in parent
};

struct IPCMessage {
    IPCCommand command; // IN
    uint64_t params[10]; // IN
    NTSTATUS result; // OUT
    char error_msg[256]; // OUT
};


class ChildMemoryManager {
private:
    pid_t child_pid;

public:
    explicit ChildMemoryManager(pid_t pid) : child_pid(pid) {}

    bool read_memory(uintptr_t addr, void* buffer, size_t size) const {
        size_t bytes_read = 0;
        auto* buf = static_cast<uint8_t*>(buffer);

        while (bytes_read < size) {
            errno = 0;
            long word = ptrace(PTRACE_PEEKDATA, child_pid, addr + bytes_read, nullptr);
            if (errno != 0) {
                return false;
            }

            size_t to_copy = min(sizeof(long), size - bytes_read);
            memcpy(buf + bytes_read, &word, to_copy);
            bytes_read += to_copy;
        }
        return true;
    }

    bool write_memory(uintptr_t addr, const void* buffer, size_t size) const {
        size_t bytes_written = 0;
        auto* buf = static_cast<const uint8_t*>(buffer);

        while (bytes_written < size) {
            long word;
            if (size - bytes_written < sizeof(long)) {
                // Partial write - read-modify-write
                errno = 0;
                word = ptrace(PTRACE_PEEKDATA, child_pid, addr + bytes_written, nullptr);
                if (errno != 0) return false;
            }

            size_t to_copy = min(sizeof(long), size - bytes_written);
            memcpy(&word, buf + bytes_written, to_copy);

            if (ptrace(PTRACE_POKEDATA, child_pid, addr + bytes_written, word) == -1) {
                return false;
            }
            bytes_written += to_copy;
        }
        return true;
    }

    template<typename T>
    std::optional<T> read(uintptr_t addr) {
        T value;
        if (read_memory(addr, &value, sizeof(T))) {
            return value;
        }
        return std::nullopt;
    }

    template<typename T>
    bool write(uintptr_t addr, const T& value) {
        return write_memory(addr, &value, sizeof(T));
    }

    std::optional<std::string> read_string(uintptr_t addr, size_t max_len = 4096) {
        std::string result;
        result.reserve(256);

        for (size_t i = 0; i < max_len; i++) {
            auto ch = read<char>(addr + i);
            if (!ch || *ch == '\0') break;
            result.push_back(*ch);
        }
        return result;
    }

    std::optional<std::wstring> read_wstring(uintptr_t addr, size_t max_len = 4096) {
        std::wstring result;
        result.reserve(256);

        for (size_t i = 0; i < max_len; i++) {
            auto ch = read<wchar_t>(addr + i * sizeof(wchar_t));
            if (!ch || *ch == L'\0') break;
            result.push_back(*ch);
        }
        return result;
    }

    std::optional<std::u16string> read_u16string(uintptr_t addr, size_t max_len = 4096) {
        std::u16string result;
        result.reserve(256);

        for (size_t i = 0; i < max_len; i++) {
            auto ch = read<char16_t>(addr + i * sizeof(char16_t));
            if (!ch || *ch == u'\0') break;
            result.push_back(*ch);
        }
        return result;
    }

    [[nodiscard]] pid_t get_pid() const { return child_pid; }
};

class SyscallParameterReader {
private:
    ChildMemoryManager& mgr;
    const user_regs_struct& regs;

public:
    SyscallParameterReader(ChildMemoryManager& m, const user_regs_struct& r)
        : mgr(m), regs(r) {}

    template<typename T>
    std::optional<T> get_param(size_t param_index) const {
        // Windows x64 calling convention: first 4 params in rcx, rdx, r8, r9
        // Additional params on stack at rsp + 0x20 + (param_index - 4) * 8
        if (param_index < 4) {
            switch (param_index) {
                case 0: return (T)regs.rcx; // use C-style cast: T can be pointer or integer
                case 1: return (T)regs.rdx;
                case 2: return (T)regs.r8;
                case 3: return (T)regs.r9;
                default: return std::nullopt;
            }
        }

        const uintptr_t stack_offset = 0x20 + (param_index - 4) * 8;
        const uintptr_t param_addr = regs.rsp + stack_offset;

        return mgr.read<T>(param_addr);
    }
};

class SystemCallManager {
private:
    int parent_to_child[2]{};
    int child_to_parent[2]{};
    bool is_child_process;
    pid_t child_pid;
    bool is_enabled_ = true;

    // 0x1
    IPCMessage Client_NtWorkerFactoryWorkerReady(ChildMemoryManager &mgr, const user_regs_struct &regs) {
        const SyscallParameterReader reader(mgr, regs);
        // invoke server handler
        IPCMessage message = {};
        message.command = IPCCommand::SYSCALL_NTWORKERFACTORYWORKERREADY;
        message.params[0] = reinterpret_cast<uint64_t>(g_tls.process);
        message.params[1] = reinterpret_cast<uint64_t>(reader.get_param<HANDLE>(0).value());
        const IPCMessage response = send_ipc_message(message);
        return response;
    }

    static IPCMessage Server_NtWorkerFactoryWorkerReady(const IPCMessage& message);

    // 0x3
    IPCMessage Client_NtMapUserPhysicalPagesScatter(ChildMemoryManager &mgr, const user_regs_struct &regs) {
        const SyscallParameterReader reader(mgr, regs);
        // invoke server handler
        IPCMessage message = {};
        message.command = IPCCommand::SYSCALL_NTMAPUSERPHYSICALPAGESSCATTER;
        message.params[0] = reinterpret_cast<uint64_t>(g_tls.process);
        message.params[1] = reinterpret_cast<uint64_t>(reader.get_param<HANDLE>(0).value());
        message.params[2] = reinterpret_cast<uint64_t>(reader.get_param<PVOID*>(1).value());
        message.params[3] = static_cast<uint64_t>(reader.get_param<SIZE_T>(2).value());
        message.params[4] = reinterpret_cast<uint64_t>(reader.get_param<PULONG_PTR>(3).value());
        const IPCMessage response = send_ipc_message(message);
        return response;
    }

    static IPCMessage Server_NtMapUserPhysicalPagesScatter(const IPCMessage& message);

    // 0x9
    IPCMessage Client_NtRemoveIoCompletion(ChildMemoryManager &mgr, const user_regs_struct &regs) {
        const SyscallParameterReader reader(mgr, regs);
        // invoke server handler
        IPCMessage message = {};
        message.command = IPCCommand::SYSCALL_NTREMOVEIOCOMPLETION;
        message.params[0] = reinterpret_cast<uint64_t>(g_tls.process);
        message.params[1] = reinterpret_cast<uint64_t>(reader.get_param<HANDLE>(0).value());
        message.params[2] = reinterpret_cast<uint64_t>(reader.get_param<PVOID*>(1).value());
        message.params[3] = reinterpret_cast<uint64_t>(reader.get_param<PVOID*>(2).value());
        message.params[4] = reinterpret_cast<uint64_t>(reader.get_param<PIO_STATUS_BLOCK>(3).value());
        message.params[5] = reinterpret_cast<uint64_t>(reader.get_param<PLARGE_INTEGER>(4).value());
        const IPCMessage response = send_ipc_message(message);
        return response;
    }

    static IPCMessage Server_NtRemoveIoCompletion(const IPCMessage& message);

    // 0xD
    IPCMessage Client_NtSetInformationThread(ChildMemoryManager &mgr, const user_regs_struct &regs) {
        const SyscallParameterReader reader(mgr, regs);
        // invoke server handler
        IPCMessage message = {};
        message.command = IPCCommand::SYSCALL_NTSETINFORMATIONTHREAD;
        message.params[0] = reinterpret_cast<uint64_t>(g_tls.thread);
        message.params[1] = reinterpret_cast<uint64_t>(reader.get_param<HANDLE>(0).value());
        message.params[2] = static_cast<uint64_t>(reader.get_param<THREADINFOCLASS>(1).value());
        message.params[3] = reinterpret_cast<uint64_t>(reader.get_param<PVOID>(2).value());
        message.params[4] = static_cast<uint64_t>(reader.get_param<ULONG>(3).value());
        const IPCMessage response = send_ipc_message(message);
        return response;
    }

    static IPCMessage Server_NtSetInformationThread(const IPCMessage& message);

    // 0xE
    IPCMessage Client_NtSetEvent(ChildMemoryManager &mgr, const user_regs_struct &regs) {
        const SyscallParameterReader reader(mgr, regs);
        // invoke server handler
        IPCMessage message = {};
        message.command = IPCCommand::SYSCALL_NTSETEVENT;
        message.params[0] = reinterpret_cast<uint64_t>(g_tls.process);
        message.params[1] = reinterpret_cast<uint64_t>(reader.get_param<HANDLE>(0).value());
        message.params[2] = reinterpret_cast<uint64_t>(reader.get_param<PLONG>(1).value());
        const IPCMessage response = send_ipc_message(message);
        return response;
    }

    static IPCMessage Server_NtSetEvent(const IPCMessage& message);

    // 0x11
    IPCMessage Client_NtQueryInformationFile(ChildMemoryManager &mgr, const user_regs_struct &regs) {
        const SyscallParameterReader reader(mgr, regs);
        // invoke server handler
        IPCMessage message = {};
        message.command = IPCCommand::SYSCALL_NTQUERYINFORMATIONFILE;
        message.params[0] = reinterpret_cast<uint64_t>(g_tls.process);
        message.params[1] = reinterpret_cast<uint64_t>(reader.get_param<HANDLE>(0).value());
        message.params[2] = reinterpret_cast<uint64_t>(reader.get_param<PIO_STATUS_BLOCK>(1).value());
        message.params[3] = reinterpret_cast<uint64_t>(reader.get_param<PVOID>(2).value());
        message.params[4] = static_cast<uint64_t>(reader.get_param<ULONG>(3).value());
        message.params[5] = static_cast<uint64_t>(reader.get_param<FILE_INFORMATION_CLASS>(4).value());
        const IPCMessage response = send_ipc_message(message);
        return response;
    }

    static IPCMessage Server_NtQueryInformationFile(const IPCMessage& message);

    // 0x14
    IPCMessage Client_NtFindAtom(ChildMemoryManager &mgr, const user_regs_struct &regs) {
        const SyscallParameterReader reader(mgr, regs);
        // invoke server handler
        IPCMessage message = {};
        message.command = IPCCommand::SYSCALL_NTFINDATOM;
        message.params[0] = reinterpret_cast<uint64_t>(g_tls.process);
        message.params[1] = reinterpret_cast<uint64_t>(reader.get_param<PWCHAR>(0).value());
        message.params[2] = static_cast<uint64_t>(reader.get_param<ULONG>(1).value());
        message.params[3] = reinterpret_cast<uint64_t>(reader.get_param<ATOM*>(2).value());
        const IPCMessage response = send_ipc_message(message);
        return response;
    }

    static IPCMessage Server_NtFindAtom(const IPCMessage& message);

    // 0x19
    IPCMessage Client_NtQueryInformationProcess(ChildMemoryManager &mgr, const user_regs_struct &regs) {
        const SyscallParameterReader reader(mgr, regs);
        // invoke server handler
        IPCMessage message = {};
        message.command = IPCCommand::SYSCALL_NTQUERYINFORMATIONPROCESS;
        message.params[0] = reinterpret_cast<uint64_t>(g_tls.process);
        message.params[1] = reinterpret_cast<uint64_t>(reader.get_param<HANDLE>(0).value());
        message.params[2] = static_cast<uint64_t>(reader.get_param<PROCESSINFOCLASS>(1).value());
        message.params[3] = reinterpret_cast<uint64_t>(reader.get_param<PVOID>(2).value());
        message.params[4] = static_cast<uint64_t>(reader.get_param<ULONG>(3).value());
        message.params[5] = reinterpret_cast<uint64_t>(reader.get_param<PULONG>(4).value());
        const IPCMessage response = send_ipc_message(message);
        return response;
    }

    static IPCMessage Server_NtQueryInformationProcess(const IPCMessage& message);

    // 0x1B
    IPCMessage Client_NtWriteFileGather(ChildMemoryManager &mgr, const user_regs_struct &regs) {
        const SyscallParameterReader reader(mgr, regs);
        // invoke server handler
        IPCMessage message = {};
        message.command = IPCCommand::SYSCALL_NTWRITEFILEGATHER;
        message.params[0] = reinterpret_cast<uint64_t>(g_tls.process);
        message.params[1] = reinterpret_cast<uint64_t>(reader.get_param<HANDLE>(0).value());
        message.params[2] = reinterpret_cast<uint64_t>(reader.get_param<HANDLE>(1).value());
        message.params[3] = reinterpret_cast<uint64_t>(reader.get_param<PIO_APC_ROUTINE>(2).value());
        message.params[4] = reinterpret_cast<uint64_t>(reader.get_param<PVOID>(3).value());
        message.params[5] = reinterpret_cast<uint64_t>(reader.get_param<PIO_STATUS_BLOCK>(4).value());
        message.params[6] = reinterpret_cast<uint64_t>(reader.get_param<PFILE_SEGMENT_ELEMENT>(5).value());
        message.params[7] = static_cast<uint64_t>(reader.get_param<ULONG>(6).value());
        message.params[8] = reinterpret_cast<uint64_t>(reader.get_param<PLARGE_INTEGER>(7).value());
        message.params[9] = reinterpret_cast<uint64_t>(reader.get_param<PULONG>(8).value());
        const IPCMessage response = send_ipc_message(message);
        return response;
    }

    static IPCMessage Server_NtWriteFileGather(const IPCMessage& message);

    // 0x27
    IPCMessage Client_NtSetInformationFile(ChildMemoryManager &mgr, const user_regs_struct &regs) {
        const SyscallParameterReader reader(mgr, regs);
        // invoke server handler
        IPCMessage message = {};
        message.command = IPCCommand::SYSCALL_NTSETINFORMATIONFILE;
        message.params[0] = reinterpret_cast<uint64_t>(g_tls.process);
        message.params[1] = reinterpret_cast<uint64_t>(reader.get_param<HANDLE>(0).value());
        message.params[2] = reinterpret_cast<uint64_t>(reader.get_param<PIO_STATUS_BLOCK>(1).value());
        message.params[3] = reinterpret_cast<uint64_t>(reader.get_param<PVOID>(2).value());
        message.params[4] = static_cast<uint64_t>(reader.get_param<ULONG>(3).value());
        message.params[5] = static_cast<uint64_t>(reader.get_param<FILE_INFORMATION_CLASS>(4).value());
        const IPCMessage response = send_ipc_message(message);
        return response;
    }

    static IPCMessage Server_NtSetInformationFile(const IPCMessage& message);

    // 0x36
    IPCMessage Client_NtQuerySystemInformation(ChildMemoryManager &mgr, const user_regs_struct &regs) {
        const SyscallParameterReader reader(mgr, regs);
        // invoke server handler
        IPCMessage message = {};
        message.command = IPCCommand::SYSCALL_NTQUERYSYSTEMINFORMATION;
        message.params[0] = reinterpret_cast<uint64_t>(g_tls.process);
        message.params[1] = static_cast<uint64_t>(reader.get_param<SYSTEM_INFORMATION_CLASS>(0).value());
        message.params[2] = reinterpret_cast<uint64_t>(reader.get_param<PVOID>(1).value());
        message.params[3] = static_cast<uint64_t>(reader.get_param<ULONG>(2).value());
        message.params[4] = reinterpret_cast<uint64_t>(reader.get_param<PULONG>(3).value());
        const IPCMessage response = send_ipc_message(message);
        return response;
    }

    static IPCMessage Server_NtQuerySystemInformation(const IPCMessage& message);

    // 0x47
    IPCMessage Client_NtAddAtom(ChildMemoryManager &mgr, const user_regs_struct &regs) {
        const SyscallParameterReader reader(mgr, regs);
        // invoke server handler
        IPCMessage message = {};
        message.command = IPCCommand::SYSCALL_NTADDATOM;
        message.params[0] = reinterpret_cast<uint64_t>(g_tls.process);
        message.params[1] = reinterpret_cast<uint64_t>(reader.get_param<PWCHAR>(0).value());
        message.params[2] = static_cast<uint64_t>(reader.get_param<ULONG>(1).value());
        message.params[3] = reinterpret_cast<uint64_t>(reader.get_param<ATOM*>(2).value());
        const IPCMessage response = send_ipc_message(message);
        return response;
    }

    static IPCMessage Server_NtAddAtom(const IPCMessage& message);

    // 0xBA
    IPCMessage Client_NtCreateProcess(ChildMemoryManager &mgr, const user_regs_struct &regs) {
        const SyscallParameterReader reader(mgr, regs);
        // invoke server handler
        IPCMessage message = {};
        message.command = IPCCommand::SYSCALL_NTCREATEPROCESS;
        message.params[0] = reinterpret_cast<uint64_t>(g_tls.process);
        message.params[1] = reinterpret_cast<uint64_t>(reader.get_param<PHANDLE>(0).value());
        message.params[2] = static_cast<uint64_t>(reader.get_param<ACCESS_MASK>(1).value());
        message.params[3] = reinterpret_cast<uint64_t>(reader.get_param<POBJECT_ATTRIBUTES>(2).value());
        message.params[4] = reinterpret_cast<uint64_t>(reader.get_param<HANDLE>(3).value());
        message.params[5] = static_cast<uint64_t>(reader.get_param<BOOLEAN>(4).value());
        message.params[6] = reinterpret_cast<uint64_t>(reader.get_param<HANDLE>(5).value());
        message.params[7] = reinterpret_cast<uint64_t>(reader.get_param<HANDLE>(6).value());
        message.params[8] = reinterpret_cast<uint64_t>(reader.get_param<HANDLE>(7).value());
        const IPCMessage response = send_ipc_message(message);
        return response;
    }

    static IPCMessage Server_NtCreateProcess(const IPCMessage& message);

    // 0xEA
    IPCMessage Client_NtFlushKey(ChildMemoryManager &mgr, const user_regs_struct &regs) {
        const SyscallParameterReader reader(mgr, regs);
        // invoke server handler
        IPCMessage message = {};
        message.command = IPCCommand::SYSCALL_NTFLUSHKEY;
        message.params[0] = reinterpret_cast<uint64_t>(g_tls.process);
        message.params[1] = reinterpret_cast<uint64_t>(reader.get_param<HANDLE>(0).value());
        const IPCMessage response = send_ipc_message(message);
        return response;
    }

    static IPCMessage Server_NtFlushKey(const IPCMessage& message);

    // 0x162
    IPCMessage Client_NtQuerySystemInformationEx(ChildMemoryManager &mgr, const user_regs_struct &regs) {
        const SyscallParameterReader reader(mgr, regs);
        // invoke server handler
        IPCMessage message = {};
        message.command = IPCCommand::SYSCALL_NTQUERYSYSTEMINFORMATIONEX;
        message.params[0] = reinterpret_cast<uint64_t>(g_tls.process);
        message.params[1] = static_cast<uint64_t>(reader.get_param<SYSTEM_INFORMATION_CLASS>(0).value());
        message.params[2] = reinterpret_cast<uint64_t>(reader.get_param<PVOID>(1).value());
        message.params[3] = static_cast<uint64_t>(reader.get_param<ULONG>(2).value());
        message.params[4] = reinterpret_cast<uint64_t>(reader.get_param<PVOID>(3).value());
        message.params[5] = static_cast<uint64_t>(reader.get_param<ULONG>(4).value());
        message.params[6] = reinterpret_cast<uint64_t>(reader.get_param<PULONG>(5).value());
        const IPCMessage response = send_ipc_message(message);
        return response;
    }

    static IPCMessage Server_NtQuerySystemInformationEx(const IPCMessage& message);

    // 0x168
    IPCMessage Client_NtRaiseException(ChildMemoryManager &mgr, const user_regs_struct &regs) {
        const SyscallParameterReader reader(mgr, regs);
        // Log the exception and terminate the process
        PEXCEPTION_RECORD ExceptionRecord = reader.get_param<PEXCEPTION_RECORD>(0).value();
        PCONTEXT ContextRecord = reader.get_param<PCONTEXT>(1).value();
        BOOLEAN FirstChance = reader.get_param<BOOLEAN>(2).value();

        // do not send IPC message, just handle it here
        error("Child process raised an exception, terminating...");
        error("FirstChance: ", FirstChance);
        const auto record_ptr = reinterpret_cast<uintptr_t>(ExceptionRecord);
        auto record = mgr.read<EXCEPTION_RECORD>(record_ptr);
        if (record) {
            error("Exception Code: ", std::hex, record->ExceptionCode);
            error("Exception Address: ", record->ExceptionAddress);
        } else {
            error("Failed to read exception record");
        }
        const auto context_ptr = reinterpret_cast<uintptr_t>(ContextRecord);
        if (const auto context = mgr.read<CONTEXT>(context_ptr)) {
            error("ContextFlags: ", std::hex, context->ContextFlags);
            error("Dr0: ", std::hex, context->Dr0);
            error("Dr1: ", std::hex, context->Dr1);
            error("Dr2: ", std::hex, context->Dr2);
            error("Dr3: ", std::hex, context->Dr3);
            error("Dr6: ", std::hex, context->Dr6);
            error("Dr7: ", std::hex, context->Dr7);
            error("SegCs: ", std::hex, context->SegCs);
            error("SegDs: ", std::hex, context->SegDs);
            error("SegEs: ", std::hex, context->SegEs);
            error("SegFs: ", std::hex, context->SegFs);
            error("SegGs: ", std::hex, context->SegGs);
            error("SegSs: ", std::hex, context->SegSs);
            error("EFlags: ", std::hex, context->EFlags);
            error("LastBranchFromRip: ", std::hex, context->LastBranchFromRip);
            error("LastBranchToRip: ", std::hex, context->LastBranchToRip);
            error("LastExceptionFromRip: ", std::hex, context->LastExceptionFromRip);
            error("LastExceptionToRip: ", std::hex, context->LastExceptionToRip);
            error("RBP", std::hex, context->Rbp);
            error("RIP: ", std::hex, context->Rip);
            error("RSP: ", std::hex, context->Rsp);
            error("RAX: ", std::hex, context->Rax);
            error("RBX: ", std::hex, context->Rbx);
            error("RCX: ", std::hex, context->Rcx);
            error("RDX: ", std::hex, context->Rdx);
            error("RSI: ", std::hex, context->Rsi);
            error("RDI: ", std::hex, context->Rdi);
            error("R8: ", std::hex, context->R8);
            error("R9: ", std::hex, context->R9);
            error("R10: ", std::hex, context->R10);
            error("R11: ", std::hex, context->R11);
            error("R12: ", std::hex, context->R12);
            error("R13: ", std::hex, context->R13);
            error("R14: ", std::hex, context->R14);
            error("R15: ", std::hex, context->R15);
        } else {
            error("Failed to read context");
        }
        // Terminate the process
        exit(1);

        // This line will never be reached, but we need to return something
        IPCMessage response = {};
        response.result = STATUS_SUCCESS;
        return response;
    }

public:
    SystemCallManager() : is_child_process(false), child_pid(0) {
        if (pipe(parent_to_child) == -1 || pipe(child_to_parent) == -1) {
            throw std::runtime_error("Failed to create IPC pipes");
        }

        // Make pipes non-blocking for better control
        fcntl(parent_to_child[0], F_SETFL, O_NONBLOCK);
        fcntl(child_to_parent[0], F_SETFL, O_NONBLOCK);
    }

    void setup_as_child() {
        is_child_process = true;
        close(child_to_parent[0]);  // Child won't read responses
        close(parent_to_child[1]);  // Child won't send requests
    }

    void setup_as_parent(pid_t pid) {
        is_child_process = false;
        child_pid = pid;
        close(child_to_parent[1]);  // Parent won't send responses
        close(parent_to_child[0]);  // Parent won't read requests
    }

    void disable() {
        is_enabled_ = false;
    }

    void enable() {
        is_enabled_ = true;
    }

    bool is_enabled() const {
        return is_enabled_;
    }

    IPCMessage send_ipc_message(const IPCMessage& message) {
        if (!is_enabled_) {
            IPCMessage response = {};
            response.result = STATUS_UNSUCCESSFUL;
            snprintf(response.error_msg, sizeof(response.error_msg), "IPC is disabled");
            return response;
        }

        if (is_child_process) {
            // Child process: send request to parent and wait for response
            if (write(parent_to_child[1], &message, sizeof(message)) != sizeof(message)) {
                IPCMessage response = {};
                response.result = STATUS_UNSUCCESSFUL;
                snprintf(response.error_msg, sizeof(response.error_msg), "Failed to send IPC message to parent");
                return response;
            }

            // Wait for response
            IPCMessage response;
            ssize_t bytes_read = read(child_to_parent[0], &response, sizeof(response));
            if (bytes_read != sizeof(response)) {
                IPCMessage error_response = {};
                error_response.result = STATUS_UNSUCCESSFUL;
                snprintf(error_response.error_msg, sizeof(error_response.error_msg), "Failed to read IPC response from parent");
                return error_response;
            }
            return response;
        } else {
            // Parent process: wait for request from child and send response
            IPCMessage request;
            ssize_t bytes_read = read(child_to_parent[0], &request, sizeof(request));
            if (bytes_read != sizeof(request)) {
                IPCMessage response = {};
                response.result = STATUS_UNSUCCESSFUL;
                snprintf(response.error_msg, sizeof(response.error_msg), "Failed to read IPC request from child");
                return response;
            }

            // TODO: Dispatch to appropriate server handler based on request.command
        }
    }

    [[nodiscard]] int get_parent_read_fd() const { return child_to_parent[0]; }
    [[nodiscard]] int get_parent_write_fd() const { return parent_to_child[1]; }

    [[nodiscard]] int get_child_read_fd() const { return parent_to_child[0]; }
    [[nodiscard]] int get_child_write_fd() const { return child_to_parent[1]; }
};

class Process {
public:
    pid_t pid{}; // POSIX process ID
    pid_t monitor_pid{}; // Monitor process PID (0 if not monitored)
    HANDLE parent{}; // Handle to the parent process
    std::unordered_map<HANDLE, std::shared_ptr<VirtualMemoryAllocation>> virtual_memory_allocations;
    std::unordered_map<HANDLE, std::shared_ptr<Heap>> heaps;
    std::unordered_set<std::shared_ptr<CriticalSection>> critical_sections;
    std::vector<std::shared_ptr<Heap>> heaps_vec;
    std::unordered_map<uintptr_t, std::shared_ptr<PageMapping>> page_mappings; // key is the base virtual address
    HANDLE default_heap{ g_next_handle };
    HMODULE hmodule{};
    PWSTR environment{ nullptr };
    int exit_code{ 0 };
    std::shared_mutex lock; // To protect concurrent access to the process
    std::condition_variable exit_cv; // To signal process exit
    std::string cmdline; // Command line
    std::string image_path; // Full path to the executable
    std::u16string cmdline_u16; // Command line in UTF-16
    std::u16string image_path_u16; // Full path to the executable in UTF-16
    std::atomic<bool> has_threads{false};
    std::atomic<bool> is_paused{true};
    std::shared_ptr<SystemCallManager> ipc;


    int priority{ NORMAL_PRIORITY_CLASS }; // Current priority
    int base_priority{ NORMAL_PRIORITY_CLASS }; // Base priority (used to restore priority after boost)

    // Creation time
    std::chrono::system_clock::time_point creation_time = std::chrono::system_clock::now();
    // Exit time
    std::chrono::system_clock::time_point exit_time;

    Process() {
        heaps[default_heap]; // default heap
        ++g_next_handle_num;
        constexpr char environment_narrow[] = "SystemRoot=C:\\Windows\0TEMP=C:\\Temp\0TMP=C:\\Temp\0\0";
        constexpr size_t env_size = sizeof(environment_narrow);
        environment = new WCHAR[env_size];
        for (size_t i = 0; i < env_size; ++i) {
            environment[i] = static_cast<WCHAR>(environment_narrow[i]);
        }
    }
};



class RegistryKey {
public:
    std::string path;
    std::unordered_map<std::string, std::vector<BYTE>> values;
    std::unordered_map<std::string, std::shared_ptr<RegistryKey>> subkeys;
    std::mutex lock; // To protect concurrent access to the key
};

class Registry {
public:
    std::unordered_map<HANDLE, std::shared_ptr<RegistryKey>> keys = {
        { static_cast<HANDLE>(HKEY_CLASSES_ROOT), std::make_shared<RegistryKey>("HKEY_CLASSES_ROOT") },
        { static_cast<HANDLE>(HKEY_CURRENT_USER), std::make_shared<RegistryKey>("HKEY_CURRENT_USER") },
        { static_cast<HANDLE>(HKEY_LOCAL_MACHINE), std::make_shared<RegistryKey>("HKEY_LOCAL_MACHINE") },
        { static_cast<HANDLE>(HKEY_USERS), std::make_shared<RegistryKey>("HKEY_USERS") },
        { static_cast<HANDLE>(HKEY_PERFORMANCE_TEXT), std::make_shared<RegistryKey>("HKEY_PERFORMANCE_TEXT") },
        { static_cast<HANDLE>(HKEY_PERFORMANCE_DATA), std::make_shared<RegistryKey>("HKEY_PERFORMANCE_DATA") },
        { static_cast<HANDLE>(HKEY_CURRENT_CONFIG), std::make_shared<RegistryKey>("HKEY_CURRENT_CONFIG") },
        { static_cast<HANDLE>(HKEY_DYN_DATA), std::make_shared<RegistryKey>("HKEY_DYN_DATA") }
    };

    std::shared_mutex g_registry_mutex;

    void save_to_file(const std::string& filename) {
        nlohmann::json j;
        {
            std::shared_lock lock(g_registry_mutex);
            for (const auto& [handle, key] : keys) {
                std::unique_lock key_lock(key->lock);
                nlohmann::json key_json;
                key_json["path"] = key->path;

                nlohmann::json values_json;
                for (const auto& [value_name, value_data] : key->values) {
                    values_json[value_name] = std::vector<BYTE>(value_data);
                }
                key_json["values"] = values_json;

                nlohmann::json subkeys_json;
                for (const auto& [subkey_name, subkey] : key->subkeys) {
                    subkeys_json[subkey_name] = subkey->path; // Just store path for simplicity
                }
                key_json["subkeys"] = subkeys_json;

                j[std::to_string(reinterpret_cast<uintptr_t>(handle))] = key_json;
            }
        }

        if (std::ofstream file(filename); file.is_open()) {
            file << j.dump(4);
            file.close();
        } else {
            error("Failed to open registry save file: ", filename);
        }
    }

    void flush_to_disk() {
        save_to_file("registry_backup.json");
    }
};



// Global state
std::shared_mutex g_refcnts_mutex;
std::unordered_map<HANDLE, size_t> g_refcnts;
std::shared_mutex g_events_mutex;
std::unordered_map<HANDLE, std::shared_ptr<Event>> g_events;
std::shared_mutex g_semaphores_mutex;
std::unordered_map<HANDLE, std::shared_ptr<Semaphore>> g_semaphores;
std::shared_mutex g_mutexes_mutex;
std::unordered_map<HANDLE, std::shared_ptr<Mutex>> g_mutexes;
std::shared_mutex g_timers_mutex;
std::unordered_map<HANDLE, std::shared_ptr<Timer>> g_timers;
std::shared_mutex g_waitable_timers_mutex;
std::unordered_map<HANDLE, std::shared_ptr<WaitableTimer>> g_waitable_timers;
std::shared_mutex g_mappings_mutex;
std::unordered_map<HANDLE, std::shared_ptr<Mapping>> g_mappings;
std::shared_mutex g_threads_mutex;
std::unordered_map<HANDLE, std::shared_ptr<Thread>> g_threads;
std::shared_mutex g_processes_mutex;
std::unordered_map<HANDLE, std::shared_ptr<Process>> g_processes;
std::shared_mutex g_files_mutex;
std::unordered_map<HANDLE, std::shared_ptr<File>> g_files;
std::shared_mutex g_modules_mutex;
std::unordered_map<HANDLE, std::shared_ptr<Module>> g_modules;
std::shared_mutex g_io_completion_ports_mutex;
std::unordered_map<HANDLE, std::shared_ptr<IoCompletionPort>> g_io_completion_ports;
static uint64_t g_next_atom_value = 1;
std::shared_mutex g_atom_table_mutex;
std::unordered_map<std::u16string, RTL_ATOM> g_atom_table; // for lookup by name
std::shared_mutex g_reverse_atom_table_mutex;
std::unordered_map<RTL_ATOM, std::u16string> g_reverse_atom_table; // for lookup by atom
Registry g_registry;

IPCMessage SystemCallManager::Server_NtWorkerFactoryWorkerReady(const IPCMessage &message) {
    IPCMessage response = {};
    response.result = STATUS_SUCCESS;
    snprintf(response.error_msg, sizeof(response.error_msg), "NtWorkerFactoryWorkerReady is not implemented, stubbing");
    return response;
}

IPCMessage SystemCallManager::Server_NtMapUserPhysicalPagesScatter(const IPCMessage &message) {
    std::shared_ptr<Process> process = g_processes[reinterpret_cast<HANDLE>(message.params[0])];
    auto hProcess = reinterpret_cast<HANDLE>(message.params[1]);
    auto VirtualAddresses = reinterpret_cast<PVOID*>(message.params[2]);
    auto NumberOfPages = static_cast<SIZE_T>(message.params[3]);
    auto PageFrameNumbers = reinterpret_cast<PULONG_PTR>(message.params[4]);

    IPCMessage response = {};
    response.result = STATUS_SUCCESS;

    for (SIZE_T i = 0; i < NumberOfPages; ++i) {
        if (VirtualAddresses[i] == nullptr) continue;
        void *vaddr = VirtualAddresses[i];
        std::shared_lock lock(process->lock);
        auto it = process->page_mappings.find(reinterpret_cast<uintptr_t>(vaddr));
        if (it == process->page_mappings.end()) {
            response.result = STATUS_INVALID_PARAMETER;
            snprintf(response.error_msg, sizeof(response.error_msg), "No page mapping found for address %p", VirtualAddresses[i]);
            return response;
        }
        const auto& mapping = it->second;
        if (PageFrameNumbers && PageFrameNumbers[i] != 0) {
            mapping->paddr = PageFrameNumbers[i];
            mapping->size = PAGE_SIZE;
            mapping->vaddr = vaddr;
        } else {
            mapping->paddr = 0;
            mapping->size = 0;
            mapping->vaddr = nullptr;
        }
    }
    return response;
}

IPCMessage SystemCallManager::Server_NtRemoveIoCompletion(const IPCMessage &message) {
    std::shared_ptr<Process> process = g_processes[reinterpret_cast<HANDLE>(message.params[0])];
    auto IoCompletion = reinterpret_cast<HANDLE>(message.params[1]);
    auto KeyContext = reinterpret_cast<PVOID*>(message.params[2]);
    auto ApcContext = reinterpret_cast<PVOID*>(message.params[3]);
    auto IoStatusBlock = reinterpret_cast<PIO_STATUS_BLOCK>(message.params[4]);
    auto Timeout = reinterpret_cast<PLARGE_INTEGER>(message.params[5]);

    IPCMessage response = {};
    response.result = STATUS_SUCCESS;

    std::shared_ptr<IoCompletionPort> port;
    {
        std::shared_lock lock(g_io_completion_ports_mutex);
        const auto it = g_io_completion_ports.find(IoCompletion);
        if (it == g_io_completion_ports.end()) {
            response.result = STATUS_INVALID_HANDLE;
            snprintf(response.error_msg, sizeof(response.error_msg), "Invalid IoCompletion handle");
            return response;
        }
        port = it->second;
    }

    DWORD bytes_transferred;
    PVOID key;
    LPOVERLAPPED overlapped;

    if (!g_io_completion_ports.empty()) {
        // port->queue is std::deque
        std::unique_lock lock(port->mutex);
        if (port->queue.empty()) {
            if (Timeout) {
                // Convert relative timeout to absolute time point
                auto now = std::chrono::steady_clock::now();
                auto timeout_duration = std::chrono::nanoseconds(-(*Timeout).QuadPart * 100); // Convert 100-nanosecond intervals to nanoseconds
                auto timeout_time = now + timeout_duration;

                if (port->cv.wait_until(lock, timeout_time, [&]() { return !port->queue.empty(); })) {
                    // Woken up and queue is not empty
                } else {
                    // Timeout occurred
                    response.result = STATUS_TIMEOUT;
                    snprintf(response.error_msg, sizeof(response.error_msg), "NtRemoveIoCompletion timed out");
                    return response;
                }
            } else {
                port->cv.wait(lock, [&]() { return !port->queue.empty(); });
            }
        }
        if (port->queue.empty()) {
            response.result = STATUS_NO_MORE_ENTRIES;
            snprintf(response.error_msg, sizeof(response.error_msg), "No entries in IoCompletionPort");
            return response;
        }
        const auto entry = port->queue.front();
        port->queue.pop_front();
        bytes_transferred = std::get<2>(entry);
        key = std::get<1>(entry);
        overlapped = std::get<0>(entry);
    } else {
        response.result = STATUS_NO_MORE_ENTRIES;
        snprintf(response.error_msg, sizeof(response.error_msg), "No IoCompletionPorts available");
        return response;
    }
    if (KeyContext) *KeyContext = key;
    if (ApcContext) *ApcContext = overlapped;
    if (IoStatusBlock) {
        IoStatusBlock->Status = STATUS_SUCCESS;
        IoStatusBlock->Information = bytes_transferred;
    }
    return response;
}

IPCMessage SystemCallManager::Server_NtSetInformationThread(const IPCMessage &message) {
    std::shared_ptr<Process> process = g_processes[reinterpret_cast<HANDLE>(message.params[0])];
    auto ThreadHandle = reinterpret_cast<HANDLE>(message.params[1]);
    auto ThreadInformationClass = static_cast<THREADINFOCLASS>(message.params[2]);
    auto ThreadInformation = reinterpret_cast<PVOID>(message.params[3]);
    auto ThreadInformationLength = static_cast<ULONG>(message.params[4]);

    IPCMessage response = {};
    response.result = STATUS_SUCCESS;

    const auto it = g_threads.find(ThreadHandle);
    if (it == g_threads.end()) {
        response.result = STATUS_INVALID_HANDLE;
        snprintf(response.error_msg, sizeof(response.error_msg), "Invalid thread handle");
        return response;
    }

    const std::shared_ptr<Thread> thread_ctx = it->second;

    ChildMemoryManager memory_mgr(process->pid);

    switch (ThreadInformationClass) {
        case ThreadZeroTlsCell: {
            if (ThreadInformationLength != sizeof(ULONG)) {
                response.result = STATUS_INFO_LENGTH_MISMATCH;
                return response;
            }
            auto info_ptr = reinterpret_cast<uintptr_t>(ThreadInformation);
            auto index = memory_mgr.read<ULONG>(info_ptr);
            g_tls.tls_data[*index] = nullptr;
            return STATUS_SUCCESS;
        }
        case ThreadImpersonationToken: {
            if (ThreadInformationLength != sizeof(HANDLE)) {
                return STATUS_INFO_LENGTH_MISMATCH;
            }
            auto info_ptr = reinterpret_cast<uintptr_t>(ThreadInformation);
            auto token_handle = memory_mgr.read<HANDLE>(info_ptr);
            if (!token_handle) {
                return STATUS_ACCESS_VIOLATION;
            }
            // We do not currently support impersonation tokens
            return STATUS_SUCCESS;
        }
        case ThreadPriority: {
            if (ThreadInformationLength != sizeof(LONG)) {
                return STATUS_INFO_LENGTH_MISMATCH;
            }
            const auto info_ptr = reinterpret_cast<uintptr_t>(ThreadInformation);
            const auto priority = memory_mgr.read<LONG>(info_ptr);
            if (!priority) {
                return STATUS_ACCESS_VIOLATION;
            }
            thread_ctx->priority = *priority;
            return STATUS_SUCCESS;
        }
        case ThreadBasePriority: {
            if (ThreadInformationLength != sizeof(LONG)) {
                return STATUS_INFO_LENGTH_MISMATCH;
            }
            const auto info_ptr = reinterpret_cast<uintptr_t>(ThreadInformation);
            auto base_priority = memory_mgr.read<LONG>(info_ptr);
            if (!base_priority) {
                return STATUS_ACCESS_VIOLATION;
            }
            thread_ctx->base_priority = *base_priority;
            return STATUS_SUCCESS;
        }
        case ThreadAffinityMask: {
            if (ThreadInformationLength != sizeof(ULONG_PTR)) {
                return STATUS_INFO_LENGTH_MISMATCH;
            }
            const auto info_ptr = reinterpret_cast<uintptr_t>(ThreadInformation);
            const auto affinity = memory_mgr.read<ULONG_PTR>(info_ptr);
            if (!affinity) {
                return STATUS_ACCESS_VIOLATION;
            }
            thread_ctx->affinity_mask = affinity.value();
            // also set with pthread
            cpu_set_t cpuset;
            CPU_ZERO(&cpuset);
            for (size_t cpu = 0; cpu < sizeof(ULONG_PTR) * 8; cpu++) {
                if (affinity.value() & (1ULL << cpu)) {
                    CPU_SET(cpu, &cpuset);
                }
            }
            pthread_setaffinity_np(it->second->tid, sizeof(cpu_set_t), &cpuset);
            return STATUS_SUCCESS;
        }
        case ThreadHideFromDebugger: {
            // No action needed in this implementation
            return STATUS_SUCCESS;
        }
        case ThreadQuerySetWin32StartAddress: {
            if (ThreadInformationLength != sizeof(PVOID)) {
                return STATUS_INFO_LENGTH_MISMATCH;
            }
            const auto info_ptr = reinterpret_cast<uintptr_t>(ThreadInformation);
            auto start_address = memory_mgr.read<PVOID>(info_ptr);
            if (!start_address) {
                return STATUS_ACCESS_VIOLATION;
            }
            thread_ctx->start_address = start_address.value_or(nullptr);
            return STATUS_SUCCESS;
        }
        case ThreadGroupInformation: {
            if (ThreadInformationLength != sizeof(USHORT)) {
                return STATUS_INFO_LENGTH_MISMATCH;
            }
            const auto info_ptr = reinterpret_cast<uintptr_t>(ThreadInformation);
            auto group = memory_mgr.read<GROUP_AFFINITY>(info_ptr);
            if (!group) {
                return STATUS_ACCESS_VIOLATION;
            }
            thread_ctx->affinity_mask = group->Mask;
            return STATUS_SUCCESS;
        }
        case ThreadNameInformation: {
            if (ThreadInformationLength < sizeof(THREAD_NAME_INFORMATION)) {
                return STATUS_INFO_LENGTH_MISMATCH;
            }
            const auto info_ptr = reinterpret_cast<uintptr_t>(ThreadInformation);
            auto name_info = memory_mgr.read<THREAD_NAME_INFORMATION>(info_ptr);
            if (!name_info) {
                return STATUS_ACCESS_VIOLATION;
            }
            size_t name_length = name_info->ThreadName.Length;

            if (name_length > 0 && name_length <= 256) {
                std::vector<char> name_buffer(name_length + 1, 0);
                auto name_ptr = reinterpret_cast<uintptr_t>(name_info->ThreadName.Buffer);
                for (size_t i = 0; i < name_length; i++) {
                    auto ch = memory_mgr.read<char>(name_ptr + i);
                    if (!ch) {
                        return STATUS_ACCESS_VIOLATION;
                    }
                    name_buffer[i] = *ch;
                }
                pthread_setname_np(thread_ctx->tid, name_buffer.data());
            } else {
                return STATUS_INVALID_PARAMETER;
            }
            return STATUS_SUCCESS;
        }
        case ThreadWow64Context: {
            // We do not support WOW64 in this implementation
            return STATUS_SUCCESS;
        }
        case ThreadEnableAlignmentFaultFixup: {
            // No action needed in this implementation
            return STATUS_SUCCESS;
        }
        case ThreadPowerThrottlingState: {
            if (ThreadInformationLength != sizeof(THREAD_POWER_THROTTLING_STATE)) {
                return STATUS_INFO_LENGTH_MISMATCH;
            }
            const auto info_ptr = reinterpret_cast<uintptr_t>(ThreadInformation);
            auto power_state = memory_mgr.read<THREAD_POWER_THROTTLING_STATE>(info_ptr);
            if (!power_state) {
                return STATUS_ACCESS_VIOLATION;
            }
            // We do not currently manage power throttling
            return STATUS_SUCCESS;
        }
        case ThreadIdealProcessor: {
            if (ThreadInformationLength != sizeof(ULONG)) {
                return STATUS_INFO_LENGTH_MISMATCH;
            }
            const auto info_ptr = reinterpret_cast<uintptr_t>(ThreadInformation);
            auto ideal_processor = memory_mgr.read<ULONG>(info_ptr);
            if (!ideal_processor) {
                return STATUS_ACCESS_VIOLATION;
            }
            // We do not currently manage ideal processor
            return STATUS_SUCCESS;
        }
        case ThreadPriorityBoost: {
            if (ThreadInformationLength != sizeof(DWORD)) {
                return STATUS_INFO_LENGTH_MISMATCH;
            }
            const auto info_ptr = reinterpret_cast<uintptr_t>(ThreadInformation);
            auto boost = memory_mgr.read<DWORD>(info_ptr);
            if (!boost) {
                return STATUS_ACCESS_VIOLATION;
            }
            thread_ctx->priority = *boost ? thread_ctx->base_priority + 1 : thread_ctx->base_priority;
            return STATUS_SUCCESS;
        }
        case ThreadManageWritesToExecutableMemory: {
            if (ThreadInformationLength != sizeof(MANAGE_WRITES_TO_EXECUTABLE_MEMORY)) {
                return STATUS_INFO_LENGTH_MISMATCH;
            }
            // We do not currently manage writes to executable memory
            return STATUS_SUCCESS;
        }
        default:
            return STATUS_NOT_IMPLEMENTED;
    }
}


static void update_system_times() {
    if (!g_kuser_shared_data) return;

    const ULONGLONG system_time = get_system_time_as_file_time();
    const ULONGLONG interrupt_time = get_interrupt_time();
    const ULONGLONG tick_count = get_tick_count();

    // Update SystemTime
    g_kuser_shared_data->SystemTime.LowPart = static_cast<ULONG>(system_time & 0xFFFFFFFF);
    g_kuser_shared_data->SystemTime.High1Time = static_cast<LONG>(system_time >> 32);
    g_kuser_shared_data->SystemTime.High2Time = g_kuser_shared_data->SystemTime.High1Time;

    // Update InterruptTime
    g_kuser_shared_data->InterruptTime.LowPart = static_cast<ULONG>(interrupt_time & 0xFFFFFFFF);
    g_kuser_shared_data->InterruptTime.High1Time = static_cast<LONG>(interrupt_time >> 32);
    g_kuser_shared_data->InterruptTime.High2Time = g_kuser_shared_data->InterruptTime.High1Time;

    // Update TickCount
    g_kuser_shared_data->TickCount.LowPart = static_cast<ULONG>(tick_count & 0xFFFFFFFF);
    g_kuser_shared_data->TickCount.High1Time = static_cast<LONG>(tick_count >> 32);
    g_kuser_shared_data->TickCount.High2Time = static_cast<LONG>(tick_count >> 32);
    g_kuser_shared_data->TickCountQuad = tick_count;
    g_kuser_shared_data->TickCountLowDeprecated = static_cast<ULONG>(tick_count & 0xFFFFFFFF);
}

static bool initialize_kuser_shared_data() {
    trace("Initializing KUSER_SHARED_DATA at 0x", std::hex, KUSER_SHARED_DATA_ADDRESS, std::dec);

    void* addr = mmap(reinterpret_cast<void*>(KUSER_SHARED_DATA_ADDRESS),
                     KUSER_SHARED_DATA_SIZE,
                     PROT_READ | PROT_WRITE,
                     MAP_SHARED | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                     -1, 0);

    if (addr == MAP_FAILED || addr != reinterpret_cast<void*>(KUSER_SHARED_DATA_ADDRESS)) {
        error("Failed to allocate KUSER_SHARED_DATA at required address");
        return false;
    }

    g_kuser_shared_data = static_cast<KUSER_SHARED_DATA*>(addr);
    memset(g_kuser_shared_data, 0, KUSER_SHARED_DATA_SIZE);

    // Initialize with Windows 10 values
    g_kuser_shared_data->TickCountMultiplier = 0xFA000000;

    // System root path
    constexpr WCHAR system_root[] = { 'L', 'C', ':', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\0' };
    for (size_t i = 0; i < sizeof(system_root) / sizeof(WCHAR); ++i) {
        g_kuser_shared_data->_NtSystemRoot[i] = system_root[i];
    }

    // Crypto exponent
    g_kuser_shared_data->CryptoExponent = 65537;
    g_kuser_shared_data->TimeZoneId = 0;
    g_kuser_shared_data->LargePageMinimum = 0x200000;
    g_kuser_shared_data->_NtProductType = _NtProductWin_Nt;
    g_kuser_shared_data->ProductTypeIsValid = TRUE;
    g_kuser_shared_data->NativeProcessorArchitecture = PROCESSOR_ARCHITECTURE_AMD64;
    g_kuser_shared_data->_NtMajorVersion = 10;
    g_kuser_shared_data->_NtMinorVersion = 0;
    g_kuser_shared_data->_NtBuildNumber = 19045;

    // Initialize processor features
    g_kuser_shared_data->ProcessorFeatures[PF_FLOATING_POINT_PRECISION_ERRATA] = FALSE;
    g_kuser_shared_data->ProcessorFeatures[PF_FLOATING_POINT_EMULATED] = FALSE;
    g_kuser_shared_data->ProcessorFeatures[PF_COMPARE_EXCHANGE_DOUBLE] = TRUE;
    g_kuser_shared_data->ProcessorFeatures[PF_MMX_INSTRUCTIONS_AVAILABLE] = TRUE;
    g_kuser_shared_data->ProcessorFeatures[PF_XMMI_INSTRUCTIONS_AVAILABLE] = TRUE;
    g_kuser_shared_data->ProcessorFeatures[PF_3DNOW_INSTRUCTIONS_AVAILABLE] = FALSE;
    g_kuser_shared_data->ProcessorFeatures[PF_RDTSC_INSTRUCTION_AVAILABLE] = TRUE;
    g_kuser_shared_data->ProcessorFeatures[PF_PAE_ENABLED] = TRUE;
    g_kuser_shared_data->ProcessorFeatures[PF_XMMI64_INSTRUCTIONS_AVAILABLE] = TRUE;
    g_kuser_shared_data->ProcessorFeatures[PF_SSE_DAZ_MODE_AVAILABLE] = TRUE;
    g_kuser_shared_data->ProcessorFeatures[PF_NX_ENABLED] = TRUE;
    g_kuser_shared_data->ProcessorFeatures[PF_SSE3_INSTRUCTIONS_AVAILABLE] = TRUE;
    g_kuser_shared_data->ProcessorFeatures[PF_COMPARE_EXCHANGE128] = TRUE;
    g_kuser_shared_data->ProcessorFeatures[PF_COMPARE64_EXCHANGE128] = TRUE;
    g_kuser_shared_data->ProcessorFeatures[PF_XSAVE_ENABLED] = TRUE;

    g_kuser_shared_data->SuiteMask = 0x100;
    g_kuser_shared_data->KdDebuggerEnabled = FALSE;
    g_kuser_shared_data->NXSupportPolicy = 1;
    g_kuser_shared_data->SEHValidationPolicy = 1;
    g_kuser_shared_data->ActiveConsoleId = 1;
    g_kuser_shared_data->NumberOfPhysicalPages = 0x200000;
    g_kuser_shared_data->SafeBootMode = FALSE;
    g_kuser_shared_data->QpcFrequency = 3000000000LL;

    std::random_device rd;
    g_kuser_shared_data->Cookie = rd();

    g_kuser_shared_data->ActiveProcessorCount = std::thread::hardware_concurrency();
    g_kuser_shared_data->UnparkedProcessorCount = g_kuser_shared_data->ActiveProcessorCount;
    g_kuser_shared_data->ActiveGroupCount = 1;
    g_kuser_shared_data->QpcBypassEnabled = 1;
    g_kuser_shared_data->QpcSystemTimeIncrement = 333333;
    g_kuser_shared_data->QpcInterruptTimeIncrement = 333333;
    g_kuser_shared_data->SystemCall = 0;

    g_kuser_shared_data->SystemTime = { .LowPart = static_cast<ULONG>(get_system_time_as_file_time()) & 0xFFFFFFFF,
                                        .High1Time = static_cast<LONG>(get_system_time_as_file_time() >> 32),
                                        .High2Time = static_cast<LONG>(get_system_time_as_file_time() >> 32) };
    g_kuser_shared_data->TickCount = { .LowPart = static_cast<ULONG>(get_tick_count()), .High1Time = 0, .High2Time = 0 };
    g_kuser_shared_data->TickCountQuad = g_kuser_shared_data->TickCount.LowPart |
                                         (static_cast<ULONG64>(g_kuser_shared_data->TickCount.High1Time) << 32);
    g_kuser_shared_data->QpcBias = 0;
    g_kuser_shared_data->QpcReserved = 0;
    g_kuser_shared_data->InterruptTimeBias = 0;

    update_system_times();

    // Make read-only
    mprotect(g_kuser_shared_data, KUSER_SHARED_DATA_SIZE, PROT_READ);

    trace("KUSER_SHARED_DATA initialization complete");
    return true;
}

static void update_kuser_shared_data() {
    if (!g_kuser_shared_data) return;

    std::lock_guard<std::shared_mutex> lock(g_kuser_update_mutex);
    mprotect(g_kuser_shared_data, KUSER_SHARED_DATA_SIZE, PROT_READ | PROT_WRITE);
    update_system_times();
    mprotect(g_kuser_shared_data, KUSER_SHARED_DATA_SIZE, PROT_READ);
}

static void cleanup_kuser_shared_data() {
    if (g_kuser_shared_data) {
        munmap(g_kuser_shared_data, KUSER_SHARED_DATA_SIZE);
        g_kuser_shared_data = nullptr;
    }
}

static void initialize_default_current_peb() {
    if (g_current_peb) return;

    g_current_peb = new PEB();
    memset(g_current_peb, 0, sizeof(PEB));

    g_current_peb->NumberOfProcessors = sysconf(_SC_NPROCESSORS_ONLN);
    g_current_peb->OSMajorVersion = 10;
    g_current_peb->OSMinorVersion = 0;
    g_current_peb->OSBuildNumber = 19045;
    g_current_peb->OSPlatformId = VER_PLATFORM_WIN32_NT;
    g_current_peb->NumberOfHeaps = 1;

    auto& process_info = g_processes[g_tls.process];
    g_current_peb->ProcessHeaps = reinterpret_cast<PVOID*>(process_info->heaps_vec.data());
    g_current_peb->ProcessHeap = process_info->default_heap;

    g_current_peb->LdrData = new PEB_LDR_DATA();
    memset(g_current_peb->LdrData, 0, sizeof(PEB_LDR_DATA));
    g_current_peb->LdrData->EntryInProgress = process_info->hmodule;
    g_current_peb->LdrData->Initialized = /* Whether the loader is initialized */ TRUE;
    /*g_current_peb->LdrData->InInitializationOrderModuleList.Flink = &process_info.in_init_order_module_list;
    g_current_peb->LdrData->InInitializationOrderModuleList.Blink = &process_info.in_init_order_module_list;
    g_current_peb->LdrData->InLoadOrderModuleList.Flink = &process_info.in_load_order_module_list;
    g_current_peb->LdrData->InLoadOrderModuleList.Blink = &process_info.in_load_order_module_list;
    g_current_peb->LdrData->InMemoryOrderModuleList.Flink = &process_info.in_memory_order_module_list;
    g_current_peb->LdrData->InMemoryOrderModuleList.Blink = &process_info.in_memory_order_module_list;*/
    g_current_peb->LdrData->Length = sizeof(PEB_LDR_DATA);
    g_current_peb->LdrData->ShutdownInProgress = FALSE;
    g_current_peb->LdrData->ShutdownThreadId = nullptr;

    g_current_peb->FastPebLock = new RTL_CRITICAL_SECTION();
    memset(g_current_peb->FastPebLock, 0, sizeof(RTL_CRITICAL_SECTION));

    g_current_peb->SessionId = 1;

    g_current_peb->ProcessParameters = new RTL_USER_PROCESS_PARAMETERS();
    memset(g_current_peb->ProcessParameters, 0, sizeof(RTL_USER_PROCESS_PARAMETERS));
    g_current_peb->ProcessParameters->Environment = process_info->environment;

    g_current_peb->ProcessParameters->CurrentDirectory.DosPath.Buffer = new WCHAR[4];
    g_current_peb->ProcessParameters->CurrentDirectory.DosPath.MaximumLength = 8;
    const WCHAR cwd[] = { 'C', ':', '\\', '\0' };
    memcpy(g_current_peb->ProcessParameters->CurrentDirectory.DosPath.Buffer, cwd, sizeof(cwd));
    g_current_peb->ProcessParameters->CurrentDirectory.DosPath.Length = 6;

    // Create current directory handle
    int cwd_fd = open(".", O_RDONLY | O_DIRECTORY);
    if (cwd_fd >= 0) {
        auto cwd_handle = std::make_shared<File>();
        cwd_handle->fd = cwd_fd;
        cwd_handle->path = ".";
        cwd_handle->is_directory = true;
        g_current_peb->ProcessParameters->CurrentDirectory.Handle = g_next_handle;
        g_files[g_next_handle] = cwd_handle;
        ++g_next_handle_num;
    }
    g_current_peb->ImageBaseAddress = process_info->hmodule;

    g_current_peb->ApiSetMap = new API_SET_NAMESPACE();
    memset(g_current_peb->ApiSetMap, 0, sizeof(API_SET_NAMESPACE));
    static_cast<API_SET_NAMESPACE*>(g_current_peb->ApiSetMap)->Size = sizeof(API_SET_NAMESPACE);
    static_cast<API_SET_NAMESPACE*>(g_current_peb->ApiSetMap)->Version = 2;

    g_current_peb->SharedData = reinterpret_cast<PKUSER_SHARED_DATA>(KUSER_SHARED_DATA_ADDRESS);

    g_current_peb->HeapSegmentReserve = 0x10000; // 64KB
    g_current_peb->HeapSegmentCommit = 0x1000; // 4KB
    g_current_peb->HeapDeCommitTotalFreeThreshold = 0x10000;
    g_current_peb->HeapDeCommitFreeBlockThreshold = 0x1000;

    g_current_peb->NumberOfProcessors = sysconf(_SC_NPROCESSORS_ONLN);

    trace("Initialized PEB at ", std::hex, reinterpret_cast<uintptr_t>(g_current_peb));
}

static void cleanup_current_peb() {
    if (g_current_peb) {
        delete g_current_peb->LdrData;
        delete g_current_peb->FastPebLock;
        delete[] g_current_peb->ProcessParameters->CurrentDirectory.DosPath.Buffer;
        delete g_current_peb->ProcessParameters;
        delete static_cast<API_SET_NAMESPACE*>(g_current_peb->ApiSetMap);
        delete g_current_peb;
        g_current_peb = nullptr;
    }
}

static void initialize_default_current_teb() {
    if (g_current_teb) return;

    g_current_teb = new TEB();
    memset(g_current_teb, 0, sizeof(TEB));

    g_current_teb->Peb = g_current_peb;
    g_current_teb->ClientId.UniqueProcess = reinterpret_cast<HANDLE>(g_processes[g_tls.process]->pid);
    g_current_teb->ClientId.UniqueThread = g_tls.thread;
    g_current_teb->EnvironmentPointer = g_processes[g_tls.process]->environment;
    g_current_teb->LastErrorValue = g_tls.last_error;

    g_current_teb->Tib.StackBase = nullptr;
    g_current_teb->Tib.StackLimit = nullptr;
    g_current_teb->Tib.SubSystemTib = nullptr;
    g_current_teb->Tib.FiberData = nullptr;
    g_current_teb->Tib.ArbitraryUserPointer = nullptr;
    g_current_teb->Tib.Self = &g_current_teb->Tib;

    trace("Initialized TEB at ", std::hex, reinterpret_cast<uintptr_t>(g_current_teb));
}

static void cleanup_current_teb() {
    if (g_current_teb) {
        delete g_current_teb;
        g_current_teb = nullptr;
    }
}
class MemoryManager {
public:
    static void* allocate_executable_memory(size_t size, uintptr_t preferred_addr = 0) {
        if (preferred_addr != 0) {
            void* addr = mmap(reinterpret_cast<void*>(preferred_addr), size,
                             PROT_READ | PROT_WRITE | PROT_EXEC,
                             MAP_SHARED | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
            if (addr != MAP_FAILED && addr == reinterpret_cast<void*>(preferred_addr)) {
                trace("Allocated at preferred address: 0x", std::hex, preferred_addr, std::dec);
                return addr;
            }
            trace("Failed to allocate at preferred address 0x", std::hex, preferred_addr,
                  ", trying alternative location", std::dec);
        }

        void* addr = mmap(nullptr, size,
                         PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_SHARED | MAP_ANONYMOUS, -1, 0);

        if (addr != MAP_FAILED) {
            trace("Allocated at alternative address: 0x", std::hex,
                  reinterpret_cast<uintptr_t>(addr), std::dec);
        }
        return addr;
    }

    static void apply_section_permissions(const LIEF::PE::Binary& pe, void* mem, const uintptr_t base_addr) {
        for (const LIEF::PE::Section& section : pe.sections()) {
            const uint32_t virtual_addr = section.virtual_address();
            const size_t section_size = section.virtual_size();

            if (section_size == 0) continue;

            int prot = PROT_READ;
            const uint32_t characteristics = section.characteristics();

            prot |= PROT_WRITE; // Keep all writable for relocations & IAT
            if (characteristics & static_cast<uint32_t>(LIEF::PE::Section::CHARACTERISTICS::MEM_EXECUTE))
                prot |= PROT_EXEC;

            if (prot & PROT_EXEC) {
                prot |= PROT_READ;
            }

            void* section_addr = reinterpret_cast<void*>(base_addr + virtual_addr);
            trace("Setting section ", converter.from_bytes(section.name()),
                  " permissions: ", (prot & PROT_READ ? "R" : "-"),
                  (prot & PROT_WRITE ? "W" : "-"), (prot & PROT_EXEC ? "X" : "-"));

            if (mprotect(section_addr, section_size, prot) != 0) {
                warn("Failed to set permissions for section ",
                      converter.from_bytes(section.name()), ": ", strerror(errno));
            }
        }
    }

    static void apply_relocations(const LIEF::PE::Binary& pe, void* mem, uintptr_t base_addr) {
        if (!pe.has_relocations()) {
            trace("No relocations found");
            return;
        }

        const uintptr_t original_base = pe.optional_header().imagebase();
        const int64_t delta = static_cast<int64_t>(base_addr) - static_cast<int64_t>(original_base);

        if (delta == 0) {
            trace("Loaded at preferred base - no relocations needed");
            return;
        }

        trace("Applying relocations with delta: 0x", std::hex, delta, std::dec);

        size_t reloc_count = 0;
        for (const LIEF::PE::Relocation& reloc_block : pe.relocations()) {
            for (const auto& entry : reloc_block.entries()) {
                const uint32_t rva = entry.position();

                if (rva >= pe.optional_header().sizeof_image() - 8) {
                    continue;
                }

                const uintptr_t fix_addr = base_addr + rva;

                switch (entry.type()) {
                    case LIEF::PE::RelocationEntry::BASE_TYPES::ABS:
                        break;
                    case LIEF::PE::RelocationEntry::BASE_TYPES::HIGH:
                        *reinterpret_cast<uint16_t*>(fix_addr) += static_cast<uint16_t>((delta >> 16) & 0xFFFF);
                        reloc_count++;
                        break;
                    case LIEF::PE::RelocationEntry::BASE_TYPES::LOW:
                        *reinterpret_cast<uint16_t*>(fix_addr) += static_cast<uint16_t>(delta & 0xFFFF);
                        reloc_count++;
                        break;
                    case LIEF::PE::RelocationEntry::BASE_TYPES::HIGHLOW:
                        *reinterpret_cast<uint32_t*>(fix_addr) += static_cast<uint32_t>(delta & 0xFFFFFFFF);
                        reloc_count++;
                        break;
                    case LIEF::PE::RelocationEntry::BASE_TYPES::DIR64:
                        *reinterpret_cast<uint64_t*>(fix_addr) += static_cast<uint64_t>(delta);
                        reloc_count++;
                        break;
                    default:
                        trace("Unsupported relocation type: ", static_cast<uint16_t>(entry.type()));
                        break;
                }
            }
        }
        trace("Applied ", reloc_count, " relocations");

        // Also find any references to the original base in each section and fix them (scan .data & .rdata)
        return; // Disabled for now as it causes issues with some binaries
        for (const LIEF::PE::Section& section : pe.sections()) {
            /*if (section.name() != ".data" && section.name() != ".rdata") {
                continue;
            }*/
            const uint32_t virtual_addr = section.virtual_address();
            const size_t section_size = section.virtual_size();
            if (section_size < 8) continue;
            const uintptr_t section_start = base_addr + virtual_addr;
            const uintptr_t section_end = section_start + section_size - 8;
            size_t fixup_count = 0;
            for (uintptr_t addr = section_start; addr <= section_end; addr++) {
                if (auto* potential_ptr = reinterpret_cast<uint64_t*>(addr);
                    *potential_ptr >= original_base &&
                    *potential_ptr < original_base + pe.optional_header().sizeof_image()) {
                    // Fix it up
                    *potential_ptr += static_cast<uint64_t>(delta);
                    fixup_count++;
                }
            }
            if (fixup_count > 0) {
                trace("Fixed ", fixup_count, " references to original base in section ",
                      converter.from_bytes(section.name()));
            }
        }
    }

private:
    static void initialize_security_cookie(const LIEF::PE::Binary& pe, uintptr_t base_addr) {
        if (!pe.load_configuration()) {
            trace("No load config - skipping security cookie initialization");
            return;
        }

        const auto& load_config = pe.load_configuration();
        if (load_config->security_cookie() == 0) {
            trace("No security cookie - skipping initialization");
            return;
        }

        const uintptr_t cookie_rva = load_config->security_cookie() - pe.optional_header().imagebase();
        if (cookie_rva >= pe.optional_header().sizeof_image() - sizeof(uintptr_t)) {
            warn("Invalid security cookie RVA");
            return;
        }

        auto cookie_addr = reinterpret_cast<uintptr_t*>(base_addr + cookie_rva);
        if (*cookie_addr != 0x2B992DDFA232) {
            trace("Security cookie already initialized");
            return;
        }

        uintptr_t new_cookie = static_cast<uintptr_t>(time(nullptr)) ^ reinterpret_cast<uintptr_t>(&new_cookie);
        new_cookie = (new_cookie << 32) | (new_cookie >> 32);
        if (new_cookie == 0x2B992DDFA232) {
            new_cookie ^= 0x5A5A5A5A5A5A5A5A;
        }
        *cookie_addr = new_cookie;
        trace("Initialized security cookie at 0x", std::hex, reinterpret_cast<uintptr_t>(cookie_addr),
              " with value 0x", new_cookie, std::dec);
    }
};

// ============================================================================
// API SET RESOLVER
// ============================================================================

class ApiSetResolver {
private:
    std::unordered_map<std::string, std::string> api_mapping;
    bool is_loaded = false;

    static std::string trim(const std::string& str) {
        const size_t start = str.find_first_not_of(" \t\r\n");
        if (start == std::string::npos) return "";
        const size_t end = str.find_last_not_of(" \t\r\n");
        return str.substr(start, end - start + 1);
    }

    bool load_apiset_text(const std::string& filename) {
        std::ifstream file(filename);
        if (!file.is_open()) {
            trace("Could not open API set text file: ", converter.from_bytes(filename));
            return false;
        }

        std::string line;
        int line_number = 0;
        int parsed_count = 0;

        while (std::getline(file, line)) {
            line_number++;
            line = trim(line);

            if (line.empty() || line[0] == '#' || line.starts_with("//")) {
                continue;
            }

            if (!line.starts_with("apiset ")) {
                continue;
            }

            line = line.substr(7);
            line = trim(line);

            const size_t equals_pos = line.find('=');
            if (equals_pos == std::string::npos) {
                warn("Invalid format at line ", line_number, ": ", converter.from_bytes(line));
                continue;
            }

            std::string api_name = trim(line.substr(0, equals_pos));
            std::string dll_name = trim(line.substr(equals_pos + 1));

            if (!dll_name.empty() && !dll_name.ends_with(".dll")) {
                dll_name += ".dll";
            }

            if (api_name.empty()) {
                warn("Empty API name at line ", line_number);
                continue;
            }

            std::ranges::transform(api_name, api_name.begin(), ::tolower);
            api_mapping[api_name] = dll_name;
            parsed_count++;
        }

        if (parsed_count > 0) {
            trace("Loaded ", parsed_count, " API set mappings from text file: ", converter.from_bytes(filename));
            return true;
        }
        return false;
    }

    bool load_apiset_json(const std::string& filename) {
        try {
            std::ifstream file(filename);
            if (!file.is_open()) {
                trace("Could not open API set JSON file: ", converter.from_bytes(filename));
                return false;
            }

            nlohmann::json data;
            file >> data;

            int parsed_count = 0;
            for (const auto& ns : data["namespaces"]) {
                std::string name = ns["name"];
                std::string host = ns["host"];
                std::ranges::transform(name, name.begin(), ::tolower);
                api_mapping[name] = host;
                parsed_count++;
            }

            trace("Loaded ", parsed_count, " API set mappings from JSON file: ", converter.from_bytes(filename));
            return true;
        } catch (const std::exception& e) {
            trace("Error loading API set JSON: ", e.what());
            return false;
        }
    }

    enum class FileFormat { UNKNOWN, JSON, TEXT };

    static FileFormat detect_format(const std::string& filename) {
        std::ifstream file(filename);
        if (!file.is_open()) return FileFormat::UNKNOWN;

        std::string line;
        while (std::getline(file, line)) {
            line = trim(line);
            if (line.empty() || line[0] == '#' || line.starts_with("//")) {
                continue;
            }

            if (line[0] == '{' || line.starts_with("\"namespaces\"")) {
                return FileFormat::JSON;
            }

            if (line.starts_with("apiset ") && line.find('=') != std::string::npos) {
                return FileFormat::TEXT;
            }

            if (line.length() > 10) break;
        }

        if (filename.ends_with(".json")) return FileFormat::JSON;
        if (filename.ends_with(".txt") || filename.ends_with(".def")) return FileFormat::TEXT;

        return FileFormat::UNKNOWN;
    }

public:
    bool load_apiset_file(const std::string& filename) {
        const FileFormat format = detect_format(filename);

        switch (format) {
            case FileFormat::JSON:
                if (load_apiset_json(filename)) {
                    is_loaded = true;
                    return true;
                }
                break;
            case FileFormat::TEXT:
                if (load_apiset_text(filename)) {
                    is_loaded = true;
                    return true;
                }
                break;
            case FileFormat::UNKNOWN:
                if (load_apiset_json(filename) || load_apiset_text(filename)) {
                    is_loaded = true;
                    return true;
                }
                break;
        }
        return false;
    }

    bool load_multiple_files(const std::vector<std::string>& filenames) {
        bool any_loaded = false;
        for (const auto& filename : filenames) {
            if (load_apiset_file(filename)) {
                any_loaded = true;
            }
        }
        return any_loaded;
    }

    std::string resolve_dll(const std::string& dll_name) const {
        if (!is_loaded) {
            return dll_name;
        }

        std::string lower_name = dll_name;
        std::ranges::transform(lower_name, lower_name.begin(), ::tolower);

        if (const auto it = api_mapping.find(lower_name); it != api_mapping.end()) {
            if (it->second.empty()) {
                trace("API set ", converter.from_bytes(dll_name), " has no implementation");
                return dll_name;
            }
            trace("API set resolved: ", converter.from_bytes(dll_name), " -> ", converter.from_bytes(it->second));
            return it->second;
        }

        return dll_name;
    }

    static bool is_api_set(const std::string& dll_name) {
        return dll_name.starts_with("api-ms-") || dll_name.starts_with("ext-ms-");
    }

    void populate_peb_api_set_map() const {
        if (!g_current_peb) {
            trace("PEB is null, cannot populate ApiSetMap");
            return;
        }

        if (g_current_peb->ApiSetMap) {
            free(g_current_peb->ApiSetMap);
            g_current_peb->ApiSetMap = nullptr;
        }

        if (api_mapping.empty()) {
            trace("No API set mappings to populate");
            g_current_peb->ApiSetMap = static_cast<API_SET_NAMESPACE*>(malloc(sizeof(API_SET_NAMESPACE)));
            if (g_current_peb->ApiSetMap) {
                auto* api_set_namespace = static_cast<API_SET_NAMESPACE*>(g_current_peb->ApiSetMap);
                memset(api_set_namespace, 0, sizeof(API_SET_NAMESPACE));
                api_set_namespace->Size = sizeof(API_SET_NAMESPACE);
                api_set_namespace->Version = 6;
                api_set_namespace->Count = 0;
                api_set_namespace->EntryOffset = sizeof(API_SET_NAMESPACE);
            }
            return;
        }

        // Calculate required memory size
        size_t total_size = sizeof(API_SET_NAMESPACE);
        size_t entries_size = api_mapping.size() * sizeof(API_SET_NAMESPACE_ENTRY);
        size_t strings_size = 0;

        for (std::pair<std::string, std::string> api : api_mapping) {
            // remove .dll from api_name if present
            if (api.first.ends_with(".dll")) {
                api.first = api.first.substr(0, api.first.length() - 4);
            }
            // ensure api_name is null-terminated
            if (!api.first.empty() && api.first.back() != '\0') {
                api.first += '\0';
            }
            // ensure dll_name is null-terminated
            if (!api.first.empty() && api.first.back() != '\0') {
                api.first += '\0';
            }
            strings_size += (api.first.length() + 1) * sizeof(WCHAR);
            if (!api.second.empty()) {
                strings_size += (api.second.length() + 1) * sizeof(WCHAR);
                strings_size += sizeof(API_SET_VALUE_ENTRY);
            }
        }

        total_size = (total_size + entries_size + strings_size + 7) & ~7;

        trace("Allocating ", total_size, " bytes for API set map with ", api_mapping.size(), " entries");

        g_current_peb->ApiSetMap = static_cast<API_SET_NAMESPACE*>(malloc(total_size));
        if (!g_current_peb->ApiSetMap) {
            trace("Failed to allocate memory for ApiSetMap");
            return;
        }

        auto* api_set_namespace = static_cast<API_SET_NAMESPACE*>(g_current_peb->ApiSetMap);
        memset(api_set_namespace, 0, total_size);

        api_set_namespace->Size = total_size;
        api_set_namespace->Version = 6;
        api_set_namespace->Flags = 0;
        api_set_namespace->Count = api_mapping.size();
        api_set_namespace->EntryOffset = sizeof(API_SET_NAMESPACE);
        api_set_namespace->HashOffset = 0;
        api_set_namespace->HashFactor = 0;

        trace("Successfully populated PEB ApiSetMap with ", api_mapping.size(), " API set mappings");
    }

    void print_statistics() const {
        if (!is_loaded) {
            trace("No API set mappings loaded");
            return;
        }

        int implemented_count = 0;
        int unimplemented_count = 0;

        for (const auto& [api, dll] : api_mapping) {
            if (dll.empty()) {
                unimplemented_count++;
            } else {
                implemented_count++;
            }
        }

        trace("API Set Statistics:");
        trace("  Total mappings: ", api_mapping.size());
        trace("  Implemented: ", implemented_count);
        trace("  Unimplemented: ", unimplemented_count);
    }
};

ApiSetResolver api_resolver;

struct LoadedModule {
    std::wstring name;
    uintptr_t base_address;
    size_t size;
    std::shared_ptr<LIEF::PE::Binary> pe_binary;
    bool is_dll;
    uintptr_t entry_point;
    bool imports_resolved = false;

    enum class ImportState {
        NOT_STARTED,
        IN_PROGRESS,
        COMPLETED
    };
    ImportState import_state = ImportState::NOT_STARTED;

    LoadedModule(std::wstring n, const uintptr_t base, const size_t sz,
                 std::shared_ptr<LIEF::PE::Binary> pe, const bool DLL = false)
        : name(std::move(n)), base_address(base), size(sz), pe_binary(std::move(pe)),
          is_dll(DLL), entry_point(0) {
        if (pe_binary && pe_binary->optional_header().addressof_entrypoint() != 0) {
            entry_point = base_address + pe_binary->optional_header().addressof_entrypoint();
        }
    }
};


struct FunctionWrapper {
    void* original_func;
    void* wrapper_func;
    std::string func_name;
    std::string dll_name;
};

class AssemblyWrapperGenerator {
private:
    static constexpr size_t WRAPPER_SIZE = 128;

    struct WrapperData {
        void* original_func;
        const char* func_name;
        const char* dll_name;
    };

    static void log_function_call(const char* dll_name, const char* func_name, void* original_func) {
        trace("CALL: ", dll_name, "::", func_name, " -> 0x", std::hex, original_func, std::dec);
    }

public:
    static void* create_wrapper(void* original_func, const char* func_name, const char* dll_name) {
        // For now, return original function - wrapper generation is complex
        // In a full implementation, this would generate assembly trampolines
        return original_func;
    }

    static void cleanup_wrapper(void* wrapper_mem) {
        if (wrapper_mem) {
            munmap(wrapper_mem, WRAPPER_SIZE);
        }
    }
};

// ============================================================================
// EXPORT RESOLVER
// ============================================================================

class ExportResolver {
private:
    std::unordered_map<uintptr_t, LoadedModule*>& module_by_address;
    std::unordered_map<std::wstring, LoadedModule*>& module_by_name;
    std::vector<std::shared_ptr<LoadedModule>>& loaded_modules;
    ApiSetResolver& api_resolver;
    std::vector<std::wstring>& dll_search_paths;

    // Forward declaration of the loader class method we need
    class WindowsPELoader* loader_instance;

    static std::string normalize_dll_name(const std::string& dll_name) {
        std::string normalized = dll_name;
        std::ranges::transform(normalized, normalized.begin(), ::tolower);
        if (!normalized.ends_with(".dll")) {
            normalized += ".dll";
        }
        return normalized;
    }

    [[nodiscard]] std::wstring find_dll_file(const std::wstring& dll_name) const {
        if (std::filesystem::exists(dll_name)) {
            return dll_name;
        }

        std::wstring dll_with_ext = dll_name;
        if (!dll_with_ext.ends_with(L".dll")) {
            dll_with_ext += L".dll";
            if (std::filesystem::exists(dll_with_ext)) {
                return dll_with_ext;
            }
        }

        for (const auto& path : dll_search_paths) {
            std::filesystem::path full_path = std::filesystem::path(path) / dll_with_ext;
            if (std::filesystem::exists(full_path)) {
                return full_path.wstring();
            }
        }

        return L"";
    }

    [[nodiscard]] LoadedModule* load_module_for_forward(const std::wstring& dll_name) const {
        std::wstring dll_lower = dll_name;
        std::ranges::transform(dll_lower, dll_lower.begin(), ::tolower);

        // Check if already loaded
        if (auto it = module_by_name.find(dll_lower); it != module_by_name.end()) {
            return it->second;
        }

        trace("Loading module for forward: ", dll_name);

        // Find and parse DLL
        std::wstring dll_path = find_dll_file(dll_name);
        if (dll_path.empty()) {
            trace("Could not find DLL for forward: ", dll_name);
            return nullptr;
        }

        std::string dll_path_str = converter.to_bytes(dll_path);
        std::shared_ptr<LIEF::PE::Binary> pe_binary(
            LIEF::PE::Parser::parse(dll_path_str).release());

        if (!pe_binary) {
            trace("Failed to parse PE DLL for forward: ", dll_path);
            return nullptr;
        }

        // Allocate and map memory
        size_t image_size = pe_binary->optional_header().sizeof_image();
        image_size = (image_size + 4095) & ~4095;

        uintptr_t preferred_base = pe_binary->optional_header().imagebase();
        void* memory = MemoryManager::allocate_executable_memory(image_size, preferred_base);

        if (!memory) {
            trace("Failed to allocate memory for forward DLL: ", dll_name);
            return nullptr;
        }

        auto base_addr = reinterpret_cast<uintptr_t>(memory);
        memset(memory, 0, image_size);

        // Map sections
        for (const auto& section : pe_binary->sections()) {
            uint32_t virtual_addr = section.virtual_address();
            auto raw_data = section.content();

            if (virtual_addr + raw_data.size() <= image_size) {
                memcpy(reinterpret_cast<void*>(base_addr + virtual_addr),
                       raw_data.data(), raw_data.size());
            }
        }

        // Create module entry
        auto module = std::make_shared<LoadedModule>(
            dll_lower, base_addr, image_size, std::move(pe_binary), true);
        LoadedModule* module_ptr = module.get();

        loaded_modules.push_back(std::move(module));
        module_by_address[base_addr] = module_ptr;
        module_by_name[dll_lower] = module_ptr;

        // Apply relocations and permissions
        MemoryManager::apply_relocations(*module_ptr->pe_binary, memory, base_addr);
        MemoryManager::apply_section_permissions(*module_ptr->pe_binary, memory, base_addr);

        trace("Successfully loaded module for forward: ", dll_name, " at 0x", std::hex, base_addr, std::dec);
        return module_ptr;
    }

public:
    ExportResolver(std::unordered_map<uintptr_t, LoadedModule*>& modules,
                   std::unordered_map<std::wstring, LoadedModule*>& by_name,
                   std::vector<std::shared_ptr<LoadedModule>>& loaded_mods,
                   ApiSetResolver& resolver,
                   std::vector<std::wstring>& search_paths)
        : module_by_address(modules), module_by_name(by_name),
          loaded_modules(loaded_mods), api_resolver(resolver),
          dll_search_paths(search_paths), loader_instance(nullptr) {}

    void* find_export(LoadedModule* module, const std::wstring& func_name) {
        if (!module || !module->pe_binary->has_exports()) {
            return nullptr;
        }

        trace("Looking for export '", func_name, "' in module '", module->name, "'");

        const LIEF::PE::Export* export_table = module->pe_binary->get_export();

        for (const auto& entry : export_table->entries()) {
            if (converter.from_bytes(entry.name()) == func_name) {
                uint32_t address = entry.address();
                if (address == 0) address = entry.function_rva();

                if (address == 0) {
                    trace("Export has no valid address");
                    return nullptr;
                }

                // Check if this is a forwarded export
                const LIEF::PE::DataDirectory* export_dir = nullptr;
                for (const auto& dir : module->pe_binary->data_directories()) {
                    if (dir.type() == LIEF::PE::DataDirectory::TYPES::EXPORT_TABLE) {
                        export_dir = &dir;
                        break;
                    }
                }

                if (export_dir && address >= export_dir->RVA() &&
                    address < export_dir->RVA() + export_dir->size()) {
                    // Forwarded export
                    const char* forwarder_string = reinterpret_cast<const char*>(
                        module->base_address + address);
                    trace("Forwarded export: ", func_name, " -> ", forwarder_string);
                    return resolve_forwarded_export(module, forwarder_string);
                } else {
                    // Direct export
                    void* direct_addr = reinterpret_cast<void*>(module->base_address + address);
                    trace("Direct export: ", func_name, " = 0x", std::hex,
                          reinterpret_cast<uintptr_t>(direct_addr), std::dec);
                    return direct_addr;
                }
            }
        }

        trace("Export not found: ", func_name);
        return nullptr;
    }

    void* resolve_forwarded_export(LoadedModule* module, const std::string& forwarder_string) {
        size_t dot_pos = forwarder_string.find('.');
        if (dot_pos == std::string::npos) {
            trace("Invalid forwarder string (no dot): ", converter.from_bytes(forwarder_string));
            return nullptr;
        }

        std::string target_dll = normalize_dll_name(forwarder_string.substr(0, dot_pos));
        std::string target_func = forwarder_string.substr(dot_pos + 1);

        // Handle ordinal forwards (e.g., "KERNEL32.#123")
        bool is_ordinal = target_func.starts_with("#");
        uint32_t ordinal = 0;
        if (is_ordinal) {
            try {
                ordinal = std::stoul(target_func.substr(1));
            } catch (const std::exception&) {
                trace("Invalid ordinal in forward: ", converter.from_bytes(forwarder_string));
                return nullptr;
            }
        }

        // Resolve API sets
        if (ApiSetResolver::is_api_set(target_dll)) {
            std::string resolved = api_resolver.resolve_dll(target_dll);
            if (resolved != target_dll) {
                target_dll = normalize_dll_name(resolved);
                trace("API set resolved for forward: ", converter.from_bytes(forwarder_string), " -> ",  converter.from_bytes(target_dll), ".",  converter.from_bytes(target_func));
            }
        }

        std::wstring target_dll_wide = converter.from_bytes(target_dll);

        trace("Resolving forward: ", converter.from_bytes(target_dll), ".", converter.from_bytes(target_func));

        // Find or load the target module
        LoadedModule* target_module = nullptr;
        std::wstring target_dll_lower = target_dll_wide;
        std::ranges::transform(target_dll_lower, target_dll_lower.begin(), ::tolower);

        if (auto it = module_by_name.find(target_dll_lower); it != module_by_name.end()) {
            target_module = it->second;
        } else {
            // Load the module
            target_module = load_module_for_forward(target_dll_wide);
            if (!target_module) {
                trace("Failed to load target module for forward: ", converter.from_bytes(target_dll));
                return nullptr;
            }
        }

        if (!target_module->pe_binary->has_exports()) {
            trace("Target module has no exports: ", converter.from_bytes(target_dll));
            return nullptr;
        }

        // Find the target function
        const LIEF::PE::Export* export_table = target_module->pe_binary->get_export();

        if (is_ordinal) {
            // Look up by ordinal
            for (const auto& entry : export_table->entries()) {
                if (entry.ordinal() == ordinal) {
                    uint32_t address = entry.address();
                    if (address == 0) address = entry.function_rva();

                    if (address == 0) {
                        trace("Forward target ordinal has no valid address: ", ordinal);
                        return nullptr;
                    }

                    void* target_addr = reinterpret_cast<void*>(target_module->base_address + address);
                    trace("Forward resolved by ordinal: ", converter.from_bytes(forwarder_string), " -> 0x", std::hex,
                          reinterpret_cast<uintptr_t>(target_addr), std::dec);
                    return target_addr;
                }
            }
            trace("Forward target ordinal not found: ", ordinal, " in ", converter.from_bytes(target_dll));
        } else {
            // Look up by name
            std::wstring target_func_wide = converter.from_bytes(target_func);
            for (const auto& entry : export_table->entries()) {
                if (converter.from_bytes(entry.name()) == target_func_wide) {
                    uint32_t address = entry.address();
                    if (address == 0) address = entry.function_rva();

                    if (address == 0) {
                        trace("Forward target function has no valid address: ", converter.from_bytes(target_func));
                        return nullptr;
                    }

                    // Check for nested forwarding
                    const LIEF::PE::DataDirectory* export_dir = nullptr;
                    for (const auto& dir : target_module->pe_binary->data_directories()) {
                        if (dir.type() == LIEF::PE::DataDirectory::TYPES::EXPORT_TABLE) {
                            export_dir = &dir;
                            break;
                        }
                    }

                    if (export_dir && address >= export_dir->RVA() &&
                        address < export_dir->RVA() + export_dir->size()) {
                        // Nested forward - recursively resolve
                        const char* nested_forwarder = reinterpret_cast<const char*>(
                            target_module->base_address + address);
                        trace("Nested forward detected: ", converter.from_bytes(target_func), " -> ", nested_forwarder);
                        return resolve_forwarded_export(target_module, nested_forwarder);
                    } else {
                        void* target_addr = reinterpret_cast<void*>(target_module->base_address + address);
                        trace("Forward resolved: ", converter.from_bytes(forwarder_string), " -> 0x", std::hex,
                              reinterpret_cast<uintptr_t>(target_addr), std::dec);
                        return target_addr;
                    }
                }
            }
            trace("Forward target function not found: ", converter.from_bytes(target_func), " in ", converter.from_bytes(target_dll));
        }

        return nullptr;
    }
};

// ============================================================================
// IMPORT RESOLVER
// ============================================================================

class ImportResolver {
private:
    std::vector<std::shared_ptr<LoadedModule>>& loaded_modules;
    std::unordered_map<std::wstring, LoadedModule*>& module_by_name;
    std::unordered_map<uintptr_t, LoadedModule*>& module_by_address;
    ApiSetResolver& api_resolver;
    ExportResolver& export_resolver;
    bool enable_function_tracing;
    std::unordered_map<void*, void*> function_wrappers;
    std::shared_mutex resolution_mutex;  // NEW: Protects import resolution

public:
    ImportResolver(std::vector<std::shared_ptr<LoadedModule>>& modules,
                   std::unordered_map<std::wstring, LoadedModule*>& by_name,
                   std::unordered_map<uintptr_t, LoadedModule*>& by_address,
                   ApiSetResolver& resolver, ExportResolver& export_res)
        : loaded_modules(modules), module_by_name(by_name), module_by_address(by_address),
          api_resolver(resolver), export_resolver(export_res), enable_function_tracing(false) {}

    void resolve_imports(const LIEF::PE::Binary& pe, uintptr_t base_addr);
    void set_function_tracing(bool enable) { enable_function_tracing = enable; }

private:
    void* create_function_wrapper(void* original_func, const std::string& func_name, const std::string& dll_name) {
        if (!enable_function_tracing) {
            return original_func ? original_func :
                   AssemblyWrapperGenerator::create_wrapper(nullptr, func_name.c_str(), dll_name.c_str());
        }

        if (auto it = function_wrappers.find(original_func); it != function_wrappers.end()) {
            return it->second;
        }

        void* wrapper = AssemblyWrapperGenerator::create_wrapper(
            original_func, func_name.c_str(), dll_name.c_str());

        if (wrapper && wrapper != original_func && original_func) {
            function_wrappers[original_func] = wrapper;
        }

        return wrapper;
    }
};

void ImportResolver::resolve_imports(const LIEF::PE::Binary& pe, uintptr_t base_addr) {
    if (!pe.has_imports()) {
        return;
    }

    trace("\n=== RESOLVING IMPORTS ===");

    // Find current module
    LoadedModule* current_module = nullptr;
    for (const auto& [addr, module] : module_by_address) {
        if (addr == base_addr) {
            current_module = module;
            break;
        }
    }

    if (!current_module) {
        trace("ERROR: Could not find current module for base address 0x", std::hex, base_addr, std::dec);
        return;
    }

    std::wstring current_module_name = current_module->name;

    // Process imports
    for (const LIEF::PE::Import& import : pe.imports()) {
        std::wstring original_dll_name = converter.from_bytes(import.name());
        std::ranges::transform(original_dll_name, original_dll_name.begin(), ::tolower);

        if (original_dll_name == current_module_name) {
            trace("Skipping import resolution for self-dependency: ", current_module_name);
            continue;
        }

        // Apply API set resolution to get the actual DLL we should resolve against
        std::wstring resolved_dll_name = original_dll_name;
        bool is_api_set = false;

        if (std::string dll_name_str = converter.to_bytes(original_dll_name);
            ApiSetResolver::is_api_set(dll_name_str)) {
            std::string resolved = api_resolver.resolve_dll(dll_name_str);
            if (resolved != dll_name_str) {
                resolved_dll_name = converter.from_bytes(resolved);
                std::ranges::transform(resolved_dll_name, resolved_dll_name.begin(), ::tolower);
                is_api_set = true;
                trace("API SET RESOLUTION: ", original_dll_name, " -> ", resolved_dll_name);
            }
        }

        // Look up the RESOLVED module (not the original API set)
        LoadedModule* dll_module = nullptr;
        if (auto it = module_by_name.find(resolved_dll_name); it != module_by_name.end()) {
            dll_module = it->second;
        }

        if (!dll_module) {
            warn("No module loaded for resolved DLL: ", resolved_dll_name,
                 " (original: ", original_dll_name, ")");
            continue;
        }

        trace("\n--- Resolving imports from: ", original_dll_name,
              (is_api_set ? L" (resolved to " + resolved_dll_name + L")" : L""), " ---");

        // Resolve each function import
        for (const LIEF::PE::ImportEntry& entry : import.entries()) {
            if (entry.name().empty()) {
                continue;
            }

            const std::wstring& func_name = converter.from_bytes(entry.name());
            trace("Resolving: ", func_name, " from ", resolved_dll_name);

            // Find the export in the RESOLVED module (e.g., kernel32.dll, not api-ms-*)
            void* func_addr = export_resolver.find_export(dll_module, func_name);

            // Create wrapper (handles both resolved and unresolved functions)
            void* wrapped_func = create_function_wrapper(
                func_addr,
                entry.name(),
                converter.to_bytes(resolved_dll_name) // Use resolved DLL name for wrapper
            );

            uint64_t iat_rva = entry.iat_address();
            if (iat_rva == 0 || iat_rva >= pe.optional_header().sizeof_image()) {
                trace("  Invalid IAT RVA: 0x", std::hex, iat_rva, std::dec);
                continue;
            }

            auto* iat_ptr = reinterpret_cast<uintptr_t*>(base_addr + iat_rva);

            if (!wrapped_func) {
                trace("  RESOLUTION FAILED for ", func_name, " in ", resolved_dll_name);
                *iat_ptr = 0;
            } else {
                if (func_addr) {
                    trace("  RESOLUTION SUCCESS: ", func_name, " -> 0x", std::hex,
                          reinterpret_cast<uintptr_t>(func_addr), std::dec,
                          " (from ", resolved_dll_name, ")");
                } else {
                    trace("  STUB CREATED: ", func_name, " -> stub at 0x", std::hex,
                          reinterpret_cast<uintptr_t>(wrapped_func), std::dec);
                }
                *iat_ptr = reinterpret_cast<uintptr_t>(wrapped_func);
            }
        }
    }

    // Mark imports as resolved
    if (current_module) {
        current_module->imports_resolved = true;
        current_module->import_state = LoadedModule::ImportState::COMPLETED;
    }

    trace("=== IMPORT RESOLUTION COMPLETE ===\n");
}

enum class Message {
    CREATE_EVENT,
    SET_EVENT,
    RESET_EVENT,
    WAIT_EVENT,
    CREATE_SEMAPHORE,
    RELEASE_SEMAPHORE,
    CREATE_MUTEX,
    RELEASE_MUTEX,
    CREATE_CRITICAL_SECTION,
    ENTER_CRITICAL_SECTION,
    LEAVE_CRITICAL_SECTION,
    DELETE_CRITICAL_SECTION,
    CREATE_TIMER,
    SET_TIMER,
    CANCEL_TIMER,
    CREATE_WAITABLE_TIMER,
    SET_WAITABLE_TIMER,
    CANCEL_WAITABLE_TIMER,
    CREATE_MAPPING,
    MAP_VIEW_OF_FILE,
    UNMAP_VIEW_OF_FILE,
    CREATE_THREAD,
    EXIT_THREAD,
    CREATE_PROCESS,
    EXIT_PROCESS,
    CREATE_FILE,
    READ_FILE,
    WRITE_FILE,
    CLOSE_FILE,
    LOAD_MODULE,
    GET_PROC_ADDRESS,
    CREATE_IO_COMPLETION_PORT,
    POST_QUEUED_COMPLETION_STATUS,
    GET_QUEUED_COMPLETION_STATUS,
    CLOSE_HANDLE,
};

NTSTATUS _NtWorkerFactoryWorkerReady(ChildMemoryManager& mgr, HANDLE WorkerFactory) {
    trace("Emulated NtWorkerFactoryWorkerReady called with WorkerFactory=0x", std::hex, (uintptr_t)WorkerFactory, std::dec);
    trace("NtWorkerFactoryWorkerReady: No operation performed (stub).");
    return STATUS_SUCCESS;
}

NTSTATUS _NtRemoveIoCompletion(ChildMemoryManager& mgr, HANDLE IoCompletionHandle, PVOID* KeyContext, PVOID* ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER Timeout) {
    trace("Emulated NtRemoveIoCompletion called with IoCompletionHandle=0x", std::hex, (uintptr_t)IoCompletionHandle,
          ", KeyContext=0x", (uintptr_t)KeyContext, ", ApcContext=0x", (uintptr_t)ApcContext,
          ", IoStatusBlock=0x", (uintptr_t)IoStatusBlock, ", Timeout=0x", (uintptr_t)Timeout, std::dec);
    if (IoCompletionHandle == nullptr) {
        return STATUS_INVALID_HANDLE;
    }
    std::shared_ptr<IoCompletionPort> io_completion_port = g_io_completion_ports[IoCompletionHandle];
    if (!io_completion_port) {
        return STATUS_INVALID_HANDLE;
    }
    for (std::tuple<HANDLE, LPOVERLAPPED, PVOID> &io_completion : io_completion_port->queue) {
        if (KeyContext) {
            if (!mgr.write_memory(reinterpret_cast<uintptr_t>(KeyContext), &std::get<0>(io_completion), sizeof(HANDLE))) {
                return STATUS_ACCESS_VIOLATION;
            }
        }
        if (ApcContext) {
            if (!mgr.write_memory(reinterpret_cast<uintptr_t>(ApcContext), &std::get<1>(io_completion), sizeof(LPOVERLAPPED))) {
                return STATUS_ACCESS_VIOLATION;
            }
        }
        io_completion_port->queue.pop_front();
    }

    if (IoStatusBlock) {
        IO_STATUS_BLOCK status_block = {};
        status_block.Status = io_completion_port->status;
        if (io_completion_port->status == STATUS_SUCCESS) {
            status_block.Information = io_completion_port->num_of_bytes_transferred;
        } else {
            status_block.Information = 0;
        }
        if (!mgr.write_memory(reinterpret_cast<uintptr_t>(IoStatusBlock), &status_block, sizeof(IO_STATUS_BLOCK))) {
            return STATUS_ACCESS_VIOLATION;
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS _NtSetInformationThread(
    ChildMemoryManager& memory_mgr,
    HANDLE ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength) {

    trace("_NtSetInformationThread called");

    if (!ThreadInformation) {
        return STATUS_INVALID_PARAMETER;
    }

    std::shared_ptr<Process> process = g_processes[g_tls.process];
    if (!process) {
        return STATUS_INVALID_HANDLE;
    }

    auto it = g_threads.find(ThreadHandle);
    if (it == g_threads.end()) {
        return STATUS_INVALID_HANDLE;
    }

    std::shared_ptr<Thread> thread_ctx = it->second;

    switch (ThreadInformationClass) {
        case ThreadZeroTlsCell: {
            if (ThreadInformationLength != sizeof(ULONG)) {
                return STATUS_INFO_LENGTH_MISMATCH;
            }
            auto info_ptr = reinterpret_cast<uintptr_t>(ThreadInformation);
            auto index = memory_mgr.read<ULONG>(info_ptr);
            g_tls.tls_data[*index] = nullptr;
            return STATUS_SUCCESS;
        }
        case ThreadImpersonationToken: {
            if (ThreadInformationLength != sizeof(HANDLE)) {
                return STATUS_INFO_LENGTH_MISMATCH;
            }
            auto info_ptr = reinterpret_cast<uintptr_t>(ThreadInformation);
            auto token_handle = memory_mgr.read<HANDLE>(info_ptr);
            if (!token_handle) {
                return STATUS_ACCESS_VIOLATION;
            }
            // We do not currently support impersonation tokens
            return STATUS_SUCCESS;
        }
        case ThreadPriority: {
            if (ThreadInformationLength != sizeof(LONG)) {
                return STATUS_INFO_LENGTH_MISMATCH;
            }
            const auto info_ptr = reinterpret_cast<uintptr_t>(ThreadInformation);
            const auto priority = memory_mgr.read<LONG>(info_ptr);
            if (!priority) {
                return STATUS_ACCESS_VIOLATION;
            }
            thread_ctx->priority = *priority;
            return STATUS_SUCCESS;
        }
        case ThreadBasePriority: {
            if (ThreadInformationLength != sizeof(LONG)) {
                return STATUS_INFO_LENGTH_MISMATCH;
            }
            const auto info_ptr = reinterpret_cast<uintptr_t>(ThreadInformation);
            auto base_priority = memory_mgr.read<LONG>(info_ptr);
            if (!base_priority) {
                return STATUS_ACCESS_VIOLATION;
            }
            thread_ctx->base_priority = *base_priority;
            return STATUS_SUCCESS;
        }
        case ThreadAffinityMask: {
            if (ThreadInformationLength != sizeof(ULONG_PTR)) {
                return STATUS_INFO_LENGTH_MISMATCH;
            }
            const auto info_ptr = reinterpret_cast<uintptr_t>(ThreadInformation);
            const auto affinity = memory_mgr.read<ULONG_PTR>(info_ptr);
            if (!affinity) {
                return STATUS_ACCESS_VIOLATION;
            }
            thread_ctx->affinity_mask = affinity.value();
            // also set with pthread
            cpu_set_t cpuset;
            CPU_ZERO(&cpuset);
            for (size_t cpu = 0; cpu < sizeof(ULONG_PTR) * 8; cpu++) {
                if (affinity.value() & (1ULL << cpu)) {
                    CPU_SET(cpu, &cpuset);
                }
            }
            pthread_setaffinity_np(it->second->tid, sizeof(cpu_set_t), &cpuset);
            return STATUS_SUCCESS;
        }
        case ThreadHideFromDebugger: {
            // No action needed in this implementation
            return STATUS_SUCCESS;
        }
        case ThreadQuerySetWin32StartAddress: {
            if (ThreadInformationLength != sizeof(PVOID)) {
                return STATUS_INFO_LENGTH_MISMATCH;
            }
            const auto info_ptr = reinterpret_cast<uintptr_t>(ThreadInformation);
            auto start_address = memory_mgr.read<PVOID>(info_ptr);
            if (!start_address) {
                return STATUS_ACCESS_VIOLATION;
            }
            thread_ctx->start_address = start_address.value_or(nullptr);
            return STATUS_SUCCESS;
        }
        case ThreadGroupInformation: {
            if (ThreadInformationLength != sizeof(USHORT)) {
                return STATUS_INFO_LENGTH_MISMATCH;
            }
            const auto info_ptr = reinterpret_cast<uintptr_t>(ThreadInformation);
            auto group = memory_mgr.read<GROUP_AFFINITY>(info_ptr);
            if (!group) {
                return STATUS_ACCESS_VIOLATION;
            }
            thread_ctx->affinity_mask = group->Mask;
            return STATUS_SUCCESS;
        }
        case ThreadNameInformation: {
            if (ThreadInformationLength < sizeof(THREAD_NAME_INFORMATION)) {
                return STATUS_INFO_LENGTH_MISMATCH;
            }
            const auto info_ptr = reinterpret_cast<uintptr_t>(ThreadInformation);
            auto name_info = memory_mgr.read<THREAD_NAME_INFORMATION>(info_ptr);
            if (!name_info) {
                return STATUS_ACCESS_VIOLATION;
            }
            size_t name_length = name_info->ThreadName.Length;

            if (name_length > 0 && name_length <= 256) {
                std::vector<char> name_buffer(name_length + 1, 0);
                auto name_ptr = reinterpret_cast<uintptr_t>(name_info->ThreadName.Buffer);
                for (size_t i = 0; i < name_length; i++) {
                    auto ch = memory_mgr.read<char>(name_ptr + i);
                    if (!ch) {
                        return STATUS_ACCESS_VIOLATION;
                    }
                    name_buffer[i] = *ch;
                }
                pthread_setname_np(thread_ctx->tid, name_buffer.data());
            } else {
                return STATUS_INVALID_PARAMETER;
            }
            return STATUS_SUCCESS;
        }
        case ThreadWow64Context: {
            // We do not support WOW64 in this implementation
            return STATUS_SUCCESS;
        }
        case ThreadEnableAlignmentFaultFixup: {
            // No action needed in this implementation
            return STATUS_SUCCESS;
        }
        case ThreadPowerThrottlingState: {
            if (ThreadInformationLength != sizeof(THREAD_POWER_THROTTLING_STATE)) {
                return STATUS_INFO_LENGTH_MISMATCH;
            }
            const auto info_ptr = reinterpret_cast<uintptr_t>(ThreadInformation);
            auto power_state = memory_mgr.read<THREAD_POWER_THROTTLING_STATE>(info_ptr);
            if (!power_state) {
                return STATUS_ACCESS_VIOLATION;
            }
            // We do not currently manage power throttling
            return STATUS_SUCCESS;
        }
        case ThreadIdealProcessor: {
            if (ThreadInformationLength != sizeof(ULONG)) {
                return STATUS_INFO_LENGTH_MISMATCH;
            }
            const auto info_ptr = reinterpret_cast<uintptr_t>(ThreadInformation);
            auto ideal_processor = memory_mgr.read<ULONG>(info_ptr);
            if (!ideal_processor) {
                return STATUS_ACCESS_VIOLATION;
            }
            // We do not currently manage ideal processor
            return STATUS_SUCCESS;
        }
        case ThreadPriorityBoost: {
            if (ThreadInformationLength != sizeof(DWORD)) {
                return STATUS_INFO_LENGTH_MISMATCH;
            }
            const auto info_ptr = reinterpret_cast<uintptr_t>(ThreadInformation);
            auto boost = memory_mgr.read<DWORD>(info_ptr);
            if (!boost) {
                return STATUS_ACCESS_VIOLATION;
            }
            thread_ctx->priority = *boost ? thread_ctx->base_priority + 1 : thread_ctx->base_priority;
            return STATUS_SUCCESS;
        }
        case ThreadManageWritesToExecutableMemory: {
            if (ThreadInformationLength != sizeof(MANAGE_WRITES_TO_EXECUTABLE_MEMORY)) {
                return STATUS_INFO_LENGTH_MISMATCH;
            }
            // We do not currently manage writes to executable memory
            return STATUS_SUCCESS;
        }
        default:
            return STATUS_NOT_IMPLEMENTED;
    }
}

NTSTATUS _NtSetEvent(ChildMemoryManager& mgr, HANDLE EventHandle, PLONG PreviousState) {
    trace("Emulated NtSetEvent called with EventHandle=0x", std::hex, (uintptr_t)EventHandle,
          ", PreviousState=0x", (uintptr_t)PreviousState, std::dec);

    if (EventHandle == nullptr) {
        return STATUS_INVALID_HANDLE;
    }

    const auto it = g_events.find(EventHandle);
    if (it == g_events.end()) {
        return STATUS_INVALID_HANDLE;
    }

    const std::shared_ptr<Event> event = it->second;
    if (!event) {
        return STATUS_INVALID_HANDLE;
    }

    const LONG prev = event->signaled ? 1 : 0;

    {
        std::lock_guard lock(event->mutex);
        event->signaled = true;
        event->cv.notify_all();
    }

    if (PreviousState) {
        if (!mgr.write_memory(reinterpret_cast<uintptr_t>(PreviousState), &prev, sizeof(LONG))) {
            return STATUS_ACCESS_VIOLATION;
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS _NtQueryInformationFile(
    ChildMemoryManager& memory_mgr,
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass) {
    trace("_NtQueryInformationFile called with handle ", FileHandle,
          ", class ", FileInformationClass);

    if (!FileHandle || FileHandle == reinterpret_cast<HANDLE>(-1)) {
        return STATUS_INVALID_HANDLE;
    }

    if (!FileInformation) {
        return STATUS_INVALID_PARAMETER;
    }

    File *device = nullptr;
    {
        std::shared_ptr<Process> process = g_processes[g_tls.process];
        if (!process) {
            return STATUS_INVALID_HANDLE;
        }

        auto it = g_files.find(FileHandle);
        if (it == g_files.end()) {
            return STATUS_INVALID_HANDLE;
        }
        device = it->second.get();
    }

    NTSTATUS status = STATUS_SUCCESS;
    ULONG bytes_returned = 0;
    ULONG required_length = 0;

    // Get file stats
    struct stat st{};
    if (fstat(device->fd, &st) != 0) {
        return errno_to_ntstatus(errno);
    }

    switch (FileInformationClass) {
        case FileBasicInformation: {
            required_length = sizeof(FILE_BASIC_INFORMATION);
            if (Length < required_length) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            FILE_BASIC_INFORMATION basic_info = {};

            // Convert Unix timestamps to Windows FILETIME
            basic_info.CreationTime.QuadPart =
                static_cast<LONGLONG>(static_cast<ULONGLONG>(st.st_ctim.tv_sec) * 10000000ULL +
                                      st.st_ctim.tv_nsec / 100ULL + 116444736000000000ULL);

            basic_info.LastAccessTime.QuadPart =
                static_cast<LONGLONG>(static_cast<ULONGLONG>(st.st_atim.tv_sec) * 10000000ULL +
                                      st.st_atim.tv_nsec / 100ULL + 116444736000000000ULL);

            basic_info.LastWriteTime.QuadPart =
                static_cast<LONGLONG>(static_cast<ULONGLONG>(st.st_mtim.tv_sec) * 10000000ULL +
                                      st.st_mtim.tv_nsec / 100ULL + 116444736000000000ULL);

            basic_info.ChangeTime = basic_info.LastWriteTime;

            // Convert file attributes
            basic_info.FileAttributes = FILE_ATTRIBUTE_NORMAL;
            if (S_ISDIR(st.st_mode)) {
                basic_info.FileAttributes |= FILE_ATTRIBUTE_DIRECTORY;
            }
            if (!(st.st_mode & S_IWUSR)) {
                basic_info.FileAttributes |= FILE_ATTRIBUTE_READONLY;
            }
            if (device->attributes & FILE_ATTRIBUTE_TEMPORARY) {
                basic_info.FileAttributes |= FILE_ATTRIBUTE_TEMPORARY;
            }

            if (auto info_ptr = reinterpret_cast<uintptr_t>(FileInformation); !memory_mgr.write(info_ptr, basic_info)) {
                status = STATUS_ACCESS_VIOLATION;
                break;
            }

            bytes_returned = sizeof(FILE_BASIC_INFORMATION);
            break;
        }

        case FileStandardInformation: {
            required_length = sizeof(FILE_STANDARD_INFORMATION);
            if (Length < required_length) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            FILE_STANDARD_INFORMATION std_info = {};

            std_info.AllocationSize.QuadPart = st.st_blocks * 512; // Convert blocks to bytes
            std_info.EndOfFile.QuadPart = st.st_size;
            std_info.NumberOfLinks = st.st_nlink;
            std_info.DeletePending = (device->attributes & FILE_ATTRIBUTE_TEMPORARY) != 0;
            std_info.Directory = S_ISDIR(st.st_mode);

            if (auto info_ptr = reinterpret_cast<uintptr_t>(FileInformation); !memory_mgr.write(info_ptr, std_info)) {
                status = STATUS_ACCESS_VIOLATION;
                break;
            }

            bytes_returned = sizeof(FILE_STANDARD_INFORMATION);
            break;
        }

        case FilePositionInformation: {
            required_length = sizeof(FILE_POSITION_INFORMATION);
            if (Length < required_length) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            FILE_POSITION_INFORMATION pos_info;
            off_t current_pos = lseek(device->fd, 0, SEEK_CUR);
            if (current_pos == -1) {
                status = errno_to_ntstatus(errno);
                break;
            }

            pos_info.CurrentByteOffset.QuadPart = current_pos;
            device->file_pointer = current_pos;

            auto info_ptr = reinterpret_cast<uintptr_t>(FileInformation);
            if (!memory_mgr.write(info_ptr, pos_info)) {
                status = STATUS_ACCESS_VIOLATION;
                break;
            }

            bytes_returned = sizeof(FILE_POSITION_INFORMATION);
            break;
        }

        case FileInternalInformation: {
            required_length = sizeof(LARGE_INTEGER);
            if (Length < required_length) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            // Use inode number as internal identifier
            LARGE_INTEGER internal_info;
            internal_info.QuadPart = st.st_ino;

            auto info_ptr = reinterpret_cast<uintptr_t>(FileInformation);
            if (!memory_mgr.write(info_ptr, internal_info)) {
                status = STATUS_ACCESS_VIOLATION;
                break;
            }

            bytes_returned = sizeof(LARGE_INTEGER);
            break;
        }

        case FileModeInformation: {
            required_length = sizeof(FILE_MODE_INFORMATION);
            if (Length < required_length) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            FILE_MODE_INFORMATION mode_info;
            mode_info.Mode = device->access | device->share_mode | device->disposition | device->flags;

            if (auto info_ptr = reinterpret_cast<uintptr_t>(FileInformation); !memory_mgr.write(info_ptr, mode_info)) {
                status = STATUS_ACCESS_VIOLATION;
                break;
            }

            bytes_returned = sizeof(FILE_MODE_INFORMATION);
            break;
        }

        case FileAlignmentInformation: {
            required_length = sizeof(ULONG);
            if (Length < required_length) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            // Return device alignment (typically 512 bytes)
            ULONG alignment = 1; // No special alignment required
            if (device->flags & FILE_FLAG_NO_BUFFERING) {
                alignment = 512; // Sector alignment for unbuffered I/O
            }

            if (auto info_ptr = reinterpret_cast<uintptr_t>(FileInformation); !memory_mgr.write(info_ptr, alignment)) {
                status = STATUS_ACCESS_VIOLATION;
                break;
            }

            bytes_returned = sizeof(ULONG);
            break;
        }

        default:
            trace("Unsupported FileInformationClass: ", FileInformationClass);
            status = STATUS_INVALID_INFO_CLASS;
            required_length = 0;
            break;
    }

    // Update IO status block
    if (IoStatusBlock) {
        IO_STATUS_BLOCK status_block;
        status_block.Status = status;
        status_block.Information = bytes_returned;

        auto status_ptr = reinterpret_cast<uintptr_t>(IoStatusBlock);
        if (!memory_mgr.write(status_ptr, status_block)) {
            return STATUS_ACCESS_VIOLATION;
        }
    }

    return status;
}


NTSTATUS _NtQueryInformationProcess(
    ChildMemoryManager &memory_mgr,
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength) {
    trace("_NtQueryInformationProcess called with ProcessHandle=", ProcessHandle,
          ", ProcessInformationClass=", ProcessInformationClass, ", ProcessInformationLength=", ProcessInformationLength,
          ", ReturnLength=", ReturnLength);
    if (ProcessHandle == /* current process */ reinterpret_cast<HANDLE>(-1)) {
        ProcessHandle = g_tls.process;
    }

    // also implement IPC

    switch (ProcessInformationClass) {
        case ProcessBasePriority: {
            // Not implemented
            return STATUS_NOT_IMPLEMENTED;
        }
        case ProcessRaisePriority: {
            // Not implemented
            return STATUS_NOT_IMPLEMENTED;
        }
        case ProcessExceptionPort: {
            // Not implemented
            return STATUS_NOT_IMPLEMENTED;
        }
        case ProcessAccessToken: {
            // wine doesnt even know its params' types soo.... do not implement it
            return STATUS_NOT_IMPLEMENTED;
        }
        case ProcessLdtInformation: {
            // Not implemented
            return STATUS_NOT_IMPLEMENTED;
        }
        case ProcessLdtSize: {
            // Not implemented
            return STATUS_NOT_IMPLEMENTED;
        }
        case ProcessIoPortHandlers: {
            // Not implemented
            return STATUS_NOT_IMPLEMENTED;
        }
        case ProcessPooledUsageAndLimits: {
            // Not implemented
            return STATUS_NOT_IMPLEMENTED;
        }
        // try to implement as much as possible
        case ProcessWorkingSetWatch: {
            // Not implemented
            return STATUS_NOT_IMPLEMENTED;
        }
        case ProcessUserModeIOPL: {
            // Not implemented
            return STATUS_NOT_IMPLEMENTED;
        }
        case ProcessEnableAlignmentFaultFixup: {
            // Not implemented
            return STATUS_NOT_IMPLEMENTED;
        }
        case ProcessWx86Information: {
            // Not implemented
            return STATUS_NOT_IMPLEMENTED;
        }
        case ProcessDeviceMap: {
            // Not implemented
            return STATUS_NOT_IMPLEMENTED;
        }
        case ProcessForegroundInformation: {
            // Not implemented
            return STATUS_NOT_IMPLEMENTED;
        }
        case ProcessLUIDDeviceMapsEnabled: {
            // Not implemented
            return STATUS_NOT_IMPLEMENTED;
        }
        case ProcessBreakOnTermination: {
            // Not implemented
            return STATUS_NOT_IMPLEMENTED;
        }
        case ProcessHandleTracing: {
            // Not implemented
            return STATUS_NOT_IMPLEMENTED;
        }
        case ProcessBasicInformation: {
            if (ProcessInformationLength < sizeof(PROCESS_BASIC_INFORMATION)) {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            PROCESS_BASIC_INFORMATION pbi = {};
            std::shared_ptr<Process> proc_ctx = nullptr;

            if (!ProcessHandle || ProcessHandle == reinterpret_cast<HANDLE>(-1)) {
                proc_ctx = g_processes[g_tls.process];
            } else {
                std::shared_lock lock(g_processes_mutex);
                auto it = g_processes.find(ProcessHandle);
                if (it != g_processes.end()) {
                    proc_ctx = it->second;
                }
            }

            if (!proc_ctx) {
                return STATUS_INVALID_HANDLE;
            }

            pbi.PebBaseAddress = g_current_peb;
            pbi.UniqueProcessId = proc_ctx->pid;
            pbi.InheritedFromUniqueProcessId = g_processes[proc_ctx->parent]->pid;
            pbi.ExitStatus = proc_ctx->exit_code;
            pbi.BasePriority = 8; // Normal priority

            uintptr_t info_ptr = reinterpret_cast<uintptr_t>(ProcessInformation);
            if (!memory_mgr.write(info_ptr, pbi)) {
                return STATUS_ACCESS_VIOLATION;
            }

            if (ReturnLength) {
                uintptr_t ret_len_ptr = reinterpret_cast<uintptr_t>(ReturnLength);
                if (!memory_mgr.write(ret_len_ptr, sizeof(PROCESS_BASIC_INFORMATION))) {
                    return STATUS_ACCESS_VIOLATION;
                }
            }

            return STATUS_SUCCESS;
        }
        case ProcessIoCounters: {
            if (ProcessInformationLength < sizeof(IO_COUNTERS)) {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            IO_COUNTERS io_counters = {};
            // In a full implementation, these would be tracked
            io_counters.ReadOperationCount = 0;
            io_counters.WriteOperationCount = 0;
            io_counters.OtherOperationCount = 0;
            io_counters.ReadTransferCount = 0;
            io_counters.WriteTransferCount = 0;
            io_counters.OtherTransferCount = 0;
            uintptr_t info_ptr = reinterpret_cast<uintptr_t>(ProcessInformation);
            if (!memory_mgr.write(info_ptr, io_counters)) {
                return STATUS_ACCESS_VIOLATION;
            }
            if (ReturnLength) {
                uintptr_t ret_len_ptr = reinterpret_cast<uintptr_t>(ReturnLength);
                if (!memory_mgr.write(ret_len_ptr, sizeof(IO_COUNTERS))) {
                    return STATUS_ACCESS_VIOLATION;
                }
            }
            return STATUS_SUCCESS;
        }
        case ProcessVmCounters: {
            if (ProcessInformationLength < sizeof(VM_COUNTERS)) {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            VM_COUNTERS vm_counters = {};
            // In a full implementation, these would be tracked
            vm_counters.PeakVirtualSize = 0;
            vm_counters.VirtualSize = 0;
            vm_counters.PageFaultCount = 0;
            vm_counters.PeakWorkingSetSize = 0;
            vm_counters.WorkingSetSize = 0;
            vm_counters.QuotaPeakPagedPoolUsage = 0;
            vm_counters.QuotaPagedPoolUsage = 0;
            vm_counters.QuotaPeakNonPagedPoolUsage = 0;
            vm_counters.QuotaNonPagedPoolUsage = 0;
            vm_counters.PagefileUsage = 0;
            vm_counters.PeakPagefileUsage = 0;

            uintptr_t info_ptr = reinterpret_cast<uintptr_t>(ProcessInformation);
            if (!memory_mgr.write(info_ptr, vm_counters)) {
                return STATUS_ACCESS_VIOLATION;
            }
            if (ReturnLength) {
                uintptr_t ret_len_ptr = reinterpret_cast<uintptr_t>(ReturnLength);
                if (!memory_mgr.write(ret_len_ptr, sizeof(VM_COUNTERS))) {
                    return STATUS_ACCESS_VIOLATION;
                }
            }
            return STATUS_SUCCESS;
        }
        case ProcessTimes: {
            if (ProcessInformationLength < sizeof(KERNEL_USER_TIMES) * 4) {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            KERNEL_USER_TIMES times = {};

            times.CreateTime.QuadPart = 0; // Not tracked
            times.ExitTime.QuadPart = 0;   // Not tracked
            times.KernelTime.QuadPart = 0; // Not tracked
            times.UserTime.QuadPart = 0;   // Not tracked

            return STATUS_SUCCESS;
        }
        case ProcessDebugPort: {
            if (ProcessInformationLength < sizeof(DWORD_PTR)) {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            DWORD_PTR debug_port = 0; // No debug port set

            auto info_ptr = reinterpret_cast<uintptr_t>(ProcessInformation);
            if (!memory_mgr.write(info_ptr, debug_port)) {
                return STATUS_ACCESS_VIOLATION;
            }

            if (ReturnLength) {
                auto ret_len_ptr = reinterpret_cast<uintptr_t>(ReturnLength);
                if (!memory_mgr.write(ret_len_ptr, sizeof(HANDLE))) {
                    return STATUS_ACCESS_VIOLATION;
                }
            }

            return STATUS_SUCCESS;
        }
        case ProcessPriorityBoost: {
            if (ProcessInformationLength < sizeof(ULONG)) {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            ULONG priority_boost = 0; // No boost

            uintptr_t info_ptr = reinterpret_cast<uintptr_t>(ProcessInformation);
            if (!memory_mgr.write(info_ptr, priority_boost)) {
                return STATUS_ACCESS_VIOLATION;
            }

            if (ReturnLength) {
                uintptr_t ret_len_ptr = reinterpret_cast<uintptr_t>(ReturnLength);
                if (!memory_mgr.write(ret_len_ptr, sizeof(ULONG))) {
                    return STATUS_ACCESS_VIOLATION;
                }
            }

            return STATUS_SUCCESS;
        }
        case ProcessDebugFlags: {
            if (ProcessInformationLength < sizeof(ULONG)) {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            ULONG debug_flags = 0; // No special debug flags

            uintptr_t info_ptr = reinterpret_cast<uintptr_t>(ProcessInformation);
            if (!memory_mgr.write(info_ptr, debug_flags)) {
                return STATUS_ACCESS_VIOLATION;
            }

            if (ReturnLength) {
                uintptr_t ret_len_ptr = reinterpret_cast<uintptr_t>(ReturnLength);
                if (!memory_mgr.write(ret_len_ptr, sizeof(ULONG))) {
                    return STATUS_ACCESS_VIOLATION;
                }
            }

            return STATUS_SUCCESS;
        }
        case ProcessDefaultHardErrorMode: {
            if (ProcessInformationLength < sizeof(ULONG)) {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            ULONG hard_error_mode = 0; // Default mode

            uintptr_t info_ptr = reinterpret_cast<uintptr_t>(ProcessInformation);
            if (!memory_mgr.write(info_ptr, hard_error_mode)) {
                return STATUS_ACCESS_VIOLATION;
            }

            if (ReturnLength) {
                uintptr_t ret_len_ptr = reinterpret_cast<uintptr_t>(ReturnLength);
                if (!memory_mgr.write(ret_len_ptr, sizeof(ULONG))) {
                    return STATUS_ACCESS_VIOLATION;
                }
            }

            return STATUS_SUCCESS;
        }
        case ProcessDebugObjectHandle: {
            if (ProcessInformationLength < sizeof(ULONG_PTR)) {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            ULONG_PTR debug_object = 0; // No debug object

            auto info_ptr = reinterpret_cast<uintptr_t>(ProcessInformation);
            if (!memory_mgr.write(info_ptr, debug_object)) {
                return STATUS_ACCESS_VIOLATION;
            }

            if (ReturnLength) {
                auto ret_len_ptr = reinterpret_cast<uintptr_t>(ReturnLength);
                if (!memory_mgr.write(ret_len_ptr, sizeof(HANDLE))) {
                    return STATUS_ACCESS_VIOLATION;
                }
            }

            return STATUS_SUCCESS;
        }
        case ProcessHandleCount: {
            if (ProcessInformationLength < sizeof(ULONG)) {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            ULONG handle_count = 0;

            if (!ProcessHandle || ProcessHandle == reinterpret_cast<HANDLE>(-1)) {
                handle_count += g_processes[g_tls.process]->heaps.size();
            } else {
                handle_count += g_processes[ProcessHandle]->heaps.size();
            }

            if (auto info_ptr = reinterpret_cast<uintptr_t>(ProcessInformation); !memory_mgr.write(info_ptr, handle_count)) {
                return STATUS_ACCESS_VIOLATION;
            }

            if (ReturnLength) {
                if (auto ret_len_ptr = reinterpret_cast<uintptr_t>(ReturnLength); !memory_mgr.write(ret_len_ptr, sizeof(ULONG))) {
                    return STATUS_ACCESS_VIOLATION;
                }
            }

            return STATUS_SUCCESS;
        }
        case ProcessHandleTable: {
            // Not implemented
            return STATUS_SUCCESS;
        }
        case ProcessAffinityMask: {
            if (ProcessInformationLength < sizeof(ULONG_PTR)) {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            cpu_set_t cpu_set;
            CPU_ZERO(&cpu_set);
            pthread_getaffinity_np(pthread_self(), sizeof(cpu_set), &cpu_set);
            ULONG_PTR affinity_mask = 0;
            for (int i = 0; i < min(CPU_SETSIZE, sizeof(LONG_PTR)); ++i) {
                if (CPU_ISSET(i, &cpu_set)) {
                    affinity_mask |= (1ULL << i);
                }
            }

            if (auto info_ptr = reinterpret_cast<uintptr_t>(ProcessInformation); !memory_mgr.write(info_ptr, affinity_mask)) {
                return STATUS_ACCESS_VIOLATION;
            }

            if (ReturnLength) {
                if (auto ret_len_ptr = reinterpret_cast<uintptr_t>(ReturnLength); !memory_mgr.write(ret_len_ptr, sizeof(ULONG_PTR))) {
                    return STATUS_ACCESS_VIOLATION;
                }
            }

            return STATUS_SUCCESS;
        }
        case ProcessSessionInformation: {
            if (ProcessInformationLength < sizeof(ULONG)) {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            auto info_ptr = reinterpret_cast<uintptr_t>(ProcessInformation);
            if (ULONG session_id = 0; !memory_mgr.write(info_ptr, session_id)) {
                return STATUS_ACCESS_VIOLATION;
            }

            if (ReturnLength) {
                if (auto ret_len_ptr = reinterpret_cast<uintptr_t>(ReturnLength); !memory_mgr.write(ret_len_ptr, sizeof(ULONG))) {
                    return STATUS_ACCESS_VIOLATION;
                }
            }

            return STATUS_SUCCESS;
        }
        case ProcessWow64Information: {
            if (ProcessInformationLength < sizeof(PVOID)) {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            auto info_ptr = reinterpret_cast<uintptr_t>(ProcessInformation);
            if (PVOID wow64_info = nullptr; !memory_mgr.write(info_ptr, wow64_info)) {
                return STATUS_ACCESS_VIOLATION;
            }

            if (ReturnLength) {
                if (auto ret_len_ptr = reinterpret_cast<uintptr_t>(ReturnLength); !memory_mgr.write(ret_len_ptr, sizeof(PVOID))) {
                    return STATUS_ACCESS_VIOLATION;
                }
            }

            return STATUS_SUCCESS;
        }
        case ProcessImageFileName: {
            if (ProcessInformationLength < sizeof(UNICODE_STRING) + 1) {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            const std::u16string &image_path = g_processes[g_tls.process]->image_path_u16;
            if (image_path.empty()) {
                return STATUS_UNSUCCESSFUL;
            }

            UNICODE_STRING us = {};
            us.Length = static_cast<USHORT>(image_path.size() * sizeof(WCHAR));
            us.MaximumLength = us.Length + sizeof(WCHAR);
            us.Buffer = new WCHAR[image_path.size() + 1];
            std::ranges::copy(image_path, us.Buffer);
            us.Buffer[image_path.size()] = u'\0';
            // prepend "\??\" to the path
            std::u16string full_path = u"\\??\\" + image_path;
            us.Length = static_cast<USHORT>(full_path.size() * sizeof(WCHAR));
            us.MaximumLength = us.Length + sizeof(WCHAR);
            std::ranges::copy(full_path, us.Buffer);
            us.Buffer[full_path.size()] = u'\0';
            auto info_ptr = reinterpret_cast<uintptr_t>(ProcessInformation);
            if (!memory_mgr.write(info_ptr, us)) {
                delete[] us.Buffer;
                return STATUS_ACCESS_VIOLATION;
            }
            if (info_ptr + sizeof(UNICODE_STRING) + us.Length > info_ptr + ProcessInformationLength) {
                delete[] us.Buffer;
                return STATUS_INFO_LENGTH_MISMATCH;
            }
            for (size_t i = 0; i < us.Length; i++) {
                if (!memory_mgr.write(info_ptr + sizeof(UNICODE_STRING) + i, us.Buffer[i])) {
                    delete[] us.Buffer;
                    return STATUS_ACCESS_VIOLATION;
                }
            }
            if (ReturnLength) {
                auto ret_len_ptr = reinterpret_cast<uintptr_t>(ReturnLength);
                if (ULONG ret_len = sizeof(UNICODE_STRING) + us.Length; !memory_mgr.write(ret_len_ptr, ret_len)) {
                    delete[] us.Buffer;
                    return STATUS_ACCESS_VIOLATION;
                }
            }
            delete[] us.Buffer;
            return STATUS_SUCCESS;
        }
        case ProcessImageFileNameWin32: {
            if (ProcessInformationLength < 15) { // 15 is the length of "C:\\Windows\\"
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            const std::u16string &image_path = g_processes[g_tls.process]->image_path_u16;
            if (image_path.empty()) {
                return STATUS_UNSUCCESSFUL;
            }

            std::string ascii_path = converter16.to_bytes(image_path);
            if (ascii_path.size() >= ProcessInformationLength) {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            uintptr_t info_ptr = reinterpret_cast<uintptr_t>(ProcessInformation);
            for (size_t i = 0; i < ascii_path.size(); i++) {
                if (!memory_mgr.write(info_ptr + i, ascii_path[i])) {
                    return STATUS_ACCESS_VIOLATION;
                }
            }

            if (ReturnLength) {
                uintptr_t ret_len_ptr = reinterpret_cast<uintptr_t>(ReturnLength);
                ULONG ret_len = static_cast<ULONG>(ascii_path.size() + 1);
                if (!memory_mgr.write(ret_len_ptr, ret_len)) {
                    return STATUS_ACCESS_VIOLATION;
                }
            }

            return STATUS_SUCCESS;
        }
        case ProcessExecuteFlags: {
            if (ProcessInformationLength < sizeof(ULONG)) {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            ULONG exec_flags = 0; // No special flags

            uintptr_t info_ptr = reinterpret_cast<uintptr_t>(ProcessInformation);
            if (!memory_mgr.write(info_ptr, exec_flags)) {
                return STATUS_ACCESS_VIOLATION;
            }

            if (ReturnLength) {
                uintptr_t ret_len_ptr = reinterpret_cast<uintptr_t>(ReturnLength);
                if (!memory_mgr.write(ret_len_ptr, sizeof(ULONG))) {
                    return STATUS_ACCESS_VIOLATION;
                }
            }

            return STATUS_SUCCESS;
        }
        case ProcessPriorityClass: {
            if (ProcessInformationLength < sizeof(ULONG)) {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            ULONG priority_class = NORMAL_PRIORITY_CLASS;

            uintptr_t info_ptr = reinterpret_cast<uintptr_t>(ProcessInformation);
            if (!memory_mgr.write(info_ptr, priority_class)) {
                return STATUS_ACCESS_VIOLATION;
            }

            if (ReturnLength) {
                uintptr_t ret_len_ptr = reinterpret_cast<uintptr_t>(ReturnLength);
                if (!memory_mgr.write(ret_len_ptr, sizeof(ULONG))) {
                    return STATUS_ACCESS_VIOLATION;
                }
            }

            return STATUS_SUCCESS;
        }
        case ProcessCookie: {
            if (ProcessInformationLength < sizeof(ULONG)) {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            ULONG cookie = g_kuser_shared_data->Cookie;

            uintptr_t info_ptr = reinterpret_cast<uintptr_t>(ProcessInformation);
            if (!memory_mgr.write(info_ptr, cookie)) {
                return STATUS_ACCESS_VIOLATION;
            }

            if (ReturnLength) {
                uintptr_t ret_len_ptr = reinterpret_cast<uintptr_t>(ReturnLength);
                if (!memory_mgr.write(ret_len_ptr, sizeof(ULONG))) {
                    return STATUS_ACCESS_VIOLATION;
                }
            }

            return STATUS_SUCCESS;
        }
        case ProcessImageInformation: {
            if (ProcessInformationLength < sizeof(SECTION_IMAGE_INFORMATION)) {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            SECTION_IMAGE_INFORMATION sii = {};
            sii.TransferAddress = nullptr;
            sii.ZeroBits = 0;
            sii.MaximumStackSize = 0x100000; // 1 MB
            sii.CommittedStackSize = 0x10000; // 64 KB
            sii.SubSystemType = IMAGE_SUBSYSTEM_WINDOWS_CUI;
            sii.CheckSum = 0;
            sii.ImageCharacteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE;
            sii.DllCharacteristics = 0;
            sii.LoaderFlags = 0;
            sii.ImageFileSize = 0; // Unknown
            sii.CheckSum = 0; // Unknown

            uintptr_t info_ptr = reinterpret_cast<uintptr_t>(ProcessInformation);
            if (!memory_mgr.write(info_ptr, sii)) {
                return STATUS_ACCESS_VIOLATION;
            }

            if (ReturnLength) {
                uintptr_t ret_len_ptr = reinterpret_cast<uintptr_t>(ReturnLength);
                if (!memory_mgr.write(ret_len_ptr, sizeof(SECTION_IMAGE_INFORMATION))) {
                    return STATUS_ACCESS_VIOLATION;
                }
            }

            return STATUS_SUCCESS;
        }
        case ProcessCycleTime: {
            if (ProcessInformationLength < sizeof(ULONG64)) {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            ULONG64 cycle_time = 0; // Not tracked

            uintptr_t info_ptr = reinterpret_cast<uintptr_t>(ProcessInformation);
            if (!memory_mgr.write(info_ptr, cycle_time)) {
                return STATUS_ACCESS_VIOLATION;
            }

            if (ReturnLength) {
                uintptr_t ret_len_ptr = reinterpret_cast<uintptr_t>(ReturnLength);
                if (!memory_mgr.write(ret_len_ptr, sizeof(ULONG64))) {
                    return STATUS_ACCESS_VIOLATION;
                }
            }

            return STATUS_SUCCESS;
        }
        case ProcessQuotaLimits: {
            if (ProcessInformationLength < sizeof(QUOTA_LIMITS)) {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            QUOTA_LIMITS ql = {};
            // In a full implementation, these would be tracked
            ql.PagedPoolLimit = static_cast<SIZE_T>(-1);
            ql.NonPagedPoolLimit = static_cast<SIZE_T>(-1);
            ql.PagefileLimit = static_cast<SIZE_T>(-1);
            ql.TimeLimit.QuadPart = 0;

            uintptr_t info_ptr = reinterpret_cast<uintptr_t>(ProcessInformation);
            if (!memory_mgr.write(info_ptr, ql)) {
                return STATUS_ACCESS_VIOLATION;
            }

            if (ReturnLength) {
                if (uintptr_t ret_len_ptr = reinterpret_cast<uintptr_t>(ReturnLength); !memory_mgr.write(ret_len_ptr, sizeof(QUOTA_LIMITS))) {
                    return STATUS_ACCESS_VIOLATION;
                }
            }

            return STATUS_SUCCESS;
        }
        default: {
            trace("Unsupported ProcessInformationClass: ", ProcessInformationClass);
            return STATUS_INVALID_INFO_CLASS;
        }
    }
}

NTSTATUS _NtAddAtom(
    ChildMemoryManager& memory_mgr,
    PWSTR AtomName,
    USHORT Length,
    PRTL_ATOM Atom) {

    trace("NtAddAtom called");
    if (!AtomName || !Atom) {
        return STATUS_INVALID_PARAMETER;
    }
    // Read atom name from child memory
    const auto name_ptr = reinterpret_cast<uintptr_t>(AtomName);
    const auto name = memory_mgr.read_u16string(name_ptr, Length / sizeof(WCHAR));
    if (!name) {
        return STATUS_ACCESS_VIOLATION;
    }
    RTL_ATOM &atom = g_atom_table[*name];
    if (atom == 0) {
        atom = ++g_next_atom_value;
    }
    g_reverse_atom_table[atom] = *name;
    if (const auto atom_ptr = reinterpret_cast<uintptr_t>(Atom); !memory_mgr.write(atom_ptr, atom)) {
        return STATUS_ACCESS_VIOLATION;
    }
    trace("Added atom: ", converter.from_bytes(converter16.to_bytes(*name)), " with value ", atom);
    return STATUS_SUCCESS;
}

NTSTATUS _NtFindAtom(
    ChildMemoryManager& memory_mgr,
    PWSTR AtomName,
    USHORT Length,
    PRTL_ATOM Atom) {
    trace("NtFindAtom called");
    if (!AtomName || !Atom) {
        return STATUS_INVALID_PARAMETER;
    }
    // Read atom name from child memory
    const auto name_ptr = reinterpret_cast<uintptr_t>(AtomName);
    const auto name = memory_mgr.read_u16string(name_ptr, Length / sizeof(WCHAR));
    if (!name) {
        return STATUS_ACCESS_VIOLATION;
    }
    RTL_ATOM atom = 0;
    if (const auto it = g_atom_table.find(*name); it != g_atom_table.end()) {
        atom = it->second;
    }
    if (const auto atom_ptr = reinterpret_cast<uintptr_t>(Atom); !memory_mgr.write(atom_ptr, atom)) {
        return STATUS_ACCESS_VIOLATION;
    }
    trace("Found atom: ", converter.from_bytes(converter16.to_bytes(*name)), " with value ", atom);
    return atom != 0 ? STATUS_SUCCESS : STATUS_OBJECT_NAME_NOT_FOUND;
}

NTSTATUS _NtQueueApcThread(
    ChildMemoryManager&,
    HANDLE ThreadHandle,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcArgument1,
    PVOID ApcArgument2,
    PVOID ApcArgument3) {

    trace("_NtQueueApcThread called");

    std::shared_lock lock(g_threads_mutex);
    const auto it = g_threads.find(ThreadHandle);
    if (it == g_threads.end()) {
        return STATUS_INVALID_HANDLE;
    }

    const APC apc{ reinterpret_cast<PNTAPCFUNC>(ApcRoutine), reinterpret_cast<ULONG_PTR>(ApcArgument1), reinterpret_cast<ULONG_PTR>(ApcArgument2), reinterpret_cast<ULONG_PTR>(ApcArgument3) };

    std::lock_guard apc_lock(it->second->apc_lock);
    it->second->apc_queue.push_back(apc);

    return STATUS_SUCCESS;
}

NTSTATUS _NtWriteFileGather(
    ChildMemoryManager& mgr,
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PFILE_SEGMENT_ELEMENT SegmentArray,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key) {

    trace("_NtWriteFileGather called");

    if (!SegmentArray || Length == 0 || Length % PAGE_SIZE != 0) {
        return STATUS_INVALID_PARAMETER;
    }

    const std::shared_ptr<File> device = g_files[FileHandle];
    if (!device) {
        return STATUS_INVALID_HANDLE;
    }

    // Validate that we have a valid file descriptor
    if (device->fd < 0) {
        return STATUS_INVALID_HANDLE;
    }

    // Calculate total buffer size from segments
    size_t segment_count = Length / PAGE_SIZE;
    std::vector<iovec> iovecs;
    iovecs.reserve(segment_count);

    // Read segment array from child memory
    auto segment_array_ptr = reinterpret_cast<uintptr_t>(SegmentArray);
    for (size_t i = 0; i < segment_count; i++) {
        auto segment = mgr.read<FILE_SEGMENT_ELEMENT>(segment_array_ptr + i * sizeof(FILE_SEGMENT_ELEMENT));
        if (!segment) {
            return STATUS_ACCESS_VIOLATION;
        }

        // Each segment points to a page of data
        iovec iov;
        iov.iov_base = segment->Buffer;
        iov.iov_len = PAGE_SIZE;
        iovecs.push_back(iov);
    }

    // Perform scattered write using writev
    const off_t offset = ByteOffset ? ByteOffset->QuadPart : device->file_pointer;
    ssize_t bytes_written;

    if (ByteOffset) {
        // Use pwritev for positioned write
        bytes_written = pwritev(device->fd, iovecs.data(), iovecs.size(), offset);
    } else {
        // Use writev for sequential writing
        bytes_written = writev(device->fd, iovecs.data(), iovecs.size());
    }

    NTSTATUS status;
    if (bytes_written == -1) {
        status = errno_to_ntstatus(errno);
        bytes_written = 0;
    } else {
        status = STATUS_SUCCESS;
        if (!ByteOffset) {
            device->file_pointer += bytes_written;
        }
    }

    // Update IO status block
    if (IoStatusBlock) {
        IO_STATUS_BLOCK status_block;
        status_block.Status = status;
        status_block.Information = bytes_written;
        if (!mgr.write_memory(reinterpret_cast<uintptr_t>(IoStatusBlock), &status_block, sizeof(IO_STATUS_BLOCK))) {
            return STATUS_ACCESS_VIOLATION;
        }
    }

    // Signal event if provided
    if (Event && status == STATUS_SUCCESS) {
        if (const auto event_it = g_events.find(Event); event_it != g_events.end()) {
            std::lock_guard lock(event_it->second->mutex);
            event_it->second->signaled = true;
            event_it->second->cv.notify_all();
        }
    }

    // Call APC routine if provided
    if (ApcRoutine && status == STATUS_SUCCESS) {
        _NtQueueApcThread(mgr, g_tls.thread, ApcRoutine, ApcContext, IoStatusBlock, 0);
    }

    return STATUS_SUCCESS;
}

NTSTATUS _NtSetInformationFile(
    ChildMemoryManager& memory_mgr,
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass) {

    trace("_NtSetInformationFile called with handle ", FileHandle,
          ", class ", FileInformationClass);

    if (!FileHandle || FileHandle == reinterpret_cast<HANDLE>(-1)) {
        return STATUS_INVALID_HANDLE;
    }

    if (!FileInformation || Length == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    std::shared_ptr<File> device = g_files[FileHandle];
    if (!device) {
        return STATUS_INVALID_HANDLE;
    }

    NTSTATUS status = STATUS_SUCCESS;
    ULONG bytes_used = 0;

    switch (FileInformationClass) {
        case FileBasicInformation: {
            if (Length < sizeof(FILE_BASIC_INFORMATION)) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            uintptr_t info_ptr = reinterpret_cast<uintptr_t>(FileInformation);
            auto basic_info = memory_mgr.read<FILE_BASIC_INFORMATION>(info_ptr);
            if (!basic_info) {
                status = STATUS_ACCESS_VIOLATION;
                break;
            }

            // Convert Windows file attributes to POSIX
            struct stat st;
            if (fstat(device->fd, &st) != 0) {
                status = errno_to_ntstatus(errno);
                break;
            }

            // Set timestamps if provided (non-zero values)
            if (basic_info->LastWriteTime.QuadPart != 0 ||
                basic_info->LastAccessTime.QuadPart != 0) {
                timespec times[2];

                // Convert Windows FILETIME to Unix timespec
                if (basic_info->LastAccessTime.QuadPart != 0) {
                    ULONGLONG unix_time = (basic_info->LastAccessTime.QuadPart - 116444736000000000ULL) / 10000000ULL;
                    times[0].tv_sec = unix_time;
                    times[0].tv_nsec = ((basic_info->LastAccessTime.QuadPart - 116444736000000000ULL) % 10000000ULL) * 100;
                } else {
                    times[0] = st.st_atim; // Keep current access time
                }

                if (basic_info->LastWriteTime.QuadPart != 0) {
                    ULONGLONG unix_time = (basic_info->LastWriteTime.QuadPart - 116444736000000000ULL) / 10000000ULL;
                    times[1].tv_sec = unix_time;
                    times[1].tv_nsec = ((basic_info->LastWriteTime.QuadPart - 116444736000000000ULL) % 10000000ULL) * 100;
                } else {
                    times[1] = st.st_mtim; // Keep the current modification time
                }

                if (futimens(device->fd, times) != 0) {
                    status = errno_to_ntstatus(errno);
                    break;
                }
            }

            // Handle file attributes (limited support)
            if (basic_info->FileAttributes != 0) {
                mode_t new_mode = st.st_mode;

                // Read-only attribute
                if (basic_info->FileAttributes & FILE_ATTRIBUTE_READONLY) {
                    new_mode &= ~(S_IWUSR | S_IWGRP | S_IWOTH);
                } else if (st.st_mode & S_IRUSR) {
                    new_mode |= S_IWUSR; // Restore write permission for the owner
                }

                if (fchmod(device->fd, new_mode) != 0) {
                    status = errno_to_ntstatus(errno);
                    break;
                }
            }

            bytes_used = sizeof(FILE_BASIC_INFORMATION);
            break;
        }

        case FilePositionInformation: {
            if (Length < sizeof(FILE_POSITION_INFORMATION)) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            uintptr_t info_ptr = reinterpret_cast<uintptr_t>(FileInformation);
            auto pos_info = memory_mgr.read<FILE_POSITION_INFORMATION>(info_ptr);
            if (!pos_info) {
                status = STATUS_ACCESS_VIOLATION;
                break;
            }

            // Set the file position
            off_t new_pos = lseek(device->fd, pos_info->CurrentByteOffset.QuadPart, SEEK_SET);
            if (new_pos == -1) {
                status = errno_to_ntstatus(errno);
                break;
            }

            // Update cached position
            device->file_pointer = new_pos;
            bytes_used = sizeof(FILE_POSITION_INFORMATION);
            break;
        }

        case FileEndOfFileInformation: {
            if (Length < sizeof(FILE_END_OF_FILE_INFORMATION)) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            uintptr_t info_ptr = reinterpret_cast<uintptr_t>(FileInformation);
            auto eof_info = memory_mgr.read<FILE_END_OF_FILE_INFORMATION>(info_ptr);
            if (!eof_info) {
                status = STATUS_ACCESS_VIOLATION;
                break;
            }

            // Truncate or extend the file
            if (ftruncate(device->fd, eof_info->EndOfFile.QuadPart) != 0) {
                status = errno_to_ntstatus(errno);
                break;
            }

            bytes_used = sizeof(FILE_END_OF_FILE_INFORMATION);
            break;
        }

        case FileAllocationInformation: {
            if (Length < sizeof(FILE_ALLOCATION_INFORMATION)) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            uintptr_t info_ptr = reinterpret_cast<uintptr_t>(FileInformation);
            auto alloc_info = memory_mgr.read<FILE_ALLOCATION_INFORMATION>(info_ptr);
            if (!alloc_info) {
                status = STATUS_ACCESS_VIOLATION;
                break;
            }

            // Pre-allocate space (the best effort)
            if (fallocate(device->fd, 0, 0, alloc_info->AllocationSize.QuadPart) != 0) {
                // fallocate might not be supported, try ftruncate as fallback
                struct stat st;
                if (fstat(device->fd, &st) == 0 &&
                    st.st_size < alloc_info->AllocationSize.QuadPart) {
                    if (ftruncate(device->fd, alloc_info->AllocationSize.QuadPart) != 0) {
                        status = errno_to_ntstatus(errno);
                        break;
                    }
                }
            }

            bytes_used = sizeof(FILE_ALLOCATION_INFORMATION);
            break;
        }

        case FileDispositionInformation: {
            if (Length < sizeof(FILE_DISPOSITION_INFORMATION)) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            uintptr_t info_ptr = reinterpret_cast<uintptr_t>(FileInformation);
            auto disp_info = memory_mgr.read<FILE_DISPOSITION_INFORMATION>(info_ptr);
            if (!disp_info) {
                status = STATUS_ACCESS_VIOLATION;
                break;
            }

            // Mark for deletion on close
            if (disp_info->DoDeleteFile) {
                device->attributes |= FILE_ATTRIBUTE_TEMPORARY; // Use as a delete flag
                trace("File marked for deletion on close");
            } else {
                device->attributes &= ~FILE_ATTRIBUTE_TEMPORARY;
                trace("File unmarked for deletion");
            }

            bytes_used = sizeof(FILE_DISPOSITION_INFORMATION);
            break;
        }

        case FileModeInformation: {
            if (Length < sizeof(FILE_MODE_INFORMATION)) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            auto info_ptr = reinterpret_cast<uintptr_t>(FileInformation);
            auto mode_info = memory_mgr.read<FILE_MODE_INFORMATION>(info_ptr);
            if (!mode_info) {
                status = STATUS_ACCESS_VIOLATION;
                break;
            }

            // Update file mode flags
            device->flags = mode_info->Mode;

            // Apply some mode flags to the file descriptor
            if (int flags = fcntl(device->fd, F_GETFL); flags != -1) {
                if (mode_info->Mode & FILE_SYNCHRONOUS_IO_NONALERT) {
                    flags |= O_SYNC;
                } else {
                    flags &= ~O_SYNC;
                }
                fcntl(device->fd, F_SETFL, flags);
            }

            bytes_used = sizeof(FILE_MODE_INFORMATION);
            break;
        }

        case FileCompletionInformation: {
            if (Length < sizeof(FILE_COMPLETION_INFORMATION)) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            auto info_ptr = reinterpret_cast<uintptr_t>(FileInformation);
            auto comp_info = memory_mgr.read<FILE_COMPLETION_INFORMATION>(info_ptr);
            if (!comp_info) {
                status = STATUS_ACCESS_VIOLATION;
                break;
            }

            // Associate file with I/O completion port
            std::shared_lock lock(g_io_completion_ports_mutex);
            if (!g_io_completion_ports.contains(comp_info->CompletionPort)) {
                status = STATUS_INVALID_HANDLE;
                break;
            }
            device->iocp = comp_info->CompletionPort;
            device->completion_key = comp_info->CompletionKey;

            bytes_used = sizeof(FILE_COMPLETION_INFORMATION);
            break;
        }

        case FileRenameInformation: {
            if (Length < sizeof(FILE_RENAME_INFORMATION)) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            uintptr_t info_ptr = reinterpret_cast<uintptr_t>(FileInformation);
            auto rename_info = memory_mgr.read<FILE_RENAME_INFORMATION>(info_ptr);
            if (!rename_info) {
                status = STATUS_ACCESS_VIOLATION;
                break;
            }

            // Read the new filename
            if (rename_info->FileNameLength == 0) {
                status = STATUS_INVALID_PARAMETER;
                break;
            }

            auto new_name = memory_mgr.read_wstring(
                reinterpret_cast<uintptr_t>(FileInformation) + offsetof(FILE_RENAME_INFORMATION, FileName),
                rename_info->FileNameLength / sizeof(WCHAR));

            if (!new_name) {
                status = STATUS_ACCESS_VIOLATION;
                break;
            }

            // Convert to regular string and create a path
            std::string new_path;
            for (char16_t c : *new_name) {
                new_path.push_back(static_cast<char>(c));
            }

            // Convert a Windows path to a Unix path
            std::ranges::replace(new_path, '\\', '/');
            if (new_path.starts_with("\\??\\")) {
                new_path = new_path.substr(4);
            }

            // Get the current file path for rename
            char current_path[PATH_MAX];
            if (snprintf(current_path, sizeof(current_path), "/proc/self/fd/%d", device->fd) >= sizeof(current_path)) {
                status = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }

            char resolved_path[PATH_MAX];
            if (readlink(current_path, resolved_path, sizeof(resolved_path) - 1) == -1) {
                status = errno_to_ntstatus(errno);
                break;
            }
            resolved_path[sizeof(resolved_path) - 1] = '\0';

            // Perform rename
            if (rename(resolved_path, new_path.c_str()) != 0) {
                if (errno == EEXIST && !rename_info->ReplaceIfExists) {
                    status = STATUS_OBJECT_NAME_COLLISION;
                } else {
                    status = errno_to_ntstatus(errno);
                }
                break;
            }

            // Update device path
            device->path = new_path;
            trace("File renamed to: ", converter.from_bytes(new_path));

            bytes_used = sizeof(FILE_RENAME_INFORMATION) + rename_info->FileNameLength;
            break;
        }

        default:
            trace("Unsupported FileInformationClass: ", FileInformationClass);
            status = STATUS_INVALID_INFO_CLASS;
            break;
    }

    // Update IO status block
    if (IoStatusBlock) {
        IO_STATUS_BLOCK status_block;
        status_block.Status = status;
        status_block.Information = bytes_used;

        uintptr_t status_ptr = reinterpret_cast<uintptr_t>(IoStatusBlock);
        if (!memory_mgr.write(status_ptr, status_block)) {
            return STATUS_ACCESS_VIOLATION;
        }
    }

    return status;
}

NTSTATUS _NtQuerySystemInformation(
    ChildMemoryManager& memory_mgr,
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength) {

    trace("_NtQuerySystemInformation called with class ", SystemInformationClass);

    NTSTATUS status = STATUS_SUCCESS;
    ULONG required_length = 0;

    switch (SystemInformationClass) {
        case SystemBasicInformation:
        case SystemNativeBasicInformation: {
            required_length = sizeof(SYSTEM_BASIC_INFORMATION);
            if (SystemInformationLength >= required_length) {
                if (SystemInformation) {
                    SYSTEM_BASIC_INFORMATION info;
                    info.ActiveProcessorsAffinityMask = g_threads[g_tls.thread]->affinity_mask;
                    info.NumberOfProcessors = static_cast<BYTE>(std::popcount(info.ActiveProcessorsAffinityMask));
                    info.PageSize = PAGE_SIZE;
                    info.HighestUserAddress = reinterpret_cast<PVOID>(0x00007FFFFFFFFFFF);
                    info.KeMaximumIncrement = PAGE_SIZE;
                    info.LowestUserAddress = reinterpret_cast<PVOID>(0x0000000000400000);

                    // number of pages
                    struct sysinfo sys_info;
                    if (sysinfo(&sys_info) == 0) {
                        info.MmNumberOfPhysicalPages = sys_info.totalram / PAGE_SIZE;
                    } else {
                        info.MmNumberOfPhysicalPages = 0;
                    }

                    info.MmLowestPhysicalPage = 0;
                    info.MmHighestPhysicalPage = info.MmNumberOfPhysicalPages - 1;
                    info.AllocationGranularity = 64 * 1024; // 64 KB
                    info.NumberOfProcessors = sysconf(_SC_NPROCESSORS_ONLN);
                    info.unknown = 0;

                    if (auto info_ptr = reinterpret_cast<uintptr_t>(SystemInformation); !memory_mgr.write(info_ptr, info)) {
                        status = STATUS_ACCESS_VIOLATION;
                    }
                } else {
                    status = STATUS_ACCESS_VIOLATION;
                }
            } else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
            break;
        }

        case SystemPerformanceInformation: {
            required_length = sizeof(SYSTEM_PERFORMANCE_INFORMATION);
            if (SystemInformationLength >= required_length) {
                if (SystemInformation) {
                    SYSTEM_PERFORMANCE_INFORMATION info = {};
                    // available pages
                    struct sysinfo sys_info;
                    if (sysinfo(&sys_info) == 0) {
                        info.AvailablePages = sys_info.freeram / PAGE_SIZE;
                    } else {
                        info.AvailablePages = 0;
                    }
                    if (auto info_ptr = reinterpret_cast<uintptr_t>(SystemInformation); !memory_mgr.write(info_ptr, info)) {
                        status = STATUS_ACCESS_VIOLATION;
                    }
                } else {
                    status = STATUS_ACCESS_VIOLATION;
                }
            } else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
            break;
        }

        case SystemTimeOfDayInformation: {
            required_length = sizeof(SYSTEM_TIMEOFDAY_INFORMATION);
            if (SystemInformationLength >= required_length) {
                if (SystemInformation) {
                    SYSTEM_TIMEOFDAY_INFORMATION time_info;
                    memset(&time_info, 0, sizeof(time_info));

                    LARGE_INTEGER system_time;
                    // get linux time
                    timespec ts;
                    if (clock_gettime(CLOCK_REALTIME, &ts) == 0) {
                        // convert to windows time
                        system_time.QuadPart = static_cast<ULONGLONG>(ts.tv_sec) * 10000000ULL + static_cast<ULONGLONG>(ts.tv_nsec) / 100;
                        system_time.QuadPart += 116444736000000000ULL; // Convert to FILETIME epoch
                    }
                    if (uintptr_t info_ptr = reinterpret_cast<uintptr_t>(SystemInformation); !memory_mgr.write(info_ptr, time_info)) {
                        status = STATUS_ACCESS_VIOLATION;
                    }
                } else {
                    status = STATUS_ACCESS_VIOLATION;
                }
            } else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
            break;
        }
        case SystemProcessInformation: {
            required_length = sizeof(SYSTEM_PROCESS_INFORMATION) * g_processes.size();
            if (SystemInformationLength >= required_length) {
                if (SystemInformation) {
                    std::vector<SYSTEM_PROCESS_INFORMATION> proc_infos(g_processes.size());
                    memset(proc_infos.data(), 0, proc_infos.size() * sizeof(SYSTEM_PROCESS_INFORMATION));

                    size_t index = 0;
                    for (const auto &process: g_processes | std::views::values) {
                        if (index >= proc_infos.size()) break;

                        SYSTEM_PROCESS_INFORMATION* current = &proc_infos[index];
                        current->NextEntryOffset = (index == g_processes.size() - 1) ? 0 : sizeof(SYSTEM_PROCESS_INFORMATION);
                        current->CreationTime.QuadPart = process->creation_time.time_since_epoch().count() * 100; // in 100-nanosecond intervals
                        current->UniqueProcessId = reinterpret_cast<HANDLE>(process->pid);
                        current->ParentProcessId = reinterpret_cast<HANDLE>(g_processes[process->parent]->pid);
                        current->HandleCount = process->heaps.size();
                        current->dwThreadCount = 0;
                        for (const auto &thread : g_threads | std::views::values) {
                            if (thread->pid == process->pid) {
                                current->dwThreadCount++;
                            }
                        }
                        current->dwBasePriority = process->base_priority;

                        index++;
                    }

                    uintptr_t info_ptr = reinterpret_cast<uintptr_t>(SystemInformation);
                    for (size_t i = 0; i < proc_infos.size(); i++) {
                        if (!memory_mgr.write(info_ptr + i * sizeof(SYSTEM_PROCESS_INFORMATION), proc_infos[i])) {
                            status = STATUS_ACCESS_VIOLATION;
                            break;
                        }
                    }
                } else {
                    status = STATUS_ACCESS_VIOLATION;
                }
            } else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
            break;
        }

        case SystemModuleInformation: {
            // Fake module information
            static const char* fake_modules[] = {
                R"(\SystemRoot\system32\ntoskrnl.exe)",
                R"(\SystemRoot\system32\hal.dll)",
                R"(\SystemRoot\system32\drivers\mountmgr.sys)"
            };

            required_length = sizeof(RTL_PROCESS_MODULES) +
                             sizeof(RTL_PROCESS_MODULE_INFORMATION) * (std::size(fake_modules) - 1);

            if (SystemInformationLength >= required_length) {
                if (SystemInformation) {
                    RTL_PROCESS_MODULES modules;
                    memset(&modules, 0, sizeof(modules));
                    modules.ModulesCount = std::size(fake_modules);

                    uintptr_t modules_ptr = reinterpret_cast<uintptr_t>(SystemInformation);
                    if (!memory_mgr.write(modules_ptr, modules)) {
                        status = STATUS_ACCESS_VIOLATION;
                        break;
                    }

                    for (size_t i = 0; i < std::size(fake_modules); i++) {
                        RTL_PROCESS_MODULE_INFORMATION module;
                        memset(&module, 0, sizeof(module));

                        module.ImageBaseAddress = reinterpret_cast<PVOID>(0x10000000 + i * 0x200000);
                        module.ImageSize = 0x200000;
                        module.LoadOrderIndex = static_cast<USHORT>(i);
                        module.LoadCount = 1;

                        for (size_t j = 0; j < strlen(fake_modules[i]) && j < sizeof(module.Name) - 1; j++) {
                            module.Name[j] = static_cast<UCHAR>(fake_modules[i][j]);
                        }

                        const char* filename = strrchr(fake_modules[i], '\\');
                        module.NameOffset = filename ?
                            static_cast<WORD>(filename - fake_modules[i] + 1) : 0;

                        uintptr_t module_ptr = modules_ptr + offsetof(RTL_PROCESS_MODULES, Modules) +
                                              i * sizeof(RTL_PROCESS_MODULE_INFORMATION);
                        if (!memory_mgr.write(module_ptr, module)) {
                            status = STATUS_ACCESS_VIOLATION;
                            break;
                        }
                    }
                } else {
                    status = STATUS_ACCESS_VIOLATION;
                }
            } else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
            break;
        }

        default:
            trace("Unhandled SystemInformationClass: ", SystemInformationClass);
            status = STATUS_NOT_IMPLEMENTED;
            break;
    }

    if (ReturnLength) {
        if (auto return_length_ptr = reinterpret_cast<uintptr_t>(ReturnLength); !memory_mgr.write(return_length_ptr, required_length)) {
            if (status == STATUS_SUCCESS) {
                status = STATUS_ACCESS_VIOLATION;
            }
        }
    }

    return status;
}

NTSTATUS _NtQuerySystemInformationEx(
    ChildMemoryManager& memory_mgr,
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID QueryInformation,
    ULONG QueryInformationLength,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength) {
    trace("_NtQuerySystemInformationEx called with class ", SystemInformationClass);

    NTSTATUS status = STATUS_NOT_IMPLEMENTED;
    ULONG required_length = 0;

    switch (SystemInformationClass) {
        case SystemLogicalProcessorInformationEx: {
            if (!QueryInformation || QueryInformationLength < sizeof(LOGICAL_PROCESSOR_RELATIONSHIP)) {
                return STATUS_INVALID_PARAMETER;
            }

            // Read query information from child memory
            uintptr_t query_ptr = reinterpret_cast<uintptr_t>(QueryInformation);
            auto relationship = memory_mgr.read<LOGICAL_PROCESSOR_RELATIONSHIP>(query_ptr);
            if (!relationship) {
                return STATUS_ACCESS_VIOLATION;
            }

            required_length = sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX);
            if (SystemInformationLength >= required_length && SystemInformation) {
                SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX info = {};

                info.Size = sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX);
                info.Relationship = *relationship;

                if (*relationship == RelationProcessorCore) {
                    info.Processor.Flags = 0;
                    info.Processor.EfficiencyClass = 0;
                    info.Processor.Reserved[0] = 0;
                    info.Processor.Reserved[1] = 0;
                    info.Processor.GroupCount = 1;
                    info.Processor.GroupMask[0].Mask = (1ULL << sysconf(_SC_NPROCESSORS_ONLN)) - 1;
                    info.Processor.GroupMask[0].Group = 0;
                }

                if (uintptr_t info_ptr = reinterpret_cast<uintptr_t>(SystemInformation); !memory_mgr.write(info_ptr, info)) {
                    status = STATUS_ACCESS_VIOLATION;
                } else {
                    status = STATUS_SUCCESS;
                }
            } else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
            break;
        }

        default:
            status = STATUS_INVALID_INFO_CLASS;
            break;
    }

    if (ReturnLength) {
        uintptr_t return_length_ptr = reinterpret_cast<uintptr_t>(ReturnLength);
        if (!memory_mgr.write(return_length_ptr, required_length)) {
            if (status == STATUS_SUCCESS) {
                status = STATUS_ACCESS_VIOLATION;
            }
        }
    }

    return status;
}

NTSTATUS _NtCreateProcess(
    ChildMemoryManager& memory_mgr,
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ParentProcess,
    BOOLEAN InheritObjectTable,
    HANDLE SectionHandle,
    HANDLE DebugPort,
    HANDLE ExceptionPort) {

}

NTSTATUS _NtCreateProcessEx(
    ChildMemoryManager &memory_mgr,
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ParentProcess,
    ULONG Flags, // PROCESS_CREATE_FLAGS_*
    HANDLE SectionHandle,
    HANDLE DebugPort,
    HANDLE TokenHandle,
    ULONG Reserved // JobMemberLevel
) {

    trace("_NtCreateProcessEx called with flags: 0x", std::hex, Flags, std::dec);

    if (Flags & PROCESS_CREATE_FLAGS_INHERIT_HANDLES) {
        return _NtCreateProcess(
            memory_mgr,
            ProcessHandle,
            DesiredAccess,
            ObjectAttributes,
            ParentProcess,
            TRUE,  // InheritObjectTable
            SectionHandle,
            DebugPort,
            nullptr  // ExceptionPort
        );
    }
    return _NtCreateProcess(
        memory_mgr,
        ProcessHandle,
        DesiredAccess,
        ObjectAttributes,
        ParentProcess,
        FALSE,  // InheritObjectTable
        SectionHandle,
        DebugPort,
        nullptr  // ExceptionPort
    );
}

NTSTATUS _NtRaiseException(
    ChildMemoryManager & memory_mgr,
     PEXCEPTION_RECORD ExceptionRecord,
     PCONTEXT ContextRecord,
     BOOLEAN FirstChance
    ) {
    trace("_NtRaiseException called");
    // For simplicity, we will just log the exception and terminate the process
    if (!ExceptionRecord || !ContextRecord) {
        return STATUS_INVALID_PARAMETER;
    }
    uintptr_t record_ptr = reinterpret_cast<uintptr_t>(ExceptionRecord);
    auto record = memory_mgr.read<EXCEPTION_RECORD>(record_ptr);
    if (!record) {
        return STATUS_ACCESS_VIOLATION;
    }
    trace("Exception Code: ", std::hex, record->ExceptionCode);
    trace("Exception Address: ", record->ExceptionAddress);

    trace("Exception Context: ");
    const auto context_ptr = reinterpret_cast<uintptr_t>(ContextRecord);
    if (const auto context = memory_mgr.read<CONTEXT>(context_ptr)) {
        trace("ContextFlags: ", std::hex, context->ContextFlags);
        trace("Dr0: ", std::hex, context->Dr0);
        trace("Dr1: ", std::hex, context->Dr1);
        trace("Dr2: ", std::hex, context->Dr2);
        trace("Dr3: ", std::hex, context->Dr3);
        trace("Dr6: ", std::hex, context->Dr6);
        trace("Dr7: ", std::hex, context->Dr7);
        trace("SegCs: ", std::hex, context->SegCs);
        trace("SegDs: ", std::hex, context->SegDs);
        trace("SegEs: ", std::hex, context->SegEs);
        trace("SegFs: ", std::hex, context->SegFs);
        trace("SegGs: ", std::hex, context->SegGs);
        trace("SegSs: ", std::hex, context->SegSs);
        trace("EFlags: ", std::hex, context->EFlags);
        trace("LastBranchFromRip: ", std::hex, context->LastBranchFromRip);
        trace("LastBranchToRip: ", std::hex, context->LastBranchToRip);
        trace("LastExceptionFromRip: ", std::hex, context->LastExceptionFromRip);
        trace("LastExceptionToRip: ", std::hex, context->LastExceptionToRip);
        trace("RBP", std::hex, context->Rbp);
        trace("RIP: ", std::hex, context->Rip);
        trace("RSP: ", std::hex, context->Rsp);
        trace("RAX: ", std::hex, context->Rax);
        trace("RBX: ", std::hex, context->Rbx);
        trace("RCX: ", std::hex, context->Rcx);
        trace("RDX: ", std::hex, context->Rdx);
        trace("RSI: ", std::hex, context->Rsi);
        trace("RDI: ", std::hex, context->Rdi);
        trace("R8: ", std::hex, context->R8);
        trace("R9: ", std::hex, context->R9);
        trace("R10: ", std::hex, context->R10);
        trace("R11: ", std::hex, context->R11);
        trace("R12: ", std::hex, context->R12);
        trace("R13: ", std::hex, context->R13);
        trace("R14: ", std::hex, context->R14);
        trace("R15: ", std::hex, context->R15);
    } else {
        trace("Failed to read context");
    }
    // Terminate the process
    exit(1);
    return STATUS_SUCCESS; // This line will never be reached
}

NTSTATUS _NtFlushKey(
    ChildMemoryManager& memory_mgr,
    HANDLE KeyHandle) {

    trace("_NtFlushKey called");

    g_registry.flush_to_disk(); // Flush all changes to disk (TODO: optimize to specific key)
}

class ProcessManager {
private:
    std::shared_ptr<SystemCallManager> ipc_manager;

    // Launch a new process using posix_spawn (not fork!)
    pid_t create_process_native(const Process& info) {
        std::string image_path_str = converter.to_bytes(info.image_path);

        // Prepare arguments
        std::vector<char*> argv;
        argv.push_back(const_cast<char*>(image_path_str.c_str()));
        argv.push_back(nullptr);

        // Prepare environment
        std::vector<char*> envp;
        if (info.environment) {
            // Parse Windows environment block
            // TODO: Convert WCHAR* environment to char* array
        }
        envp.push_back(nullptr);

        // Use posix_spawn instead of fork
        pid_t pid;
        posix_spawn_file_actions_t actions;
        posix_spawn_file_actions_init(&actions);

        // Set up IPC file descriptors
        posix_spawn_file_actions_adddup2(&actions,
            ipc_manager->get_child_read_fd(), STDIN_FILENO);
        posix_spawn_file_actions_adddup2(&actions,
            ipc_manager->get_child_write_fd(), STDOUT_FILENO);

        int result = posix_spawn(&pid, image_path_str.c_str(),
            &actions, nullptr, argv.data(), envp.data());

        posix_spawn_file_actions_destroy(&actions);

        if (result != 0) {
            error("posix_spawn failed: ", strerror(result));
            return -1;
        }

        return pid;
    }

public:
    explicit ProcessManager(std::shared_ptr<SystemCallManager> ipc)
        : ipc_manager(std::move(ipc)) {}

    NTSTATUS create_process(
        PHANDLE ProcessHandle,
        const Process& info) {

        // Create new process entry
        auto process = std::make_shared<Process>();

        // Launch the process
        pid_t pid = create_process_native(info);
        if (pid == -1) {
            return STATUS_UNSUCCESSFUL;
        }

        process->pid = pid;
        process->parent = info.parent;
        process->image_path = info.image_path;

        HANDLE handle = g_next_handle;
        ++g_next_handle_num;

        g_processes[handle] = process;
        *ProcessHandle = handle;

        // Set up IPC for this process
        ipc_manager->setup_as_parent(pid);

        trace("Created process: PID=", pid, ", Handle=", handle);
        return STATUS_SUCCESS;
    }
};

class WindowsPELoader {
    struct ReservedRange {
        uintptr_t start;
        uintptr_t end;
        std::wstring owner;
    };
    std::vector<ReservedRange> reserved_ranges;

    // Add dependency tracking
    std::unordered_set<std::wstring> loading_modules; // Track modules currently being loaded to detect cycles
    std::vector<LoadedModule*> load_order; // Track order for proper initialization

    // Check if an address range conflicts with reserved ranges
    bool is_address_range_available(uintptr_t start, size_t size) const {
        const uintptr_t end = start + size;
        for (const auto& range : reserved_ranges) {
            if (!(end <= range.start || start >= range.end)) {
                return false; // Overlap detected
            }
        }
        return true;
    }

    void* allocate_memory_avoiding_conflicts(size_t size, uintptr_t preferred_addr = 0) const {
        if (preferred_addr != 0) {
            // Check if the preferred address conflicts with reserved ranges
            if (is_address_range_available(preferred_addr, size)) {
                void* addr = mmap(reinterpret_cast<void*>(preferred_addr), size,
                                 PROT_READ | PROT_WRITE | PROT_EXEC,
                                 MAP_SHARED | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
                if (addr != MAP_FAILED && addr == reinterpret_cast<void*>(preferred_addr)) {
                    trace("Allocated at preferred address: 0x", std::hex, preferred_addr, std::dec);
                    return addr;
                }
            } else {
                trace("Preferred address 0x", std::hex, preferred_addr,
                      " conflicts with reserved range, finding alternative", std::dec);
            }
        }

        // Find an alternative address that doesn't conflict
        void* addr = MemoryManager::allocate_executable_memory(size);
        if (addr) {
            trace("Allocated at alternative address: 0x", std::hex,
                  reinterpret_cast<uintptr_t>(addr), std::dec);
        }
        return addr;
    }

    // Reserve an address range
    void reserve_address_range(uintptr_t start, size_t size, const std::wstring& owner) {
        reserved_ranges.push_back({start, start + size, owner});
        trace("Reserved address range 0x", std::hex, start, " - 0x", start + size,
              " for ", owner, std::dec);
    }

    // Pre-load ntdll.dll at its preferred base
    bool preload_ntdll() {
        const std::wstring ntdll_name = L"ntdll.dll";

        // Check if already loaded
        if (module_by_name.contains(ntdll_name)) {
            trace("ntdll.dll already loaded");
            return true;
        }

        trace("Pre-loading ntdll.dll at preferred base...");

        // Find ntdll.dll file
        const std::wstring ntdll_path = find_dll_file(ntdll_name);
        if (ntdll_path.empty()) {
            warn("Could not find ntdll.dll - this may cause issues");
            return false;
        }

        // Parse ntdll.dll
        const std::string ntdll_path_str = converter.to_bytes(ntdll_path);
        std::shared_ptr<LIEF::PE::Binary> pe_binary(
            LIEF::PE::Parser::parse(ntdll_path_str).release());

        if (!pe_binary) {
            warn("Failed to parse ntdll.dll");
            return false;
        }

        // Get preferred base and size
        const uintptr_t preferred_base = pe_binary->optional_header().imagebase();
        size_t image_size = pe_binary->optional_header().sizeof_image();
        image_size = (image_size + 4095) & ~4095; // Align to page size

        trace("ntdll.dll preferred base: 0x", std::hex, preferred_base, std::dec);
        trace("ntdll.dll image size: ", image_size, " bytes");

        // Try to allocate at a preferred base with high priority
        void* memory = mmap(reinterpret_cast<void*>(preferred_base), image_size,
                           PROT_READ | PROT_WRITE | PROT_EXEC,
                           MAP_SHARED | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);

        if (memory == MAP_FAILED || memory != reinterpret_cast<void*>(preferred_base)) {
            warn("Failed to allocate ntdll.dll at preferred base 0x", std::hex, preferred_base,
                 " - this may cause compatibility issues", std::dec);

            // Try alternative allocation
            memory = MemoryManager::allocate_executable_memory(image_size);
            if (!memory) {
                error("Failed to allocate memory for ntdll.dll at any address");
                return false;
            }
        } else {
            trace("Successfully allocated ntdll.dll at preferred base 0x", std::hex, preferred_base, std::dec);
        }

        auto base_addr = reinterpret_cast<uintptr_t>(memory);
        memset(memory, 0, image_size);

        // Map sections
        for (const auto& section : pe_binary->sections()) {
            uint32_t virtual_addr = section.virtual_address();
            auto raw_data = section.content();

            if (virtual_addr + raw_data.size() <= image_size) {
                memcpy(reinterpret_cast<void*>(base_addr + virtual_addr),
                       raw_data.data(), raw_data.size());
            }
        }

        // Create module entry
        auto module = std::make_shared<LoadedModule>(
            ntdll_name, base_addr, image_size, std::move(pe_binary), true);
        LoadedModule* module_ptr = module.get();

        loaded_modules.push_back(std::move(module));
        module_by_address[base_addr] = module_ptr;
        module_by_name[ntdll_name] = module_ptr;

        // Apply relocations and permissions
        MemoryManager::apply_relocations(*module_ptr->pe_binary, memory, base_addr);
        // Reloc entry_point
        module_ptr->entry_point = base_addr +
            (module_ptr->pe_binary->optional_header().addressof_entrypoint());

        MemoryManager::apply_section_permissions(*module_ptr->pe_binary, memory, base_addr);

        // Reserve the address range to prevent conflicts
        reserve_address_range(base_addr, image_size, ntdll_name);

        trace("ntdll.dll pre-loaded successfully at 0x", std::hex, base_addr, std::dec);
        return true;
    }

    // Enhanced dependency resolution
    bool load_dependencies_recursive(LoadedModule* module) {
        if (!module || !module->pe_binary->has_imports()) {
            return true;
        }

        const std::wstring& module_name = module->name;

        trace("Loading dependencies for: ", module_name);

        // Collect all dependencies first
        std::vector<std::wstring> dependencies;

        for (const auto& import : module->pe_binary->imports()) {
            if (import.name().empty()) continue;

            std::wstring dep_name = converter.from_bytes(import.name());
            std::ranges::transform(dep_name, dep_name.begin(), ::tolower);

            // Skip self-references
            if (dep_name == module_name) {
                trace("Skipping self-dependency: ", dep_name);
                continue;
            }

            // Apply API set resolution
            if (std::string dep_name_str = converter.to_bytes(dep_name);
                ApiSetResolver::is_api_set(dep_name_str)) {
                std::string resolved = api_resolver.resolve_dll(dep_name_str);
                dep_name = converter.from_bytes(resolved);
                std::ranges::transform(dep_name, dep_name.begin(), ::tolower);
                trace("API SET RESOLUTION: ", converter.from_bytes(import.name()), " -> ", dep_name);
            }

            dependencies.push_back(dep_name);
        }

        // Load each dependency recursively
        for (const auto& dep_name : dependencies) {
            // Check if already loaded
            if (module_by_name.contains(dep_name)) {
                trace("Dependency already loaded: ", dep_name);
                continue;
            }

            // Check for circular dependencies
            if (loading_modules.contains(dep_name)) {
                warn("Circular dependency detected: ", module_name, " -> ", dep_name);
                continue;
            }

            trace("Loading dependency: ", dep_name, " for ", module_name);

            auto [success, dep_module] = load_pe_dll_internal(dep_name);
            if (!dep_module) {
                warn("Failed to load dependency: ", dep_name, " for ", module_name);
                // Don't fail completely - continue with other dependencies
                continue;
            }
        }

        return true;
    }

    std::pair<bool, LoadedModule*> load_pe_dll_internal(const std::wstring& dll_name) {
        std::wstring dll_lower = dll_name;
        std::ranges::transform(dll_lower, dll_lower.begin(), ::tolower);

        // Prevent circular loading
        if (loading_modules.contains(dll_lower)) {
            trace("Circular dependency prevented: ", dll_name);
            return { false, nullptr };
        }

        // Check if already loaded
        if (auto it = module_by_name.find(dll_lower); it != module_by_name.end()) {
            return { true, it->second };
        }

        // Add to loading set
        loading_modules.insert(dll_lower);

        // Resolve API sets
        std::wstring actual_dll_name = dll_name;
        bool is_api_set = false;

        if (std::string dll_name_str = converter.to_bytes(dll_name);
            ApiSetResolver::is_api_set(dll_name_str)) {
            std::string resolved = api_resolver.resolve_dll(dll_name_str);
            if (resolved != dll_name_str) {
                actual_dll_name = converter.from_bytes(resolved);
                is_api_set = true;
                trace("API set ", dll_name, " resolved to: ", actual_dll_name);
            }
        }

        std::wstring actual_dll_lower = actual_dll_name;
        std::ranges::transform(actual_dll_lower, actual_dll_lower.begin(), ::tolower);

        // Check if the resolved name is already loaded
        if (auto it = module_by_name.find(actual_dll_lower); it != module_by_name.end()) {
            if (dll_lower != actual_dll_lower) {
                module_by_name[dll_lower] = it->second;
            }
            loading_modules.erase(dll_lower);
            return { true, it->second };
        }

        // Find and parse DLL
        std::wstring dll_path = find_dll_file(actual_dll_name);
        if (dll_path.empty()) {
            trace("Could not find DLL: ", actual_dll_name);
            loading_modules.erase(dll_lower);
            return { false, nullptr };
        }

        std::string dll_path_str = converter.to_bytes(dll_path);
        std::shared_ptr<LIEF::PE::Binary> pe_binary(
            LIEF::PE::Parser::parse(dll_path_str).release());

        if (!pe_binary) {
            trace("Failed to parse PE DLL: ", dll_path);
            loading_modules.erase(dll_lower);
            return { false, nullptr };
        }

        // Allocate memory with conflict avoidance
        size_t image_size = pe_binary->optional_header().sizeof_image();
        image_size = (image_size + 4095) & ~4095;

        uintptr_t preferred_base = pe_binary->optional_header().imagebase();

        // Use enhanced allocation method
        void* memory = allocate_memory_avoiding_conflicts(image_size, preferred_base);

        if (!memory) {
            trace("Failed to allocate memory for DLL: ", dll_name);
            loading_modules.erase(dll_lower);
            return { false, nullptr };
        }

        auto base_addr = reinterpret_cast<uintptr_t>(memory);
        memset(memory, 0, image_size);

        // Map sections
        for (const auto& section : pe_binary->sections()) {
            uint32_t virtual_addr = section.virtual_address();
            auto raw_data = section.content();

            if (virtual_addr + raw_data.size() <= image_size) {
                memcpy(reinterpret_cast<void*>(base_addr + virtual_addr),
                       raw_data.data(), raw_data.size());
            }
        }

        // Create module entry
        auto module = std::make_shared<LoadedModule>(
            actual_dll_lower, base_addr, image_size, std::move(pe_binary), true);
        LoadedModule* module_ptr = module.get();

        loaded_modules.push_back(std::move(module));
        module_by_address[base_addr] = module_ptr;
        module_by_name[actual_dll_lower] = module_ptr;

        // Create alias if needed
        if (dll_lower != actual_dll_lower) {
            module_by_name[dll_lower] = module_ptr;
        }

        // Apply relocations and permissions
        MemoryManager::apply_relocations(*module_ptr->pe_binary, memory, base_addr);
        MemoryManager::apply_section_permissions(*module_ptr->pe_binary, memory, base_addr);

        // Reserve address range if at preferred base
        if (base_addr == preferred_base) {
            reserve_address_range(base_addr, image_size, actual_dll_name);
        }

        // Add to load order for later processing
        load_order.push_back(module_ptr);

        trace("Successfully loaded module: ", dll_name, " at 0x", std::hex, base_addr, std::dec);

        // Recursively load dependencies
        if (!load_dependencies_recursive(module_ptr)) {
            warn("Failed to load some dependencies for: ", dll_name);
        }

        loading_modules.erase(dll_lower);
        return { true, module_ptr };
    }

public:
    // Public interface - now calls internal method
    std::pair<bool, LoadedModule*> load_pe_dll(const std::wstring& dll_name) {
        // Clear load order tracking for each top-level call
        bool is_top_level = loading_modules.empty();

        auto result = load_pe_dll_internal(dll_name);

        // If this was a top-level call, resolve imports for all loaded modules
        if (is_top_level && !load_order.empty()) {
            resolve_imports_for_loaded_modules();
            load_order.clear();
        }

        return result;
    }

private:
    // Resolve imports for all newly loaded modules in correct order
    void resolve_imports_for_loaded_modules() {
        trace("\n=== RESOLVING IMPORTS FOR ALL LOADED MODULES ===");

        // Process modules in load order (dependencies first)
        for (LoadedModule* module : load_order) {
            if (module->import_state != LoadedModule::ImportState::COMPLETED) {
                trace("Resolving imports for: ", module->name);
                module->import_state = LoadedModule::ImportState::IN_PROGRESS;

                import_resolver->resolve_imports(*module->pe_binary, module->base_address);

                module->import_state = LoadedModule::ImportState::COMPLETED;
                module->imports_resolved = true;
            }
        }

        // Call DllMain for all newly loaded DLLs in load order
        for (LoadedModule* module : load_order) {
            if (module->is_dll && module->entry_point != 0) {
                trace("Calling DllMain for: ", module->name);
                call_dll_main_monitored(module, 1); // DLL_PROCESS_ATTACH
            }
        }

        trace("=== IMPORT RESOLUTION COMPLETE ===\n");
    }
public:
    static int call_windows_function_safe(uintptr_t func_addr, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3, uintptr_t arg4) {
        {
            trace("Attempting to call function at 0x", std::hex, func_addr, std::dec);
            trace("Arguments: 0x", std::hex, arg1, ", 0x", arg2, ", 0x", arg3, ", 0x", arg4, std::dec);

            // Print first few bytes of function for debugging
            auto func_bytes = reinterpret_cast<uint8_t*>(func_addr);
            trace("Function bytes: ");
            for (int i = 0; i < 64; i++) {
                trace(std::hex, std::setw(2), std::setfill<wchar_t>('0'), static_cast<int>(func_bytes[i]), " ");
            }
            trace(std::dec);

            cs_insn *insn;
            csh handle;
            if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
                trace("Failed to initialize Capstone");
            }
            else {
                size_t count = cs_disasm(handle, func_bytes, 64, func_addr, 0, &insn);
                if (count > 0) {
                    trace("Disassembly of first 64 bytes:");
                    for (size_t j = 0; j < count; j++) {
                        trace("0x", std::hex, insn[j].address, ": ", insn[j].mnemonic, " ", insn[j].op_str, std::dec);
                    }
                    cs_free(insn, count);
                } else {
                    trace("Failed to disassemble function bytes");
                }
            }
            cs_close(&handle);
            // Check for common Windows function prologs
            if (func_bytes[0] == 0x48 && func_bytes[1] == 0x89 && func_bytes[2] == 0x5C && func_bytes[3] == 0x24) {
                trace("Detected Windows x64 function prolog: mov [rsp+XX], rbx");
            } else if (func_bytes[0] == 0x48 && func_bytes[1] == 0x83 && func_bytes[2] == 0xEC) {
                trace("Detected Windows x64 function prolog: sub rsp, XX");
            } else if (func_bytes[0] == 0x55) {
                trace("Detected function prolog: push rbp");
            } else {
                trace("WARNING: Unrecognized function prolog - might not be a valid function");
            }
        }

        uintptr_t result;
        uintptr_t saved_rsp;

        void* rip_val;

        asm volatile(
            "lea (%%rip), %0"
            : "=r"(rip_val)   // output: put into any register
        );

        trace("Preparing to call function at 0x", std::hex, func_addr, std::dec);

        // CRITICAL: Stop and wait for the parent
        trace("Current RIP: 0x", std::hex, reinterpret_cast<uintptr_t>(rip_val), std::dec);
        raise(SIGSTOP);

        // FIXED: Proper stack alignment and shadow space allocation
        asm volatile (
            // Save original RSP
            "movq %%rsp, %[saved_rsp]\n\t"

            // Ensure we have enough stack space (but don't destroy alignment)
            "subq $128, %%rsp\n\t"  // Allocate plenty of stack space

            // Align to 16 bytes (Windows x64 ABI requirement)
            "andq $-16, %%rsp\n\t"

            // Allocate 32-byte shadow space (Windows x64 requirement)
            "subq $32, %%rsp\n\t"

            // Set up Windows x64 calling convention parameters
            "movq %[arg1], %%rcx\n\t"    // 1st argument -> RCX
            "movq %[arg2], %%rdx\n\t"    // 2nd argument -> RDX
            "movq %[arg3], %%r8\n\t"     // 3rd argument -> R8
            "movq %[arg4], %%r9\n\t"     // 4th argument -> R9

            // also push the arguments onto the stack for safety
            "push %[arg4]\n\t"
            "push %[arg3]\n\t"
            "push %[arg2]\n\t"
            "push %[arg1]\n\t"

            // Call the function
            "callq *%[func_addr]\n\t"

            // Store return value
            "movq %%rax, %[result]\n\t"

            // Restore original stack pointer
            "movq %[saved_rsp], %%rsp\n\t"

            : [result] "=m" (result), [saved_rsp] "=m" (saved_rsp)
            : [func_addr] "r" (func_addr), [arg1] "r" (arg1), [arg2] "r" (arg2), [arg3] "r" (arg3), [arg4] "r" (arg4)
            : "rax", "rcx", "rdx", "r8", "r9", "r10", "r11", "memory"
        );

        ret("Function returned: 0x", std::hex, result, std::dec);
        return static_cast<int>(result);
    }

    static void call_dll_main(LoadedModule* module, uint32_t reason) {
        if (!module || !module->pe_binary) return;

        auto entry_point = module->pe_binary->entrypoint();
        if (entry_point == 0) {
            trace("No entry point for module: ", module->name);
            return;
        }

        uintptr_t func_addr = module->base_address + entry_point;

        trace("Calling DllMain of ", module->name, " at 0x", std::hex, func_addr, std::dec);

        // Call DllMain with (HINSTANCE, reason, NULL)
        call_windows_function_safe(
            func_addr,
            module->base_address,  // HINSTANCE
            reason,               // Reason
            0,                    // Reserved
            0                     // Unused
        );
    }

    // Enhanced main executable loading that properly handles all dependencies
    int load_and_execute(const std::wstring& pe_path, int argc, char* argv[]) {
        trace("Loading PE file: ", pe_path);
        trace("Syscall monitoring ", (syscall_monitor->is_enabled() ? "ENABLED" : "DISABLED"));

        // CRITICAL: Pre-load ntdll.dll first to secure its preferred base
        if (!preload_ntdll()) {
            warn("Failed to pre-load ntdll.dll - continuing anyway");
        }

        // Parse main PE file
        std::shared_ptr<LIEF::PE::Binary> pe_binary(
            LIEF::PE::Parser::parse(converter.to_bytes(pe_path)).release());

        if (!pe_binary) {
            error("Failed to parse PE file: ", pe_path);
            return 1;
        }

        // Load and map the main executable (using conflict-aware allocation)
        size_t image_size = pe_binary->optional_header().sizeof_image();
        image_size = (image_size + 4095) & ~4095;

        uintptr_t preferred_base = pe_binary->optional_header().imagebase();
        void* memory = allocate_memory_avoiding_conflicts(image_size, preferred_base);

        if (!memory) {
            error("Failed to allocate memory for main executable");
            return 1;
        }

        auto base_addr = reinterpret_cast<uintptr_t>(memory);
        memset(memory, 0, image_size);

        // Map sections
        for (const auto& section : pe_binary->sections()) {
            const uint32_t virtual_addr = section.virtual_address();
            auto raw_data = section.content();

            if (virtual_addr + raw_data.size() <= image_size) {
                memcpy(reinterpret_cast<void*>(base_addr + virtual_addr),
                       raw_data.data(), raw_data.size());
            }
        }

        // Create the main module
        auto main_module = std::make_shared<LoadedModule>(
            pe_path, base_addr, image_size, std::move(pe_binary), false);
        LoadedModule* main_module_ptr = main_module.get();

        loaded_modules.push_back(std::move(main_module));
        module_by_address[base_addr] = main_module_ptr;

        // Reserve address range for the main executable
        if (base_addr == preferred_base) {
            reserve_address_range(base_addr, image_size, pe_path);
        }

        // Apply relocations and permissions
        MemoryManager::apply_relocations(*main_module_ptr->pe_binary, memory, base_addr);
        MemoryManager::apply_section_permissions(*main_module_ptr->pe_binary, memory, base_addr);

        // Initialize globals
        g_tls.process = reinterpret_cast<HANDLE>(1);
        g_tls.thread = reinterpret_cast<HANDLE>(0);
        g_processes[g_tls.process] = std::make_shared<Process>();
        g_processes[g_tls.process]->hmodule = reinterpret_cast<HMODULE>(base_addr);

        if (!g_current_teb || !g_current_peb) {
            error("Current TEB or PEB not initialized");
            return 1;
        }

        if (const long ret = syscall(SYS_arch_prctl, ARCH_SET_GS, reinterpret_cast<uintptr_t>(g_current_teb)); ret != 0) {
            error("arch_prctl failed: ", strerror(errno));
            return 1;
        }

        // Load ALL dependencies recursively (ntdll.dll already loaded)
        load_order.push_back(main_module_ptr);

        if (!load_dependencies_recursive(main_module_ptr)) {
            warn("Failed to load some dependencies for main executable");
        }

        // Resolve imports for all modules
        resolve_imports_for_loaded_modules();
        load_order.clear();

        // Print allocation summary
        print_allocation_summary();

        // Execute entry point
        uintptr_t entry_rva = main_module_ptr->pe_binary->optional_header().addressof_entrypoint();
        if (entry_rva == 0) {
            error("No entry point found");
            return 1;
        }

        uintptr_t entry_point = base_addr + entry_rva;
        trace("Entry point: 0x", std::hex, entry_point, std::dec);

        if (syscall_monitor->is_enabled()) {
            pid_t child = fork();
            if (child == -1) {
                error("Failed to fork");
                return 1;
            }

            if (child == 0) {
                if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
                    error("ptrace TRACEME failed");
                    exit(1);
                }

                call_windows_function_safe(entry_point, base_addr, 0, 0, 0);
                exit(0);
            } else {
                int status;
                waitpid(child, &status, 0);
                if (WIFSTOPPED(status)) {
                    syscall_monitor->trace_child_execution(child, L"Main execution");
                }
            }
        } else {
            call_windows_function_safe(
                entry_point, base_addr, argc, reinterpret_cast<uintptr_t>(argv), 0);
        }

        return 0;
    }

    // Print summary of module allocations
    void print_allocation_summary() const {
        trace("\n=== Module Allocation Summary ===");
        for (const auto& module : loaded_modules) {
            bool at_preferred = false;
            if (module->pe_binary) {
                uintptr_t preferred = module->pe_binary->optional_header().imagebase();
                at_preferred = (module->base_address == preferred);
            }

            trace("Module: ", module->name);
            trace("  Allocated at: 0x", std::hex, module->base_address, std::dec);
            trace("  At preferred base: ", (at_preferred ? "YES" : "NO"));
            if (!at_preferred && module->pe_binary) {
                trace("  Preferred was: 0x", std::hex,
                      module->pe_binary->optional_header().imagebase(), std::dec);
            }
        }
        trace("===============================\n");
    }

    // Core data
    std::vector<std::shared_ptr<LoadedModule>> loaded_modules;
    std::unordered_map<std::wstring, LoadedModule*> module_by_name;
    std::unordered_map<uintptr_t, LoadedModule*> module_by_address;
    std::vector<std::wstring> dll_search_paths;

    // Components
    std::shared_ptr<ExportResolver> export_resolver;
    std::shared_ptr<ImportResolver> import_resolver;
    std::shared_ptr<SystemCallManager> syscall_monitor;

    // Configuration
    bool enable_function_tracing;
    std::unordered_map<void*, void*> function_wrappers;

public:
    explicit WindowsPELoader(bool monitor_syscalls = true, const bool trace_functions = true)
        : enable_function_tracing(trace_functions) {

        dll_search_paths.emplace_back(L".");
        dll_search_paths.emplace_back(L"./dlls");

        export_resolver = std::make_shared<ExportResolver>(
            module_by_address,
            module_by_name,
            loaded_modules,
            api_resolver,
            dll_search_paths
        );
        import_resolver = std::make_shared<ImportResolver>(loaded_modules, module_by_name,
                                                          module_by_address, api_resolver, *export_resolver);
        import_resolver->set_function_tracing(trace_functions);

        const std::vector<std::string> candidates = {
            "10.0.19041.1-AMD64.json",
            "apisetschema.spec",
            "./apiset/10.0.19041.1-AMD64.json",
            "./apiset/apisetschema.spec"
        };

        api_resolver.load_multiple_files(candidates);
        initialize_kuser_shared_data();
        initialize_default_current_peb();
        initialize_default_current_teb();
        api_resolver.populate_peb_api_set_map();
    }

    ~WindowsPELoader() {
        for (const auto& wrapper : function_wrappers | std::views::values) {
            AssemblyWrapperGenerator::cleanup_wrapper(wrapper);
        }

        for (const auto& module : loaded_modules) {
            if (module->base_address && module->size > 0) {
                munmap(reinterpret_cast<void*>(module->base_address), module->size);
            }
        }
    }

    // Public methods
    bool load_api_mappings(const std::string& filename) {
        return api_resolver.load_apiset_file(filename);
    }

    bool load_api_mappings_multiple(const std::vector<std::string>& filenames) {
        return api_resolver.load_multiple_files(filenames);
    }

    void add_dll_search_path(const std::wstring& path) {
        dll_search_paths.push_back(path);
    }

    void set_syscall_monitoring(bool enable) {
        syscall_monitor->set_monitoring(enable);
    }

    void set_function_tracing(bool enable) {
        enable_function_tracing = enable;
        import_resolver->set_function_tracing(enable);
    }

    void print_apiset_statistics() const {
        api_resolver.print_statistics();
    }

    void print_loaded_modules() const {
        trace("\n=== Loaded Modules ===");
        for (const auto& module : loaded_modules) {
            trace("Module: ", module->name);
            trace("  Base: 0x", std::hex, module->base_address, std::dec);
            trace("  Size: ", module->size, " bytes");
            trace("  Type: ", (module->is_dll ? "DLL" : "EXE"));
            if (module->entry_point != 0) {
                trace("  Entry: 0x", std::hex, module->entry_point, std::dec);
            }
            trace();
        }
        trace("======================");
    }

    std::wstring find_dll_file(const std::wstring& dll_name) const {
        if (std::filesystem::exists(dll_name)) {
            return dll_name;
        }

        std::wstring dll_with_ext = dll_name;
        if (!dll_with_ext.ends_with(L".dll")) {
            dll_with_ext += L".dll";
            if (std::filesystem::exists(dll_with_ext)) {
                return dll_with_ext;
            }
        }

        for (const auto& path : dll_search_paths) {
            std::filesystem::path full_path = std::filesystem::path(path) / dll_with_ext;
            if (std::filesystem::exists(full_path)) {
                return full_path.wstring();
            }
        }

        return L"";
    }

    void call_dll_main_monitored(LoadedModule* module, uint32_t reason) const {
        if (!module || !module->is_dll || module->entry_point == 0) {
            return;
        }

        const std::wstring reason_str = (reason == 1) ? L"DLL_PROCESS_ATTACH" :
                                 (reason == 0) ? L"DLL_PROCESS_DETACH" :
                                 (reason == 2) ? L"DLL_THREAD_ATTACH" :
                                 (reason == 3) ? L"DLL_THREAD_DETACH" : L"UNKNOWN";

        const std::wstring context = L"DllMain(" + module->name + L", " + reason_str + L")";

        if (syscall_monitor->is_enabled()) {
            const pid_t child = fork();
            if (child == -1) {
                error("Failed to fork for DLL monitoring");
                return;
            }

            if (child == 0) {
                if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
                    error("ptrace TRACEME failed for DLL");
                    exit(1);
                }

                call_windows_function_safe(
                    module->entry_point, module->base_address, reason, 0, 0);
                exit(0);
            } else {
                int status;
                waitpid(child, &status, 0);
                if (WIFSTOPPED(status)) {
                    syscall_monitor->trace_child_execution(child, context);
                }
            }
        } else {
            call_dll_main(module, reason);
        }
    }
};

// ============================================================================
// MAIN FUNCTION
// ============================================================================

int main(int argc, char* argv[]) {
    if (argc < 2) {
        trace("Usage: ", argv[0], " <pe_file> [options] [dll_paths...]");
        trace("Options:");
        trace("  --no-monitoring     Disable syscall monitoring");
        trace("  --no-tracing        Disable function tracing");
        trace("  --apiset <file>     Load API set mappings");
        trace("  --stats             Show API set statistics");
        return 1;
    }

    try {
        bool enable_monitoring = true;
        bool enable_tracing = true;
        bool show_stats = false;
        std::vector<std::string> apiset_files;
        int path_start_idx = 2;

        // Parse command line options
        for (int i = 2; i < argc; i++) {
            std::string arg = argv[i];

            if (arg == "--no-monitoring") {
                enable_monitoring = false;
                path_start_idx = i + 1;
            } else if (arg == "--no-tracing") {
                enable_tracing = false;
                path_start_idx = i + 1;
            } else if (arg == "--stats") {
                show_stats = true;
                path_start_idx = i + 1;
            } else if (arg == "--apiset" && i + 1 < argc) {
                apiset_files.emplace_back(argv[i + 1]);
                i++;
                path_start_idx = i + 1;
            } else {
                break;
            }
        }

        WindowsPELoader loader(enable_monitoring, enable_tracing);

        // Load API set files
        if (!apiset_files.empty()) {
            loader.load_api_mappings_multiple(apiset_files);
        }

        if (show_stats) {
            loader.print_apiset_statistics();
        }

        // Add DLL search paths
        for (int i = path_start_idx; i < argc; i++) {
            loader.add_dll_search_path(converter.from_bytes(argv[i]));
        }

        int result = loader.load_and_execute(converter.from_bytes(argv[1]), argc - 1, argv + 1);
        loader.print_loaded_modules();

        return result;
    } catch (const std::exception& e) {
        error("Error: ", e.what());
        return 1;
    }
}