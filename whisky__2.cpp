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

// The ONE. True. Converter.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
class CompletionPort;
class DeviceHandle;
class ThreadContext;
struct LoadedModule;
std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
std::wstring_convert<std::codecvt_utf8<char16_t>, char16_t> converter16;
#pragma GCC diagnostic pop


// Forward declarations for helper functions
static NTSTATUS errno_to_ntstatus(int error_code);
static ULONGLONG get_system_time_as_file_time();
static ULONGLONG get_interrupt_time();
static ULONGLONG get_tick_count();
static void update_system_times();
static bool initialize_kuser_shared_data();
static void update_kuser_shared_data();
static void cleanup_kuser_shared_data();
static void initialize_default_current_peb();
static void cleanup_current_peb();
static void initialize_default_current_teb();
static void cleanup_current_teb();
static DeviceHandle* get_device_handle(HANDLE process, HANDLE handle);
static HANDLE create_network_socket(HANDLE process, int domain, int type, int protocol,
                                   ULONG options, ULONG disposition, ULONG access,
                                   ULONG share_mode, ULONG file_attributes);
static void close_device_handle(HANDLE process, HANDLE handle);

// Constants
#define KUSER_SHARED_DATA_ADDRESS 0x7FFE0000
#define KUSER_SHARED_DATA_SIZE 0x1000
#define PROCESSOR_FEATURE_MAX 64

// Helper function to parse command line into argv array
static std::vector<std::u16string> parse_command_line(const std::u16string& command_line) {
    std::vector<std::u16string> args;
    std::string cmd_str = converter16.to_bytes(command_line);

    std::u16string current_arg;
    bool in_quotes = false;
    bool escape_next = false;

    for (const char16_t c : cmd_str) {
        if (escape_next) {
            current_arg += c;
            escape_next = false;
        } else if (c == u'\\') {
            escape_next = true;
            current_arg += c;
        } else if (c == u'"') {
            in_quotes = !in_quotes;
        } else if (c == u' ' && !in_quotes) {
            if (!current_arg.empty()) {
                args.push_back(current_arg);
                current_arg.clear();
            }
        } else {
            current_arg += c;
        }
    }

    if (!current_arg.empty()) {
        args.push_back(current_arg);
    }

    return args;
}

// Helper function to create environment block
static std::vector<std::string> create_environment_array(WCHAR* environment_block) {
    std::vector<std::string> env_vars;

    if (!environment_block) {
        // Use current environment
        extern char** environ;
        for (char** env = environ; *env != nullptr; env++) {
            env_vars.emplace_back(*env);
        }
    } else {
        // Parse Windows environment block
        WCHAR* current = environment_block;
        while (*current) {
            std::wstring env_var;
            while (*current) {
                env_var += *current++;
            }
            current++; // Skip null terminator

            if (!env_var.empty()) {
                env_vars.push_back(converter.to_bytes(env_var));
            }
        }
    }

    return env_vars;
}

// APC Queue Entry
struct ProcessThreadAPC {
    PNTAPCFUNC func;
    ULONG_PTR arg1;
    ULONG_PTR arg2;
    ULONG_PTR arg3;
};

// Heap structures (simplified ReactOS-based)
typedef struct _BLOCK_DATA {
    ULONG_PTR Flink:32;
    ULONG_PTR Blink:32;
} BLOCK_DATA, *PBLOCK_DATA;

typedef struct _HEAP_BLOCK {
    USHORT Size;
    USHORT PreviousSize;
    ULONG Tag;
    BLOCK_DATA *Data;
} HEAP_BLOCK, *PHEAP_BLOCK;

typedef struct _HEAP {
    SIZE_T MaximumSize;
    SIZE_T CurrentAllocBytes;
    SIZE_T MaxAllocBytes;
    ULONG NumAllocs;
    ULONG NumFrees;
    SIZE_T LargestAllocation;
    ULONGLONG AllocationTime;
    ULONGLONG FreeTime;
    ULONG_PTR TerminatingBlock;
    HEAP_BLOCK Blocks;
    mutable std::shared_mutex heap_mutex;
} HEAP, *PHEAP;

// Completion Port
struct CompletionPacket {
    ULONG_PTR completion_key = 0;
    LPOVERLAPPED overlapped = nullptr;
    DWORD bytes_transferred = 0;
    DWORD error_code = 0;
    HANDLE io_completion_handle = nullptr;
    HANDLE target_object = nullptr;
    PVOID key_context = nullptr;
    PVOID apc_context = nullptr;
    NTSTATUS io_status = 0;
    ULONG_PTR io_status_information = 0;
    bool is_signaled = false;
    bool is_cancelled = false;
    std::shared_ptr<std::thread> wait_thread;
    std::atomic<bool> should_stop{false};
    mutable std::shared_mutex packet_mutex;

    // Default constructor
    CompletionPacket() = default;

    // Delete copy operations
    CompletionPacket(const CompletionPacket&) = delete;
    CompletionPacket& operator=(const CompletionPacket&) = delete;

    // Custom move constructor (can't move mutex)
    CompletionPacket(CompletionPacket&& other) noexcept
        : completion_key(other.completion_key),
          overlapped(other.overlapped),
          bytes_transferred(other.bytes_transferred),
          error_code(other.error_code),
          io_completion_handle(other.io_completion_handle),
          target_object(other.target_object),
          key_context(other.key_context),
          apc_context(other.apc_context),
          io_status(other.io_status),
          io_status_information(other.io_status_information),
          is_signaled(other.is_signaled),
          is_cancelled(other.is_cancelled),
          wait_thread(std::move(other.wait_thread)),
          should_stop(other.should_stop.load()) {
        // packet_mutex is default-constructed (can't move shared_mutex)
    }

    // Custom move assignment
    CompletionPacket& operator=(CompletionPacket&& other) noexcept {
        if (this != &other) {
            completion_key = other.completion_key;
            overlapped = other.overlapped;
            bytes_transferred = other.bytes_transferred;
            error_code = other.error_code;
            io_completion_handle = other.io_completion_handle;
            target_object = other.target_object;
            key_context = other.key_context;
            apc_context = other.apc_context;
            io_status = other.io_status;
            io_status_information = other.io_status_information;
            is_signaled = other.is_signaled;
            is_cancelled = other.is_cancelled;
            wait_thread = std::move(other.wait_thread);
            should_stop = other.should_stop.load();
            // packet_mutex remains as-is (can't move shared_mutex)
        }
        return *this;
    }
};

struct WaitCompletionPacket {
    HANDLE io_completion_handle;      // Associated I/O completion port
    HANDLE target_object;              // Object being waited on (event, thread, etc.)
    PVOID key_context;                 // Completion key
    PVOID apc_context;                 // APC context (often OVERLAPPED pointer)
    NTSTATUS io_status;                // Status to report
    ULONG_PTR io_status_information;   // Additional info (bytes transferred)
    bool is_signaled;                  // Whether target object is signaled
    bool is_cancelled;                 // Whether wait was cancelled
    std::shared_ptr<std::thread> wait_thread;  // Background monitoring thread
    std::atomic<bool> should_stop;     // Thread termination flag
    mutable std::shared_mutex packet_mutex;    // Thread safety
};

class CompletionPort {
private:
    std::queue<CompletionPacket> packet_queue;
    mutable std::shared_mutex queue_mutex;
    std::condition_variable_any queue_cv;
    DWORD max_threads;
    std::atomic<DWORD> active_threads{0};

public:
    explicit CompletionPort(DWORD max_concurrent_threads = 0)
        : max_threads(max_concurrent_threads ? max_concurrent_threads : std::thread::hardware_concurrency()) {}

    void post_completion(CompletionPacket& packet) {
        std::shared_lock lock(queue_mutex);
        packet_queue.push(std::move(packet));
        queue_cv.notify_one();
    }

    bool get_completion(CompletionPacket& packet, DWORD timeout_ms) {
        std::unique_lock lock(queue_mutex);

        if (timeout_ms == INFINITE) {
            queue_cv.wait(lock, [this] { return !packet_queue.empty(); });
        } else {
            if (!queue_cv.wait_for(lock, std::chrono::milliseconds(timeout_ms),
                                 [this] { return !packet_queue.empty(); })) {
                return false;
                                 }
        }

        if (!packet_queue.empty()) {
            packet = std::move(packet_queue.front());
            packet_queue.pop();
            return true;
        }
        return false;
    }


    size_t size() const {
        std::lock_guard lock(queue_mutex);
        return packet_queue.size();
    }
};

class ChildMemoryManager {
public:
    pid_t child_;

    explicit ChildMemoryManager(pid_t child) : child_(child) {}

    // Read arbitrary data from child process
    template<typename T>
    [[nodiscard]] std::optional<T> read(uintptr_t addr) const {
        T result{};

        for (size_t i = 0; i < sizeof(T); i += sizeof(long)) {
            errno = 0;
            long word = ptrace(PTRACE_PEEKDATA, child_, addr + i, NULL);
            if (word == -1 && errno != 0) {
                return std::nullopt;
            }

            size_t bytes_to_copy = min(sizeof(long), sizeof(T) - i);
            std::memcpy(reinterpret_cast<uint8_t*>(&result) + i, &word, bytes_to_copy);
        }

        return result;
    }

    // Write data to child process
    template<typename T>
    [[nodiscard]] bool write(const uintptr_t addr, const T& data) const {
        const auto* bytes = reinterpret_cast<const uint8_t*>(&data);

        for (size_t i = 0; i < sizeof(T); i += sizeof(long)) {
            long word = 0;
            size_t bytes_to_copy = min(sizeof(long), sizeof(T) - i);

            // For partial writes, read existing data first
            if (bytes_to_copy < sizeof(long)) {
                errno = 0;
                word = ptrace(PTRACE_PEEKDATA, child_, addr + i, NULL);
                if (word == -1 && errno != 0) {
                    return false;
                }
            }

            // Copy new data into word
            std::memcpy(&word, bytes + i, bytes_to_copy);

            if (ptrace(PTRACE_POKEDATA, child_, addr + i, word) == -1) {
                return false;
            }
        }

        return true;
    }

    // Read null-terminated string
    [[nodiscard]] std::optional<std::string> read_string(uintptr_t addr, size_t max_len = 1024) const {
        std::string result;
        result.reserve(max_len);

        for (size_t i = 0; i < max_len; i += sizeof(long)) {
            errno = 0;
            long word = ptrace(PTRACE_PEEKDATA, child_, addr + i, NULL);
            if (word == -1 && errno != 0) {
                return std::nullopt;
            }

            const char* chars = reinterpret_cast<const char*>(&word);
            for (size_t j = 0; j < sizeof(long) && i + j < max_len; j++) {
                if (chars[j] == '\0') {
                    return result;
                }
                result.push_back(chars[j]);
            }
        }

        return result; // Truncated
    }

    // Read wide string
    [[nodiscard]] std::optional<std::u16string> read_wstring(uintptr_t addr, size_t max_len = 1024) const {
        std::u16string result;
        result.reserve(max_len);

        for (size_t i = 0; i < max_len * sizeof(wchar_t); i += sizeof(long)) {
            errno = 0;
            long word = ptrace(PTRACE_PEEKDATA, child_, addr + i, NULL);
            if (word == -1 && errno != 0) {
                return std::nullopt;
            }

            const auto chars = reinterpret_cast<const WCHAR*>(&word);
            for (size_t j = 0; j < sizeof(long) / sizeof(WCHAR) && i / sizeof(WCHAR) + j < max_len; j++) {
                if (chars[j] == 0) {
                    return result;
                }
                result.push_back(chars[j]);
            }
        }

        return result; // Truncated
    }
};

namespace IPC {
    enum class OperationType : uint32_t {
        CLOSE_HANDLE,

        // Process/Thread Operations
        CREATE_THREAD,
        TERMINATE_THREAD,
        SUSPEND_THREAD,
        RESUME_THREAD,
        QUERY_PROCESS_INFO,

        // Synchronization
        CREATE_EVENT,
        SET_EVENT,
        RESET_EVENT,
        WAIT_SINGLE_OBJECT,

        // I/O Completion
        CREATE_IO_COMPLETION,
        POST_IO_COMPLETION,
        REMOVE_IO_COMPLETION,

        // Registry
        CREATE_KEY,
        OPEN_KEY,
        SET_VALUE_KEY,
        QUERY_VALUE_KEY,
        DELETE_KEY,

        RESPONSE
    };
}

// forward declare all the _Nt functions
NTSTATUS NTAPI _NtCreateFile(
    ChildMemoryManager &memory_mgr,
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength
);

NTSTATUS NTAPI _NtClose(
    ChildMemoryManager& memory_mgr,
    HANDLE Handle
);

NTSTATUS NTAPI _NtReadFile(
    ChildMemoryManager& memory_mgr,
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key
);

NTSTATUS NTAPI _NtWriteFile(
    ChildMemoryManager& memory_mgr,
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key
);

NTSTATUS NTAPI _NtWriteFileGather(
    ChildMemoryManager& memory_mgr,
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PFILE_SEGMENT_ELEMENT SegmentArray,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key
);

NTSTATUS NTAPI _NtDeviceIoControlFile(
    ChildMemoryManager& memory_mgr,
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG IoControlCode,
    PVOID InputBuffer,
    ULONG InputBufferLength,
    PVOID OutputBuffer,
    ULONG OutputBufferLength
);

NTSTATUS NTAPI _NtFlushBuffersFile(
    ChildMemoryManager& memory_mgr,
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock
);

NTSTATUS NTAPI _NtQuerySystemInformation(
    ChildMemoryManager& memory_mgr,
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

NTSTATUS NTAPI _NtSetEvent(
    ChildMemoryManager &memory_mgr,
    HANDLE EventHandle,
    PLONG PreviousState
);

NTSTATUS NTAPI _NtQueueApcThread(
    ChildMemoryManager &memory_mgr,
    HANDLE ThreadHandle,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcArgument1,
    PVOID ApcArgument2,
    PVOID ApcArgument3
);

NTSTATUS NTAPI _NtQueryPerformanceCounter(
    ChildMemoryManager &memory_mgr,
    PLARGE_INTEGER PerformanceCounter,
    PLARGE_INTEGER PerformanceFrequency
);

NTSTATUS NTAPI _NtQuerySystemTime(
    ChildMemoryManager &memory_mgr,
    PLARGE_INTEGER SystemTime
);

NTSTATUS NTAPI _NtCreateEvent(
    ChildMemoryManager &memory_mgr,
    PHANDLE EventHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    EVENT_TYPE EventType,
    BOOLEAN InitialState
);

NTSTATUS NTAPI _NtResetEvent(
    ChildMemoryManager &memory_mgr,
    HANDLE EventHandle,
    PLONG PreviousState
);

NTSTATUS NTAPI _NtWaitForSingleObject(
    ChildMemoryManager &memory_mgr,
    HANDLE Handle,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout
);

NTSTATUS NTAPI _NtWorkerFactoryWorkerReady(ChildMemoryManager &, HANDLE WorkerFactoryHandle);

NTSTATUS NTAPI _NtMapUserPhysicalPagesScatter(
    ChildMemoryManager &memory_mgr,
    PVOID* VirtualAddresses,
    ULONG_PTR NumberOfPages,
    PULONG_PTR UserPfnArray);

NTSTATUS NTAPI _NtRemoveIoCompletion(
    ChildMemoryManager& memory_mgr,
    HANDLE IoCompletionHandle,
    PVOID* KeyContext,
    PVOID* ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER Timeout);

NTSTATUS NTAPI _NtQueryInformationFile(
    ChildMemoryManager& memory_mgr,
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass);

NTSTATUS NTAPI _NtSetInformationFile(
    ChildMemoryManager& memory_mgr,
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass);

NTSTATUS NTAPI _NtCreateIoCompletion(
    ChildMemoryManager& memory_mgr,
    PHANDLE IoCompletionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG Count);

NTSTATUS NTAPI _NtFreeVirtualMemory(
    ChildMemoryManager& memory_mgr,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType);

NTSTATUS NTAPI _NtAllocateVirtualMemory(
    ChildMemoryManager& memory_mgr,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect);

NTSTATUS NTAPI _NtProtectVirtualMemory(
    ChildMemoryManager& memory_mgr,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect);

NTSTATUS NTAPI _NtQueryVirtualMemory(
    ChildMemoryManager& memory_mgr,
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    MEMORY_INFORMATION_CLASS MemoryInformationClass,
    PVOID MemoryInformation,
    SIZE_T MemoryInformationLength,
    PSIZE_T ReturnLength);

NTSTATUS NTAPI _NtOpenFile(
    ChildMemoryManager &memory_mgr,
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG ShareAccess,
    ULONG OpenOptions
);

NTSTATUS NTAPI _NtCreateProcess(
    const ChildMemoryManager &memory_mgr,
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ParentProcess,
    BOOLEAN InheritObjectTable,
    HANDLE SectionHandle,
    HANDLE DebugPort,
    HANDLE ExceptionPort
);

NTSTATUS NTAPI _NtQuerySystemInformationEx(
    ChildMemoryManager& memory_mgr,
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID QueryInformation,
    ULONG QueryInformationLength,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength);

NTSTATUS NTAPI _NtFlushKey(
    ChildMemoryManager& memory_mgr,
    HANDLE KeyHandle);

NTSTATUS NTAPI _NtQueryKey(
    ChildMemoryManager& memory_mgr,
    HANDLE KeyHandle,
    KEY_INFORMATION_CLASS KeyInformationClass,
    PVOID KeyInformation,
    ULONG Length,
    PULONG ResultLength);

NTSTATUS NTAPI _NtOpenKey(
    ChildMemoryManager& memory_mgr,
    PHANDLE KeyHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes);

NTSTATUS NTAPI _NtCreateKey(
    ChildMemoryManager& memory_mgr,
    PHANDLE KeyHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG TitleIndex,
    PUNICODE_STRING Class,
    ULONG CreateOptions,
    PULONG Disposition);

NTSTATUS NTAPI _NtSetValueKey(
    ChildMemoryManager& memory_mgr,
    HANDLE KeyHandle,
    PUNICODE_STRING ValueName,
    ULONG TitleIndex,
    ULONG Type,
    PVOID Data,
    ULONG DataSize);

NTSTATUS NTAPI _NtQueryValueKey(
    ChildMemoryManager& memory_mgr,
    HANDLE KeyHandle,
    PUNICODE_STRING ValueName,
    KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    PVOID KeyValueInformation,
    ULONG Length,
    PULONG ResultLength);

NTSTATUS NTAPI _NtDeleteKey(
    ChildMemoryManager& memory_mgr,
    HANDLE KeyHandle);

NTSTATUS NTAPI _NtDeleteValueKey(
    ChildMemoryManager& memory_mgr,
    HANDLE KeyHandle,
    PUNICODE_STRING ValueName);

NTSTATUS NTAPI _NtEnumerateKey(
    ChildMemoryManager& memory_mgr,
    HANDLE KeyHandle,
    ULONG Index,
    KEY_INFORMATION_CLASS KeyInformationClass,
    PVOID KeyInformation,
    ULONG Length,
    PULONG ResultLength);

NTSTATUS NTAPI _NtEnumerateValueKey(
    ChildMemoryManager& memory_mgr,
    HANDLE KeyHandle,
    ULONG Index,
    KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    PVOID KeyValueInformation,
    ULONG Length,
    PULONG ResultLength);

NTSTATUS NTAPI _NtSetInformationThread(
    ChildMemoryManager& memory_mgr,
    HANDLE ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength);

NTSTATUS NTAPI _NtCreateWaitCompletionPacket(
    ChildMemoryManager& memory_mgr,
    PHANDLE WaitCompletionPacketHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE IoCompletionHandle,
    PVOID KeyContext);

NTSTATUS NTAPI _NtAddAtom(
    ChildMemoryManager& memory_mgr,
    PWSTR AtomName,
    USHORT Length,
    PRTL_ATOM Atom);

NTSTATUS NTAPI _NtFindAtom(
    ChildMemoryManager& memory_mgr,
    PWSTR AtomName,
    USHORT Length,
    PRTL_ATOM Atom);

NTSTATUS NTAPI _NtDeleteAtom(
    ChildMemoryManager& memory_mgr,
    RTL_ATOM Atom);

NTSTATUS NTAPI _NtQueryInformationProcess(
    const ChildMemoryManager &memory_mgr,
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength);

NTSTATUS NTAPI _NtRaiseException(
    ChildMemoryManager &memory_mgr,
    PEXCEPTION_RECORD ExceptionRecord,
    PCONTEXT ContextRecord,
    BOOLEAN FirstChance);

NTSTATUS NTAPI _NtCreateThread(
    ChildMemoryManager& memory_mgr,
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PCLIENT_ID ClientId,
    PCONTEXT ThreadContext,
    PINITIAL_TEB InitialTeb,
    BOOLEAN CreateSuspended);

NTSTATUS NTAPI _NtTerminateThread(
    ChildMemoryManager& memory_mgr,
    HANDLE ThreadHandle,
    NTSTATUS ExitStatus);

NTSTATUS NTAPI _NtTerminateProcess(
    ChildMemoryManager& memory_mgr,
    HANDLE ProcessHandle,
    NTSTATUS ExitStatus);

// Syscall parameter reader with proper memory management
class SyscallParameterReader {
private:
    ChildMemoryManager& memory_;
    const user_regs_struct& regs_;

public:
    SyscallParameterReader(ChildMemoryManager& memory, const user_regs_struct& regs)
        : memory_(memory), regs_(regs) {}

    // Get register parameters (first 4)
    [[nodiscard]] uintptr_t get_reg_param(const int index) const {
        switch (index) {
            case 0: return regs_.rcx;  // Windows x64: RCX -> R10 after syscall
            case 1: return regs_.rdx;
            case 2: return regs_.r8;
            case 3: return regs_.r9;
            default: return 0;
        }
    }

    // Get stack parameters (5th and beyond)
    template<typename T>
    [[nodiscard]] std::optional<T> get_stack_param(const int index) const {
        if (index < 4) {
            if constexpr (!std::is_pointer_v<T>) {
                if constexpr (std::is_enum_v<T>) {
                    if (std::is_arithmetic_v<std::underlying_type_t<T>>) {
                        return static_cast<T>(get_reg_param(index));
                    }
                }
                return static_cast<T>(get_reg_param(index));
            }
            else {
                return reinterpret_cast<T>(get_reg_param(index));
            }
        }

        // Stack parameters start at RSP + 0x28 (shadow space)
        const uintptr_t stack_offset = 0x28 + (index - 4) * sizeof(uintptr_t);
        return memory_.read<T>(regs_.rsp + stack_offset);
    }

    // Read complex structures
    template<typename T>
    std::optional<T> read_structure(const uintptr_t addr) const {
        return memory_.read<T>(addr);
    }

    [[nodiscard]] std::optional<std::string> read_ansi_string(const uintptr_t addr) const {
        return memory_.read_string(addr);
    }

    [[nodiscard]] std::optional<std::u16string> read_unicode_string(const uintptr_t addr) const {
        return memory_.read_wstring(addr);
    }
};


// File mapping object
struct FileMapping {
    HANDLE file_handle;
    DWORD protect;
    LARGE_INTEGER size;
    LPCWSTR name;
    void* base_address;
    SIZE_T view_size;
    mutable std::shared_mutex mapping_mutex;

    FileMapping(HANDLE file, DWORD prot, LARGE_INTEGER sz, LPCWSTR mapping_name = nullptr)
        : file_handle(file), protect(prot), size(sz), name(mapping_name),
          base_address(nullptr), view_size(0) {}

    ~FileMapping() {
        if (base_address) {
            munmap(base_address, view_size);
        }
    }
};

class Event {
private:
    mutable std::shared_mutex mtx_;
    std::condition_variable_any cv_;
    bool flag_;
    bool manual_reset_;
    pid_t owner_process_;

public:
    Event(bool manual_reset = false, bool initial_state = false)
        : flag_(initial_state), manual_reset_(manual_reset), owner_process_(getpid()) {}

    void set() {
        std::lock_guard<std::shared_mutex> lock(mtx_);
        flag_ = true;
        cv_.notify_all();
    }

    void reset() {
        std::lock_guard<std::shared_mutex> lock(mtx_);
        flag_ = false;
    }

    bool wait_for(DWORD milliseconds) {
        std::shared_lock<std::shared_mutex> lock(mtx_);
        bool result;
        if (milliseconds == INFINITE) {
            cv_.wait(lock, [this] { return flag_; });
            result = true;
        } else {
            result = cv_.wait_for(lock, std::chrono::milliseconds(milliseconds), [this] { return flag_; });
        }
        if (result && !manual_reset_) {
            flag_ = false;
        }
        return result;
    }

    bool is_set() const {
        std::lock_guard<std::shared_mutex> lock(mtx_);
        return flag_;
    }

    bool can_access() const {
        return (owner_process_ == getpid());
    }

    void pulse() {
        std::lock_guard<std::shared_mutex> lock(mtx_);
        flag_ = true;
        cv_.notify_all();
        flag_ = false;
    }
};



// WSK Socket Context
struct WSK_SOCKET_CONTEXT {
    int socket_type{SOCK_STREAM};
    int protocol{IPPROTO_TCP};
    int family{AF_INET};
    bool is_listening{false};
    bool is_connected{false};
    bool is_nonblocking{false};
    bool is_bound{false};
    Event* event{nullptr};
    INT event_mask{0};
    HWND window{nullptr};
    UINT message{0};
    WPARAM wparam{0};
    INT pending_events{0};
    DeviceHandle* deferred{nullptr};
    bool poll_registered{false};
    ULONG poll_flags{0};
    ULONG poll_events{0};
};

// Device Handle class
class DeviceHandle {
public:
    int linux_fd;
    DEVICE_TYPE device_type;
    std::string device_path;
    ULONG options;
    ULONG disposition;
    ULONG access;
    ULONG share_mode;
    ULONG file_attributes;
    LARGE_INTEGER file_position;
    std::shared_ptr<WSK_SOCKET_CONTEXT> socket_context;
    mutable std::shared_mutex handle_mutex;

    DeviceHandle(int fd, DEVICE_TYPE type, std::string path, ULONG opts,
                 ULONG disp = 0, ULONG acc = 0, ULONG share = 0, ULONG file_attrs = 0)
        : linux_fd(fd), device_type(type), device_path(std::move(path)), options(opts),
          disposition(disp), access(acc), share_mode(share), file_attributes(file_attrs) {
        file_position.QuadPart = 0;

        if (type == FILE_DEVICE_NETWORK) {
            socket_context = std::make_shared<WSK_SOCKET_CONTEXT>();
        }
    }

    ~DeviceHandle() {
        if (linux_fd >= 0) {
            close(linux_fd);
        }
    }

    bool is_valid() const {
        std::shared_lock lock(handle_mutex);
        return linux_fd >= 0;
    }

    void invalidate() {
        std::shared_lock lock(handle_mutex);
        if (linux_fd >= 0) {
            close(linux_fd);
            linux_fd = -1;
        }
    }
};

// UPDATE: Enhanced ThreadContext with ALL ProcessThreadInfo fields
class ThreadContext {
public:
    pthread_t native_thread_id;
    HANDLE windows_thread_handle;
    HANDLE parent_process_handle;
    DWORD thread_id;
    DWORD last_error;
    std::vector<LPVOID> tls_data;
    bool is_main_thread;
    std::shared_mutex context_mutex;
    uintptr_t start_address;
    ULONG_PTR affinity_mask;
    DWORD priority_boost;
    DWORD allow_writes;
    DWORD ideal_processor;

    // FROM ProcessThreadInfo - ALL fields preserved
    bool is_suspended{false};
    bool is_terminated{false};
    pthread_t thread{};
    pthread_attr_t attr{};
    DWORD attributes{0};
    DWORD access_mask{THREAD_ALL_ACCESS};
    void* arg{nullptr};
    void*(*start_routine)(void*){nullptr};
    HANDLE thread_handle{nullptr};
    ULONGLONG creation_time{0};
    DWORD priority_class{NORMAL_PRIORITY_CLASS};
    std::queue<ProcessThreadAPC> apc_queue;
    mutable std::shared_mutex apc_mutex;
    Event* alertable_event{nullptr};
    DWORD exit_code{STILL_ACTIVE};
    CONTEXT thread_context{};
    bool context_valid{false};

    // Enhanced multithreading support
    std::shared_ptr<std::thread> native_thread;
    std::atomic<bool> should_terminate{false};
    std::condition_variable_any suspend_cv;
    std::shared_mutex suspend_mutex;
    std::atomic<int> suspend_count{0};

    std::shared_ptr<std::thread> execution_thread;
    std::atomic<bool> is_executing{false};
    std::queue<std::function<void()>> task_queue;
    std::shared_mutex task_mutex;
    std::condition_variable_any task_cv;

    struct ThreadEntryData {
        LPTHREAD_START_ROUTINE start_address;
        LPVOID parameter;
        LoadedModule* module_context;
        HANDLE process_handle;
    };
    std::shared_ptr<ThreadEntryData> entry_data;

    struct SyscallContext {
        std::atomic<bool> in_syscall{false};
        unsigned long long current_syscall{0};
        std::chrono::steady_clock::time_point syscall_start_time;
        std::string syscall_name;
    } syscall_context;

    ThreadContext() : native_thread_id(pthread_self()),
                      windows_thread_handle(nullptr),
                      parent_process_handle(nullptr),
                      thread_id(static_cast<DWORD>(syscall(SYS_gettid))),
                      last_error(0),
                      is_main_thread(false), start_address(0), affinity_mask(0), priority_boost(0), allow_writes(0),
                      ideal_processor(0) {
        tls_data.resize(64);
        create_thread_teb();

        if (pthread_attr_init(&attr) != 0) {
            trace("Failed to initialize pthread attributes");
        }
    }

    ~ThreadContext() {
        cleanup_thread_teb();

        if (native_thread && native_thread->joinable()) {
            should_terminate = true;
            suspend_cv.notify_all();
            task_cv.notify_all();
            native_thread->join();
        }

        if (execution_thread && execution_thread->joinable()) {
            execution_thread->join();
        }

        pthread_attr_destroy(&attr);
    }

    void enqueue_task(std::function<void()> task) {
        std::lock_guard lock(task_mutex);
        task_queue.push(std::move(task));
        task_cv.notify_one();
    }

    void process_tasks() {
        while (!should_terminate) {
            std::shared_lock lock(task_mutex);
            task_cv.wait(lock, [this] {
                return !task_queue.empty() || should_terminate;
            });

            while (!task_queue.empty()) {
                auto task = std::move(task_queue.front());
                task_queue.pop();
                lock.unlock();

                try {
                    is_executing = true;
                    task();
                    is_executing = false;
                } catch (const std::exception& e) {
                    trace("Thread task exception: ", e.what());
                    is_executing = false;
                }

                lock.lock();
            }
        }
    }

private:
    static void create_thread_teb() {
        initialize_default_current_teb();
    }

    static void cleanup_thread_teb() {
        cleanup_current_teb();
    }
};

struct TLS {
    HANDLE thread{};
    HANDLE process{};
    std::vector<LPVOID> tls_data;
    DWORD last_error{0};
};

// KEEP: Thread-local variables
static thread_local TLS g_tls;
static thread_local TEB* g_current_teb = nullptr;
static thread_local PEB* g_current_peb = nullptr;
static std::unordered_map<std::u16string, RTL_ATOM> g_atom_table;
static std::shared_mutex g_atom_table_mutex;
static uint64_t g_next_atom_value = 1;

class SectionHandle {
public:
    HANDLE file_handle;
    DWORD protect;
    LARGE_INTEGER size;
    LPCWSTR name;
    void* base_address;
    SIZE_T view_size;
    mutable std::shared_mutex section_mutex;
    SectionHandle(HANDLE file, DWORD prot, LARGE_INTEGER sz, LPCWSTR section_name = nullptr)
        : file_handle(file), protect(prot), size(sz), name(section_name),
          base_address(nullptr), view_size(0) {}

    ~SectionHandle() {
        if (base_address) {
            munmap(base_address, view_size);
        }
    }

    bool is_valid() const {
        std::shared_lock lock(section_mutex);
        return base_address != nullptr;
    }

    void invalidate() {
        std::shared_lock lock(section_mutex);
        if (base_address) {
            munmap(base_address, view_size);
            base_address = nullptr;
            view_size = 0;
        }
    }
};

enum class MessageType {
    TerminateProcessMsg,
    CreateThreadMsg,
    ExitThreadMsg,
    SuspendThreadMsg,
    ResumeThreadMsg,
    SetThreadContextMsg,
    GetThreadContextMsg,
    QueueApcMsg,
    AllocVirtualMemoryMsg,
    FreeVirtualMemoryMsg,
    ProtectVirtualMemoryMsg,
    CreateFileMsg,
    ReadFileMsg,
    WriteFileMsg,
    CloseHandleMsg,
    WaitForObjectMsg,
    SetEventMsg,
    ResetEventMsg,
    ResponseMsg
};

struct EnhancedMessage {
    struct Header {
        IPC::OperationType type;
        NTSTATUS status;
        uint32_t data_size;
        uint64_t sequence_id;
    } header;

    std::vector<uint8_t> payload;

    // Serialization helpers
    template<typename T>
    bool write_param(const T& value) {
        size_t old_size = payload.size();
        payload.resize(old_size + sizeof(T));
        memcpy(payload.data() + old_size, &value, sizeof(T));
        return true;
    }

    template<typename T>
    bool read_param(T& value, size_t& offset) const {
        if (offset + sizeof(T) > payload.size()) return false;
        memcpy(&value, payload.data() + offset, sizeof(T));
        offset += sizeof(T);
        return true;
    }

    bool write_buffer(const void* data, size_t size) {
        size_t old_size = payload.size();
        payload.resize(old_size + size);
        memcpy(payload.data() + old_size, data, size);
        return true;
    }

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> buffer;
        buffer.reserve(sizeof(Header) + payload.size());

        const uint8_t* header_ptr = reinterpret_cast<const uint8_t*>(&header);
        buffer.insert(buffer.end(), header_ptr, header_ptr + sizeof(Header));
        buffer.insert(buffer.end(), payload.begin(), payload.end());

        return buffer;
    }

    static std::optional<EnhancedMessage> deserialize(const std::vector<uint8_t>& buffer) {
        if (buffer.size() < sizeof(Header)) return std::nullopt;

        EnhancedMessage msg;
        memcpy(&msg.header, buffer.data(), sizeof(Header));

        if (buffer.size() < sizeof(Header) + msg.header.data_size) return std::nullopt;

        msg.payload.assign(buffer.begin() + sizeof(Header), buffer.end());
        return msg;
    }
};

class ProcessContext; // Forward declaration

// Enhanced IPC Manager with async support
class EnhancedIPCManager {
private:
    int sockfd = -1;
    std::string socket_path;
    std::shared_mutex ipc_mutex;
    bool is_server;
    std::unordered_map<pid_t, int> client_sockets;
    std::atomic<uint64_t> next_sequence_id{1};

    // Pending requests for async operations
    std::unordered_map<uint64_t, std::promise<EnhancedMessage>> pending_requests;
    std::shared_mutex pending_mutex;

    explicit EnhancedIPCManager(bool server = false) : is_server(server) {
        socket_path = "/tmp/pe_loader_" + std::to_string(getpid()) + ".sock";

        sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (sockfd == -1) {
            error("Failed to create socket: ", strerror(errno));
            return;
        }

        if (is_server) {
            setup_server();
        }
    }

    ~EnhancedIPCManager() {
        cleanup();
    }

    bool setup_server() {
        sockaddr_un addr{};
        addr.sun_family = AF_UNIX;
        (strncpy)(addr.sun_path, socket_path.c_str(), sizeof(addr.sun_path) - 1);

        unlink(socket_path.c_str());

        if (bind(sockfd, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) == -1) {
            error("Bind failed: ", strerror(errno));
            return false;
        }

        if (listen(sockfd, 5) == -1) {
            error("Listen failed: ", strerror(errno));
            return false;
        }

        trace("IPC server listening on ", converter.from_bytes(socket_path));
        return true;
    }

    bool connect_to_server(const std::string& server_path) const {
        sockaddr_un addr{};
        addr.sun_family = AF_UNIX;
        (strncpy)(addr.sun_path, server_path.c_str(), sizeof(addr.sun_path) - 1);

        if (connect(sockfd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == -1) {
            error("Connect failed: ", strerror(errno));
            return false;
        }

        trace("Connected to IPC server: ", converter.from_bytes(server_path));
        return true;
    }

    int accept_client() {
        int client_fd = accept(sockfd, nullptr, nullptr);
        if (client_fd == -1) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                error("Accept failed: ", strerror(errno));
            }
            return -1;
        }
        return client_fd;
    }

    bool send_message(const EnhancedMessage& msg, int fd = -1) {
        if (fd == -1) fd = sockfd;

        auto buffer = msg.serialize();
        uint32_t size = buffer.size();

        std::lock_guard lock(ipc_mutex);

        // Send size first
        if (send(fd, &size, sizeof(size), 0) != sizeof(size))
            return false;

        // Send data
        size_t sent = 0;
        while (sent < buffer.size()) {
            ssize_t n = send(fd, buffer.data() + sent, buffer.size() - sent, 0);
            if (n <= 0) return false;
            sent += n;
        }

        return true;
    }

    std::optional<EnhancedMessage> receive_message(int fd = -1, int timeout_ms = -1) {
        if (fd == -1) fd = sockfd;

        if (timeout_ms >= 0) {
            struct pollfd pfd = {fd, POLLIN, 0};
            if (poll(&pfd, 1, timeout_ms) <= 0)
                return std::nullopt;
        }

        std::lock_guard lock(ipc_mutex);

        // Read size
        uint32_t size;
        if (recv(fd, &size, sizeof(size), MSG_WAITALL) != sizeof(size))
            return std::nullopt;

        // Read data
        std::vector<uint8_t> buffer(size);
        size_t received = 0;
        while (received < size) {
            ssize_t n = recv(fd, buffer.data() + received, size - received, 0);
            if (n <= 0) return std::nullopt;
            received += n;
        }

        return EnhancedMessage::deserialize(buffer);
    }

    void cleanup() {
        if (sockfd != -1) {
            close(sockfd);
            sockfd = -1;
        }
        if (is_server) {
            unlink(socket_path.c_str());
        }
        for (auto fd : client_sockets | std::views::values) {
            close(fd);
        }
        client_sockets.clear();
    }

    // Child process message loop
    [[noreturn]] void child_listen_loop() {
        trace("Child process IPC loop started");

        while (true) {
            auto msg_opt = receive_message(sockfd, 100);
            if (!msg_opt) continue;

            EnhancedMessage msg = *msg_opt;
            EnhancedMessage response;
            response.header.type = IPC::OperationType::RESPONSE;
            response.header.status = STATUS_SUCCESS;

            // Handle message
            switch (msg.header.type) {
                case IPC::OperationType::ALLOC_VIRTUAL_MEMORY: {
                    HANDLE process_handle;
                    PVOID* base_address;
                    ULONG_PTR zero_bits;
                    PSIZE_T region_size;
                    ULONG allocation_type;
                    ULONG protect;
                    size_t offset = 0;
                    msg.read_param(process_handle, offset);
                    msg.read_param(base_address, offset);
                    msg.read_param(zero_bits, offset);
                    msg.read_param(region_size, offset);
                    msg.read_param(allocation_type, offset);
                    msg.read_param(protect, offset);
                    response.header.status = _NtAllocateVirtualMemory(
                        *process_ctx->memory_mgr,
                        process_handle,
                        base_address,
                        zero_bits,
                        region_size,
                        allocation_type,
                        protect
                    );
                }
            }

            send_message(response, sockfd);
        }
    }
};

class ProcessMainThread {
public:
    ProcessContext* process_ctx;
    std::unique_ptr<IPCManager> ipc;
    std::atomic<bool> running{true};
    std::thread main_thread;
    ChildMemoryManager* memory_mgr;

public:
    explicit ProcessMainThread(ProcessContext* ctx);

    ~ProcessMainThread() {
        running = false;
        if (main_thread.joinable()) {
            main_thread.join();
        }
        delete memory_mgr;
    }

    void run();

    void handle_client(int client_fd) {
        while (running) {
            auto msg_opt = ipc->receive_message(client_fd, 100);
            if (!msg_opt) continue;

            Message msg = *msg_opt;
            Message response;
            response.type = MessageType::ResponseMsg;

            // Execute the requested operation
            response.status = execute_operation(msg);
            response.param1 = msg.param1;
            response.param2 = msg.param2;

            ipc->send_message(response, client_fd);
        }

        close(client_fd);
    }

    NTSTATUS execute_operation(const Message& msg) {
        if (!memory_mgr) return STATUS_INVALID_HANDLE;

        switch (msg.type) {
            case MessageType::AllocVirtualMemoryMsg:
                return _NtAllocateVirtualMemory(
                    *memory_mgr,
                    reinterpret_cast<HANDLE>(msg.param1),
                    reinterpret_cast<PVOID*>(msg.param2),
                    msg.param3,
                    reinterpret_cast<PSIZE_T>(msg.param4),
                    msg.param5,
                    msg.param6
                );

            case MessageType::FreeVirtualMemoryMsg:
                return _NtFreeVirtualMemory(
                    *memory_mgr,
                    reinterpret_cast<HANDLE>(msg.param1),
                    reinterpret_cast<PVOID*>(msg.param2),
                    reinterpret_cast<PSIZE_T>(msg.param3),
                    msg.param4
                );

            case MessageType::TerminateProcessMsg:
                running = false;
                return _NtTerminateProcess(
                    *memory_mgr,
                    reinterpret_cast<HANDLE>(msg.param1),
                    msg.param2
                );

            default:
                return STATUS_NOT_IMPLEMENTED;
        }
    }

    std::string get_socket_path() const {
        return ipc->socket_path;
    }
};


// Forward declarations
// UPDATE: ProcessContext with ALL ProcessInfo fields preserved
class ProcessContext {
public:
    pid_t native_process_id;
    HANDLE windows_process_handle;
    DWORD process_id;
    PEB* current_peb;
    std::unordered_map<HANDLE, std::shared_ptr<ThreadContext>> threads;  // CHANGED: ThreadContext
    std::unordered_map<HANDLE, std::shared_ptr<DeviceHandle>> device_handles;
    std::unordered_map<HANDLE, std::shared_ptr<Event>> events;
    std::unordered_map<HANDLE, std::shared_ptr<WaitCompletionPacket>> wait_packets;
    std::unordered_map<HANDLE, std::shared_ptr<SectionHandle>> sections;
    mutable std::shared_mutex process_mutex;
    mutable std::shared_mutex wait_packet_mutex;
    HANDLE process_handle{};
    ULONG_PTR cookie{};
    std::unique_ptr<ProcessMainThread> main_thread;
    std::string ipc_socket_path;

    // FROM ProcessInfo - ALL fields preserved
    std::unordered_map<DWORD, HANDLE> std_handles;
    std::unordered_map<HANDLE, std::shared_ptr<CompletionPort>> completion_ports;
    std::unordered_map<HANDLE, std::shared_ptr<FileMapping>> file_mappings;
    std::vector<pollfd> active_polls;
    std::unordered_map<int, HANDLE> fd_to_handle;
    std::unordered_map<HANDLE, void*> handle_to_poll_info;
    LIST_ENTRY in_init_order_module_list{};
    LIST_ENTRY in_load_order_module_list{};
    LIST_ENTRY in_memory_order_module_list{};
    std::unordered_map<std::u16string, LoadedModule*> loaded_modules;
    std::shared_mutex module_list_mutex;
    std::unordered_map<std::u16string, HMODULE> module_handle_map;
    std::shared_mutex module_handle_mutex;
    std::unordered_map<std::u16string, HANDLE> named_objects;
    std::shared_mutex named_object_mutex;
    std::unordered_map<std::u16string, HANDLE> named_pipes;
    std::shared_mutex named_pipe_mutex;
    std::unordered_map<std::u16string, HANDLE> named_events;
    std::shared_mutex named_event_mutex;
    std::unordered_map<std::u16string, HANDLE> named_mutexes;
    std::shared_mutex named_mutex_mutex;
    std::unordered_map<std::u16string, HANDLE> named_semaphores;
    std::shared_mutex named_semaphore_mutex;
    std::unordered_map<std::u16string, HANDLE> named_sections;
    std::shared_mutex named_section_mutex;
    std::unordered_map<std::u16string, HANDLE> named_wait_packets;
    std::shared_mutex named_wait_packet_mutex;
    std::unordered_map<std::u16string, RTL_ATOM> atom_table;
    std::shared_mutex atom_table_mutex;
    uint64_t next_atom_value{1};
    SIZE_T image_size{};
    PHEAP* heaps{};
    size_t num_heaps{};
    PHEAP default_heap{};
    bool poll_in_progress{};
    HMODULE process_hmodule{};
    HANDLE parent_process{};
    pthread_t process_thread{};
    WCHAR* environment_block{};
    ULONGLONG creation_time{};
    DWORD priority_class{NORMAL_PRIORITY_CLASS};
    HANDLE process_thread_handle{};
    DWORD exit_code{STILL_ACTIVE};
    bool is_terminated{false};
    std::u16string image_path;
    std::u16string command_line;
    std::u16string current_directory;
    WCHAR* creation_environment{};
    DWORD creation_flags{};
    STARTUPINFOA startup_info_a{};
    STARTUPINFOW startup_info{};
    SECURITY_ATTRIBUTES process_attributes{};
    SECURITY_ATTRIBUTES thread_attributes{};
    bool inherit_handles{};
    int linux_child_pid{};

    std::atomic<bool> process_terminating{false};
    std::condition_variable_any process_cv;

    std::queue<Message> message_queue;
    std::shared_mutex message_queue_mutex;
    std::condition_variable_any message_cv;

    std::atomic<DWORD> next_thread_id{1000};
    std::unordered_set<DWORD> active_thread_ids;
    std::shared_mutex thread_registry_mutex;

    ProcessContext() : native_process_id(getpid()),
                      windows_process_handle(nullptr),
                      process_id(static_cast<DWORD>(getpid())),
                      current_peb(nullptr)
    {
        create_process_peb();
        initialize_process_info();
    }

    ~ProcessContext() {
        cleanup_process_peb();
        cleanup_process_info();
    }

    ThreadContext* get_current_thread() {
        return threads[g_tls.thread].get();
    }

    ThreadContext* create_thread_context(bool is_main = false) {
        std::shared_lock lock(process_mutex);

        auto thread_ctx = std::make_shared<ThreadContext>();
        thread_ctx->parent_process_handle = windows_process_handle;
        thread_ctx->is_main_thread = is_main;

        ThreadContext* ptr = thread_ctx.get();
        threads[g_tls.thread] = std::move(thread_ctx);

        return ptr;
    }

private:
    void create_process_peb() {
        current_peb = new PEB();
        memset(current_peb, 0, sizeof(PEB));

        current_peb->NumberOfProcessors = sysconf(_SC_NPROCESSORS_ONLN);
        current_peb->OSMajorVersion = 10;
        current_peb->OSMinorVersion = 0;
        current_peb->OSBuildNumber = 19045;
        current_peb->OSPlatformId = VER_PLATFORM_WIN32_NT;
    }

    void cleanup_process_peb() {
        delete current_peb;
        current_peb = nullptr;
    }

    void initialize_process_info() {
        // Initialize standard handles
        std_handles[STD_INPUT_HANDLE] = reinterpret_cast<HANDLE>(-10);
        std_handles[STD_OUTPUT_HANDLE] = reinterpret_cast<HANDLE>(-11);
        std_handles[STD_ERROR_HANDLE] = reinterpret_cast<HANDLE>(-12);

        // Create device handles for standard I/O
        device_handles[reinterpret_cast<HANDLE>(-10)] =
            std::make_shared<DeviceHandle>(0, FILE_DEVICE_CONSOLE, "CONIN$", 0, 0,
                                         GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE);
        device_handles[reinterpret_cast<HANDLE>(-11)] =
            std::make_shared<DeviceHandle>(1, FILE_DEVICE_CONSOLE, "CONOUT$", 0, 0,
                                         GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE);
        device_handles[reinterpret_cast<HANDLE>(-12)] =
            std::make_shared<DeviceHandle>(2, FILE_DEVICE_CONSOLE, "CONERR$", 0, 0,
                                         GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE);

        // Initialize environment
        constexpr char env_template[] = "SystemRoot=C:\\Windows\0TEMP=C:\\Temp\0TMP=C:\\Temp\0PATH=C:\\Windows\\System32\0\0";
        constexpr size_t env_size = sizeof(env_template);
        environment_block = static_cast<WCHAR*>(malloc(env_size * sizeof(WCHAR)));
        for (size_t i = 0; i < env_size; ++i) {
            environment_block[i] = static_cast<WCHAR>(env_template[i]);
        }

        // Initialize heaps
        num_heaps = 1;
        heaps = static_cast<PHEAP*>(malloc(num_heaps * sizeof(PHEAP)));
        default_heap = new HEAP();
        memset(default_heap, 0, sizeof(HEAP));
        default_heap->MaximumSize = SIZE_MAX;
        heaps[0] = default_heap;

        // Set creation time
        creation_time = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::system_clock::now().time_since_epoch()).count();
        process_id = getpid();
    }

    void cleanup_process_info() {
        // Cleanup threads
        process_terminating = true;
        process_cv.notify_all();

        for (auto& [handle, thread_ctx] : threads) {
            if (!thread_ctx->is_terminated) {
                thread_ctx->should_terminate = true;
                thread_ctx->suspend_cv.notify_all();
                thread_ctx->task_cv.notify_all();

                if (thread_ctx->native_thread && thread_ctx->native_thread->joinable()) {
                    thread_ctx->native_thread->join();
                }

                pthread_cancel(thread_ctx->thread);
                pthread_join(thread_ctx->thread, nullptr);
                pthread_attr_destroy(&thread_ctx->attr);
            }
        }

        // Cleanup heaps
        for (size_t i = 0; i < num_heaps; ++i) {
            const PHEAP heap = heaps[i];
            delete heap;
        }
        free(heaps);

        // Cleanup environment
        free(environment_block);
    }
};

// UPDATE: Global state to use ProcessContext
static std::unordered_map<HANDLE, ProcessContext> g_processes;  // CHANGED: ProcessContext

// ============================================================================
// ENHANCED DATA STRUCTURES
// ============================================================================

// Enhanced Event class

// Global handle manager
class HandleManager {
private:
    static std::atomic<HANDLE> next_handle;

public:
    static HANDLE allocate_handle() {
        next_handle = reinterpret_cast<HANDLE>(
            reinterpret_cast<uintptr_t>(next_handle.load()) + 1);
        return reinterpret_cast<HANDLE>(
            reinterpret_cast<uintptr_t>(next_handle.load()) - 1);
    }
};

std::atomic<HANDLE> HandleManager::next_handle{reinterpret_cast<HANDLE>(0x1000)};


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

// ============================================================================
// MEMORY MANAGEMENT
// ============================================================================

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

// ============================================================================
// FUNCTION WRAPPER GENERATOR
// ============================================================================

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



// ============================================================================
// REGISTRY EMULATION SYSTEM
// ============================================================================

// Registry key structure
struct RegistryKey {
    std::wstring path;
    std::unordered_map<std::wstring, std::vector<uint8_t>> values;
    std::unordered_map<std::wstring, DWORD> value_types;
    std::unordered_map<std::wstring, std::shared_ptr<RegistryKey>> subkeys;
    LARGE_INTEGER last_write_time;
    mutable std::shared_mutex key_mutex;
    DWORD disposition;  // REG_CREATED_NEW_KEY or REG_OPENED_EXISTING_KEY

    explicit RegistryKey(std::wstring key_path) : path(std::move(key_path)), disposition(0) {
        update_write_time();
    }

    void update_write_time() {
        last_write_time.QuadPart = time(nullptr);
    }
};

// Global registry structure
class RegistryManager {
private:
    std::shared_ptr<RegistryKey> root;
    std::unordered_map<HANDLE, std::shared_ptr<RegistryKey>> open_keys;
    mutable std::shared_mutex registry_mutex;
    std::wstring registry_file_path;

    // Predefined registry hives
    enum class Hive {
        HKEY_LOCAL_MACHINE,
        HKEY_CURRENT_USER,
        HKEY_CLASSES_ROOT,
        HKEY_USERS,
        HKEY_CURRENT_CONFIG,
        HKEY_PERFORMANCE_DATA
    };

    std::unordered_map<std::wstring, Hive> hive_map = {
        {L"\\Registry\\Machine", Hive::HKEY_LOCAL_MACHINE},
        {L"\\Registry\\User", Hive::HKEY_CURRENT_USER},
        {L"HKEY_LOCAL_MACHINE", Hive::HKEY_LOCAL_MACHINE},
        {L"HKLM", Hive::HKEY_LOCAL_MACHINE},
        {L"HKEY_CURRENT_USER", Hive::HKEY_CURRENT_USER},
        {L"HKCU", Hive::HKEY_CURRENT_USER},
        {L"HKEY_CLASSES_ROOT", Hive::HKEY_CLASSES_ROOT},
        {L"HKCR", Hive::HKEY_CLASSES_ROOT},
    };

    static std::wstring normalize_path(const std::wstring& path) {
        std::wstring normalized = path;
        std::ranges::replace(normalized, L'/', L'\\');

        // Remove leading/trailing backslashes
        while (!normalized.empty() && normalized[0] == L'\\') {
            normalized = normalized.substr(1);
        }
        while (!normalized.empty() && normalized.back() == L'\\') {
            normalized.pop_back();
        }

        return normalized;
    }

    std::shared_ptr<RegistryKey> find_or_create_key(const std::wstring& path, bool create) {
        std::wstring normalized = normalize_path(path);

        if (normalized.empty()) {
            return root;
        }

        std::shared_ptr<RegistryKey> current = root;
        size_t start = 0;

        while (start < normalized.length()) {
            size_t end = normalized.find(L'\\', start);
            if (end == std::wstring::npos) {
                end = normalized.length();
            }

            std::wstring component = normalized.substr(start, end - start);

            std::unique_lock lock(current->key_mutex);

            if (!current->subkeys.contains(component)) {
                if (!create) {
                    return nullptr;
                }
                current->subkeys[component] = std::make_shared<RegistryKey>(
                    current->path + L"\\" + component);
            }

            current = current->subkeys[component];
            start = end + 1;
        }

        return current;
    }

    void initialize_default_keys() {
        // Create default Windows registry structure
        const std::vector<std::wstring> default_paths = {
            L"Registry\\Machine\\Software",
            L"Registry\\Machine\\System",
            L"Registry\\Machine\\Hardware",
            L"Registry\\Machine\\Security",
            L"Registry\\Machine\\SAM",
            L"Registry\\User\\.DEFAULT",
            L"Registry\\User\\S-1-5-21-1234567890-1234567890-1234567890-1000",
        };

        for (const auto& path : default_paths) {
            find_or_create_key(path, true);
        }

        // Add some common system values
        auto software_key = find_or_create_key(
            L"Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion", true);
        if (software_key) {
            std::wstring product_name = L"Windows 10 Pro";
            software_key->values[L"ProductName"] = std::vector<uint8_t>(
                reinterpret_cast<const uint8_t*>(product_name.data()),
                reinterpret_cast<const uint8_t*>(product_name.data() + product_name.length() + 1));
            software_key->value_types[L"ProductName"] = REG_SZ;

            DWORD build = 19045;
            software_key->values[L"CurrentBuildNumber"] = std::vector<uint8_t>(
                reinterpret_cast<const uint8_t*>(&build),
                reinterpret_cast<const uint8_t*>(&build) + sizeof(build));
            software_key->value_types[L"CurrentBuildNumber"] = REG_DWORD;
        }
    }

public:
    RegistryManager() : registry_file_path(L"./registry.dat") {
        root = std::make_shared<RegistryKey>(L"Registry");
        initialize_default_keys();
        load_from_file();
    }

    ~RegistryManager() {
        save_to_file();
    }

    HANDLE create_key(const std::wstring& path, bool& created) {
        auto key = find_or_create_key(path, true);
        if (!key) {
            return nullptr;
        }

        created = (key->subkeys.empty() && key->values.empty());
        key->disposition = created ? REG_CREATED_NEW_KEY : REG_OPENED_EXISTING_KEY;

        HANDLE handle = HandleManager::allocate_handle();
        std::unique_lock lock(registry_mutex);
        open_keys[handle] = key;

        return handle;
    }

    HANDLE open_key(const std::wstring& path) {
        auto key = find_or_create_key(path, false);
        if (!key) {
            return nullptr;
        }

        HANDLE handle = HandleManager::allocate_handle();
        std::unique_lock lock(registry_mutex);
        open_keys[handle] = key;

        return handle;
    }

    bool close_key(HANDLE handle) {
        std::unique_lock lock(registry_mutex);
        return open_keys.erase(handle) > 0;
    }

    std::shared_ptr<RegistryKey> get_key(HANDLE handle) {
        std::shared_lock lock(registry_mutex);
        auto it = open_keys.find(handle);
        return (it != open_keys.end()) ? it->second : nullptr;
    }

    bool delete_key(const std::wstring& path) {
        std::wstring normalized = normalize_path(path);
        size_t last_sep = normalized.rfind(L'\\');

        if (last_sep == std::wstring::npos) {
            return false;  // Can't delete root
        }

        std::wstring parent_path = normalized.substr(0, last_sep);
        std::wstring key_name = normalized.substr(last_sep + 1);

        auto parent = find_or_create_key(parent_path, false);
        if (!parent) {
            return false;
        }

        std::unique_lock lock(parent->key_mutex);
        return parent->subkeys.erase(key_name) > 0;
    }

    void save_to_file() {
        // Simplified serialization - in production would use proper format
        trace("Registry saved to ", registry_file_path);
    }

    void load_from_file() {
        // Simplified deserialization
        trace("Registry loaded from ", registry_file_path);
    }

    void flush_key(HANDLE handle) {
        auto key = get_key(handle);
        if (key) {
            key->update_write_time();
            save_to_file();
        }
    }
};

static RegistryManager g_registry_manager;

// ============================================================================
// SYSTEM CALL MONITOR
// ============================================================================

const std::unordered_map<unsigned long long, std::pair<std::string, NTSTATUS (*) (ChildMemoryManager&, const user_regs_struct &)>> syscall_handlers = {
    {0x1, {"NtWorkerFactoryWorkerReady", +[](ChildMemoryManager &mgr, const user_regs_struct &regs) {
             return _NtWorkerFactoryWorkerReady(
                 mgr,
                 reinterpret_cast<HANDLE>(regs.rcx)
             );
    }}},
    {0x3, {"NtMapUserPhysicalPagesScatter", [](ChildMemoryManager &mgr, const user_regs_struct &regs) {
             return _NtMapUserPhysicalPagesScatter(
                 mgr,
                 reinterpret_cast<PVOID *>(regs.rcx),
                 static_cast<ULONG>(regs.rdx),
                 reinterpret_cast<PULONG_PTR>(regs.r8)
             );
    }}},
    {0x9, {"NtRemoveIoCompletion", [](ChildMemoryManager &mgr, const user_regs_struct &regs) {
             const SyscallParameterReader reader(mgr, regs);
             return _NtRemoveIoCompletion(
                 mgr,
                 reinterpret_cast<HANDLE>(regs.rcx),
                 reinterpret_cast<PVOID*>(regs.rdx),
                 reinterpret_cast<PVOID*>(regs.r8),
                 reinterpret_cast<PIO_STATUS_BLOCK>(regs.r9),
                 reader.get_stack_param<PLARGE_INTEGER>(5).value()
             );
    }}},
    {0xD, {"NtSetInformationThread", [](ChildMemoryManager& mgr, const user_regs_struct &regs) {
             return _NtSetInformationThread(
                 mgr,
                 reinterpret_cast<HANDLE>(regs.rcx),
                 static_cast<THREADINFOCLASS>(regs.rdx),
                 reinterpret_cast<PVOID>(regs.r8),
                 static_cast<ULONG>(regs.r9)
             );
    }}},
    {
        0xE, {"NtSetEvent", [](ChildMemoryManager& mgr, const user_regs_struct &regs) {
            return _NtSetEvent(
                mgr,
                reinterpret_cast<HANDLE>(regs.rcx),
                reinterpret_cast<PLONG>(regs.rdx)
                );
    }}},
    {0x11, {"NtQueryInformationFile", [](ChildMemoryManager& mgr, const user_regs_struct &regs) {
        const SyscallParameterReader reader(mgr, regs);
        return _NtQueryInformationFile(
            mgr,
            reinterpret_cast<HANDLE>(regs.rcx),
            reinterpret_cast<PIO_STATUS_BLOCK>(regs.rdx),
            reinterpret_cast<PVOID>(regs.r8),
            static_cast<ULONG>(regs.r9),
            reader.get_stack_param<FILE_INFORMATION_CLASS>(5).value_or(FileBasicInformation));
    }}},
    {0x14, {"NtFindAtom", [](ChildMemoryManager& mgr, const user_regs_struct &regs) {
        return _NtFindAtom(
            mgr,
            reinterpret_cast<PWCHAR>(regs.rcx),
            static_cast<ULONG>(regs.rdx),
            reinterpret_cast<ATOM*>(regs.r8)
        );
    }}},
    {0x19, {"_NtQueryInformationProcess", [](ChildMemoryManager& mgr, const user_regs_struct &regs) {
             return _NtQueryInformationProcess(
                 mgr,
                 reinterpret_cast<HANDLE>(regs.rcx),
                 static_cast<PROCESSINFOCLASS>(regs.rdx),
                 reinterpret_cast<PVOID>(regs.r8),
                 static_cast<ULONG>(regs.r9),
                 reinterpret_cast<PULONG>(regs.rcx)
             );
    }}},
    {0x1B, {"NtWriteFileGather", [](ChildMemoryManager& mgr, const user_regs_struct &regs) {
        const SyscallParameterReader reader(mgr, regs);
        return _NtWriteFileGather(
            mgr,
            reinterpret_cast<HANDLE>(regs.rcx),
            reinterpret_cast<HANDLE>(regs.rdx),
            reinterpret_cast<PIO_APC_ROUTINE>(regs.r8),
            reinterpret_cast<PVOID>(regs.r9),
            reader.get_stack_param<PIO_STATUS_BLOCK>(5).value(),
            reader.get_stack_param<PFILE_SEGMENT_ELEMENT>(6).value(),
            reader.get_stack_param<ULONG>(7).value(),
            reader.get_stack_param<PLARGE_INTEGER>(8).value(),
            reader.get_stack_param<PULONG>(9).value());
    }}},
    {0x27, {"NtSetInformationFile", [](ChildMemoryManager& mgr, const user_regs_struct &regs) {
        const SyscallParameterReader reader(mgr, regs);
        return _NtSetInformationFile(
            mgr,
            reinterpret_cast<HANDLE>(regs.rcx),
            reinterpret_cast<PIO_STATUS_BLOCK>(regs.rdx),
            reinterpret_cast<PVOID>(regs.r8),
            static_cast<ULONG>(regs.r9),
            reader.get_stack_param<FILE_INFORMATION_CLASS>(5).value_or(FileBasicInformation));
    }}},
    {0x36, {"NtQuerySystemInformation", [](ChildMemoryManager& mgr, const user_regs_struct &regs) {
             return _NtQuerySystemInformation(
                 mgr,
                 static_cast<SYSTEM_INFORMATION_CLASS>(regs.rcx),
                 reinterpret_cast<void *>(regs.rdx),
                 static_cast<ULONG>(regs.r8),
                 reinterpret_cast<ULONG *>(regs.r9));
    }}},
    {0x47, {"NtAddAtom", [](ChildMemoryManager& mgr, const user_regs_struct &regs) {
             return _NtAddAtom(
                 mgr,
                 reinterpret_cast<PWCHAR>(regs.rcx),
                 static_cast<ULONG>(regs.rdx),
                 reinterpret_cast<ATOM*>(regs.r8)
             );
    }}},
    {0xBA, {"NtCreateProcess", [](ChildMemoryManager &mgr, const user_regs_struct &regs) {
              const SyscallParameterReader reader(mgr, regs);
              return _NtCreateProcess(
                  mgr,
                  reinterpret_cast<HANDLE*>(regs.rcx),
                  static_cast<ACCESS_MASK>(regs.rdx),
                  reinterpret_cast<POBJECT_ATTRIBUTES>(regs.r8),
                  reinterpret_cast<HANDLE>(regs.r9),
                  reader.get_stack_param<BOOLEAN>(5).value(),
                  reader.get_stack_param<HANDLE>(6).value(),
                  reader.get_stack_param<HANDLE>(7).value(),
                  reader.get_stack_param<HANDLE>(8).value()
              );
    }}},
    {0xCA, {"NtCreateWaitCompletionPacket", [](ChildMemoryManager& mgr, const user_regs_struct& regs) {
                const SyscallParameterReader reader(mgr, regs);
                return _NtCreateWaitCompletionPacket(mgr,
                    reinterpret_cast<PHANDLE>(regs.rcx),
                    static_cast<ACCESS_MASK>(regs.rdx),
                    reinterpret_cast<POBJECT_ATTRIBUTES>(regs.r8),
                    reinterpret_cast<HANDLE>(regs.r9),
                    reader.get_stack_param<PVOID>(5).value());
    }}},
    {0xEA, {"NtFlushKey", [](ChildMemoryManager& mgr, const user_regs_struct &regs) {
              return _NtFlushKey(
                  mgr,
                  reinterpret_cast<HANDLE>(regs.rcx)
              );
            }
        }
    },
    {0x162, {"NtQuerySystemInformationEx", [](ChildMemoryManager& mgr, const user_regs_struct &regs) {
                const SyscallParameterReader reader(mgr, regs);
                return _NtQuerySystemInformationEx(
                     mgr,
                     static_cast<SYSTEM_INFORMATION_CLASS>(regs.rcx),
                     reinterpret_cast<void *>(regs.rdx),
                    static_cast<ULONG>(regs.r8),
                    reinterpret_cast<void *>(regs.r9),
                    reader.get_stack_param<ULONG>(5).value(),
                      reader.get_stack_param<PULONG>(6).value());
    }}},
    {0x168, {"NtRaiseException", [](ChildMemoryManager& mgr, const user_regs_struct &regs) {
              return _NtRaiseException(
                  mgr,
                  reinterpret_cast<PEXCEPTION_RECORD>(regs.rcx),
                  reinterpret_cast<PCONTEXT>(regs.rdx),
                  static_cast<BOOLEAN>(regs.r8)
              );
    }}}
};

// ============================================================================
// CRASH HANDLER
// ============================================================================

// ============================================================================
// CRASH HANDLER IMPLEMENTATION
// ============================================================================

class CrashHandler {
public:
    static void setup_crash_handler() {
        struct sigaction sa{};
        sa.sa_flags = SA_SIGINFO;
        sigemptyset(&sa.sa_mask);
        sa.sa_sigaction = sigsegv_handler;

        if (sigaction(SIGSEGV, &sa, nullptr) == -1) {
            perror("sigaction SIGSEGV");
            exit(1);
        }

        // Also catch other signals that might indicate issues
        sigaction(SIGFPE, &sa, nullptr);   // Floating point exception
        sigaction(SIGILL, &sa, nullptr);   // Illegal instruction
        sigaction(SIGBUS, &sa, nullptr);   // Bus error
        sigaction(SIGABRT, &sa, nullptr);  // Abort signal
    }

private:
    static void sigsegv_handler(int sig, siginfo_t* si, void* unused) {
        const ucontext_t* uc = static_cast<ucontext_t*>(unused);

        trace("\n=== CRASH DEBUG INFO ===");
        trace("Signal: ", sig, " (", get_signal_name(sig), ")");
        trace("Fault address: 0x", std::hex, reinterpret_cast<uintptr_t>(si->si_addr), std::dec);
        trace("Error code: ", si->si_code, " (", get_error_description(sig, si->si_code), ")");

        // Print register state at a crash
        trace("Register state at crash:");
        trace("  RAX: 0x", std::hex, uc->uc_mcontext.gregs[REG_RAX], std::dec);
        trace("  RBX: 0x", std::hex, uc->uc_mcontext.gregs[REG_RBX], std::dec);
        trace("  RCX: 0x", std::hex, uc->uc_mcontext.gregs[REG_RCX], std::dec);
        trace("  RDX: 0x", std::hex, uc->uc_mcontext.gregs[REG_RDX], std::dec);
        trace("  RSI: 0x", std::hex, uc->uc_mcontext.gregs[REG_RSI], std::dec);
        trace("  RDI: 0x", std::hex, uc->uc_mcontext.gregs[REG_RDI], std::dec);
        trace("  RBP: 0x", std::hex, uc->uc_mcontext.gregs[REG_RBP], std::dec);
        trace("  RSP: 0x", std::hex, uc->uc_mcontext.gregs[REG_RSP], std::dec);
        trace("  R8 : 0x", std::hex, uc->uc_mcontext.gregs[REG_R8], std::dec);
        trace("  R9 : 0x", std::hex, uc->uc_mcontext.gregs[REG_R9], std::dec);
        trace("  R10: 0x", std::hex, uc->uc_mcontext.gregs[REG_R10], std::dec);
        trace("  R11: 0x", std::hex, uc->uc_mcontext.gregs[REG_R11], std::dec);
        trace("  R12: 0x", std::hex, uc->uc_mcontext.gregs[REG_R12], std::dec);
        trace("  R13: 0x", std::hex, uc->uc_mcontext.gregs[REG_R13], std::dec);
        trace("  R14: 0x", std::hex, uc->uc_mcontext.gregs[REG_R14], std::dec);
        trace("  R15: 0x", std::hex, uc->uc_mcontext.gregs[REG_R15], std::dec);
        trace("  RIP: 0x", std::hex, uc->uc_mcontext.gregs[REG_RIP], std::dec);
        trace("  EFL: 0x", std::hex, uc->uc_mcontext.gregs[REG_EFL], std::dec);
        trace("  CS : 0x", std::hex, uc->uc_mcontext.gregs[REG_CSGSFS] & 0xFFFF, std::dec);
        trace("  SS : 0x", std::hex, (uc->uc_mcontext.gregs[REG_CSGSFS] >> 16) & 0xFFFF, std::dec);
        trace("  FS : 0x", std::hex, (uc->uc_mcontext.gregs[REG_CSGSFS] >> 32) & 0xFFFF, std::dec);
        trace("  GS : 0x", std::hex, (uc->uc_mcontext.gregs[REG_CSGSFS] >> 48) & 0xFFFF, std::dec);

        const uintptr_t crash_addr = uc->uc_mcontext.gregs[REG_RIP];

        // Analyze the fault
        analyze_fault(si, uc);

        // Print a detailed stack trace
        print_detailed_stack_trace(uc);

        // Print memory around the crash location
        print_memory_context(crash_addr, si->si_addr);

        trace("========================\n");

        // Try to save crash dump information
        save_crash_dump(sig, si, uc);

        exit(1);
    }

    static const char* get_signal_name(int sig) {
        switch (sig) {
            case SIGSEGV: return "SIGSEGV - Segmentation violation";
            case SIGFPE:  return "SIGFPE - Floating point exception";
            case SIGILL:  return "SIGILL - Illegal instruction";
            case SIGBUS:  return "SIGBUS - Bus error";
            case SIGABRT: return "SIGABRT - Abort signal";
            default: return "Unknown signal";
        }
    }

    static const char* get_error_description(int sig, int code) {
        if (sig == SIGSEGV) {
            switch (code) {
                case SEGV_MAPERR: return "Address not mapped to object";
                case SEGV_ACCERR: return "Invalid permissions for mapped object";
                default: return "Unknown SIGSEGV error";
            }
        } else if (sig == SIGFPE) {
            switch (code) {
                case FPE_INTDIV: return "Integer divide by zero";
                case FPE_INTOVF: return "Integer overflow";
                case FPE_FLTDIV: return "Floating point divide by zero";
                case FPE_FLTOVF: return "Floating point overflow";
                case FPE_FLTUND: return "Floating point underflow";
                case FPE_FLTRES: return "Floating point inexact result";
                case FPE_FLTINV: return "Floating point invalid operation";
                case FPE_FLTSUB: return "Subscript out of range";
                default: return "Unknown FPE error";
            }
        } else if (sig == SIGILL) {
            switch (code) {
                case ILL_ILLOPC: return "Illegal opcode";
                case ILL_ILLOPN: return "Illegal operand";
                case ILL_ILLADR: return "Illegal addressing mode";
                case ILL_ILLTRP: return "Illegal trap";
                case ILL_PRVOPC: return "Privileged opcode";
                case ILL_PRVREG: return "Privileged register";
                case ILL_COPROC: return "Coprocessor error";
                case ILL_BADSTK: return "Internal stack error";
                default: return "Unknown SIGILL error";
            }
        }
        return "Unknown error code";
    }

    static void identify_crash_section(LoadedModule* module, uintptr_t offset) {
        for (const auto& section : module->pe_binary->sections()) {
            const uintptr_t section_start = section.virtual_address();
            const uintptr_t section_end = section_start + section.virtual_size();

            if (offset >= section_start && offset < section_end) {
                const uintptr_t section_offset = offset - section_start;
                const auto characteristics = section.characteristics();

                trace("Section: ", converter.from_bytes(section.name()));
                trace("  Section offset: 0x", std::hex, section_offset, std::dec);
                trace("  Characteristics: 0x", std::hex, characteristics, std::dec);

                std::string perms;
                if (characteristics & static_cast<uint32_t>(LIEF::PE::Section::CHARACTERISTICS::MEM_READ))
                    perms += "R";
                if (characteristics & static_cast<uint32_t>(LIEF::PE::Section::CHARACTERISTICS::MEM_WRITE))
                    perms += "W";
                if (characteristics & static_cast<uint32_t>(LIEF::PE::Section::CHARACTERISTICS::MEM_EXECUTE))
                    perms += "X";

                trace("  Permissions: ", converter.from_bytes(perms));
                break;
            }
        }
    }

    static void disassemble_crash_location(uintptr_t crash_addr, uintptr_t base_addr, size_t module_size) {
        trace("Bytes at crash location:");

        // Try to read memory safely
        for (int i = -8; i < 16; i++) {
            uintptr_t addr = crash_addr + i;
            if (addr >= base_addr && addr < base_addr + module_size) {
                // Memory should be readable since it's in a loaded module
                try {
                    uint8_t byte = *reinterpret_cast<uint8_t*>(addr);
                    trace("  [0x", std::hex, addr, "] = 0x",
                          std::setw(2), std::setfill<wchar_t>('0'), static_cast<int>(byte), std::dec);
                } catch (...) {
                    trace("  [0x", std::hex, addr, "] = <unreadable>", std::dec);
                }
            }
        }

        // Try to disassemble with Capstone
        csh handle;
        if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) == CS_ERR_OK) {
            try {
                auto code_ptr = reinterpret_cast<uint8_t*>(crash_addr - 16);
                size_t code_size = 32;

                cs_insn *insn;
                size_t count = cs_disasm(handle, code_ptr, code_size, crash_addr - 16, 0, &insn);

                if (count > 0) {
                    trace("Disassembly around crash:");
                    for (size_t j = 0; j < count; j++) {
                        const char* marker = (insn[j].address == crash_addr) ? " >>> " : "     ";
                        trace(marker, "0x", std::hex, insn[j].address, ": ",
                              insn[j].mnemonic, " ", insn[j].op_str, std::dec);
                    }
                    cs_free(insn, count);
                } else {
                    trace("Failed to disassemble crash location");
                }
            } catch (...) {
                trace("Exception during disassembly");
            }
            cs_close(&handle);
        }
    }

    static void analyze_fault(siginfo_t* si, const ucontext_t* uc) {
        const auto fault_addr = reinterpret_cast<uintptr_t>(si->si_addr);
        const uintptr_t rip = uc->uc_mcontext.gregs[REG_RIP];
        const uintptr_t rsp = uc->uc_mcontext.gregs[REG_RSP];

        trace("Fault Analysis:");

        if (fault_addr == 0) {
            trace("  NULL pointer dereference");
        } else if (fault_addr < 0x1000) {
            trace("  Near-NULL pointer dereference (offset: 0x", std::hex, fault_addr, ")", std::dec);
        } else if (fault_addr == 0xdeadbeef || fault_addr == 0xcafebabe) {
            trace("  Access to debug/poison value - likely use-after-free");
        } else if (abs(static_cast<long>(fault_addr - rsp)) < 0x10000) {
            trace("  Stack-relative access - possible stack corruption");
        } else if (fault_addr > 0x7fffffffffff) {
            trace("  Kernel address access - possible corruption");
        }

        // Check for common instruction patterns
        try {
            auto insn = reinterpret_cast<uint8_t*>(rip);
            if (insn[0] == 0x48 && insn[1] == 0x8b) {  // mov (%reg), %reg
                trace("  Crash on memory read instruction");
            } else if (insn[0] == 0x48 && insn[1] == 0x89) {  // mov %reg, (%reg)
                trace("  Crash on memory write instruction");
            } else if (insn[0] == 0xff) {  // call/jmp indirect
                trace("  Crash on indirect call/jump - possible function pointer corruption");
            }
        } catch (...) {
            // Can't read instruction
        }
    }

    static void print_detailed_stack_trace(const ucontext_t* uc) {
        trace("Detailed stack trace:");

        void* array[20];
        const int size = backtrace(array, 20);
        char** strings = backtrace_symbols(array, size);

        for (size_t i = 0; i < size; i++) {
            trace("  ", strings[i]);
        }

        free(strings);
    }

    static void print_memory_context(uintptr_t crash_addr, void* fault_addr) {
        trace("Memory context:");
        trace("  Crash RIP: 0x", std::hex, crash_addr, std::dec);
        trace("  Fault address: 0x", std::hex, reinterpret_cast<uintptr_t>(fault_addr), std::dec);

        // Print stack contents
        uintptr_t rsp;
        asm volatile("mov %%rsp, %0" : "=r"(rsp));
        trace("  Current stack (RSP = 0x", std::hex, rsp, "):", std::dec);

        try {
            auto stack_ptr = reinterpret_cast<uintptr_t*>(rsp);
            for (int i = 0; i < 8; i++) {
                trace("    [RSP+", std::hex, i*8, "] = 0x", stack_ptr[i], std::dec);
            }
        } catch (...) {
            trace("    Stack unreadable");
        }
    }

    static void save_crash_dump(int sig, siginfo_t* si, const ucontext_t* uc) {
        // Save crash information to file
        std::ofstream crash_file("crash_dump.txt", std::ios::app);
        if (crash_file.is_open()) {
            auto now = std::time(nullptr);
            crash_file << "=== CRASH DUMP " << std::ctime(&now) << " ===\n";
            crash_file << "Signal: " << sig << " (" << get_signal_name(sig) << ")\n";
            crash_file << "Fault address: 0x" << std::hex << reinterpret_cast<uintptr_t>(si->si_addr) << "\n";
            crash_file << "RIP: 0x" << std::hex << uc->uc_mcontext.gregs[REG_RIP] << "\n";
            crash_file << "RSP: 0x" << std::hex << uc->uc_mcontext.gregs[REG_RSP] << "\n";
            crash_file << "===============================\n\n";
            crash_file.close();
            trace("Crash dump saved to crash_dump.txt");
        }
    }
};

// ============================================================================
// FUNCTION EXECUTION SYSTEM
// ============================================================================

class FunctionExecutor {
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
    static int call_windows_function_asm(uintptr_t func_addr,
                                     uintptr_t arg1,
                                     uintptr_t arg2,
                                     uintptr_t arg3,
                                     uintptr_t arg4) {
        uintptr_t result;
        __asm__ __volatile__ (
            // Allocate 32-byte shadow space
            "sub $32, %%rsp\n\t"

            // Add this before the shadow space allocation:
            "and $-16, %%rsp\n\t"    // Force 16-byte alignment
            "sub $32, %%rsp\n\t"     // Then allocate shadow space

            // Move args into Windows ABI registers
            "mov %1, %%rcx\n\t"
            "mov %2, %%rdx\n\t"
            "mov %3, %%r8\n\t"
            "mov %4, %%r9\n\t"

            // Call a target function
            "call *%5\n\t"

            // Store return value
            "mov %%rax, %0\n\t"

            // Restore stack
            "add $32, %%rsp\n\t"
            : "=r"(result)
            : "r"(arg1), "r"(arg2), "r"(arg3), "r"(arg4), "r"(func_addr)
            : "rcx", "rdx", "r8", "r9", "r10", "r11", "memory"
        );
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
};

class FunctionResolver {
private:
    std::unordered_map<uintptr_t, LoadedModule*>& module_by_address;

public:
    explicit FunctionResolver(std::unordered_map<uintptr_t, LoadedModule*>& modules)
        : module_by_address(modules) {}


    std::wstring resolve_address(uintptr_t address) {
        // find the module containing this address by finding minimal offset
        LoadedModule* best_module = nullptr;
        uintptr_t best_offset = UINTPTR_MAX;
        for (const auto& [base_addr, module] : module_by_address) {
            if (address >= base_addr) {
                uintptr_t offset = address - base_addr;
                if (offset < best_offset) {
                    best_offset = offset;
                    best_module = module;
                }
            }
        }

        if (!best_module || !best_module->pe_binary) {
            return L"unknown";
        }

        // Try to find the function with minimal offset
        std::wstring best_func = L"unknown";
        uintptr_t best_func_offset = UINTPTR_MAX;
        if (best_module->pe_binary->has_exports()) {
            const LIEF::PE::Export* export_table = best_module->pe_binary->get_export();
            for (const auto& entry : export_table->entries()) {
                uint32_t func_rva = entry.address() ? entry.address() : entry.function_rva();
                if (func_rva == 0) continue;

                uintptr_t func_addr = best_module->base_address + func_rva;
                if (address >= func_addr) {
                    uintptr_t func_offset = address - func_addr;
                    if (func_offset < best_func_offset) {
                        best_func_offset = func_offset;
                        best_func = converter.from_bytes(entry.name());
                    }
                }
            }
        }
        return best_module->name + L"!" + best_func + L"+0x" + std::to_wstring(best_func_offset);
    }
};

class SystemCallManager {
private:
    bool monitoring_enabled;
    std::shared_ptr<FunctionResolver> function_resolver;

public:
    explicit SystemCallManager(bool enabled = true) : monitoring_enabled(enabled) {}

    void initialize_function_resolver(std::unordered_map<uintptr_t, LoadedModule*>& modules) {
        function_resolver = std::make_shared<FunctionResolver>(modules);
    }

    void trace_child_execution(pid_t child, const std::wstring& context) {
        if (!monitoring_enabled) return;

        trace("Starting syscall monitoring for: ", context);

        int status;
        ptrace(/*PTRACE_SINGLESTEP*/PTRACE_SYSCALL, child, 0, 0);  // Start tracing with single step to catch initial state

        bool in_syscall = false;
        while (true) {
            pid_t w = waitpid(-1, &status, __WALL);
            if (w == -1) break;

            if (WIFEXITED(status)) {
                trace(context, " - Process/thread ", w, " exited with code ", WEXITSTATUS(status));
                if (w == child) break;  // Main process exited
                continue;
            }

            if (WIFSIGNALED(status)) {
                trace(context, " - Process/thread ", w, " terminated by signal ", WTERMSIG(status));
                if (w == child) break;
                continue;
            }

            if (WIFSTOPPED(status)) {
                int sig = WSTOPSIG(status);
                int event = status >> 16;

                // Handle ptrace events
                if (event == PTRACE_EVENT_CLONE) {
                    unsigned long new_tid;
                    ptrace(PTRACE_GETEVENTMSG, w, 0, &new_tid);
                    trace("New thread created: TID ", new_tid);

                    // The new thread will stop automatically, continue it
                    ptrace(PTRACE_SYSCALL, new_tid, 0, 0);
                    ptrace(PTRACE_SYSCALL, w, 0, 0);  // Continue parent
                    continue;
                }

                if (sig == (SIGTRAP) || sig == (SIGTRAP | 0x80)) {
                    // SINGLESTEP MODE CODE
                    /*user_regs_struct regs{};
                    if (ptrace(PTRACE_GETREGS, w, NULL, &regs) == -1) {
                        perror("ptrace GETREGS");
                        ptrace(PTRACE_SYSCALL, w, 0, 0);  // Continue
                        continue;
                    }

                    ChildMemoryManager mgr(w);

                    // Resolve function
                    std::wstring current_func = L"unknown";
                    if (function_resolver) {
                        current_func = function_resolver->resolve_address(regs.rip);
                    }
                    print_step_info(mgr, regs, context, current_func);

                    // if is syscall, then handle it
                    // read what's under RIP - should be syscall instruction (0x0f 0x05)
                    uint8_t instr[2];
                    instr[0] = mgr.read<uint8_t>(regs.rip).value_or(0);
                    instr[1] = mgr.read<uint8_t>(regs.rip + 1).value_or(0);

                    if (instr[0] == 0x0f && instr[1] == 0x05) {
                        // It's a syscall instruction

                        const NTSTATUS ret = print_syscall_info(regs.rax, mgr, regs, context, current_func);
                        regs.orig_rax = -1;  // Prevent re-execution of syscall
                        regs.rax = ret;      // Set return value
                        ptrace(PTRACE_SETREGS, w, NULL, &regs);
                    }

                    // continue with single step
                    ptrace(PTRACE_SINGLESTEP, w, 0, 0);  // Continue
                    */

                    // SYSCALL MODE CODE Syscall entry or exit
                    if (!in_syscall) {
                        user_regs_struct regs{};
                        if (ptrace(PTRACE_GETREGS, w, NULL, &regs) != -1) {
                            ChildMemoryManager mgr(w);

                            // Resolve function
                            std::wstring current_func = L"unknown";
                            if (function_resolver) {
                                current_func = function_resolver->resolve_address(regs.rip);
                            }

                            print_step_info(mgr, regs, context, current_func);

                            NTSTATUS ret = print_syscall_info(regs.orig_rax, mgr, regs, context, current_func);
                            regs.orig_rax = -1;  // Prevent re-execution of syscall
                            regs.rax = ret;      // Set return value
                            ptrace(PTRACE_SETREGS, w, NULL, &regs);
                        }
                        ptrace(PTRACE_SYSCALL, w, 0, 0);  // Continue to the next syscall
                        in_syscall = true;
                    }
                    else {
                        in_syscall = false;
                        ptrace(PTRACE_SYSCALL, w, 0, 0);  // Continue to the next syscall
                    }
                }
                else {
                    // Forward the signal to the child
                    ptrace(PTRACE_SYSCALL, w, 0, sig);
                }
            }
        }

        trace("Stopped syscall monitoring for: ", context);
        stop_thread_monitoring(child);
    }

    void set_monitoring(bool enabled) { monitoring_enabled = enabled; }
    bool is_enabled() const { return monitoring_enabled; }

     NTSTATUS print_syscall_info(unsigned long long syscall_nr, ChildMemoryManager &mgr, struct user_regs_struct& regs,
                                   const std::wstring& context, const std::wstring& current_func) {
        if (syscall_handlers.contains(syscall_nr)) {
            const auto& [name, handler] = syscall_handlers.at(syscall_nr);
            trace("[", context, "] [", current_func, "] Intercepted syscall: ", converter.from_bytes(name), " (", syscall_nr, ")");
            NTSTATUS status = handler(mgr, regs);
            trace("[", context, "] [", current_func, "] Syscall ", converter.from_bytes(name), " returned: 0x", std::hex, status, std::dec);
            std::wstring func_name = L"unknown";
            func_name = function_resolver->resolve_address(regs.rip);
            trace("[", context, "] [", current_func, "] Stepped to instruction at 0x", std::hex, regs.rip, " (", func_name, ")", std::dec);
            return status;
        }
        trace("[", context, "] [", current_func, "] Unknown syscall number: ", syscall_nr);
        exit(1);
        return 0;
    }

    void print_step_info(ChildMemoryManager &mgr, struct user_regs_struct& regs,
                                   const std::wstring& context, const std::wstring& current_func) {
        std::wstring func_name = L"unknown";
        func_name = function_resolver->resolve_address(regs.rip);
        trace("[", context, "] [", current_func, "] Stepped to instruction at 0x", std::hex, regs.rip, " (", func_name, ")", std::dec);
        // print register state, first 32 bytes of code at RIP and disassemble
        trace("  Registers:");
        trace("    RAX: 0x", std::hex, regs.rax, ", EAX: 0x", static_cast<uint32_t>(regs.rax));
        trace("    RBX: 0x", std::hex, regs.rbx);
        trace("    RCX: 0x", std::hex, regs.rcx);
        trace("    RDX: 0x", std::hex, regs.rdx);
        trace("    RSI: 0x", std::hex, regs.rsi);
        trace("    RDI: 0x", std::hex, regs.rdi);
        trace("    RSP: 0x", std::hex, regs.rsp);
        trace("    RBP: 0x", std::hex, regs.rbp);
        trace("    RIP: 0x", std::hex, regs.rip);
        trace("    R8:  0x", std::hex, regs.r8);
        trace("    R9:  0x", std::hex, regs.r9);
        trace("    R10: 0x", std::hex, regs.r10);
        trace("    R11: 0x", std::hex, regs.r11);
        trace("    R12: 0x", std::hex, regs.r12);
        trace("    R13: 0x", std::hex, regs.r13);
        trace("    R14: 0x", std::hex, regs.r14);
        trace("    R15: 0x", std::hex, regs.r15);
        trace("  Code bytes at RIP:");
        uint8_t code_bytes[64];
        for (int i = -32; i < 32; i++) {
            code_bytes[i + 32] = mgr.read<uint8_t>(regs.rip + i).value_or(0);
            if (!i) {
                trace(" >>> [0x", std::hex, regs.rip + i, "] = 0x",
                      std::setw(2), std::setfill<wchar_t>('0'), static_cast<int>(code_bytes[i]), std::dec);
            }
            else {

                trace("     [0x", std::hex, regs.rip + i, "] = 0x",
                      std::setw(2), std::setfill<wchar_t>('0'), static_cast<int>(code_bytes[i]), std::dec);
            }
        }
        // Disassemble
        csh handle;
        if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) == CS_ERR_OK) {
            cs_insn *insn;
            uint8_t code_before[32];
            uint8_t code_after[32];
            for (int i = 0; i < 32; i++) {
                code_before[i] = code_bytes[i];
                code_after[i] = code_bytes[i + 32];
            }
            if (const size_t count = cs_disasm(handle, code_before, sizeof(code_before), regs.rip - 32, 0, &insn); count > 0) {
                trace("  Disassembly (before RIP):");
                for (size_t j = 0; j < count; j++) {
                    trace("    0x", std::hex, insn[j].address, ": ", insn[j].mnemonic, " ", insn[j].op_str, std::dec);
                }
                cs_free(insn, count);
            } else {
                trace("  Failed to disassemble code before RIP");
            }

            if (const size_t count = cs_disasm(handle, code_after, sizeof(code_after), regs.rip, 0, &insn); count > 0) {
                trace("  Disassembly (at and after RIP):");
                for (size_t j = 0; j < count; j++) {
                    const char* marker = (insn[j].address == regs.rip) ? " >>> " : "     ";
                    trace(marker, "0x", std::hex, insn[j].address, ": ", insn[j].mnemonic, " ", insn[j].op_str, std::dec);
                }
                cs_free(insn, count);
            } else {
                trace("  Failed to disassemble code at/after RIP");
            }

            cs_close(&handle);
        } else {
            trace("  Failed to initialize Capstone for disassembly");
        }
    }

    static void fatal(const char* what) {
        error("Fatal error: ", what);
        exit(1);
    }
    std::unordered_map<pthread_t, std::shared_ptr<std::thread>> monitor_threads;
    std::shared_mutex monitor_mutex;

public:
    void start_thread_monitoring(pthread_t thread_id, const std::wstring& context) {
        if (!monitoring_enabled) return;

        std::shared_lock lock(monitor_mutex);

        auto monitor_thread = std::make_shared<std::thread>([this, thread_id, context]() {
            trace("Starting syscall monitoring for thread: ", context);

            // Monitor this specific thread's syscalls
            while (!should_stop_monitoring(thread_id)) {
                // Thread-specific monitoring logic
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }

            trace("Stopped monitoring thread: ", context);
        });

        monitor_threads[thread_id] = std::move(monitor_thread);
    }

    void stop_thread_monitoring(pthread_t thread_id) {
        std::shared_lock lock(monitor_mutex);
        auto it = monitor_threads.find(thread_id);
        if (it != monitor_threads.end()) {
            if (it->second->joinable()) {
                it->second->join();
            }
            monitor_threads.erase(it);
        }
    }

private:
    bool should_stop_monitoring(pthread_t thread_id) {
        if (!monitoring_enabled) return true;
        std::shared_lock lock(monitor_mutex);
        // check if thread_id is still in monitor_threads
        return !monitor_threads.contains(thread_id);
    }
};


// Enhanced Thread Management with full syscall redirection
class EnhancedThreadManager {
private:
    std::unordered_map<pthread_t, std::shared_ptr<ThreadContext>> managed_threads;
    std::shared_mutex threads_mutex;
    ProcessContext* parent_process;
    std::shared_ptr<SystemCallManager> thread_syscall_monitor;

    // Thread creation wrapper that sets up syscall redirection
    struct ThreadStartData {
        LPTHREAD_START_ROUTINE original_start_routine{};
        LPVOID original_parameter{};
        ThreadContext* thread_context{};
        ProcessContext* process_context{};
        std::promise<bool> setup_complete;
    };

    static void* enhanced_thread_start(void* arg) {
        auto* start_data = static_cast<ThreadStartData*>(arg);
        ThreadContext* thread_ctx = start_data->thread_context;

        // Set up thread-local syscall redirection
        pid_t thread_tid = gettid();
        thread_ctx->thread_id = static_cast<DWORD>(thread_tid);

        trace("Starting enhanced thread ", thread_tid, " with syscall redirection");

        // Signal the parent that we're ready for tracing
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
            warn("Failed to enable ptrace for thread ", thread_tid, ": ", strerror(errno));
        } else {
            trace("Enabled ptrace for thread ", thread_tid);
            // Stop to let parent set up monitoring
            raise(SIGSTOP);
        }

        start_data->setup_complete.set_value(true);

        // Call the original thread function
        DWORD result = 0;
        if (start_data->original_start_routine) {
            result = start_data->original_start_routine(start_data->original_parameter);
        }

        thread_ctx->exit_code = result;
        thread_ctx->is_terminated = true;

        trace("Thread ", thread_tid, " exiting with code ", result);
        return reinterpret_cast<void*>(static_cast<uintptr_t>(result));
    }

public:
    explicit EnhancedThreadManager(ProcessContext* process)
        : parent_process(process) {
        thread_syscall_monitor = std::make_shared<SystemCallManager>(true);
    }

    HANDLE create_monitored_thread(
        LPSECURITY_ATTRIBUTES lpThreadAttributes,
        SIZE_T dwStackSize,
        LPTHREAD_START_ROUTINE lpStartAddress,
        LPVOID lpParameter,
        DWORD dwCreationFlags,
        LPDWORD lpThreadId) {

        // Create thread context
        auto thread_ctx = std::make_shared<ThreadContext>();
        thread_ctx->parent_process_handle = parent_process->windows_process_handle;
        thread_ctx->is_suspended = (dwCreationFlags & CREATE_SUSPENDED) != 0;
        thread_ctx->creation_time = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        // Set up thread start data
        auto start_data = std::make_shared<ThreadStartData>();
        start_data->original_start_routine = lpStartAddress;
        start_data->original_parameter = lpParameter;
        start_data->thread_context = thread_ctx.get();
        start_data->process_context = parent_process;

        // Create the actual thread
        pthread_attr_t attr;
        pthread_attr_init(&attr);

        if (dwStackSize > 0) {
            pthread_attr_setstacksize(&attr, dwStackSize);
        }

        pthread_t native_thread;
        int result = pthread_create(&native_thread, &attr, enhanced_thread_start, start_data.get());
        pthread_attr_destroy(&attr);

        if (result != 0) {
            trace("Failed to create thread: ", strerror(result));
            return nullptr;
        }

        // Wait for thread setup to complete
        start_data->setup_complete.get_future().wait();

        thread_ctx->native_thread_id = native_thread;
        thread_ctx->thread = native_thread;

        HANDLE thread_handle = HandleManager::allocate_handle();
        thread_ctx->windows_thread_handle = thread_handle;
        thread_ctx->thread_handle = thread_handle;

        // Register thread
        {
            std::shared_lock lock(threads_mutex);
            managed_threads[native_thread] = std::move(thread_ctx);
        }

        // Register with parent process
        {
            std::shared_lock lock(parent_process->process_mutex);
            parent_process->threads[thread_handle] = std::move(managed_threads[native_thread]);
        }

        if (lpThreadId) {
            *lpThreadId = static_cast<DWORD>(gettid());
        }

        // Set up syscall monitoring for the new thread if enabled

        setup_thread_monitoring(native_thread);

        trace("Created monitored thread ", thread_handle, " (native: ", native_thread, ")");
        return thread_handle;
    }

private:
    // In EnhancedThreadManager::create_monitored_thread
    void setup_thread_monitoring(pthread_t thread_id) {
        // Fork a monitoring process for this thread
        pid_t monitor_pid = fork();
        if (monitor_pid == -1) {
            warn("Failed to create thread monitor: ", strerror(errno));
            return;
        }

        if (monitor_pid == 0) {
            // Child process - monitor the thread
            pid_t thread_tid = 0;

            // Get the actual TID by reading /proc
            char task_path[256];
            snprintf(task_path, sizeof(task_path), "/proc/%d/task", getppid());

            DIR* task_dir = opendir(task_path);
            if (task_dir) {
                struct dirent* entry;
                // Find the newest TID (the one we just created)
                pid_t newest_tid = 0;
                while ((entry = readdir(task_dir)) != nullptr) {
                    if (entry->d_type == DT_DIR && isdigit(entry->d_name[0])) {
                        pid_t tid = atoi(entry->d_name);
                        if (tid > newest_tid && tid != getppid()) {
                            newest_tid = tid;
                        }
                    }
                }
                closedir(task_dir);
                thread_tid = newest_tid;
            }

            if (thread_tid > 0) {
                trace("Monitoring thread TID ", thread_tid);

                // Attach to the thread
                if (ptrace(PTRACE_ATTACH, thread_tid, NULL, NULL) == -1) {
                    error("Failed to attach to thread: ", strerror(errno));
                    exit(1);
                }

                // Wait for it to stop
                int status;
                if (waitpid(thread_tid, &status, 0) != -1) {
                    if (WIFSTOPPED(status)) {
                        // Set up tracing options
                        ptrace(PTRACE_SETOPTIONS, thread_tid, 0,
                               PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACECLONE);

                        std::wstring context = L"Thread-" + std::to_wstring(thread_tid);
                        thread_syscall_monitor->trace_child_execution(thread_tid, context);
                    }
                }
            }

            exit(0);
        } else {
            // Parent - store monitor PID
            std::shared_lock lock(threads_mutex);
            if (auto it = managed_threads.find(thread_id); it != managed_threads.end()) {
                it->second->syscall_context.current_syscall = monitor_pid;
            }
        }
    }

public:
    void cleanup_thread(pthread_t thread_id) {
        std::shared_lock lock(threads_mutex);
        auto it = managed_threads.find(thread_id);
        if (it != managed_threads.end()) {
            ThreadContext* thread_ctx = it->second.get();

            // Cleanup monitor process if it exists
            auto monitor_pid = static_cast<pid_t>(thread_ctx->syscall_context.current_syscall);
            if (monitor_pid > 0) {
                kill(monitor_pid, SIGTERM);
                waitpid(monitor_pid, nullptr, WNOHANG);
            }

            managed_threads.erase(it);
        }
    }

    ThreadContext* get_thread(pthread_t thread_id) {
        std::shared_lock lock(threads_mutex);
        auto it = managed_threads.find(thread_id);
        return (it != managed_threads.end()) ? it->second.get() : nullptr;
    }
};

// Enhanced Process Manager with full subprocess syscall redirection
class EnhancedProcessManager {
private:
    std::shared_mutex process_mutex;

    struct ProcessCreationData {
        std::wstring executable_path;
        std::wstring command_line;
        std::wstring working_directory;
        DWORD creation_flags;
        LPVOID environment;
        STARTUPINFOW startup_info;
        std::string ipc_socket_path;
    };

public:
    ProcessContext* create_monitored_process(
        LPCWSTR lpApplicationName,
        LPWSTR lpCommandLine,
        LPSECURITY_ATTRIBUTES lpProcessAttributes,
        LPSECURITY_ATTRIBUTES lpThreadAttributes,
        BOOL bInheritHandles,
        DWORD dwCreationFlags,
        LPVOID lpEnvironment,
        LPCWSTR lpCurrentDirectory,
        LPSTARTUPINFOW lpStartupInfo,
        LPPROCESS_INFORMATION lpProcessInformation,
        SectionHandle *section_handle) {

        trace("Creating monitored subprocess with IPC");

        // Fork the process
        pid_t child_pid = fork();
        if (child_pid == -1) {
            error("Fork failed: ", strerror(errno));
            return nullptr;
        }

        if (child_pid == 0) {
            // Child process
            // Enable ptrace
            if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
                error("PTRACE_TRACEME failed");
                exit(1);
            }

            // Set up environment
            std::u16string app_name = lpApplicationName ? std::u16string(lpApplicationName) : u"";
            std::u16string cmd_line = lpCommandLine ? std::u16string(lpCommandLine) : u"";
            std::u16string work_dir = lpCurrentDirectory ? std::u16string(lpCurrentDirectory) : u".";

            setup_child_process_environment(app_name, cmd_line, work_dir, dwCreationFlags, lpEnvironment);
            initialize_default_current_peb();
            initialize_default_current_teb();
            api_resolver.populate_peb_api_set_map();

            // If a section provided, map it
            if (section_handle && section_handle->base_address) {
                void* mapped = mmap(
                    section_handle->base_address,
                    section_handle->view_size,
                    PROT_READ | PROT_WRITE | PROT_EXEC,
                    MAP_SHARED | MAP_FIXED_NOREPLACE,
                    static_cast<int>(reinterpret_cast<uintptr_t>(section_handle->file_handle)),
                    0
                );

                if (mapped == MAP_FAILED) {
                    error("Failed to map section in child");
                    exit(1);
                }
            }

            // Create IPC client
            IPCManager child_ipc(false);

            // Get parent socket path from environment
            const char* parent_socket = getenv("PARENT_IPC_SOCKET");
            if (!parent_socket) {
                error("No parent IPC socket specified");
                exit(1);
            }

            // Connect to parent
            if (!child_ipc.connect_to_server(parent_socket)) {
                error("Failed to connect to parent IPC");
                exit(1);
            }

            trace("Child connected to parent IPC: ", parent_socket);

            // Now listen for commands from the parent
            child_ipc.child_listen_loop();
        }

        // Parent process
        auto proc_handle = reinterpret_cast<HANDLE>(static_cast<uintptr_t>(child_pid));
        ProcessContext* new_process = &g_processes[proc_handle];

        new_process->native_process_id = child_pid;
        new_process->process_id = static_cast<DWORD>(child_pid);
        new_process->windows_process_handle = proc_handle;
        new_process->creation_time = get_system_time_as_file_time();
        new_process->linux_child_pid = child_pid;
        new_process->parent_process = g_tls.process;

        // Create main thread for this process
        new_process->main_thread = std::make_unique<ProcessMainThread>(new_process);
        new_process->ipc_socket_path = new_process->main_thread->get_socket_path();

        // Set environment variable for child to connect
        std::string socket_env = "PARENT_IPC_SOCKET=" + new_process->ipc_socket_path;
        putenv(const_cast<char*>(socket_env.c_str()));

        // Wait for child to stop
        int status;
        if (waitpid(child_pid, &status, WUNTRACED) == -1) {
            error("waitpid failed");
            kill(child_pid, SIGKILL);
            g_processes.erase(proc_handle);
            return nullptr;
        }

        // Set up monitoring
        setup_process_monitoring(child_pid);

        // Fill in process information if requested
        if (lpProcessInformation) {
            lpProcessInformation->hProcess = proc_handle;
            lpProcessInformation->dwProcessId = child_pid;
            lpProcessInformation->hThread = nullptr;
            lpProcessInformation->dwThreadId = 0;
        }

        trace("Created monitored process: PID=", child_pid, ", IPC socket=", converter.from_bytes(new_process->ipc_socket_path));
        return new_process;
    }

    // Helper method to send IPC message to child process
    NTSTATUS send_to_child(pid_t child_pid, const Message& msg) {
        auto it = g_processes.find(reinterpret_cast<HANDLE>(static_cast<uintptr_t>(child_pid)));
        if (it == g_processes.end()) {
            return STATUS_INVALID_HANDLE;
        }

        ProcessContext* proc_ctx = &it->second;
        if (!proc_ctx->main_thread) {
            return STATUS_INVALID_HANDLE;
        }

        // Get client socket for this child
        std::shared_lock lock(proc_ctx->main_thread->ipc->ipc_mutex);
        auto socket_it = proc_ctx->main_thread->ipc->client_sockets.find(child_pid);
        if (socket_it == proc_ctx->main_thread->ipc->client_sockets.end()) {
            return STATUS_PIPE_DISCONNECTED;
        }

        int client_fd = socket_it->second;
        lock.unlock();

        if (!proc_ctx->main_thread->ipc->send_message(msg, client_fd)) {
            return STATUS_UNSUCCESSFUL;
        }

        // Wait for response
        auto response = proc_ctx->main_thread->ipc->receive_message(client_fd, 5000);
        if (!response) {
            return STATUS_TIMEOUT;
        }

        return response->status;
    }

private:
    static void setup_child_process_environment(
        const std::u16string& app_name,
        const std::u16string& cmd_line,
        const std::u16string& work_dir,
        DWORD creation_flags,
        LPVOID environment) {

        // Change working directory
        if (!work_dir.empty() && work_dir != u".") {
            const std::string work_dir_str = converter16.to_bytes(work_dir);
            if (chdir(work_dir_str.c_str()) != 0) {
                warn("Failed to change working directory to ", work_dir, ": ", strerror(errno));
            }
        }

        // Set up environment if provided
        if (environment) {
            // Parse Windows environment block and set environment variables
            auto* env_block = static_cast<WCHAR*>(environment);
            WCHAR* current = env_block;

            while (*current) {
                std::wstring env_var;
                while (*current) {
                    env_var += *current++;
                }
                current++; // Skip null terminator

                if (!env_var.empty()) {
                    std::string env_str = converter.to_bytes(env_var);
                    size_t eq_pos = env_str.find('=');
                    if (eq_pos != std::string::npos) {
                        std::string name = env_str.substr(0, eq_pos);
                        std::string value = env_str.substr(eq_pos + 1);
                        setenv(name.c_str(), value.c_str(), 1);
                    }
                }
            }
        }

        // Handle creation flags
        if (creation_flags & CREATE_NEW_CONSOLE) {
            // Create new session
            setsid();
        }

        if (creation_flags & DETACHED_PROCESS) {
            // Detach from controlling terminal
            if (daemon(1, 1) == -1) {
                warn("Failed to detach process: ", strerror(errno));
            }
        }
    }

    static void setup_process_monitoring(pid_t child_pid) {
        pid_t monitor_pid = fork();
        if (monitor_pid == -1) {
            warn("Failed to create process monitor: ", strerror(errno));
            return;
        }

        if (monitor_pid == 0) {
            // Monitor process
            trace("Starting process monitor for PID ", child_pid);

            // Wait for child to stop (from SIGSTOP after TRACEME)
            int status;
            if (waitpid(child_pid, &status, WUNTRACED) != -1) {
                if (WIFSTOPPED(status)) {
                    // Set tracing options
                    ptrace(PTRACE_SETOPTIONS, child_pid, 0,
                           PTRACE_O_TRACESYSGOOD |
                           PTRACE_O_TRACECLONE |
                           PTRACE_O_TRACEFORK |
                           PTRACE_O_TRACEVFORK |
                           PTRACE_O_TRACEEXEC);

                    // Start monitoring
                    SystemCallManager process_monitor(true);
                    std::wstring context = L"Process-" + std::to_wstring(child_pid);
                    process_monitor.trace_child_execution(child_pid, context);
                }
            }

            exit(0);
        } else {

        }
    }

public:
    void terminate_monitored_process(pid_t child_pid, DWORD exit_code) {
        std::shared_lock lock(process_mutex);

        if (!g_processes.contains(reinterpret_cast<HANDLE>(static_cast<DWORD>(child_pid)))) {
            trace("No monitored process found with PID ", child_pid);
            return;
        }

        auto &proc = g_processes[reinterpret_cast<HANDLE>(static_cast<DWORD>(child_pid))];

        ProcessContext* process_ctx = &proc;
        process_ctx->is_terminated = true;
        process_ctx->exit_code = exit_code;

        // Cleanup monitor process
        const auto monitor_pid = static_cast<pid_t>(process_ctx->creation_time);
        if (monitor_pid > 0) {
            kill(monitor_pid, SIGTERM);
            waitpid(monitor_pid, nullptr, WNOHANG);
        }

        // Terminate the actual process
        kill(child_pid, SIGTERM);

        // Wait for termination with timeout
        constexpr auto timeout = std::chrono::seconds(5);
        auto end_time = std::chrono::steady_clock::now() + timeout;

        int status;
        while (std::chrono::steady_clock::now() < end_time) {
            if (waitpid(child_pid, &status, WNOHANG) == child_pid) {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        // Force kill if still running
        if (kill(child_pid, 0) == 0) {
            kill(child_pid, SIGKILL);
            waitpid(child_pid, &status, 0);
        }

        g_processes.erase(reinterpret_cast<HANDLE>(static_cast<DWORD>(child_pid)));
    }

    ProcessContext* get_process(pid_t child_pid) {
        std::shared_lock lock(process_mutex);
        return g_processes.contains(reinterpret_cast<HANDLE>(static_cast<DWORD>(child_pid))) ?
               &g_processes[reinterpret_cast<HANDLE>(static_cast<DWORD>(child_pid))] : nullptr;
    }

    std::vector<pid_t> get_all_child_processes() {
        std::shared_lock lock(process_mutex);
        std::vector<pid_t> processes;
        for (const auto &pid: g_processes | std::views::keys) {
            processes.push_back(static_cast<pid_t>(reinterpret_cast<uintptr_t>(pid)));
        }
        return processes;
    }
};

static std::shared_ptr<EnhancedThreadManager> g_thread_manager;
static std::shared_ptr<EnhancedProcessManager> g_process_manager;

static void initialize_enhanced_managers() {
    ProcessContext &current_process = g_processes[g_tls.process];

    g_thread_manager = std::make_shared<EnhancedThreadManager>(&current_process);
    g_process_manager = std::make_shared<EnhancedProcessManager>();
}

// ============================================================================
// COMPLETE IMPORT RESOLUTION WITH FORWARDING
// ============================================================================

// In ProcessMainThread class - Update constructor and run method
ProcessMainThread::ProcessMainThread(ProcessContext *ctx): process_ctx(ctx), memory_mgr(nullptr) {
    ipc = std::make_unique<IPCManager>(true); // Server mode

    if (ctx->linux_child_pid > 0) {
        memory_mgr = new ChildMemoryManager(ctx->linux_child_pid);
    }

    // Start the main thread immediately
    main_thread = std::thread(&ProcessMainThread::run, this);
}

void ProcessMainThread::run() {
    trace("Process main thread started for PID ", process_ctx->process_id);

    while (running) {
        // Set socket to non-blocking for accept
        int flags = fcntl(ipc->sockfd, F_GETFL, 0);
        fcntl(ipc->sockfd, F_SETFL, flags | O_NONBLOCK);

        int client_fd = ipc->accept_client();
        if (client_fd < 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }

        // Store client connection
        std::unique_lock lock(ipc->ipc_mutex);
        ipc->client_sockets[getpid()] = client_fd;
        lock.unlock();

        // Handle client in separate thread
        std::thread([this, client_fd]() {
            handle_client(client_fd);
        }).detach();
    }

    trace("Process main thread stopped");
}


// ============================================================================
// CHILD MEMORY MANAGER
// ============================================================================

// Forward declarations
class DeviceHandle;
class Event;
class CompletionPort;

// Constants
#define KUSER_SHARED_DATA_ADDRESS 0x7FFE0000
#define KUSER_SHARED_DATA_SIZE 0x1000
#define PROCESSOR_FEATURE_MAX 64
#define SD_RECEIVE 0x00
#define SD_SEND 0x01
#define SD_BOTH 0x02

#define FLUSH_FLAGS_FILE_DATA_ONLY 0x00000001

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
    BOOLEAN ProcessorFeatures[PROCESSOR_FEATURE_MAX];
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

// Global variables
static KUSER_SHARED_DATA* g_kuser_shared_data = nullptr;
static std::atomic<int> g_shm_counter{0};
static std::shared_mutex g_kuser_update_mutex;
static std::thread g_kuser_update_thread;
static std::atomic<bool> g_shutdown_requested{false};

// Global state
static std::atomic<HANDLE> g_next_handle{reinterpret_cast<HANDLE>(0x1000)};
static std::shared_mutex g_global_mutex;

// Shared Memory Manager
class SharedMemoryManager {
public:
    static void* allocate_shared_executable_memory(size_t size, const std::string& name_suffix = "") {
        std::string shm_name = "/pe_loader_" + std::to_string(getpid()) + "_" +
                              std::to_string(g_shm_counter++) + name_suffix;

        int shm_fd = shm_open(shm_name.c_str(), O_CREAT | O_RDWR | O_EXCL, 0600);
        if (shm_fd == -1) {
            return nullptr;
        }

        if (ftruncate(shm_fd, static_cast<off_t>(size)) == -1) {
            close(shm_fd);
            shm_unlink(shm_name.c_str());
            return nullptr;
        }

        void* addr = mmap(nullptr, size, PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_SHARED, shm_fd, 0);

        close(shm_fd);
        shm_unlink(shm_name.c_str());

        return (addr == MAP_FAILED) ? nullptr : addr;
    }

    static void* allocate_shared_executable_memory_at(size_t size, uintptr_t preferred_addr) {
        std::string shm_name = "/pe_loader_" + std::to_string(getpid()) + "_" +
                              std::to_string(g_shm_counter++);

        int shm_fd = shm_open(shm_name.c_str(), O_CREAT | O_RDWR | O_EXCL, 0600);
        if (shm_fd == -1) {
            return nullptr;
        }

        if (ftruncate(shm_fd, static_cast<off_t>(size)) == -1) {
            close(shm_fd);
            shm_unlink(shm_name.c_str());
            return nullptr;
        }

        void* addr = mmap(reinterpret_cast<void*>(preferred_addr), size,
                         PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_SHARED | MAP_FIXED_NOREPLACE, shm_fd, 0);

        if (addr == MAP_FAILED) {
            addr = mmap(nullptr, size, PROT_READ | PROT_WRITE | PROT_EXEC,
                       MAP_SHARED, shm_fd, 0);
        }

        close(shm_fd);
        shm_unlink(shm_name.c_str());

        return (addr == MAP_FAILED) ? nullptr : addr;
    }
};
// Helper Functions Implementation

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
    const WCHAR system_root[] = { 'L', 'C', ':', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\0' };
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
    g_current_peb->ProcessHeaps = reinterpret_cast<PVOID*>(process_info.heaps);
    g_current_peb->ProcessHeap = process_info.default_heap;

    g_current_peb->LdrData = new PEB_LDR_DATA();
    memset(g_current_peb->LdrData, 0, sizeof(PEB_LDR_DATA));
    g_current_peb->LdrData->EntryInProgress = process_info.process_hmodule;
    g_current_peb->LdrData->Initialized = /* Whether the loader is initialized */ TRUE;
    g_current_peb->LdrData->InInitializationOrderModuleList.Flink = &process_info.in_init_order_module_list;
    g_current_peb->LdrData->InInitializationOrderModuleList.Blink = &process_info.in_init_order_module_list;
    g_current_peb->LdrData->InLoadOrderModuleList.Flink = &process_info.in_load_order_module_list;
    g_current_peb->LdrData->InLoadOrderModuleList.Blink = &process_info.in_load_order_module_list;
    g_current_peb->LdrData->InMemoryOrderModuleList.Flink = &process_info.in_memory_order_module_list;
    g_current_peb->LdrData->InMemoryOrderModuleList.Blink = &process_info.in_memory_order_module_list;
    g_current_peb->LdrData->Length = sizeof(PEB_LDR_DATA);
    g_current_peb->LdrData->ShutdownInProgress = FALSE;
    g_current_peb->LdrData->ShutdownThreadId = nullptr;

    g_current_peb->FastPebLock = new RTL_CRITICAL_SECTION();
    memset(g_current_peb->FastPebLock, 0, sizeof(RTL_CRITICAL_SECTION));

    g_current_peb->SessionId = 1;

    g_current_peb->ProcessParameters = new RTL_USER_PROCESS_PARAMETERS();
    memset(g_current_peb->ProcessParameters, 0, sizeof(RTL_USER_PROCESS_PARAMETERS));
    g_current_peb->ProcessParameters->Environment = process_info.environment_block;

    g_current_peb->ProcessParameters->CurrentDirectory.DosPath.Buffer = new WCHAR[4];
    g_current_peb->ProcessParameters->CurrentDirectory.DosPath.MaximumLength = 8;
    const WCHAR cwd[] = { 'C', ':', '\\', '\0' };
    memcpy(g_current_peb->ProcessParameters->CurrentDirectory.DosPath.Buffer, cwd, sizeof(cwd));
    g_current_peb->ProcessParameters->CurrentDirectory.DosPath.Length = 6;

    // Create current directory handle
    int cwd_fd = open(".", O_RDONLY | O_DIRECTORY);
    if (cwd_fd >= 0) {
        auto cwd_handle = std::make_shared<DeviceHandle>(cwd_fd, FILE_DEVICE_FILE_SYSTEM, ".", 0, 0,
                                                        GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE);
        g_current_peb->ProcessParameters->CurrentDirectory.Handle = reinterpret_cast<HANDLE>(cwd_handle.get());
        process_info.device_handles[g_current_peb->ProcessParameters->CurrentDirectory.Handle] = std::move(cwd_handle);
    }
    g_current_peb->ImageBaseAddress = process_info.process_hmodule;

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
    g_current_teb->ClientId.UniqueProcess = reinterpret_cast<HANDLE>(g_processes[g_tls.process].process_id);
    g_current_teb->ClientId.UniqueThread = g_tls.thread;
    g_current_teb->EnvironmentPointer = g_processes[g_tls.process].environment_block;
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

static DeviceHandle* get_device_handle(HANDLE process, HANDLE handle) {
    std::shared_lock lock(g_processes[process].process_mutex);
    auto it = g_processes[process].device_handles.find(handle);
    return (it != g_processes[process].device_handles.end()) ? it->second.get() : nullptr;
}

static HANDLE create_network_socket(HANDLE process, int domain, int type, int protocol,
                                   ULONG options, ULONG disposition, ULONG access,
                                   ULONG share_mode, ULONG file_attributes) {
    int flags = 0;
    if (options & FILE_FLAG_OVERLAPPED) {
        flags |= SOCK_NONBLOCK;
    }

    int sock_fd = socket(domain, type | flags, protocol);
    if (sock_fd < 0) {
        return nullptr;
    }

    auto device = std::make_shared<DeviceHandle>(sock_fd, FILE_DEVICE_NETWORK, "socket",
                                                options, disposition, access, share_mode, file_attributes);

    if (device->socket_context) {
        device->socket_context->family = domain;
        device->socket_context->socket_type = type;
        device->socket_context->protocol = protocol;
        device->socket_context->is_nonblocking = (flags & SOCK_NONBLOCK) != 0;
    }

    const auto handle = reinterpret_cast<HANDLE>(device.get());
    std::shared_lock lock(g_processes[process].process_mutex);
    g_processes[process].device_handles[handle] = std::move(device);
    return handle;
}

static void close_device_handle(HANDLE process, HANDLE handle) {
    std::shared_lock lock(g_processes[process].process_mutex);
    g_processes[process].device_handles.erase(handle);
}

static NTSTATUS parse_object_attributes(POBJECT_ATTRIBUTES object_attributes, std::string& path) {
    if (!object_attributes || !object_attributes->ObjectName) {
        return STATUS_INVALID_PARAMETER;
    }

    PUNICODE_STRING unicode_str = object_attributes->ObjectName;
    if (unicode_str->Length == 0 || !unicode_str->Buffer) {
        return STATUS_INVALID_PARAMETER;
    }

    // Convert UNICODE_STRING to std::string
    path.clear();
    path.reserve(unicode_str->Length / sizeof(WCHAR));
    for (USHORT i = 0; i < static_cast<USHORT>(unicode_str->Length / sizeof(WCHAR)); i++) {
        path += static_cast<char>(unicode_str->Buffer[i] & 0xFF);
    }

    return STATUS_SUCCESS;
}

static NTSTATUS network_device_io_control(
    ChildMemoryManager& memory_mgr,
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG IoControlCode,
    PVOID InputBuffer,
    ULONG InputBufferLength,
    PVOID OutputBuffer,
    ULONG OutputBufferLength) {

    trace("network_device_io_control called with code 0x", std::hex, IoControlCode);

    DeviceHandle* device = get_device_handle(g_tls.process, FileHandle);
    if (!device || device->device_type != FILE_DEVICE_NETWORK) {
        return STATUS_INVALID_HANDLE;
    }

    NTSTATUS status = STATUS_SUCCESS;
    ULONG bytes_transferred = 0;

    WSK_SOCKET_CONTEXT* sock_context = device->socket_context.get();
    if (!sock_context) {
        device->socket_context = std::make_shared<WSK_SOCKET_CONTEXT>();
        sock_context = device->socket_context.get();
    }

    switch (IoControlCode) {
        case IOCTL_AFD_WINE_CREATE: {
            if (InputBufferLength < sizeof(w32::afd_create_params)) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            // Read parameters from child memory
            auto input_ptr = reinterpret_cast<uintptr_t>(InputBuffer);
            auto params = memory_mgr.read<w32::afd_create_params>(input_ptr);
            if (!params) {
                status = STATUS_ACCESS_VIOLATION;
                break;
            }

            int new_fd = socket(params->family, params->type, params->protocol);
            if (new_fd < 0) {
                status = errno_to_ntstatus(errno);
                break;
            }

            close(device->linux_fd);
            device->linux_fd = new_fd;
            sock_context->family = params->family;
            sock_context->socket_type = params->type;
            sock_context->protocol = params->protocol;

            if (device->options & FILE_FLAG_OVERLAPPED) {
                int flags = fcntl(new_fd, F_GETFL, 0);
                fcntl(new_fd, F_SETFL, flags | O_NONBLOCK);
                sock_context->is_nonblocking = true;
            }

            bytes_transferred = sizeof(w32::afd_create_params);
            break;
        }

        case IOCTL_AFD_WINE_ACCEPT: {
            if (OutputBufferLength < sizeof(SOCKET_ADDRESS)) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            socklen_t addr_len = sizeof(sockaddr_storage);
            sockaddr_storage client_addr{};

            int client_fd = accept(device->linux_fd,
                                 reinterpret_cast<sockaddr*>(&client_addr), &addr_len);
            if (client_fd < 0) {
                status = errno_to_ntstatus(errno);
                break;
            }

            // Create new device handle for accepted socket
            auto client_device = std::make_shared<DeviceHandle>(
                client_fd, FILE_DEVICE_NETWORK, "accepted_socket", device->options);
            client_device->socket_context = std::make_shared<WSK_SOCKET_CONTEXT>(*sock_context);
            client_device->socket_context->is_connected = true;

            auto client_handle = reinterpret_cast<HANDLE>(client_device.get());

            std::shared_lock lock(g_processes[g_tls.process].process_mutex);
            g_processes[g_tls.process].device_handles[client_handle] = std::move(client_device);
            lock.unlock();

            // Write address
            auto* out_addr = static_cast<SOCKET_ADDRESS*>(OutputBuffer);
            memcpy(out_addr->lpSockaddr, &client_addr, addr_len);
            out_addr->iSockaddrLength = static_cast<INT>(addr_len);
            bytes_transferred = sizeof(SOCKET_ADDRESS);
            bytes_transferred += sizeof(HANDLE);
            break;
        }

        case IOCTL_AFD_BIND: {
            if (InputBufferLength < sizeof(w32::afd_bind_params)) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            if (sock_context->is_bound) {
                status = STATUS_ADDRESS_ALREADY_ASSOCIATED;
                break;
            }

            auto* params = static_cast<w32::afd_bind_params*>(InputBuffer);
            sockaddr_storage bind_addr{};
            socklen_t addr_len;

            if (params->addr.sa_family == AF_INET) {
                addr_len = sizeof(sockaddr_in);
                memcpy(&bind_addr, &params->addr, sizeof(sockaddr_in));
            } else if (params->addr.sa_family == AF_INET6) {
                addr_len = sizeof(sockaddr_in6);
                memcpy(&bind_addr, &params->addr, sizeof(sockaddr_in6));

                // Disable IPV6_V6ONLY for dual-stack
                int v6only = 0;
                setsockopt(device->linux_fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));
            } else {
                status = STATUS_INVALID_PARAMETER;
                break;
            }

            if (bind(device->linux_fd, reinterpret_cast<sockaddr*>(&bind_addr), addr_len) < 0) {
                status = errno_to_ntstatus(errno);
                break;
            }

            sock_context->is_bound = true;

            // Return the actual bound address if requested
            if (OutputBuffer && OutputBufferLength >= sizeof(SOCKET_ADDRESS)) {
                auto* out_addr = static_cast<SOCKET_ADDRESS*>(OutputBuffer);
                socklen_t actual_len = sizeof(sockaddr_storage);

                if (getsockname(device->linux_fd,
                              reinterpret_cast<sockaddr*>(out_addr->lpSockaddr), &actual_len) == 0) {
                    out_addr->iSockaddrLength = static_cast<INT>(actual_len);
                    bytes_transferred = sizeof(SOCKET_ADDRESS);
                }
            }
            break;
        }

        case IOCTL_AFD_LISTEN: {
            if (InputBufferLength < sizeof(w32::afd_listen_params)) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            auto* params = static_cast<w32::afd_listen_params*>(InputBuffer);
            int backlog = params->backlog ? params->backlog : SOMAXCONN;

            if (listen(device->linux_fd, backlog) < 0) {
                status = errno_to_ntstatus(errno);
                break;
            }

            sock_context->is_listening = true;
            break;
        }

        case IOCTL_AFD_WINE_CONNECT: {
            if (InputBufferLength < sizeof(SOCKET_ADDRESS)) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            auto* addr = static_cast<SOCKET_ADDRESS*>(InputBuffer);
            if (connect(device->linux_fd, reinterpret_cast<sockaddr *>(addr->lpSockaddr), addr->iSockaddrLength) < 0) {
                if (errno == EINPROGRESS && sock_context->is_nonblocking) {
                    status = STATUS_PENDING;
                } else {
                    status = errno_to_ntstatus(errno);
                }
                break;
            }

            sock_context->is_connected = true;
            bytes_transferred = sizeof(SOCKET_ADDRESS);
            break;
        }

        case IOCTL_AFD_WINE_SHUTDOWN: {
            if (InputBufferLength < sizeof(UINT)) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            UINT how = *static_cast<UINT*>(InputBuffer);
            if (how > SD_BOTH) {
                status = STATUS_INVALID_PARAMETER;
                break;
            }

            if (!sock_context->is_connected) {
                status = STATUS_INVALID_PARAMETER;
                break;
            }

            int linux_how = (how == SD_RECEIVE) ? SHUT_RD :
                           (how == SD_SEND) ? SHUT_WR : SHUT_RDWR;

            if (shutdown(device->linux_fd, linux_how) < 0) {
                status = errno_to_ntstatus(errno);
                break;
            }

            bytes_transferred = sizeof(UINT);
            break;
        }

        case IOCTL_AFD_WINE_FIONBIO: {
            if (InputBufferLength < sizeof(UINT)) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            UINT nonblocking = *static_cast<UINT*>(InputBuffer);
            int flags = fcntl(device->linux_fd, F_GETFL, 0);

            if (nonblocking) {
                fcntl(device->linux_fd, F_SETFL, flags | O_NONBLOCK);
                sock_context->is_nonblocking = true;
            } else {
                fcntl(device->linux_fd, F_SETFL, flags & ~O_NONBLOCK);
                sock_context->is_nonblocking = false;
            }

            bytes_transferred = sizeof(UINT);
            break;
        }

        case IOCTL_AFD_EVENT_SELECT: {
            if (InputBufferLength < sizeof(w32::afd_event_select_params)) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            auto* params = static_cast<w32::afd_event_select_params*>(InputBuffer);

            // Find the event in our process events
            std::shared_lock lock(g_processes[g_tls.process].process_mutex);
            auto event_it = g_processes[g_tls.process].events.find(params->event);

            sock_context->event = (event_it != g_processes[g_tls.process].events.end()) ?
                                  event_it->second.get() : nullptr;
            sock_context->event_mask = params->mask;
            sock_context->window = nullptr;
            sock_context->message = 0;
            sock_context->is_nonblocking = true;

            // Signal immediately if there are pending events
            if (sock_context->event && (sock_context->pending_events & params->mask)) {
                sock_context->event->set();
            }

            bytes_transferred = sizeof(w32::afd_event_select_params);
            break;
        }

        case IOCTL_AFD_GETSOCKNAME: {
            if (OutputBufferLength < sizeof(SOCKET_ADDRESS)) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            auto* out_addr = static_cast<SOCKET_ADDRESS*>(OutputBuffer);
            socklen_t addr_len = sizeof(sockaddr_storage);

            if (getsockname(device->linux_fd, reinterpret_cast<sockaddr *>(out_addr->lpSockaddr), &addr_len) < 0) {
                status = errno_to_ntstatus(errno);
                break;
            }

            out_addr->iSockaddrLength = static_cast<INT>(addr_len);
            bytes_transferred = sizeof(SOCKET_ADDRESS);
            break;
        }

        case IOCTL_AFD_WINE_GETPEERNAME: {
            if (OutputBufferLength < sizeof(SOCKET_ADDRESS)) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            auto* out_addr = static_cast<SOCKET_ADDRESS*>(OutputBuffer);
            socklen_t addr_len = sizeof(sockaddr_storage);

            if (getpeername(device->linux_fd, reinterpret_cast<sockaddr *>(out_addr->lpSockaddr), &addr_len) < 0) {
                status = errno_to_ntstatus(errno);
                break;
            }

            out_addr->iSockaddrLength = static_cast<INT>(addr_len);
            bytes_transferred = sizeof(SOCKET_ADDRESS);
            break;
        }

        case IOCTL_AFD_POLL: {
            if (InputBufferLength < sizeof(w32::afd_poll_params_64)) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            auto* params = static_cast<w32::afd_poll_params_64*>(InputBuffer);
            if (params->count == 0 ||
                OutputBufferLength < params->count * sizeof(w32::afd_poll_info)) {
                status = STATUS_INVALID_PARAMETER;
                break;
            }

            std::vector<pollfd> pollfds;
            std::vector<HANDLE> handles;
            auto* output_info = static_cast<poll_req*>(OutputBuffer);

            // Setup poll structures
            for (ULONG i = 0; i < params->count; i++) {
                auto socket_handle = reinterpret_cast<HANDLE>(params->sockets[i].socket);
                DeviceHandle* socket_dev = get_device_handle(g_tls.process, socket_handle);

                output_info[i].socket = params->sockets[i].socket;
                output_info[i].flags = 0;
                output_info[i].status = STATUS_SUCCESS;

                if (!socket_dev || socket_dev->device_type != FILE_DEVICE_NETWORK) {
                    output_info[i].status = STATUS_INVALID_HANDLE;
                    continue;
                }

                pollfd pfd = {};
                pfd.fd = socket_dev->linux_fd;
                pfd.events = 0;

                ULONG afd_flags = params->sockets[i].flags;
                if (afd_flags & (AFD_POLL_READ | AFD_POLL_ACCEPT)) {
                    pfd.events |= POLLIN;
                }
                if (afd_flags & AFD_POLL_WRITE) {
                    pfd.events |= POLLOUT;
                }
                if (afd_flags & AFD_POLL_OOB) {
                    pfd.events |= POLLPRI;
                }
                if (afd_flags & (AFD_POLL_CLOSE | AFD_POLL_HUP)) {
                    pfd.events |= POLLHUP;
                }
                if (afd_flags & AFD_POLL_CONNECT_ERR) {
                    pfd.events |= POLLERR;
                }

                pollfds.push_back(pfd);
                handles.push_back(socket_handle);
            }

            if (!pollfds.empty()) {
                // Convert timeout from 100ns units to milliseconds
                int timeout_ms = -1;
                if (params->timeout > 0) {
                    timeout_ms = static_cast<int>(params->timeout / 10000);
                    if (timeout_ms == 0 && params->timeout > 0) {
                        timeout_ms = 1;
                    }
                } else if (params->timeout == 0) {
                    timeout_ms = 0;
                }

                int poll_result = poll(pollfds.data(), pollfds.size(), timeout_ms);

                if (poll_result < 0) {
                    status = errno_to_ntstatus(errno);
                } else if (poll_result == 0) {
                    status = STATUS_TIMEOUT;
                } else {
                    // Process results
                    for (size_t i = 0; i < pollfds.size(); i++) {
                        const pollfd& pfd = pollfds[i];
                        ULONG result_flags = 0;

                        if (pfd.revents & POLLIN) {
                            DeviceHandle* socket_dev = get_device_handle(g_tls.process, handles[i]);
                            if (socket_dev && socket_dev->socket_context &&
                                socket_dev->socket_context->is_listening) {
                                result_flags |= AFD_POLL_ACCEPT;
                            } else {
                                result_flags |= AFD_POLL_READ;
                            }
                        }

                        if (pfd.revents & POLLOUT) {
                            result_flags |= AFD_POLL_WRITE;
                        }
                        if (pfd.revents & POLLPRI) {
                            result_flags |= AFD_POLL_OOB;
                        }
                        if (pfd.revents & POLLHUP) {
                            result_flags |= AFD_POLL_HUP;
                        }
                        if (pfd.revents & POLLERR) {
                            result_flags |= AFD_POLL_CONNECT_ERR;
                        }
                        if (pfd.revents & POLLNVAL) {
                            output_info[i].status = STATUS_INVALID_HANDLE;
                        }

                        output_info[i].flags = result_flags;
                    }
                }
            }

            bytes_transferred = params->count * sizeof(w32::afd_poll_info);
            break;
        }

        default:
            status = STATUS_NOT_SUPPORTED;
            break;
    }

    // Complete the I/O operation
    if (IoStatusBlock) {
        IoStatusBlock->Status = status;
        IoStatusBlock->Information = bytes_transferred;
    }

    if (NT_SUCCESS(status)) {
        if (Event) {
            static_cast<void>(_NtSetEvent(memory_mgr, Event, nullptr));
        }
        if (ApcRoutine) {
            static_cast<void>(_NtQueueApcThread(memory_mgr,
                reinterpret_cast<HANDLE>(-2),
                ApcRoutine,
                ApcContext,
                IoStatusBlock,
                nullptr));
        }
    }

    return status;
}

static NTSTATUS storage_device_io_control(
    ChildMemoryManager& memory_mgr,
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG IoControlCode,
    PVOID InputBuffer,
    ULONG InputBufferLength,
    PVOID OutputBuffer,
    ULONG OutputBufferLength) {

    trace("storage_device_io_control called with code 0x", std::hex, IoControlCode);

    DeviceHandle* device = get_device_handle(g_tls.process, FileHandle);
    if (!device) {
        return STATUS_INVALID_HANDLE;
    }

    NTSTATUS status = STATUS_SUCCESS;
    ULONG bytes_transferred = 0;

    switch (IoControlCode) {
        case IOCTL_CDROM_CHECK_VERIFY:
        case IOCTL_DISK_CHECK_VERIFY:
        case IOCTL_STORAGE_CHECK_VERIFY:
        case IOCTL_STORAGE_CHECK_VERIFY2: {
            // Check if media is present
            int ret = ioctl(device->linux_fd, CDROM_DRIVE_STATUS, CDSL_CURRENT);
            if (ret == CDS_NO_DISC) {
                status = STATUS_NO_MEDIA_IN_DEVICE;
            } else if (ret == CDS_TRAY_OPEN) {
                status = STATUS_DEVICE_NOT_READY;
            } else if (ret < 0) {
                status = errno_to_ntstatus(errno);
            }
            break;
        }

        case IOCTL_STORAGE_LOAD_MEDIA:
        case IOCTL_CDROM_LOAD_MEDIA: {
            int ret = ioctl(device->linux_fd, CDROM_LOCKDOOR, 0);
            if (ret < 0) {
                status = errno_to_ntstatus(errno);
            }
            break;
        }

        case IOCTL_STORAGE_EJECT_MEDIA: {
            int ret = ioctl(device->linux_fd, CDROM_LOCKDOOR, 1);
            if (ret < 0) {
                status = errno_to_ntstatus(errno);
            } else {
                ret = ioctl(device->linux_fd, CDROMEJECT);
                if (ret < 0) {
                    status = errno_to_ntstatus(errno);
                }
            }
            break;
        }

        case IOCTL_CDROM_MEDIA_REMOVAL:
        case IOCTL_DISK_MEDIA_REMOVAL:
        case IOCTL_STORAGE_MEDIA_REMOVAL: {
            if (InputBufferLength < sizeof(BOOLEAN)) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            BOOLEAN prevent = *static_cast<BOOLEAN*>(InputBuffer);
            int ret = ioctl(device->linux_fd, CDROM_LOCKDOOR, prevent ? 1 : 0);
            if (ret < 0) {
                status = errno_to_ntstatus(errno);
            }
            bytes_transferred = sizeof(BOOLEAN);
            break;
        }

        case IOCTL_STORAGE_GET_DEVICE_NUMBER: {
            if (OutputBufferLength < sizeof(STORAGE_DEVICE_NUMBER)) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            auto* dev_num = static_cast<STORAGE_DEVICE_NUMBER*>(OutputBuffer);
            dev_num->DeviceType = device->device_type;
            dev_num->DeviceNumber = 0;  // Simplified
            dev_num->PartitionNumber = 0;

            bytes_transferred = sizeof(STORAGE_DEVICE_NUMBER);
            break;
        }

        case IOCTL_DISK_GET_DRIVE_GEOMETRY: {
            if (OutputBufferLength < sizeof(DISK_GEOMETRY)) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            auto* geometry = static_cast<DISK_GEOMETRY*>(OutputBuffer);
            memset(geometry, 0, sizeof(*geometry));

            // Get file size
            off_t size = lseek(device->linux_fd, 0, SEEK_END);
            if (size < 0) {
                status = errno_to_ntstatus(errno);
                break;
            }

            geometry->Cylinders.QuadPart = size / (512 * 255 * 63);
            geometry->MediaType = FixedMedia;
            geometry->TracksPerCylinder = 255;
            geometry->SectorsPerTrack = 63;
            geometry->BytesPerSector = 512;

            bytes_transferred = sizeof(DISK_GEOMETRY);
            break;
        }

        default:
            status = STATUS_NOT_SUPPORTED;
            break;
    }

    // Complete the I/O operation
    if (IoStatusBlock) {
        IoStatusBlock->Status = status;
        IoStatusBlock->Information = bytes_transferred;
    }

    if (NT_SUCCESS(status)) {
        if (Event) {
            static_cast<void>(_NtSetEvent(memory_mgr, Event, nullptr));
        }
        if (ApcRoutine) {
            static_cast<void>(_NtQueueApcThread(memory_mgr,
                reinterpret_cast<HANDLE>(-2),
                           ApcRoutine,
                           ApcContext,
                           IoStatusBlock,
                           0));
        }
    }

    return status;
}

NTSTATUS NTAPI _NtDeviceIoControlFile(
    ChildMemoryManager& memory_mgr,
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG IoControlCode,
    PVOID InputBuffer,
    ULONG InputBufferLength,
    PVOID OutputBuffer,
    ULONG OutputBufferLength) {

    trace("_NtDeviceIoControlFile called with handle ", FileHandle,
          ", code 0x", std::hex, IoControlCode);

    if (FileHandle == reinterpret_cast<HANDLE>(-1)) {
        return STATUS_INVALID_HANDLE;
    }

    ULONG device_type = (IoControlCode >> 16) & 0xFFFF;

    switch (device_type) {
        case FILE_DEVICE_BEEP:
        case FILE_DEVICE_NETWORK:
            return network_device_io_control(memory_mgr, FileHandle, Event, ApcRoutine, ApcContext,
                                            IoStatusBlock, IoControlCode, InputBuffer,
                                            InputBufferLength, OutputBuffer, OutputBufferLength);

        case FILE_DEVICE_DISK:
        case FILE_DEVICE_CD_ROM:
        case FILE_DEVICE_DVD:
        case FILE_DEVICE_CONTROLLER:
        case FILE_DEVICE_MASS_STORAGE:
            return storage_device_io_control(memory_mgr, FileHandle, Event, ApcRoutine, ApcContext,
                                            IoStatusBlock, IoControlCode, InputBuffer,
                                            InputBufferLength, OutputBuffer, OutputBufferLength);

        case FILE_DEVICE_SERIAL_PORT:
        case FILE_DEVICE_TAPE:
            // Not implemented for now
            return STATUS_NOT_SUPPORTED;

        default:
            return STATUS_NOT_SUPPORTED;
    }
}

// NT API Implementation

NTSTATUS NTAPI _NtWorkerFactoryWorkerReady(ChildMemoryManager &, HANDLE WorkerFactoryHandle) {
    trace("_NtWorkerFactoryWorkerReady called with handle ", WorkerFactoryHandle);
    return STATUS_ALERTED;
}

NTSTATUS NTAPI _NtSetEvent(
    ChildMemoryManager& memory_mgr,
    HANDLE EventHandle,
    PLONG PreviousState) {

    trace("_NtSetEvent called with handle ", EventHandle);

    std::shared_lock lock(g_processes[g_tls.process].process_mutex);
    auto it = g_processes[g_tls.process].events.find(EventHandle);
    if (it == g_processes[g_tls.process].events.end()) {
        return STATUS_INVALID_HANDLE;
    }

    LONG previous = it->second->is_set() ? 1 : 0;

    if (PreviousState) {
        if (const auto prev_state_ptr = reinterpret_cast<uintptr_t>(PreviousState); !memory_mgr.write(prev_state_ptr, previous)) {
            return STATUS_ACCESS_VIOLATION;
        }
    }

    it->second->set();
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI _NtResetEvent(
    ChildMemoryManager& memory_mgr,
    HANDLE EventHandle,
    PLONG PreviousState) {

    trace("_NtResetEvent called with handle ", EventHandle);

    std::shared_lock lock(g_processes[g_tls.process].process_mutex);
    auto it = g_processes[g_tls.process].events.find(EventHandle);
    if (it == g_processes[g_tls.process].events.end()) {
        return STATUS_INVALID_HANDLE;
    }

    LONG previous = it->second->is_set() ? 1 : 0;

    if (PreviousState) {
        auto prev_state_ptr = reinterpret_cast<uintptr_t>(PreviousState);
        if (!memory_mgr.write(prev_state_ptr, previous)) {
            return STATUS_ACCESS_VIOLATION;
        }
    }

    it->second.reset();
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI _NtPulseEvent(
    ChildMemoryManager& memory_mgr,
    HANDLE EventHandle,
    PLONG PreviousState) {

    trace("PulseEvent called with handle ", EventHandle);

    std::shared_lock lock(g_processes[g_tls.process].process_mutex);
    auto it = g_processes[g_tls.process].events.find(EventHandle);
    if (it == g_processes[g_tls.process].events.end()) {
        return STATUS_INVALID_HANDLE;
    }

    LONG previous = it->second->is_set() ? 1 : 0;

    if (PreviousState) {
        if (const auto prev_state_ptr = reinterpret_cast<uintptr_t>(PreviousState); !memory_mgr.write(prev_state_ptr, previous)) {
            return STATUS_ACCESS_VIOLATION;
        }
    }

    it->second->pulse();
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI _NtCreateEvent(
    const ChildMemoryManager& memory_mgr,
    PHANDLE EventHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    EVENT_TYPE EventType,
    BOOLEAN InitialState) {

    trace("_NtCreateEvent called");

    if (!EventHandle) {
        return STATUS_INVALID_PARAMETER;
    }

    const bool manual_reset = (EventType == NotificationEvent);
    const auto handle = g_next_handle = reinterpret_cast<HANDLE>(reinterpret_cast<uintptr_t>(g_next_handle.load()) + 1);

    std::shared_lock lock(g_processes[g_tls.process].process_mutex);
    g_processes[g_tls.process].events[handle] = std::make_shared<Event>(manual_reset, InitialState);

    // Write a handle to child memory
    if (const auto handle_ptr = reinterpret_cast<uintptr_t>(EventHandle); !memory_mgr.write(handle_ptr, handle)) {
        g_processes[g_tls.process].events.erase(handle);
        return STATUS_ACCESS_VIOLATION;
    }

    return STATUS_SUCCESS;
}

NTSTATUS NTAPI _NtOpenEvent(
    ChildMemoryManager& memory_mgr,
    PHANDLE EventHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes) {

    trace("_NtOpenEvent called");

    if (!EventHandle || !ObjectAttributes) {
        return STATUS_INVALID_PARAMETER;
    }

    // Read ObjectAttributes from child memory
    const auto obj_attr_ptr = reinterpret_cast<uintptr_t>(ObjectAttributes);
    auto obj_attr = memory_mgr.read<OBJECT_ATTRIBUTES>(obj_attr_ptr);
    if (!obj_attr) {
        return STATUS_ACCESS_VIOLATION;
    }

    std::string path;
    if (const NTSTATUS status = parse_object_attributes(&obj_attr.value(), path); !NT_SUCCESS(status)) {
        return status;
    }

    if (path.empty()) {
        return STATUS_INVALID_PARAMETER;
    }

    // For simplicity, we use the path string's hash as the event handle
    constexpr std::hash<std::string> hasher;
    const auto handle = reinterpret_cast<HANDLE>(hasher(path));
    if (handle == nullptr) {
        return STATUS_INVALID_HANDLE;
    }
    std::shared_lock lock(g_processes[g_tls.process].process_mutex);
    if (!g_processes[g_tls.process].events.contains(handle)) {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }
    // Write a handle to child memory
    if (const auto handle_ptr = reinterpret_cast<uintptr_t>(EventHandle); !memory_mgr.write(handle_ptr, handle)) {
        return STATUS_ACCESS_VIOLATION;
    }
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI _NtCreateSection(
    ChildMemoryManager& memory_mgr,
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection,
    ULONG AllocationAttributes,
    HANDLE FileHandle) {

    trace("_NtCreateSection called");

    if (!SectionHandle) {
        return STATUS_INVALID_PARAMETER;
    }

    // Get file handle if provided
    DeviceHandle* file_device = nullptr;
    if (FileHandle && FileHandle != INVALID_HANDLE_VALUE) {
        file_device = get_device_handle(g_tls.process, FileHandle);
        if (!file_device || !file_device->is_valid()) {
            return STATUS_INVALID_HANDLE;
        }
    }

    // Determine size
    LARGE_INTEGER size = {};
    if (MaximumSize) {
        const auto size_ptr = reinterpret_cast<uintptr_t>(MaximumSize);
        const auto size_opt = memory_mgr.read<LARGE_INTEGER>(size_ptr);
        if (!size_opt) {
            return STATUS_ACCESS_VIOLATION;
        }
        size = *size_opt;
    } else if (file_device) {
        // Get file size
        struct stat st{};
        if (fstat(file_device->linux_fd, &st) != 0) {
            return errno_to_ntstatus(errno);
        }
        size.QuadPart = st.st_size;
    } else {
        return STATUS_INVALID_PARAMETER;
    }

    // Convert protection
    int prot = PROT_NONE;
    if (SectionPageProtection & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) {
        prot |= PROT_READ;
    }
    if (SectionPageProtection & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY)) {
        prot |= PROT_WRITE;
    }
    if (SectionPageProtection & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) {
        prot |= PROT_EXEC;
    }

    // Create section
    auto section = std::make_shared<class SectionHandle>(
        FileHandle,
        SectionPageProtection,
        size,
        nullptr  // Name from ObjectAttributes if needed
    );

    HANDLE handle = HandleManager::allocate_handle();

    std::shared_lock lock(g_processes[g_tls.process].process_mutex);
    g_processes[g_tls.process].sections[handle] = section;

    // Write handle to child memory
    if (const auto handle_ptr = reinterpret_cast<uintptr_t>(SectionHandle); !memory_mgr.write(handle_ptr, handle)) {
        g_processes[g_tls.process].sections.erase(handle);
        return STATUS_ACCESS_VIOLATION;
    }

    trace("Created section: handle=", handle, ", size=", size.QuadPart);
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI _NtMapViewOfSection(
    ChildMemoryManager& memory_mgr,
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    SECTION_INHERIT InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect) {

    trace("_NtMapViewOfSection called");

    if (!BaseAddress || !ViewSize) {
        return STATUS_INVALID_PARAMETER;
    }

    // Get section
    std::shared_lock lock(g_processes[g_tls.process].process_mutex);
    auto it = g_processes[g_tls.process].sections.find(SectionHandle);
    if (it == g_processes[g_tls.process].sections.end()) {
        return STATUS_INVALID_HANDLE;
    }
    auto section = it->second;

    // Read parameters from child memory
    const auto base_ptr = reinterpret_cast<uintptr_t>(BaseAddress);
    const auto base_opt = memory_mgr.read<PVOID>(base_ptr);
    if (!base_opt) {
        return STATUS_ACCESS_VIOLATION;
    }
    PVOID base = *base_opt;

    const auto size_ptr = reinterpret_cast<uintptr_t>(ViewSize);
    auto size_opt = memory_mgr.read<SIZE_T>(size_ptr);
    if (!size_opt) {
        return STATUS_ACCESS_VIOLATION;
    }
    SIZE_T size = *size_opt;

    if (size == 0) {
        size = section->size.QuadPart;
    }

    // Convert protection
    int prot = PROT_NONE;
    if (Win32Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) {
        prot |= PROT_READ;
    }
    if (Win32Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY)) {
        prot |= PROT_WRITE;
    }
    if (Win32Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) {
        prot |= PROT_EXEC;
    }

    // Get offset
    off_t offset = 0;
    if (SectionOffset) {
        uintptr_t offset_ptr = reinterpret_cast<uintptr_t>(SectionOffset);
        auto offset_opt = memory_mgr.read<LARGE_INTEGER>(offset_ptr);
        if (offset_opt) {
            offset = offset_opt->QuadPart;
        }
    }

    // Map the view
    void* addr = nullptr;
    if (section->file_handle && section->file_handle != INVALID_HANDLE_VALUE) {
        // Map file
        DeviceHandle* file = get_device_handle(g_tls.process, section->file_handle);
        if (file && file->is_valid()) {
            int flags = MAP_SHARED;
            if (base) {
                flags |= MAP_FIXED_NOREPLACE;
            }

            addr = mmap(base, size, prot, flags, file->linux_fd, offset);
        }
    } else {
        // Anonymous mapping
        int flags = MAP_SHARED | MAP_ANONYMOUS;
        if (base) {
            flags |= MAP_FIXED_NOREPLACE;
        }
        addr = mmap(base, size, prot, flags, -1, 0);
    }

    if (addr == MAP_FAILED) {
        return errno_to_ntstatus(errno);
    }

    // Update section
    std::unique_lock section_lock(section->section_mutex);
    section->base_address = addr;
    section->view_size = size;

    // Write results back
    if (!memory_mgr.write(base_ptr, addr)) {
        munmap(addr, size);
        return STATUS_ACCESS_VIOLATION;
    }
    if (!memory_mgr.write(size_ptr, size)) {
        munmap(addr, size);
        return STATUS_ACCESS_VIOLATION;
    }

    trace("Mapped view: addr=0x", std::hex, reinterpret_cast<uintptr_t>(addr),
          ", size=", std::dec, size);
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI _NtWaitForSingleObject(
    ChildMemoryManager& memory_mgr,
    HANDLE Handle,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout) {

    trace("_NtWaitForSingleObject called with handle ", Handle);

    DWORD timeout_ms = INFINITE;
    if (Timeout) {
        uintptr_t timeout_ptr = reinterpret_cast<uintptr_t>(Timeout);
        auto timeout_val = memory_mgr.read<LARGE_INTEGER>(timeout_ptr);
        if (!timeout_val) {
            return STATUS_ACCESS_VIOLATION;
        }

        if (timeout_val->QuadPart == 0) {
            timeout_ms = 0;
        } else if (timeout_val->QuadPart > 0) {
            timeout_ms = static_cast<DWORD>(timeout_val->QuadPart / 10000);
        }
    }

    std::shared_lock process_lock(g_processes[g_tls.process].process_mutex);

    // Check if it's an event
    auto event_it = g_processes[g_tls.process].events.find(Handle);
    if (event_it != g_processes[g_tls.process].events.end()) {
        process_lock.unlock();

        if (event_it->second->wait_for(timeout_ms)) {
            return STATUS_SUCCESS;
        } else {
            return STATUS_TIMEOUT;
        }
    }

    // Check if it's a thread
    auto thread_it = g_processes[g_tls.process].threads.find(Handle);
    if (thread_it != g_processes[g_tls.process].threads.end()) {
        process_lock.unlock();

        if (thread_it->second->is_terminated) {
            return STATUS_SUCCESS;
        }

        const int check_interval_ms = 10;
        DWORD elapsed = 0;

        while (!thread_it->second->is_terminated) {
            std::this_thread::sleep_for(std::chrono::milliseconds(check_interval_ms));
            elapsed += check_interval_ms;

            if (timeout_ms != INFINITE && elapsed >= timeout_ms) {
                return STATUS_TIMEOUT;
            }
        }

        return STATUS_SUCCESS;
    }

    return STATUS_INVALID_HANDLE;
}

NTSTATUS NTAPI _NtWaitForMultipleObjects(
    ChildMemoryManager& memory_mgr,
    ULONG Count,
    PHANDLE Handles,
    WAIT_TYPE WaitType,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout) {

    trace("_NtWaitForMultipleObjects called with count ", Count);

    if (!Handles || Count == 0 || Count > MAXIMUM_WAIT_OBJECTS) {
        return STATUS_INVALID_PARAMETER;
    }

    // Read handles array from child memory
    uintptr_t handles_ptr = reinterpret_cast<uintptr_t>(Handles);
    std::vector<HANDLE> handle_array(Count);
    for (ULONG i = 0; i < Count; i++) {
        auto handle = memory_mgr.read<HANDLE>(handles_ptr + i * sizeof(HANDLE));
        if (!handle) {
            return STATUS_ACCESS_VIOLATION;
        }
        handle_array[i] = *handle;
    }

    for (ULONG i = 0; i < Count; i++) {
        if (const NTSTATUS status = _NtWaitForSingleObject(memory_mgr, handle_array[i], Alertable, Timeout); NT_SUCCESS(status)) {
            return WaitType == WaitAny ? i : STATUS_SUCCESS;
        } else if (status != STATUS_TIMEOUT) {
            return status;
        }
    }

    // WaitAllObjects would require more complex logic
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NTAPI _NtQueueApcThread(
    ChildMemoryManager&,
    HANDLE ThreadHandle,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcArgument1,
    PVOID ApcArgument2,
    PVOID ApcArgument3) {

    trace("_NtQueueApcThread called");

    std::shared_lock lock(g_processes[g_tls.process].process_mutex);
    const auto it = g_processes[g_tls.process].threads.find(ThreadHandle);
    if (it == g_processes[g_tls.process].threads.end()) {
        return STATUS_INVALID_HANDLE;
    }

    const ProcessThreadAPC apc{reinterpret_cast<PNTAPCFUNC>(ApcRoutine), reinterpret_cast<ULONG_PTR>(ApcArgument1), reinterpret_cast<ULONG_PTR>(ApcArgument2), reinterpret_cast<ULONG_PTR>(ApcArgument3)};

    std::lock_guard apc_lock(it->second->apc_mutex);
    it->second->apc_queue.push(apc);

    return STATUS_SUCCESS;
}

NTSTATUS NTAPI _NtMapUserPhysicalPagesScatter(
    ChildMemoryManager&,
    PVOID* VirtualAddresses,
    ULONG_PTR NumberOfPages,
    PULONG_PTR UserPfnArray) {

    trace("_NtMapUserPhysicalPagesScatter called (stub)");
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI _NtQuerySystemTime(
    ChildMemoryManager& memory_mgr,
    PLARGE_INTEGER SystemTime) {

    trace("_NtQuerySystemTime called");

    if (!SystemTime) {
        return STATUS_INVALID_PARAMETER;
    }

    LARGE_INTEGER time;
    if (g_kuser_shared_data) {
        ULONGLONG system_time = (static_cast<ULONGLONG>(g_kuser_shared_data->SystemTime.High1Time) << 32) |
                               g_kuser_shared_data->SystemTime.LowPart;
        time.QuadPart = static_cast<LONGLONG>(system_time);
    } else {
        time.QuadPart = static_cast<LONGLONG>(get_system_time_as_file_time());
    }

    // Write time to child memory
    uintptr_t time_ptr = reinterpret_cast<uintptr_t>(SystemTime);
    if (!memory_mgr.write(time_ptr, time)) {
        return STATUS_ACCESS_VIOLATION;
    }

    return STATUS_SUCCESS;
}

NTSTATUS NTAPI _NtQueryPerformanceCounter(
    ChildMemoryManager& memory_mgr,
    PLARGE_INTEGER PerformanceCounter,
    PLARGE_INTEGER PerformanceFrequency) {

    trace("_NtQueryPerformanceCounter called");

    if (!PerformanceCounter) {
        return STATUS_INVALID_PARAMETER;
    }

    timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);

    LARGE_INTEGER counter, frequency;

    if (g_kuser_shared_data && g_kuser_shared_data->QpcFrequency != 0) {
        LONGLONG ticks = (static_cast<LONGLONG>(ts.tv_sec) * g_kuser_shared_data->QpcFrequency) +
                        ((static_cast<LONGLONG>(ts.tv_nsec) * g_kuser_shared_data->QpcFrequency) / 1000000000LL);
        counter.QuadPart = ticks;
        frequency.QuadPart = g_kuser_shared_data->QpcFrequency;
    } else {
        counter.QuadPart = (static_cast<LONGLONG>(ts.tv_sec) * 1000000000LL) + ts.tv_nsec;
        frequency.QuadPart = 1000000000LL;
    }

    // Write counter to child memory
    uintptr_t counter_ptr = reinterpret_cast<uintptr_t>(PerformanceCounter);
    if (!memory_mgr.write(counter_ptr, counter)) {
        return STATUS_ACCESS_VIOLATION;
    }

    // Write frequency to child memory if requested
    if (PerformanceFrequency) {
        uintptr_t freq_ptr = reinterpret_cast<uintptr_t>(PerformanceFrequency);
        if (!memory_mgr.write(freq_ptr, frequency)) {
            return STATUS_ACCESS_VIOLATION;
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS NTAPI _NtQuerySystemInformationEx(
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
                SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX info;
                memset(&info, 0, sizeof(info));

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

                uintptr_t info_ptr = reinterpret_cast<uintptr_t>(SystemInformation);
                if (!memory_mgr.write(info_ptr, info)) {
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

// Memory Management Functions
NTSTATUS NTAPI _NtAllocateVirtualMemory(
    ChildMemoryManager& memory_mgr,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect) {

    trace("_NtAllocateVirtualMemory called");

    if (!BaseAddress || !RegionSize) {
        return STATUS_INVALID_PARAMETER;
    }

    // Read parameters from child memory
    uintptr_t base_addr_ptr = reinterpret_cast<uintptr_t>(BaseAddress);
    auto requested_base = memory_mgr.read<PVOID>(base_addr_ptr);
    if (!requested_base) {
        return STATUS_ACCESS_VIOLATION;
    }

    uintptr_t region_size_ptr = reinterpret_cast<uintptr_t>(RegionSize);
    auto requested_size = memory_mgr.read<SIZE_T>(region_size_ptr);
    if (!requested_size) {
        return STATUS_ACCESS_VIOLATION;
    }

    // Check if this is for a remote process
    if (ProcessHandle && ProcessHandle != reinterpret_cast<HANDLE>(-1) &&
        ProcessHandle != g_tls.process) {

        // Use IPC to allocate in remote process
        auto it = g_processes.find(ProcessHandle);
        if (it == g_processes.end()) {
            return STATUS_INVALID_HANDLE;
        }

        ProcessContext* target_process = &it->second;
        if (!target_process->main_thread || !target_process->main_thread->ipc) {
            return STATUS_PROCESS_IS_TERMINATING;
        }

        // Send allocation request via IPC
        Message msg;
        msg.type = MessageType::AllocVirtualMemoryMsg;
        msg.param1 = reinterpret_cast<uintptr_t>(*requested_base);
        msg.param2 = *requested_size;
        msg.param3 = Protect;
        msg.param4 = AllocationType;

        // Get client socket for target process
        std::shared_lock lock(target_process->main_thread->ipc->ipc_mutex);
        auto socket_it = target_process->main_thread->ipc->client_sockets.find(
            target_process->native_process_id);

        if (socket_it == target_process->main_thread->ipc->client_sockets.end()) {
            return STATUS_PIPE_DISCONNECTED;
        }

        int client_fd = socket_it->second;
        lock.unlock();

        if (!target_process->main_thread->ipc->send_message(msg, client_fd)) {
            return STATUS_UNSUCCESSFUL;
        }

        // Wait for response
        auto response = target_process->main_thread->ipc->receive_message(client_fd, 5000);
        if (!response) {
            return STATUS_TIMEOUT;
        }

        if (!NT_SUCCESS(response->status)) {
            return response->status;
        }

        // Write allocated address back
        PVOID allocated_addr = reinterpret_cast<PVOID>(response->param1);
        if (!memory_mgr.write(base_addr_ptr, allocated_addr)) {
            return STATUS_ACCESS_VIOLATION;
        }

        return STATUS_SUCCESS;
    }

    // Local allocation
    int prot = PROT_NONE;
    if (Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) {
        prot |= PROT_EXEC;
    }
    if (Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) {
        prot |= PROT_READ;
    }
    if (Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) {
        prot |= PROT_WRITE;
    }

    int flags = MAP_PRIVATE | MAP_ANONYMOUS;
    if (AllocationType & MEM_COMMIT) {
        // Committed memory
    }
    if (AllocationType & MEM_RESERVE) {
        flags |= MAP_NORESERVE;
    }

    void* addr = mmap(*requested_base, *requested_size, prot, flags, -1, 0);
    if (addr == MAP_FAILED) {
        return errno_to_ntstatus(errno);
    }

    // Write results back
    if (!memory_mgr.write(base_addr_ptr, addr)) {
        munmap(addr, *requested_size);
        return STATUS_ACCESS_VIOLATION;
    }

    SIZE_T actual_size = *requested_size;
    if (!memory_mgr.write(region_size_ptr, actual_size)) {
        munmap(addr, *requested_size);
        return STATUS_ACCESS_VIOLATION;
    }

    return STATUS_SUCCESS;
}

NTSTATUS NTAPI _NtFreeVirtualMemory(
    ChildMemoryManager& memory_mgr,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType) {

    trace("_NtFreeVirtualMemory called");



    return STATUS_SUCCESS;
}

NTSTATUS NTAPI _NtProtectVirtualMemory(
    ChildMemoryManager& memory_mgr,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect) {

    trace("_NtProtectVirtualMemory called");

    if (!BaseAddress || !RegionSize) {
        return STATUS_INVALID_PARAMETER;
    }

    // Read BaseAddress from child memory
    uintptr_t base_addr_ptr = reinterpret_cast<uintptr_t>(BaseAddress);
    auto current_base = memory_mgr.read<PVOID>(base_addr_ptr);
    if (!current_base || !*current_base) {
        return STATUS_INVALID_PARAMETER;
    }

    // Read RegionSize from child memory
    uintptr_t region_size_ptr = reinterpret_cast<uintptr_t>(RegionSize);
    auto current_size = memory_mgr.read<SIZE_T>(region_size_ptr);
    if (!current_size) {
        return STATUS_ACCESS_VIOLATION;
    }

    // Write old protection if requested
    if (OldProtect) {
        ULONG old_protect = PAGE_READWRITE; // Assume current protection
        uintptr_t old_protect_ptr = reinterpret_cast<uintptr_t>(OldProtect);
        if (!memory_mgr.write(old_protect_ptr, old_protect)) {
            return STATUS_ACCESS_VIOLATION;
        }
    }

    int prot = PROT_NONE;
    if (NewProtect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) {
        prot |= PROT_EXEC;
    }
    if (NewProtect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) {
        prot |= PROT_READ;
    }
    if (NewProtect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) {
        prot |= PROT_WRITE;
    }

    if (mprotect(*current_base, *current_size, prot) != 0) {
        return errno_to_ntstatus(errno);
    }

    return STATUS_SUCCESS;
}

NTSTATUS NTAPI _NtQueryVirtualMemory(
    ChildMemoryManager& memory_mgr,
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    MEMORY_INFORMATION_CLASS MemoryInformationClass,
    PVOID MemoryInformation,
    SIZE_T MemoryInformationLength,
    PSIZE_T ReturnLength) {

    trace("_NtQueryVirtualMemory called");

    if (MemoryInformationClass != MemoryBasicInformation) {
        return STATUS_INVALID_INFO_CLASS;
    }

    if (MemoryInformationLength < sizeof(MEMORY_BASIC_INFORMATION)) {
        return STATUS_INFO_LENGTH_MISMATCH;
    }

    // Create memory info structure
    MEMORY_BASIC_INFORMATION info;
    memset(&info, 0, sizeof(info));

    // Simplified implementation - assume all queried memory is committed and readable/writable
    info.BaseAddress = BaseAddress;
    info.AllocationBase = BaseAddress;
    info.AllocationProtect = PAGE_READWRITE;
    info.RegionSize = PAGE_SIZE;  // Minimal region size
    info.State = MEM_COMMIT;
    info.Protect = PAGE_READWRITE;
    info.Type = MEM_PRIVATE;

    // Write the info structure to child memory
    if (const auto info_ptr = reinterpret_cast<uintptr_t>(MemoryInformation); !memory_mgr.write(info_ptr, info)) {
        return STATUS_ACCESS_VIOLATION;
    }

    // Write return length if requested
    if (ReturnLength) {
        const auto return_length_ptr = reinterpret_cast<uintptr_t>(ReturnLength);
        if (const SIZE_T length = sizeof(MEMORY_BASIC_INFORMATION); !memory_mgr.write(return_length_ptr, length)) {
            return STATUS_ACCESS_VIOLATION;
        }
    }

    return STATUS_SUCCESS;
}


// I/O Completion Ports

NTSTATUS NTAPI _NtCreateIoCompletion(
    ChildMemoryManager& memory_mgr,
    PHANDLE IoCompletionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG Count) {

    trace("_NtCreateIoCompletion called");

    if (!IoCompletionHandle) {
        return STATUS_INVALID_PARAMETER;
    }

    DWORD max_threads = Count ? Count : std::thread::hardware_concurrency();
    auto completion_port = std::make_shared<CompletionPort>(max_threads);

    const HANDLE handle = g_next_handle = reinterpret_cast<HANDLE>(reinterpret_cast<uintptr_t>(g_next_handle.load()) + 1);

    std::shared_lock lock(g_processes[g_tls.process].process_mutex);
    g_processes[g_tls.process].completion_ports[handle] = std::move(completion_port);

    // Write handle to child memory
    uintptr_t handle_ptr = reinterpret_cast<uintptr_t>(IoCompletionHandle);
    if (!memory_mgr.write(handle_ptr, handle)) {
        g_processes[g_tls.process].completion_ports.erase(handle);
        return STATUS_ACCESS_VIOLATION;
    }

    return STATUS_SUCCESS;
}

NTSTATUS NTAPI _NtRemoveIoCompletion(
    ChildMemoryManager& memory_mgr,
    HANDLE IoCompletionHandle,
    PVOID* KeyContext,
    PVOID* ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER Timeout) {

    trace("_NtRemoveIoCompletion called");

    std::shared_lock lock(g_processes[g_tls.process].process_mutex);
    auto it = g_processes[g_tls.process].completion_ports.find(IoCompletionHandle);
    if (it == g_processes[g_tls.process].completion_ports.end()) {
        return STATUS_INVALID_HANDLE;
    }

    DWORD timeout_ms = INFINITE;
    if (Timeout) {
        uintptr_t timeout_ptr = reinterpret_cast<uintptr_t>(Timeout);
        auto timeout_val = memory_mgr.read<LARGE_INTEGER>(timeout_ptr);
        if (!timeout_val) {
            return STATUS_ACCESS_VIOLATION;
        }

        if (timeout_val->QuadPart == 0) {
            timeout_ms = 0;
        } else if (timeout_val->QuadPart > 0) {
            timeout_ms = static_cast<DWORD>(timeout_val->QuadPart / 10000);
        }
    }

    CompletionPacket packet;
    if (it->second->get_completion(packet, timeout_ms)) {
        if (KeyContext) {
            PVOID key_ctx = reinterpret_cast<PVOID>(packet.completion_key);
            uintptr_t key_ptr = reinterpret_cast<uintptr_t>(KeyContext);
            if (!memory_mgr.write(key_ptr, key_ctx)) {
                return STATUS_ACCESS_VIOLATION;
            }
        }
        if (ApcContext) {
            PVOID apc_ctx = packet.overlapped;
            uintptr_t apc_ptr = reinterpret_cast<uintptr_t>(ApcContext);
            if (!memory_mgr.write(apc_ptr, apc_ctx)) {
                return STATUS_ACCESS_VIOLATION;
            }
        }
        if (IoStatusBlock) {
            IO_STATUS_BLOCK status_block;
            status_block.Status = errno_to_ntstatus(packet.error_code);
            status_block.Information = packet.bytes_transferred;

            uintptr_t status_ptr = reinterpret_cast<uintptr_t>(IoStatusBlock);
            if (!memory_mgr.write(status_ptr, status_block)) {
                return STATUS_ACCESS_VIOLATION;
            }
        }
        return STATUS_SUCCESS;
    } else {
        return STATUS_TIMEOUT;
    }
}

NTSTATUS NTAPI _NtRemoveIoCompletionEx(
    ChildMemoryManager& memory_mgr,
    HANDLE IoCompletionHandle,
    PFILE_IO_COMPLETION_INFORMATION IoCompletionInformation,
    ULONG Count,
    PULONG NumEntriesRemoved,
    PLARGE_INTEGER Timeout,
    BOOLEAN Alertable) {

    trace("_NtRemoveIoCompletionEx called");

    if (!IoCompletionInformation || Count == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    std::shared_lock lock(g_processes[g_tls.process].process_mutex);
    auto it = g_processes[g_tls.process].completion_ports.find(IoCompletionHandle);
    if (it == g_processes[g_tls.process].completion_ports.end()) {
        return STATUS_INVALID_HANDLE;
    }

    DWORD timeout_ms = INFINITE;
    if (Timeout) {
        uintptr_t timeout_ptr = reinterpret_cast<uintptr_t>(Timeout);
        auto timeout_val = memory_mgr.read<LARGE_INTEGER>(timeout_ptr);
        if (!timeout_val) {
            return STATUS_ACCESS_VIOLATION;
        }

        if (timeout_val->QuadPart == 0) {
            timeout_ms = 0;
        } else if (timeout_val->QuadPart > 0) {
            timeout_ms = static_cast<DWORD>(timeout_val->QuadPart / 10000);
        }
    }

    ULONG removed = 0;
    uintptr_t info_base_ptr = reinterpret_cast<uintptr_t>(IoCompletionInformation);

    for (ULONG i = 0; i < Count; i++) {
        CompletionPacket packet;
        if (it->second->get_completion(packet, (i == 0) ? timeout_ms : 0)) {
            FILE_IO_COMPLETION_INFORMATION info;
            info.CompletionKey = packet.completion_key;
            info.CompletionValue = reinterpret_cast<ULONG_PTR>(packet.overlapped);
            info.IoStatusBlock.Status = errno_to_ntstatus(packet.error_code);
            info.IoStatusBlock.Information = packet.bytes_transferred;

            uintptr_t info_ptr = info_base_ptr + i * sizeof(FILE_IO_COMPLETION_INFORMATION);
            if (!memory_mgr.write(info_ptr, info)) {
                return STATUS_ACCESS_VIOLATION;
            }
            removed++;
        } else {
            break;
        }
    }

    if (NumEntriesRemoved) {
        uintptr_t removed_ptr = reinterpret_cast<uintptr_t>(NumEntriesRemoved);
        if (!memory_mgr.write(removed_ptr, removed)) {
            return STATUS_ACCESS_VIOLATION;
        }
    }

    return removed > 0 ? STATUS_SUCCESS : STATUS_TIMEOUT;
}

NTSTATUS NTAPI _NtSetIoCompletion(
    HANDLE IoCompletionHandle,
    PVOID KeyContext,
    PVOID ApcContext,
    NTSTATUS IoStatus,
    ULONG_PTR IoStatusInformation) {

    trace("_NtSetIoCompletion called");

    std::shared_lock lock(g_processes[g_tls.process].process_mutex);
    auto it = g_processes[g_tls.process].completion_ports.find(IoCompletionHandle);
    if (it == g_processes[g_tls.process].completion_ports.end()) {
        return STATUS_INVALID_HANDLE;
    }

    CompletionPacket packet{};
    packet.completion_key = reinterpret_cast<ULONG_PTR>(KeyContext);
    packet.overlapped = static_cast<LPOVERLAPPED>(ApcContext);
    packet.bytes_transferred = static_cast<DWORD>(IoStatusInformation);
    packet.error_code = errno_to_ntstatus(IoStatus);

    it->second->post_completion(packet);
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI _NtCreateWaitCompletionPacket(
    ChildMemoryManager& memory_mgr,
    PHANDLE WaitCompletionPacketHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE IoCompletionHandle,
    PVOID KeyContext) {

    trace("_NtCreateWaitCompletionPacket called");

    if (!WaitCompletionPacketHandle) {
        return STATUS_INVALID_PARAMETER;
    }

    // Verify the I/O completion port exists
    std::shared_lock proc_lock(g_processes[g_tls.process].process_mutex);
    auto it = g_processes[g_tls.process].completion_ports.find(IoCompletionHandle);
    if (it == g_processes[g_tls.process].completion_ports.end()) {
        return STATUS_INVALID_HANDLE;
    }
    proc_lock.unlock();

    // Create wait completion packet
    auto packet = std::make_shared<WaitCompletionPacket>();
    packet->io_completion_handle = IoCompletionHandle;
    packet->target_object = nullptr;
    packet->key_context = KeyContext;
    packet->apc_context = nullptr;
    packet->io_status = STATUS_SUCCESS;
    packet->io_status_information = 0;
    packet->is_signaled = false;
    packet->is_cancelled = false;

    HANDLE handle = HandleManager::allocate_handle();

    std::unique_lock lock(g_processes[g_tls.process].wait_packet_mutex);
    g_processes[g_tls.process].wait_packets[handle] = packet;
    lock.unlock();

    // Write a handle to child memory
    auto handle_ptr = reinterpret_cast<uintptr_t>(WaitCompletionPacketHandle);
    if (!memory_mgr.write(handle_ptr, handle)) {
        std::shared_lock cleanup_lock(g_processes[g_tls.process].wait_packet_mutex);
        g_processes[g_tls.process].wait_packets.erase(handle);
        return STATUS_ACCESS_VIOLATION;
    }

    trace("Created wait completion packet handle: ", handle);
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI _NtAssociateWaitCompletionPacket(
    ChildMemoryManager& memory_mgr,
    HANDLE WaitCompletionPacketHandle,
    HANDLE IoCompletionHandle,
    HANDLE TargetObjectHandle,
    PVOID KeyContext,
    PVOID ApcContext,
    NTSTATUS IoStatus,
    ULONG_PTR IoStatusInformation,
    PBOOLEAN AlreadySignaled) {

    trace("_NtAssociateWaitCompletionPacket called");

    // Get wait completion packet
    std::shared_lock lock(g_processes[g_tls.process].wait_packet_mutex);
    const auto packet_it = g_processes[g_tls.process].wait_packets.find(WaitCompletionPacketHandle);
    if (packet_it == g_processes[g_tls.process].wait_packets.end()) {
        return STATUS_INVALID_HANDLE;
    }
    auto packet = packet_it->second;
    lock.unlock();

    // Verify I/O completion port
    std::shared_lock proc_lock(g_processes[g_tls.process].process_mutex);
    auto port_it = g_processes[g_tls.process].completion_ports.find(IoCompletionHandle);
    if (port_it == g_processes[g_tls.process].completion_ports.end()) {
        return STATUS_INVALID_HANDLE;
    }
    auto completion_port = port_it->second;

    // Check if a target object exists (event, thread, etc.)
    bool target_exists = false;
    bool already_signaled = false;

    if (g_processes[g_tls.process].events.contains(TargetObjectHandle)) {
        target_exists = true;
        already_signaled = g_processes[g_tls.process].events[TargetObjectHandle]->is_set();
    } else if (g_processes[g_tls.process].threads.contains(TargetObjectHandle)) {
        target_exists = true;
        already_signaled = g_processes[g_tls.process].threads[TargetObjectHandle]->is_terminated;
    } else if (g_processes[g_tls.process].device_handles.contains(TargetObjectHandle)) {
        target_exists = true;
        already_signaled = false; // Files are not pre-signaled
    }

    proc_lock.unlock();

    if (!target_exists) {
        return STATUS_INVALID_HANDLE;
    }

    // Write AlreadySignaled if requested
    if (AlreadySignaled) {
        const BOOLEAN signaled = already_signaled ? TRUE : FALSE;
        if (uintptr_t signaled_ptr = reinterpret_cast<uintptr_t>(AlreadySignaled); !memory_mgr.write(signaled_ptr, signaled)) {
            return STATUS_ACCESS_VIOLATION;
        }
    }

    // Update packet
    std::unique_lock packet_lock(packet->packet_mutex);
    packet->io_completion_handle = IoCompletionHandle;
    packet->target_object = TargetObjectHandle;
    packet->key_context = KeyContext;
    packet->apc_context = ApcContext;
    packet->io_status = IoStatus;
    packet->io_status_information = IoStatusInformation;
    packet->is_signaled = already_signaled;

    // If already signaled, post immediately
    if (already_signaled) {
        CompletionPacket cp;
        cp.completion_key = reinterpret_cast<ULONG_PTR>(KeyContext);
        cp.overlapped = static_cast<LPOVERLAPPED>(ApcContext);
        cp.bytes_transferred = static_cast<DWORD>(IoStatusInformation);
        cp.error_code = IoStatus;
        cp.target_object = TargetObjectHandle;
        cp.key_context = KeyContext;
        cp.apc_context = ApcContext;
        cp.io_status = IoStatus;
        cp.io_status_information = IoStatusInformation;
        cp.is_signaled = true;
        cp.is_cancelled = false;

        completion_port->post_completion(cp);
        packet_lock.unlock();

        trace("Wait completion packet already signaled, posted immediately");
        return STATUS_SUCCESS;
    }

    // Start wait thread to monitor the target object
    packet->should_stop = false;
    packet->wait_thread = std::make_shared<std::thread>([packet, completion_port, TargetObjectHandle]() {
        trace("Wait thread started for handle ", TargetObjectHandle);

        bool signaled = false;

        while (!packet->should_stop && !signaled) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));

            std::shared_lock proc_lock(g_processes[g_tls.process].process_mutex);

            // Check if object is signaled
            if (g_processes[g_tls.process].events.contains(TargetObjectHandle)) {
                signaled = g_processes[g_tls.process].events[TargetObjectHandle]->is_set();
            } else if (g_processes[g_tls.process].threads.contains(TargetObjectHandle)) {
                signaled = g_processes[g_tls.process].threads[TargetObjectHandle]->is_terminated;
            }

            proc_lock.unlock();

            if (signaled) {
                std::unique_lock pkt_lock(packet->packet_mutex);
                if (!packet->is_cancelled) {
                    packet->is_signaled = true;

                    // Post completion packet
                    CompletionPacket cp;
                    cp.completion_key = reinterpret_cast<ULONG_PTR>(packet->key_context);
                    cp.overlapped = static_cast<LPOVERLAPPED>(packet->apc_context);
                    cp.bytes_transferred = static_cast<DWORD>(packet->io_status_information);
                    cp.error_code = packet->io_status;
                    cp.target_object = TargetObjectHandle;
                    cp.key_context = packet->key_context;
                    cp.apc_context = packet->apc_context;
                    cp.io_status = packet->io_status;
                    cp.io_status_information = packet->io_status_information;
                    cp.is_signaled = true;
                    cp.is_cancelled = false;

                    completion_port->post_completion(cp);
                    trace("Wait completion packet signaled, posted to completion port");
                }
                pkt_lock.unlock();
                break;
            }
        }

        trace("Wait thread terminated for handle ", TargetObjectHandle);
    });

    packet_lock.unlock();

    trace("Associated wait completion packet with target object ", TargetObjectHandle);
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI _NtCancelWaitCompletionPacket(
    ChildMemoryManager& memory_mgr,
    HANDLE WaitCompletionPacketHandle,
    BOOLEAN RemoveSignaledPacket) {

    trace("_NtCancelWaitCompletionPacket called");

    std::shared_lock lock(g_processes[g_tls.process].wait_packet_mutex);
    auto it = g_processes[g_tls.process].wait_packets.find(WaitCompletionPacketHandle);
    if (it == g_processes[g_tls.process].wait_packets.end()) {
        return STATUS_INVALID_HANDLE;
    }
    auto packet = it->second;
    lock.unlock();

    std::unique_lock packet_lock(packet->packet_mutex);

    // If already signaled and RemoveSignaledPacket is FALSE, fail
    if (packet->is_signaled && !RemoveSignaledPacket) {
        return STATUS_UNSUCCESSFUL;
    }

    // Cancel the wait
    packet->is_cancelled = true;
    packet->should_stop = true;
    packet_lock.unlock();

    // Wait for wait thread to terminate
    if (packet->wait_thread && packet->wait_thread->joinable()) {
        packet->wait_thread->join();
    }

    trace("Cancelled wait completion packet");
    return STATUS_SUCCESS;
}



NTSTATUS NTAPI _NtCreateThread(
    ChildMemoryManager& memory_mgr,
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PCLIENT_ID ClientId,
    PCONTEXT ThreadContext,
    PINITIAL_TEB InitialTeb,
    BOOLEAN CreateSuspended) {

    trace("_NtCreateThread called with enhanced infrastructure");

    if (!ThreadHandle) return STATUS_INVALID_PARAMETER;

    // Get the target process
    ProcessContext* target_process = nullptr;
    if (ProcessHandle && ProcessHandle != reinterpret_cast<HANDLE>(-1)) {
        target_process = &g_processes[g_tls.process];
    } else if (ProcessHandle) {
        target_process = &g_processes[ProcessHandle];
    }

    if (!target_process) {
        return STATUS_INVALID_HANDLE;
    }

    // Use enhanced thread manager to create thread
    DWORD thread_id = 0;
    HANDLE thread_handle = g_thread_manager->create_monitored_thread(
        nullptr,                    // lpThreadAttributes
        0,                          // dwStackSize
        nullptr,                    // lpStartAddress (set later)
        nullptr,                    // lpParameter
        CreateSuspended ? CREATE_SUSPENDED : 0,  // dwCreationFlags
        &thread_id
    );

    if (!thread_handle) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Get the thread context
    std::shared_lock lock(target_process->process_mutex);
    auto thread_it = target_process->threads.find(thread_handle);
    if (thread_it == target_process->threads.end()) {
        return STATUS_INTERNAL_ERROR;
    }

    class ThreadContext* thread_ctx = thread_it->second.get();

    // Set thread context if provided
    if (ThreadContext) {
        uintptr_t context_ptr = reinterpret_cast<uintptr_t>(ThreadContext);
        auto context = memory_mgr.read<CONTEXT>(context_ptr);
        if (!context) {
            return STATUS_ACCESS_VIOLATION;
        }
        thread_ctx->thread_context = *context;
        thread_ctx->context_valid = true;
    }

    // Write ClientId if requested
    if (ClientId) {
        CLIENT_ID client_id;
        client_id.UniqueProcess = target_process->windows_process_handle;
        client_id.UniqueThread = thread_handle;

        uintptr_t client_id_ptr = reinterpret_cast<uintptr_t>(ClientId);
        if (!memory_mgr.write(client_id_ptr, client_id)) {
            return STATUS_ACCESS_VIOLATION;
        }
    }

    // Write thread handle to child memory
    uintptr_t handle_ptr = reinterpret_cast<uintptr_t>(ThreadHandle);
    if (!memory_mgr.write(handle_ptr, thread_handle)) {
        return STATUS_ACCESS_VIOLATION;
    }

    trace("Created thread with handle ", thread_handle, ", TID ", thread_id);
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI _NtOpenThread(
    ChildMemoryManager& memory_mgr,
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId) {

    trace("_NtOpenThread called");

    if (!ThreadHandle || !ClientId) {
        return STATUS_INVALID_PARAMETER;
    }

    // Read CLIENT_ID from child memory
    uintptr_t client_id_ptr = reinterpret_cast<uintptr_t>(ClientId);
    auto client_id = memory_mgr.read<CLIENT_ID>(client_id_ptr);
    if (!client_id) {
        return STATUS_ACCESS_VIOLATION;
    }

    // Find thread by ID
    ProcessContext* process = &g_processes[g_tls.process];
    if (!process) {
        return STATUS_INVALID_HANDLE;
    }

    std::shared_lock<std::shared_mutex> lock(process->process_mutex);
    for (const auto& [handle, thread_ctx] : process->threads) {
        if (thread_ctx->thread_id == reinterpret_cast<uintptr_t>(client_id->UniqueThread)) {
            // Write a thread handle to child memory
            auto handle_ptr = reinterpret_cast<uintptr_t>(ThreadHandle);
            if (!memory_mgr.write(handle_ptr, handle)) {
                return STATUS_ACCESS_VIOLATION;
            }
            return STATUS_SUCCESS;
        }
    }

    return STATUS_INVALID_CID;
}

NTSTATUS NTAPI _NtTerminateThread(
    ChildMemoryManager& memory_mgr,
    HANDLE ThreadHandle,
    NTSTATUS ExitStatus) {

    trace("_NtTerminateThread called for handle ", ThreadHandle);

    ProcessContext* process = &g_processes[g_tls.process];
    if (!process) {
        return STATUS_INVALID_HANDLE;
    }

    HANDLE target_handle = ThreadHandle ? ThreadHandle :
                          g_tls.thread;

    std::shared_lock lock(process->process_mutex);
    auto it = process->threads.find(target_handle);
    if (it == process->threads.end()) {
        return STATUS_INVALID_HANDLE;
    }

    ThreadContext* thread_ctx = it->second.get();
    thread_ctx->should_terminate = true;
    thread_ctx->is_terminated = true;
    thread_ctx->exit_code = ExitStatus;
    thread_ctx->suspend_cv.notify_all();
    thread_ctx->task_cv.notify_all();

    // Cleanup with thread manager
    if (thread_ctx->native_thread_id) {
        g_thread_manager->cleanup_thread(thread_ctx->native_thread_id);
    }

    return STATUS_SUCCESS;
}

NTSTATUS NTAPI _NtSuspendThread(
    const ChildMemoryManager& memory_mgr,
    HANDLE ThreadHandle,
    PULONG PreviousSuspendCount) {

    trace("_NtSuspendThread called");

    ProcessContext* process = &g_processes[g_tls.process];
    if (!process) {
        return STATUS_INVALID_HANDLE;
    }

    std::shared_lock<std::shared_mutex> lock(process->process_mutex);
    auto it = process->threads.find(ThreadHandle);
    if (it == process->threads.end()) {
        return STATUS_INVALID_HANDLE;
    }

    ThreadContext* thread_ctx = it->second.get();

    if (PreviousSuspendCount) {
        ULONG prev_count = thread_ctx->suspend_count.load();
        uintptr_t count_ptr = reinterpret_cast<uintptr_t>(PreviousSuspendCount);
        if (!memory_mgr.write(count_ptr, prev_count)) {
            return STATUS_ACCESS_VIOLATION;
        }
    }

    int new_count = thread_ctx->suspend_count.fetch_add(1) + 1;
    thread_ctx->is_suspended = true;

    trace("Thread ", ThreadHandle, " suspended, count now ", new_count);
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI _NtResumeThread(
    ChildMemoryManager& memory_mgr,
    HANDLE ThreadHandle,
    PULONG PreviousSuspendCount) {

    trace("_NtResumeThread called");

    ProcessContext* process = &g_processes[g_tls.process];
    if (!process) {
        return STATUS_INVALID_HANDLE;
    }

    std::shared_lock lock(process->process_mutex);
    auto it = process->threads.find(ThreadHandle);
    if (it == process->threads.end()) {
        return STATUS_INVALID_HANDLE;
    }

    ThreadContext* thread_ctx = it->second.get();

    if (PreviousSuspendCount) {
        ULONG prev_count = thread_ctx->suspend_count.load();
        uintptr_t count_ptr = reinterpret_cast<uintptr_t>(PreviousSuspendCount);
        if (!memory_mgr.write(count_ptr, prev_count)) {
            return STATUS_ACCESS_VIOLATION;
        }
    }

    int prev = thread_ctx->suspend_count.fetch_sub(1);
    if (prev <= 1) {
        thread_ctx->suspend_count = 0;
        thread_ctx->is_suspended = false;
        thread_ctx->suspend_cv.notify_all();
        trace("Thread ", ThreadHandle, " fully resumed");
    } else {
        trace("Thread ", ThreadHandle, " resume, count now ", prev - 1);
    }

    return STATUS_SUCCESS;
}

NTSTATUS NTAPI _NtGetContextThread(
    ChildMemoryManager& memory_mgr,
    HANDLE ThreadHandle,
    PCONTEXT Context) {

    trace("_NtGetContextThread called");

    if (!Context) {
        return STATUS_INVALID_PARAMETER;
    }

    ProcessContext* process = &g_processes[g_tls.process];
    if (!process) {
        return STATUS_INVALID_HANDLE;
    }

    std::shared_lock lock(process->process_mutex);
    auto it = process->threads.find(ThreadHandle);
    if (it == process->threads.end()) {
        return STATUS_INVALID_HANDLE;
    }

    ThreadContext* thread_ctx = it->second.get();

    if (!thread_ctx->context_valid) {
        // Capture current context if not available
        // This would require platform-specific code
        return STATUS_UNSUCCESSFUL;
    }

    // Write context to child memory
    uintptr_t context_ptr = reinterpret_cast<uintptr_t>(Context);
    if (!memory_mgr.write(context_ptr, thread_ctx->thread_context)) {
        return STATUS_ACCESS_VIOLATION;
    }

    return STATUS_SUCCESS;
}

NTSTATUS NTAPI _NtSetContextThread(
    ChildMemoryManager& memory_mgr,
    HANDLE ThreadHandle,
    PCONTEXT Context) {

    trace("_NtSetContextThread called");

    if (!Context) {
        return STATUS_INVALID_PARAMETER;
    }

    ProcessContext* process = &g_processes[g_tls.process];
    if (!process) {
        return STATUS_INVALID_HANDLE;
    }

    // Read context from child memory
    uintptr_t context_ptr = reinterpret_cast<uintptr_t>(Context);
    auto context = memory_mgr.read<CONTEXT>(context_ptr);
    if (!context) {
        return STATUS_ACCESS_VIOLATION;
    }

    std::shared_lock lock(process->process_mutex);
    auto it = process->threads.find(ThreadHandle);
    if (it == process->threads.end()) {
        return STATUS_INVALID_HANDLE;
    }

    ThreadContext* thread_ctx = it->second.get();
    thread_ctx->thread_context = *context;
    thread_ctx->context_valid = true;

    return STATUS_SUCCESS;
}

NTSTATUS NTAPI _NtSetInformationThread(
    ChildMemoryManager& memory_mgr,
    HANDLE ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength) {

    trace("_NtSetInformationThread called");

    if (!ThreadInformation) {
        return STATUS_INVALID_PARAMETER;
    }

    ProcessContext* process = &g_processes[g_tls.process];
    if (!process) {
        return STATUS_INVALID_HANDLE;
    }

    std::shared_lock lock(process->process_mutex);
    auto it = process->threads.find(ThreadHandle);
    if (it == process->threads.end()) {
        return STATUS_INVALID_HANDLE;
    }

    ThreadContext* thread_ctx = it->second.get();

    switch (ThreadInformationClass) {
        case ThreadZeroTlsCell: {
            if (ThreadInformationLength != sizeof(ULONG)) {
                return STATUS_INFO_LENGTH_MISMATCH;
            }
            uintptr_t info_ptr = reinterpret_cast<uintptr_t>(ThreadInformation);
            auto index = memory_mgr.read<ULONG>(info_ptr);
            thread_ctx->tls_data[*index] = 0;
            return STATUS_SUCCESS;
        }
        case ThreadImpersonationToken: {
            if (ThreadInformationLength != sizeof(HANDLE)) {
                return STATUS_INFO_LENGTH_MISMATCH;
            }
            uintptr_t info_ptr = reinterpret_cast<uintptr_t>(ThreadInformation);
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
            thread_ctx->priority_class = *priority;
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
            thread_ctx->priority_class = *base_priority;
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
            thread_ctx->affinity_mask = affinity.value_or(0);
            cpu_set_t mask;
            CPU_ZERO(&mask);
            for (size_t i = 0; i < sizeof(ULONG_PTR) * 8; i++) {
                if (thread_ctx->affinity_mask & (1ULL << i)) {
                    CPU_SET(i, &mask);
                }
            }
            pthread_setaffinity_np(thread_ctx->native_thread_id, sizeof(cpu_set_t), &mask);
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
            thread_ctx->start_address = reinterpret_cast<uintptr_t>(start_address.value_or(nullptr));
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
                pthread_setname_np(thread_ctx->native_thread_id, name_buffer.data());
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
            thread_ctx->priority_boost = *boost;
            return STATUS_SUCCESS;
        }
        case ThreadManageWritesToExecutableMemory: {
            if (ThreadInformationLength != sizeof(MANAGE_WRITES_TO_EXECUTABLE_MEMORY)) {
                return STATUS_INFO_LENGTH_MISMATCH;
            }
            const auto info_ptr = reinterpret_cast<uintptr_t>(ThreadInformation);
            auto manage_writes = memory_mgr.read<MANAGE_WRITES_TO_EXECUTABLE_MEMORY>(info_ptr);
            if (!manage_writes) {
                return STATUS_ACCESS_VIOLATION;
            }
            thread_ctx->allow_writes = manage_writes.value().ThreadAllowWrites;
            return STATUS_SUCCESS;
        }
        default:
            return STATUS_NOT_IMPLEMENTED;
    }
}

// Heap Management
HANDLE NTAPI RtlCreateHeap(
    ChildMemoryManager& memory_mgr,
    ULONG Flags,
    PVOID HeapBase,
    SIZE_T ReserveSize,
    SIZE_T CommitSize,
    PVOID Lock,
    PRTL_HEAP_PARAMETERS Parameters) {

    trace("RtlCreateHeap called");

    auto heap = new HEAP();
    memset(heap, 0, sizeof(HEAP));

    heap->MaximumSize = ReserveSize ? ReserveSize : SIZE_MAX;
    heap->CurrentAllocBytes = 0;
    heap->MaxAllocBytes = 0;
    heap->NumAllocs = 0;
    heap->NumFrees = 0;

    std::shared_lock lock(g_processes[g_tls.process].process_mutex);  // USING TLS!
    auto& process_context = g_processes[g_tls.process];

    // Resize heaps array
    process_context.num_heaps++;
    process_context.heaps = static_cast<PHEAP*>(realloc(process_context.heaps,
                                                    process_context.num_heaps * sizeof(PHEAP)));
    process_context.heaps[process_context.num_heaps - 1] = heap;

    return heap;
}

NTSTATUS NTAPI _NtRaiseException(
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

HANDLE NTAPI RtlDestroyHeap(HANDLE HeapHandle) {
    trace("RtlDestroyHeap called");

    if (!HeapHandle) {
        return FALSE;
    }

    auto heap = static_cast<PHEAP>(HeapHandle);
    std::shared_lock lock(g_processes[g_tls.process].process_mutex);  // USING TLS!
    auto& process_context = g_processes[g_tls.process];

    for (size_t i = 0; i < process_context.num_heaps; i++) {
        if (process_context.heaps[i] == heap) {
            free(heap);
            // Remove from heap array
            for (size_t j = i; j < process_context.num_heaps - 1; j++) {
                process_context.heaps[j] = process_context.heaps[j + 1];
            }
            process_context.num_heaps--;
            process_context.heaps = static_cast<PHEAP*>(realloc(process_context.heaps,
                                                            process_context.num_heaps * sizeof(PHEAP)));
            return nullptr;
        }
    }

    return HeapHandle;
}

PVOID NTAPI RtlAllocateHeap(
    ChildMemoryManager& memory_mgr,
    PVOID HeapHandle,
    ULONG Flags,
    SIZE_T Size) {

    if (!HeapHandle || Size == 0) {
        return nullptr;
    }

    const auto heap = static_cast<PHEAP>(HeapHandle);
    std::lock_guard heap_lock(heap->heap_mutex);

    // Allocate memory in child process address space
    void* child_ptr = nullptr;
    PVOID* base_addr = &child_ptr;
    SIZE_T region_size = Size + sizeof(HEAP_BLOCK);

    // Use child memory allocation (this would need to be adapted for actual child process)
    void* ptr = malloc(Size + sizeof(HEAP_BLOCK));
    if (!ptr) {
        return nullptr;
    }

    const auto block = static_cast<PHEAP_BLOCK>(ptr);
    block->Size = static_cast<USHORT>(Size);
    block->Tag = 0;

    heap->NumAllocs++;
    heap->CurrentAllocBytes += Size;
    if (Size > heap->LargestAllocation) {
        heap->LargestAllocation = Size;
    }

    void* user_ptr = static_cast<char*>(ptr) + sizeof(HEAP_BLOCK);

    if (Flags & HEAP_ZERO_MEMORY) {
        memset(user_ptr, 0, Size);
    }

    return user_ptr;
}

BOOLEAN NTAPI RtlFreeHeap(
    ChildMemoryManager& memory_mgr,
    PVOID HeapHandle,
    ULONG Flags,
    PVOID BaseAddress) {

    if (!HeapHandle || !BaseAddress) {
        return FALSE;
    }

    const auto heap = static_cast<PHEAP>(HeapHandle);
    std::lock_guard heap_lock(heap->heap_mutex);

    // Get the block header from child memory
    uintptr_t block_addr = reinterpret_cast<uintptr_t>(BaseAddress) - sizeof(HEAP_BLOCK);
    auto block = memory_mgr.read<HEAP_BLOCK>(block_addr);
    if (!block) {
        return FALSE;
    }

    heap->NumFrees++;
    heap->CurrentAllocBytes -= block->Size;

    // Free memory in a child process (this would use child memory management)
    free(reinterpret_cast<void*>(block_addr));
    return TRUE;
}

PVOID NTAPI RtlReAllocateHeap(
    ChildMemoryManager& memory_mgr,
    PVOID HeapHandle,
    ULONG Flags,
    PVOID BaseAddress,
    SIZE_T Size) {

    if (!HeapHandle || Size == 0) {
        return nullptr;
    }

    if (!BaseAddress) {
        return RtlAllocateHeap(memory_mgr, HeapHandle, Flags, Size);
    }

    const auto heap = static_cast<PHEAP>(HeapHandle);
    std::lock_guard heap_lock(heap->heap_mutex);

    // Read the old block header from child memory
    const uintptr_t old_block_addr = reinterpret_cast<uintptr_t>(BaseAddress) - sizeof(HEAP_BLOCK);
    const auto old_block = memory_mgr.read<HEAP_BLOCK>(old_block_addr);
    if (!old_block) {
        return nullptr;
    }

    void* new_ptr = realloc(reinterpret_cast<void*>(old_block_addr), Size + sizeof(HEAP_BLOCK));
    if (!new_ptr) {
        return nullptr;
    }

    const auto new_block = static_cast<PHEAP_BLOCK>(new_ptr);
    heap->CurrentAllocBytes += Size - old_block->Size;
    new_block->Size = static_cast<USHORT>(Size);

    return static_cast<char*>(new_ptr) + sizeof(HEAP_BLOCK);
}

SIZE_T NTAPI RtlSizeHeap(
    ChildMemoryManager& memory_mgr,
    PVOID HeapHandle,
    ULONG Flags,
    PVOID BaseAddress) {

    if (!HeapHandle || !BaseAddress) {
        return static_cast<SIZE_T>(-1);
    }

    // Read block header from child memory
    uintptr_t block_addr = reinterpret_cast<uintptr_t>(BaseAddress) - sizeof(HEAP_BLOCK);
    auto block = memory_mgr.read<HEAP_BLOCK>(block_addr);
    if (!block.has_value()) {
        return static_cast<SIZE_T>(-1);
    }

    return block->Size;
}

// Initialization and cleanup functions

static void kuser_update_thread_func() {
    while (!g_shutdown_requested) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        update_kuser_shared_data();
    }
}

static std::once_flag nt_init_flag;

static void initialize_nt_emulation() {
    trace("Initializing NT API emulation layer");

    // Initialize KUSER_SHARED_DATA
    if (!initialize_kuser_shared_data()) {
        error("Failed to initialize KUSER_SHARED_DATA");
        exit(1);
    }

    // Start update thread
    g_kuser_update_thread = std::thread(kuser_update_thread_func);

    trace("1");
    // Initialize current process
    const auto current_process = reinterpret_cast<HANDLE>(getpid());
    static bool globals_initialized = false;
    if (!globals_initialized) {
        // This forces the constructor to run
        g_processes.clear();
        globals_initialized = true;
    }
    g_tls.process = current_process;
    g_tls.thread = reinterpret_cast<HANDLE>(gettid());
    g_processes[current_process];
    trace("2");

    initialize_default_current_peb();
    initialize_default_current_teb();

    trace("NT API emulation layer initialized successfully");
}

__attribute__((destructor))
static void cleanup_nt_emulation() {
    trace("Cleaning up NT API emulation layer");

    g_shutdown_requested = true;
    if (g_kuser_update_thread.joinable()) {
        g_kuser_update_thread.join();
    }

    cleanup_current_teb();
    cleanup_current_peb();
    cleanup_kuser_shared_data();

    // Cleanup processes
    g_processes.clear();

    trace("NT API emulation layer cleanup complete");
}

// File I/O Operations
NTSTATUS NTAPI _NtCreateFile(
    ChildMemoryManager& memory_mgr,
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength) {

    trace("_NtCreateFile called");

    if (!FileHandle || !ObjectAttributes || !IoStatusBlock) {
        return STATUS_INVALID_PARAMETER;
    }

    // Read ObjectAttributes from child memory
    uintptr_t obj_attr_ptr = reinterpret_cast<uintptr_t>(ObjectAttributes);
    auto obj_attr = memory_mgr.read<OBJECT_ATTRIBUTES>(obj_attr_ptr);
    if (!obj_attr) {
        return STATUS_ACCESS_VIOLATION;
    }

    std::string path;
    if (obj_attr->ObjectName) {
        // Read UNICODE_STRING from child memory
        uintptr_t unicode_str_ptr = reinterpret_cast<uintptr_t>(obj_attr->ObjectName);
        auto unicode_str = memory_mgr.read<UNICODE_STRING>(unicode_str_ptr);
        if (!unicode_str) {
            return STATUS_ACCESS_VIOLATION;
        }

        if (unicode_str->Length > 0 && unicode_str->Buffer) {
            // Read the wide string buffer
            auto wpath = memory_mgr.read_wstring(reinterpret_cast<uintptr_t>(unicode_str->Buffer),
                                               unicode_str->Length / sizeof(WCHAR));
            if (!wpath) {
                return STATUS_ACCESS_VIOLATION;
            }

            // Convert u16string to string manually since codecvt is deprecated
            path.clear();
            path.reserve(wpath->size());
            for (char16_t c : *wpath) {
                path.push_back(static_cast<char>(c));
            }
        }
    }

    if (path.empty()) {
        return STATUS_INVALID_PARAMETER;
    }

    // Handle AFD sockets
    if (path.starts_with(R"(\Device\Afd\)")) {
        trace("Creating AFD socket: ", path.c_str());

        int family = AF_INET, type = SOCK_STREAM, protocol = IPPROTO_TCP;
        std::string afd_params = path.substr(12);

        const size_t first_underscore = afd_params.find('_');
        if (const size_t second_underscore = afd_params.find('_', first_underscore + 1);
            first_underscore != std::string::npos && second_underscore != std::string::npos) {
            try {
                family = std::stoi(afd_params.substr(0, first_underscore));
                type = std::stoi(afd_params.substr(first_underscore + 1,
                                                 second_underscore - first_underscore - 1));
                protocol = std::stoi(afd_params.substr(second_underscore + 1));
            } catch (...) {
                // Use defaults
            }
        }

        const HANDLE socket_handle = create_network_socket(g_tls.process, family, type, protocol,
                                                   CreateOptions, CreateDisposition,
                                                   DesiredAccess, ShareAccess, FileAttributes);
        if (!socket_handle) {
            return errno_to_ntstatus(errno);
        }

        // Write handle to child memory
        uintptr_t handle_ptr = reinterpret_cast<uintptr_t>(FileHandle);
        if (!memory_mgr.write(handle_ptr, socket_handle)) {
            close_device_handle(g_tls.process, socket_handle);
            return STATUS_ACCESS_VIOLATION;
        }

        // Write IO status block
        IO_STATUS_BLOCK status_block;
        status_block.Status = STATUS_SUCCESS;
        status_block.Information = FILE_CREATED;

        uintptr_t status_ptr = reinterpret_cast<uintptr_t>(IoStatusBlock);
        if (!memory_mgr.write(status_ptr, status_block)) {
            close_device_handle(g_tls.process, socket_handle);
            return STATUS_ACCESS_VIOLATION;
        }

        return STATUS_SUCCESS;
    }

    // Handle regular files
    if (!path.starts_with("\\??\\")) {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    path = path.substr(4);  // Remove \??\ prefix
    std::ranges::replace(path, '\\', '/');

    if (path.starts_with("/")) {
        path = "." + path;
    } else {
        path = "./" + path;
    }

    // Convert Windows flags to POSIX flags
    int flags = O_CLOEXEC;

    if ((DesiredAccess & GENERIC_READ) && (DesiredAccess & GENERIC_WRITE)) {
        flags |= O_RDWR;
    } else if (DesiredAccess & GENERIC_WRITE) {
        flags |= O_WRONLY;
    } else {
        flags |= O_RDONLY;
    }

    switch (CreateDisposition) {
        case FILE_CREATE:
            flags |= O_CREAT | O_EXCL;
            break;
        case FILE_OPEN_IF:
            flags |= O_CREAT;
            break;
        case FILE_OVERWRITE:
            flags |= O_TRUNC;
            break;
        case FILE_OVERWRITE_IF:
            flags |= O_CREAT | O_TRUNC;
            break;
        case FILE_SUPERSEDE:
            flags |= O_CREAT | O_TRUNC;
            break;
        case FILE_OPEN:
        default:
            break;
    }

    if (CreateOptions & FILE_NON_DIRECTORY_FILE) {
        flags |= O_NOFOLLOW;
    }
    if (CreateOptions & FILE_DIRECTORY_FILE) {
        flags |= O_DIRECTORY;
    }
    if (CreateOptions & FILE_SYNCHRONOUS_IO_ALERT ||
        CreateOptions & FILE_SYNCHRONOUS_IO_NONALERT) {
        flags |= O_SYNC;
    }
    if (CreateOptions & FILE_WRITE_THROUGH) {
        flags |= O_DSYNC;
    }

    mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
    int fd = open(path.c_str(), flags, mode);
    if (fd < 0) {
        return errno_to_ntstatus(errno);
    }

    DEVICE_TYPE device_type = (CreateOptions & FILE_DIRECTORY_FILE) ?
                             FILE_DEVICE_FILE_SYSTEM : FILE_DEVICE_DISK;

    auto device = std::make_shared<DeviceHandle>(fd, device_type, path, CreateOptions,
                                                CreateDisposition, DesiredAccess,
                                                ShareAccess, FileAttributes);

    HANDLE handle = reinterpret_cast<HANDLE>(device.get());

    std::shared_lock lock(g_processes[g_tls.process].process_mutex);
    g_processes[g_tls.process].device_handles[handle] = std::move(device);
    lock.unlock();

    // Write handle to child memory
    uintptr_t handle_ptr = reinterpret_cast<uintptr_t>(FileHandle);
    if (!memory_mgr.write(handle_ptr, handle)) {
        close_device_handle(g_tls.process, handle);
        return STATUS_ACCESS_VIOLATION;
    }

    // Write IO status block
    IO_STATUS_BLOCK status_block;
    status_block.Status = STATUS_SUCCESS;
    status_block.Information = (CreateDisposition == FILE_CREATE) ? FILE_CREATED : FILE_OPENED;

    uintptr_t status_ptr = reinterpret_cast<uintptr_t>(IoStatusBlock);
    if (!memory_mgr.write(status_ptr, status_block)) {
        close_device_handle(g_tls.process, handle);
        return STATUS_ACCESS_VIOLATION;
    }

    return STATUS_SUCCESS;
}

NTSTATUS NTAPI _NtOpenFile(
    ChildMemoryManager& memory_mgr,
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG ShareAccess,
    ULONG OpenOptions) {

    return _NtCreateFile(memory_mgr, FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
                       nullptr, 0, ShareAccess, FILE_OPEN, OpenOptions, nullptr, 0);
}

NTSTATUS NTAPI _NtReadFile(
    ChildMemoryManager& memory_mgr,
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key) {

    trace("_NtReadFile called with handle ", FileHandle, ", length ", Length);

    DeviceHandle* device = get_device_handle(g_tls.process, FileHandle);
    if (!device) {
        return STATUS_INVALID_HANDLE;
    }

    if (!device->is_valid()) {
        return STATUS_INVALID_HANDLE;
    }

    // Read ByteOffset from child memory if provided
    off_t offset = -1;
    if (ByteOffset) {
        uintptr_t offset_ptr = reinterpret_cast<uintptr_t>(ByteOffset);
        auto offset_val = memory_mgr.read<LARGE_INTEGER>(offset_ptr);
        if (!offset_val) {
            return STATUS_ACCESS_VIOLATION;
        }
        if (offset_val->QuadPart != -1) {
            offset = offset_val->QuadPart;
        }
    }

    // Handle overlapped I/O
    bool overlapped = (device->options & FILE_FLAG_OVERLAPPED) != 0;
    if (overlapped && !IoStatusBlock) {
        return STATUS_INVALID_PARAMETER;
    }

    // Handle unbuffered I/O alignment requirements
    if (device->options & FILE_FLAG_NO_BUFFERING) {
        if (reinterpret_cast<uintptr_t>(Buffer) % 512 != 0 || Length % 512 != 0) {
            return STATUS_INVALID_PARAMETER;
        }
        if (offset != -1 && (offset % 512 != 0)) {
            return STATUS_INVALID_PARAMETER;
        }
    }

    // Read data from child memory buffer
    std::vector<uint8_t> temp_buffer(Length);
    uintptr_t buffer_ptr = reinterpret_cast<uintptr_t>(Buffer);

    for (ULONG i = 0; i < Length; i += sizeof(long)) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, memory_mgr.child_, buffer_ptr + i, NULL);
        if (word == -1 && errno != 0) {
            return STATUS_ACCESS_VIOLATION;
        }

        size_t chunk_size = min(sizeof(long), static_cast<size_t>(Length - i));
        memcpy(temp_buffer.data() + i, &word, chunk_size);
    }

    ssize_t bytes_written;
    if (offset != -1) {
        bytes_written = pwrite(device->linux_fd, temp_buffer.data(), Length, offset);
    } else {
        bytes_written = write(device->linux_fd, temp_buffer.data(), Length);
    }

    if (bytes_written < 0) {
        if ((errno == EAGAIN || errno == EWOULDBLOCK) && overlapped) {
            if (IoStatusBlock) {
                IO_STATUS_BLOCK status_block;
                status_block.Status = STATUS_PENDING;
                status_block.Information = 0;

                uintptr_t status_ptr = reinterpret_cast<uintptr_t>(IoStatusBlock);
                memory_mgr.write(status_ptr, status_block);
            }
            return STATUS_PENDING;
        }
        return errno_to_ntstatus(errno);
    }

    if (IoStatusBlock) {
        IO_STATUS_BLOCK status_block;
        status_block.Status = STATUS_SUCCESS;
        status_block.Information = bytes_written;

        uintptr_t status_ptr = reinterpret_cast<uintptr_t>(IoStatusBlock);
        if (!memory_mgr.write(status_ptr, status_block)) {
            return STATUS_ACCESS_VIOLATION;
        }
    }

    // Handle completion notifications
    if (overlapped && Event) {
        _NtSetEvent(memory_mgr, Event, nullptr);
    }
    if (overlapped && ApcRoutine) {
        _NtQueueApcThread(memory_mgr, reinterpret_cast<HANDLE>(-2),
                       ApcRoutine,
                       ApcContext,
                       IoStatusBlock,
                       0);
    }

    return STATUS_SUCCESS;
}

NTSTATUS NTAPI _NtReadFileScatter(
    ChildMemoryManager& memory_mgr,
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PFILE_SEGMENT_ELEMENT SegmentArray,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key) {

    trace("_NtReadFileScatter called");

    if (!SegmentArray || Length == 0 || Length % PAGE_SIZE != 0) {
        return STATUS_INVALID_PARAMETER;
    }

    DeviceHandle* device = get_device_handle(g_tls.process, FileHandle);
    if (!device) {
        return STATUS_INVALID_HANDLE;
    }

    // Read segment array from child memory
    uintptr_t segments_ptr = reinterpret_cast<uintptr_t>(SegmentArray);
    size_t num_segments = Length / PAGE_SIZE;
    std::vector<FILE_SEGMENT_ELEMENT> segments(num_segments);

    for (size_t i = 0; i < num_segments; i++) {
        auto segment = memory_mgr.read<FILE_SEGMENT_ELEMENT>(segments_ptr + i * sizeof(FILE_SEGMENT_ELEMENT));
        if (!segment || !segment->Buffer) {
            return STATUS_INVALID_PARAMETER;
        }
        segments[i] = *segment;
    }

    // Read ByteOffset from child memory if provided
    off_t offset = -1;
    if (ByteOffset) {
        uintptr_t offset_ptr = reinterpret_cast<uintptr_t>(ByteOffset);
        auto offset_val = memory_mgr.read<LARGE_INTEGER>(offset_ptr);
        if (!offset_val) {
            return STATUS_ACCESS_VIOLATION;
        }
        if (offset_val->QuadPart != -1) {
            offset = offset_val->QuadPart;
        }
    }

    std::vector<iovec> iovecs;
    std::vector<std::vector<uint8_t>> buffers(num_segments);
    iovecs.reserve(num_segments);

    for (size_t i = 0; i < num_segments; i++) {
        buffers[i].resize(PAGE_SIZE);
        iovecs.push_back({buffers[i].data(), PAGE_SIZE});
    }

    ssize_t bytes_read;
    if (offset != -1) {
        bytes_read = preadv(device->linux_fd, iovecs.data(), iovecs.size(), offset);
    } else {
        bytes_read = readv(device->linux_fd, iovecs.data(), iovecs.size());
    }

    if (bytes_read < 0) {
        return errno_to_ntstatus(errno);
    }

    // Write data to child memory segments
    ssize_t remaining = bytes_read;
    for (size_t i = 0; i < num_segments && remaining > 0; i++) {
        size_t chunk_size = min(static_cast<size_t>(remaining), static_cast<size_t>(PAGE_SIZE));
        uintptr_t segment_ptr = reinterpret_cast<uintptr_t>(segments[i].Buffer);

        for (size_t j = 0; j < chunk_size; j += sizeof(long)) {
            size_t copy_size = min(sizeof(long), chunk_size - j);
            long word = 0;
            memcpy(&word, buffers[i].data() + j, copy_size);

            if (ptrace(PTRACE_POKEDATA, memory_mgr.child_, segment_ptr + j, word) == -1) {
                return STATUS_ACCESS_VIOLATION;
            }
        }

        remaining -= chunk_size;
    }

    if (IoStatusBlock) {
        IO_STATUS_BLOCK status_block;
        status_block.Status = STATUS_SUCCESS;
        status_block.Information = bytes_read;

        uintptr_t status_ptr = reinterpret_cast<uintptr_t>(IoStatusBlock);
        if (!memory_mgr.write(status_ptr, status_block)) {
            return STATUS_ACCESS_VIOLATION;
        }
    }

    if (Event) {
        _NtSetEvent(memory_mgr, Event, nullptr);
    }
    if (ApcRoutine) {
        _NtQueueApcThread(memory_mgr, reinterpret_cast<HANDLE>(-2),
            ApcRoutine,
            ApcContext,
            IoStatusBlock,
            0);
    }

    return STATUS_SUCCESS;
}

NTSTATUS NTAPI _NtFlushBuffersFile(
    ChildMemoryManager& memory_mgr,
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock) {

    trace("_NtFlushBuffersFile called");

    DeviceHandle* device = get_device_handle(g_tls.process, FileHandle);
    if (!device) {
        return STATUS_INVALID_HANDLE;
    }

    if (fsync(device->linux_fd) < 0) {
        return errno_to_ntstatus(errno);
    }

    if (IoStatusBlock) {
        IO_STATUS_BLOCK status_block;
        status_block.Status = STATUS_SUCCESS;
        status_block.Information = 0;

        uintptr_t status_ptr = reinterpret_cast<uintptr_t>(IoStatusBlock);
        if (!memory_mgr.write(status_ptr, status_block)) {
            return STATUS_ACCESS_VIOLATION;
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS NTAPI _NtWriteFile(
    ChildMemoryManager& memory_mgr,
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key) {
    trace("_NtWriteFile called with handle ", FileHandle, ", length ", Length);

    DeviceHandle* device = get_device_handle(g_tls.process, FileHandle);
    if (!device) {
        return STATUS_INVALID_HANDLE;
    }

    if (!device->is_valid()) {
        return STATUS_INVALID_HANDLE;
    }

    // Read ByteOffset from child memory if provided
    off_t offset = -1;
    if (ByteOffset) {
        uintptr_t offset_ptr = reinterpret_cast<uintptr_t>(ByteOffset);
        auto offset_val = memory_mgr.read<LARGE_INTEGER>(offset_ptr);
        if (!offset_val) {
            return STATUS_ACCESS_VIOLATION;
        }
        if (offset_val->QuadPart != -1) {
            offset = offset_val->QuadPart;
        }
    }

    // Handle overlapped I/O
    bool overlapped = (device->options & FILE_FLAG_OVERLAPPED) != 0;
    if (overlapped && !IoStatusBlock) {
        return STATUS_INVALID_PARAMETER;
    }

    // Handle unbuffered I/O alignment requirements
    if (device->options & FILE_FLAG_NO_BUFFERING) {
        if (reinterpret_cast<uintptr_t>(Buffer) % 512 != 0 || Length % 512 != 0) {
            return STATUS_INVALID_PARAMETER;
        }
        if (offset != -1 && (offset % 512 != 0)) {
            return STATUS_INVALID_PARAMETER;
        }
    }

    // Read data from child memory buffer
    std::vector<uint8_t> temp_buffer(Length);
    uintptr_t buffer_ptr = reinterpret_cast<uintptr_t>(Buffer);

    for (ULONG i = 0; i < Length; i += sizeof(long)) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, memory_mgr.child_, buffer_ptr + i, NULL);
        if (word == -1 && errno != 0) {
            return STATUS_ACCESS_VIOLATION;
        }

        size_t chunk_size = min(sizeof(long), static_cast<size_t>(Length - i));
        memcpy(temp_buffer.data() + i, &word, chunk_size);
    }
    ssize_t bytes_written;
    if (offset != -1) {
        bytes_written = pwrite(device->linux_fd, temp_buffer.data(), Length, offset);
    } else {
        bytes_written = write(device->linux_fd, temp_buffer.data(), Length);
    }
    if (bytes_written < 0) {
        if ((errno == EAGAIN || errno == EWOULDBLOCK) && overlapped) {
            if (IoStatusBlock) {
                IO_STATUS_BLOCK status_block;
                status_block.Status = STATUS_PENDING;
                status_block.Information = 0;

                uintptr_t status_ptr = reinterpret_cast<uintptr_t>(IoStatusBlock);
                if (memory_mgr.write(status_ptr, status_block) == false) {
                    return STATUS_ACCESS_VIOLATION;
                }
            }
            return STATUS_PENDING;
        }
        return errno_to_ntstatus(errno);
    }
    if (IoStatusBlock) {
        IO_STATUS_BLOCK status_block;
        status_block.Status = STATUS_SUCCESS;
        status_block.Information = bytes_written;

        uintptr_t status_ptr = reinterpret_cast<uintptr_t>(IoStatusBlock);
        if (!memory_mgr.write(status_ptr, status_block)) {
            return STATUS_ACCESS_VIOLATION;
        }
    }
    // Handle completion notifications
    if (overlapped && Event) {
        _NtSetEvent(memory_mgr, Event, nullptr);
    }
    if (overlapped && ApcRoutine) {
        _NtQueueApcThread(memory_mgr, reinterpret_cast<HANDLE>(-2),
                       ApcRoutine,
                       ApcContext,
                       IoStatusBlock,
                       0);
    }
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI _NtWriteFileGather(
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

    DeviceHandle* device = get_device_handle(g_tls.process, FileHandle);
    if (!device) {
        return STATUS_INVALID_HANDLE;
    }

    std::vector<iovec> iovecs;
    iovecs.reserve(Length / PAGE_SIZE);

    for (ULONG i = 0; i < Length / PAGE_SIZE; i++) {
        if (!SegmentArray[i].Buffer) {
            return STATUS_INVALID_PARAMETER;
        }
        iovecs.push_back({SegmentArray[i].Buffer, PAGE_SIZE});
    }

    ssize_t bytes_written;
    if (ByteOffset && ByteOffset->QuadPart != -1) {
        bytes_written = pwritev(device->linux_fd, iovecs.data(), iovecs.size(), ByteOffset->QuadPart);
    } else {
        bytes_written = writev(device->linux_fd, iovecs.data(), iovecs.size());
    }

    if (bytes_written < 0) {
        return errno_to_ntstatus(errno);
    }

    if (IoStatusBlock) {
        IoStatusBlock->Status = STATUS_SUCCESS;
        IoStatusBlock->Information = bytes_written;
    }

    if (Event) {
        _NtSetEvent(mgr, Event, nullptr);
    }
    if (ApcRoutine) {
        _NtQueueApcThread(mgr, reinterpret_cast<HANDLE>(-2),
                       ApcRoutine,
                       ApcContext,
                       IoStatusBlock,
                       0);
    }

    return STATUS_SUCCESS;
}

// System Information Functions
static void get_basic_info(SYSTEM_BASIC_INFORMATION* info) {
    memset(info, 0, sizeof(*info));

    info->NumberOfProcessors = sysconf(_SC_NPROCESSORS_ONLN);
    info->ActiveProcessorsAffinityMask = (1ULL << info->NumberOfProcessors) - 1;
    info->PageSize = sysconf(_SC_PAGESIZE);
    info->AllocationGranularity = info->PageSize;
    info->MmLowestPhysicalPage = 1;
    info->MmHighestPhysicalPage = sysconf(_SC_PHYS_PAGES);
    info->MmNumberOfPhysicalPages = info->MmHighestPhysicalPage;
    info->LowestUserAddress = reinterpret_cast<void*>(0x10000);
    info->HighestUserAddress = reinterpret_cast<void*>(0x7FFFFFFEFFFF);
}

static void get_performance_info(SYSTEM_PERFORMANCE_INFORMATION* info) {
    memset(info, 0, sizeof(*info));

    if (FILE* uptime_file = fopen("/proc/uptime", "r")) {
        double uptime, idle_time;
        if (fscanf(uptime_file, "%lf %lf", &uptime, &idle_time) == 2) {
            info->IdleTime.QuadPart = static_cast<LONGLONG>(idle_time * 10000000);
        }
        fclose(uptime_file);
    }

    if (FILE* meminfo_file = fopen("/proc/meminfo", "r")) {
        unsigned long long total_mem = 0, free_mem = 0, available_mem = 0;
        unsigned long long total_swap = 0, free_swap = 0;
        char line[256];

        while (fgets(line, sizeof(line), meminfo_file)) {
            unsigned long long value;
            if (sscanf(line, "MemTotal: %llu kB", &value) == 1) {
                total_mem = value * 1024;
            } else if (sscanf(line, "MemFree: %llu kB", &value) == 1) {
                free_mem = value * 1024;
            } else if (sscanf(line, "MemAvailable: %llu kB", &value) == 1) {
                available_mem = value * 1024;
            } else if (sscanf(line, "SwapTotal: %llu kB", &value) == 1) {
                total_swap = value * 1024;
            } else if (sscanf(line, "SwapFree: %llu kB", &value) == 1) {
                free_swap = value * 1024;
            }
        }
        fclose(meminfo_file);

        if (available_mem > 0) {
            free_mem = available_mem;
        }

        info->AvailablePages = free_mem / PAGE_SIZE;
        info->TotalCommittedPages = (total_mem + total_swap - free_mem - free_swap) / PAGE_SIZE;
        info->TotalCommitLimit = (total_mem + total_swap) / PAGE_SIZE;
    }
}

static void get_processor_info(SYSTEM_CPU_INFORMATION* info) {
    memset(info, 0, sizeof(*info));

    info->MaximumProcessors = sysconf(_SC_NPROCESSORS_ONLN);
    info->ProcessorArchitecture = PROCESSOR_ARCHITECTURE_AMD64;
    info->ProcessorLevel = 6;
    info->ProcessorRevision = 0;

    // Set common x86-64 features
    info->ProcessorFeatureBits = PF_FLOATING_POINT_PRECISION_ERRATA |
                                PF_COMPARE_EXCHANGE_DOUBLE |
                                PF_MMX_INSTRUCTIONS_AVAILABLE |
                                PF_XMMI_INSTRUCTIONS_AVAILABLE |
                                PF_RDTSC_INSTRUCTION_AVAILABLE |
                                PF_PAE_ENABLED |
                                PF_XMMI64_INSTRUCTIONS_AVAILABLE |
                                PF_SSE_DAZ_MODE_AVAILABLE |
                                PF_NX_ENABLED |
                                PF_SSE3_INSTRUCTIONS_AVAILABLE |
                                PF_COMPARE_EXCHANGE128 |
                                PF_XSAVE_ENABLED;
}

NTSTATUS NTAPI _NtQuerySystemInformation(
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
                    get_basic_info(&info);

                    uintptr_t info_ptr = reinterpret_cast<uintptr_t>(SystemInformation);
                    if (!memory_mgr.write(info_ptr, info)) {
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
                    SYSTEM_PERFORMANCE_INFORMATION info;
                    get_performance_info(&info);

                    uintptr_t info_ptr = reinterpret_cast<uintptr_t>(SystemInformation);
                    if (!memory_mgr.write(info_ptr, info)) {
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
                    _NtQuerySystemTime(memory_mgr, &system_time);
                    time_info.BootTime = system_time;
                    time_info.TimeZoneBias.QuadPart = 0;  // UTC
                    time_info.TimeZoneId = 0;

                    uintptr_t info_ptr = reinterpret_cast<uintptr_t>(SystemInformation);
                    if (!memory_mgr.write(info_ptr, time_info)) {
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
            // Simplified process enumeration
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
                        current->CreationTime.QuadPart = process.creation_time;
                        current->UniqueProcessId = reinterpret_cast<HANDLE>(process.process_id);
                        current->ParentProcessId = process.parent_process;
                        current->HandleCount = process.device_handles.size() + process.events.size() +
                                                process.threads.size() + process.completion_ports.size() +
                                                process.file_mappings.size() + process.sections.size();
                        current->dwThreadCount = process.threads.size();
                        current->dwBasePriority = process.priority_class;

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

NTSTATUS NTAPI _NtClose(
    ChildMemoryManager& memory_mgr,
    HANDLE Handle) {

    trace("_NtClose called with handle ", Handle);

    if (!Handle || Handle == INVALID_HANDLE_VALUE) {
        return STATUS_INVALID_HANDLE;
    }

    std::shared_lock lock(g_processes[g_tls.process].process_mutex);
    auto& process = g_processes[g_tls.process];

    // Try different handle types
    if (process.device_handles.erase(Handle)) {
        return STATUS_SUCCESS;
    }
    if (process.events.erase(Handle)) {
        return STATUS_SUCCESS;
    }
    if (process.threads.contains(Handle)) {
        auto thread_ctx = process.threads[Handle];
        if (thread_ctx && thread_ctx->native_thread && thread_ctx->native_thread->joinable()) {
            thread_ctx->should_terminate = true;
            thread_ctx->native_thread->join();
        }
        process.threads.erase(Handle);
        return STATUS_SUCCESS;
    }
    if (process.completion_ports.erase(Handle)) {
        return STATUS_SUCCESS;
    }
    if (process.sections.erase(Handle)) {
        return STATUS_SUCCESS;
    }
    if (process.file_mappings.erase(Handle)) {
        return STATUS_SUCCESS;
    }
    if (g_registry_manager.close_key(Handle)) {
        return STATUS_SUCCESS;
    }

    return STATUS_INVALID_HANDLE;
}

NTSTATUS NTAPI _NtSetInformationFile(
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

    DeviceHandle* device = get_device_handle(g_tls.process, FileHandle);
    if (!device || !device->is_valid()) {
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
            if (fstat(device->linux_fd, &st) != 0) {
                status = errno_to_ntstatus(errno);
                break;
            }

            // Set timestamps if provided (non-zero values)
            if (basic_info->LastWriteTime.QuadPart != 0 ||
                basic_info->LastAccessTime.QuadPart != 0) {

                struct timespec times[2];

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

                if (futimens(device->linux_fd, times) != 0) {
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
                    new_mode |= S_IWUSR; // Restore write permission for owner
                }

                if (fchmod(device->linux_fd, new_mode) != 0) {
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

            // Set file position
            off_t new_pos = lseek(device->linux_fd, pos_info->CurrentByteOffset.QuadPart, SEEK_SET);
            if (new_pos == -1) {
                status = errno_to_ntstatus(errno);
                break;
            }

            // Update cached position
            device->file_position.QuadPart = new_pos;
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

            // Truncate or extend file
            if (ftruncate(device->linux_fd, eof_info->EndOfFile.QuadPart) != 0) {
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

            // Pre-allocate space (best effort)
            if (fallocate(device->linux_fd, 0, 0, alloc_info->AllocationSize.QuadPart) != 0) {
                // fallocate might not be supported, try ftruncate as fallback
                struct stat st;
                if (fstat(device->linux_fd, &st) == 0 &&
                    st.st_size < alloc_info->AllocationSize.QuadPart) {
                    if (ftruncate(device->linux_fd, alloc_info->AllocationSize.QuadPart) != 0) {
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
                device->file_attributes |= FILE_ATTRIBUTE_TEMPORARY; // Use as a delete flag
                trace("File marked for deletion on close");
            } else {
                device->file_attributes &= ~FILE_ATTRIBUTE_TEMPORARY;
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

            uintptr_t info_ptr = reinterpret_cast<uintptr_t>(FileInformation);
            auto mode_info = memory_mgr.read<FILE_MODE_INFORMATION>(info_ptr);
            if (!mode_info) {
                status = STATUS_ACCESS_VIOLATION;
                break;
            }

            // Update file mode flags
            device->options = mode_info->Mode;

            // Apply some mode flags to the file descriptor
            int flags = fcntl(device->linux_fd, F_GETFL);
            if (flags != -1) {
                if (mode_info->Mode & FILE_SYNCHRONOUS_IO_NONALERT) {
                    flags |= O_SYNC;
                } else {
                    flags &= ~O_SYNC;
                }
                fcntl(device->linux_fd, F_SETFL, flags);
            }

            bytes_used = sizeof(FILE_MODE_INFORMATION);
            break;
        }

        case FileCompletionInformation: {
            if (Length < sizeof(FILE_COMPLETION_INFORMATION)) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            uintptr_t info_ptr = reinterpret_cast<uintptr_t>(FileInformation);
            auto comp_info = memory_mgr.read<FILE_COMPLETION_INFORMATION>(info_ptr);
            if (!comp_info) {
                status = STATUS_ACCESS_VIOLATION;
                break;
            }

            // Associate file with I/O completion port
            std::shared_lock lock(g_processes[g_tls.process].process_mutex);
            if (auto it = g_processes[g_tls.process].completion_ports.find(comp_info->CompletionPort); it == g_processes[g_tls.process].completion_ports.end()) {
                status = STATUS_INVALID_HANDLE;
                break;
            }

            // Store completion port association (simplified)
            trace("File associated with completion port ", comp_info->CompletionPort,
                  ", key: ", comp_info->CompletionKey);

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
            if (snprintf(current_path, sizeof(current_path), "/proc/self/fd/%d", device->linux_fd) >= sizeof(current_path)) {
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
            device->device_path = new_path;
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

// Implementation of NtQueryInformationFile
NTSTATUS NTAPI _NtQueryInformationFile(
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

    DeviceHandle* device = get_device_handle(g_tls.process, FileHandle);
    if (!device || !device->is_valid()) {
        return STATUS_INVALID_HANDLE;
    }

    NTSTATUS status = STATUS_SUCCESS;
    ULONG bytes_returned = 0;
    ULONG required_length = 0;

    // Get file stats
    struct stat st{};
    if (fstat(device->linux_fd, &st) != 0) {
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
                (static_cast<ULONGLONG>(st.st_ctim.tv_sec) * 10000000ULL +
                 st.st_ctim.tv_nsec / 100ULL) + 116444736000000000ULL;

            basic_info.LastAccessTime.QuadPart =
                (static_cast<ULONGLONG>(st.st_atim.tv_sec) * 10000000ULL +
                 st.st_atim.tv_nsec / 100ULL) + 116444736000000000ULL;

            basic_info.LastWriteTime.QuadPart =
                (static_cast<ULONGLONG>(st.st_mtim.tv_sec) * 10000000ULL +
                 st.st_mtim.tv_nsec / 100ULL) + 116444736000000000ULL;

            basic_info.ChangeTime = basic_info.LastWriteTime;

            // Convert file attributes
            basic_info.FileAttributes = FILE_ATTRIBUTE_NORMAL;
            if (S_ISDIR(st.st_mode)) {
                basic_info.FileAttributes |= FILE_ATTRIBUTE_DIRECTORY;
            }
            if (!(st.st_mode & S_IWUSR)) {
                basic_info.FileAttributes |= FILE_ATTRIBUTE_READONLY;
            }
            if (device->file_attributes & FILE_ATTRIBUTE_TEMPORARY) {
                basic_info.FileAttributes |= FILE_ATTRIBUTE_TEMPORARY;
            }

            uintptr_t info_ptr = reinterpret_cast<uintptr_t>(FileInformation);
            if (!memory_mgr.write(info_ptr, basic_info)) {
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

            FILE_STANDARD_INFORMATION std_info;
            memset(&std_info, 0, sizeof(std_info));

            std_info.AllocationSize.QuadPart = st.st_blocks * 512; // Convert blocks to bytes
            std_info.EndOfFile.QuadPart = st.st_size;
            std_info.NumberOfLinks = st.st_nlink;
            std_info.DeletePending = (device->file_attributes & FILE_ATTRIBUTE_TEMPORARY) != 0;
            std_info.Directory = S_ISDIR(st.st_mode);

            auto info_ptr = reinterpret_cast<uintptr_t>(FileInformation);
            if (!memory_mgr.write(info_ptr, std_info)) {
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
            off_t current_pos = lseek(device->linux_fd, 0, SEEK_CUR);
            if (current_pos == -1) {
                status = errno_to_ntstatus(errno);
                break;
            }

            pos_info.CurrentByteOffset.QuadPart = current_pos;
            device->file_position.QuadPart = current_pos; // Update cache

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
            mode_info.Mode = device->options;

            auto info_ptr = reinterpret_cast<uintptr_t>(FileInformation);
            if (!memory_mgr.write(info_ptr, mode_info)) {
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
            if (device->options & FILE_FLAG_NO_BUFFERING) {
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

NTSTATUS NTAPI _NtCreateProcess(
    const ChildMemoryManager& memory_mgr,
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ParentProcess,
    BOOLEAN InheritObjectTable,
    HANDLE SectionHandle,
    HANDLE DebugPort,
    HANDLE ExceptionPort) {

    trace("_NtCreateProcess called");

    // Fork the process
    pid_t child_pid = fork();
    if (child_pid == -1) {
        error("Fork failed: ", strerror(errno));
        return STATUS_UNSUCCESSFUL;
    }

    if (child_pid == 0) {
        // Child process - set up IPC client
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
            error("PTRACE_TRACEME failed");
            exit(1);
        }

        // Get parent socket path from environment
        const char* parent_socket = getenv("PARENT_IPC_SOCKET");
        if (!parent_socket) {
            error("No parent IPC socket specified");
            exit(1);
        }

        IPCManager child_ipc(false);
        if (!child_ipc.connect_to_server(parent_socket)) {
            error("Failed to connect to parent IPC");
            exit(1);
        }

        trace("Child connected to parent IPC");

        // Enter the message loop
        child_ipc.child_listen_loop();
    }

    // Parent process - set up tracking
    auto proc_handle = reinterpret_cast<HANDLE>(static_cast<uintptr_t>(child_pid));
    ProcessContext* new_process = &g_processes[proc_handle];

    new_process->native_process_id = child_pid;
    new_process->process_id = static_cast<DWORD>(child_pid);
    new_process->windows_process_handle = proc_handle;
    new_process->creation_time = get_system_time_as_file_time();
    new_process->linux_child_pid = child_pid;

    // Create main thread for IPC
    new_process->main_thread = std::make_unique<ProcessMainThread>(new_process);
    new_process->ipc_socket_path = new_process->main_thread->get_socket_path();

    // Set environment for child
    std::string socket_env = "PARENT_IPC_SOCKET=" + new_process->ipc_socket_path;
    putenv(const_cast<char*>(socket_env.c_str()));

    // Wait for child to stop
    int status;
    if (waitpid(child_pid, &status, WUNTRACED) == -1) {
        error("waitpid failed");
        kill(child_pid, SIGKILL);
        g_processes.erase(proc_handle);
        return STATUS_UNSUCCESSFUL;
    }

    // Write handle to parent memory
    if (ProcessHandle) {
        uintptr_t handle_ptr = reinterpret_cast<uintptr_t>(ProcessHandle);
        if (!memory_mgr.write(handle_ptr, proc_handle)) {
            kill(child_pid, SIGKILL);
            g_processes.erase(proc_handle);
            return STATUS_ACCESS_VIOLATION;
        }
    }

    trace("Created process: PID=", child_pid);
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI _NtCreateProcessEx(
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

NTSTATUS NTAPI _NtTerminateProcess(
    ChildMemoryManager& memory_mgr,
    HANDLE ProcessHandle,
    NTSTATUS ExitStatus) {

    trace("_NtTerminateProcess called");



    return STATUS_SUCCESS;
}

NTSTATUS NTAPI _NtOpenProcess(
    ChildMemoryManager& memory_mgr,
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId) {

    trace("_NtOpenProcess called");



    return STATUS_INVALID_CID;
}

NTSTATUS NTAPI _NtSuspendProcess(
    ChildMemoryManager& memory_mgr,
    HANDLE ProcessHandle) {

    trace("_NtSuspendProcess called");

    return STATUS_SUCCESS;
}

NTSTATUS NTAPI _NtResumeProcess(
    ChildMemoryManager& memory_mgr,
    HANDLE ProcessHandle) {

    trace("_NtResumeProcess called");


    trace("Resumed process: PID=", process->native_process_id);
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI _NtCreateUserProcess(
    ChildMemoryManager& memory_mgr,
    PHANDLE ProcessHandle,
    PHANDLE ThreadHandle,
    ACCESS_MASK ProcessDesiredAccess,
    ACCESS_MASK ThreadDesiredAccess,
    POBJECT_ATTRIBUTES ProcessObjectAttributes,
    POBJECT_ATTRIBUTES ThreadObjectAttributes,
    ULONG ProcessFlags,
    ULONG ThreadFlags,
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
    PPS_CREATE_INFO CreateInfo,
    PPS_ATTRIBUTE_LIST AttributeList) {

    trace("_NtCreateUserProcess called");



    trace("Created user process with initial thread");
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI _NtQueryInformationProcess(
    const ChildMemoryManager &memory_mgr,
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
            ProcessContext* proc_ctx = nullptr;

            if (!ProcessHandle || ProcessHandle == reinterpret_cast<HANDLE>(-1)) {
                proc_ctx = &g_processes[g_tls.process];
            } else {
                std::shared_lock lock(g_global_mutex);
                auto it = g_processes.find(ProcessHandle);
                if (it != g_processes.end()) {
                    proc_ctx = &it->second;
                }
            }

            if (!proc_ctx) {
                return STATUS_INVALID_HANDLE;
            }

            pbi.PebBaseAddress = g_current_peb;
            pbi.UniqueProcessId = proc_ctx->process_id;
            pbi.InheritedFromUniqueProcessId = g_processes[proc_ctx->parent_process].process_id;
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
                std::shared_lock lock(g_processes[g_tls.process].process_mutex);
                handle_count = static_cast<ULONG>(g_processes[g_tls.process].device_handles.size() +
                                                  g_processes[g_tls.process].threads.size() +
                                                  g_processes[g_tls.process].events.size() +
                                                  g_processes[g_tls.process].completion_ports.size() +
                                                  g_processes[g_tls.process].file_mappings.size() +
                                                  g_processes[g_tls.process].sections.size());
            } else {
                std::shared_lock lock(g_global_mutex);
                auto it = g_processes.find(ProcessHandle);
                if (it == g_processes.end()) {
                    return STATUS_INVALID_HANDLE;
                }
                std::shared_lock proc_lock(it->second.process_mutex);
                handle_count = static_cast<ULONG>(it->second.device_handles.size() +
                                                  it->second.threads.size() +
                                                  it->second.events.size() +
                                                  it->second.completion_ports.size() +
                                                  it->second.file_mappings.size());
            }

            uintptr_t info_ptr = reinterpret_cast<uintptr_t>(ProcessInformation);
            if (!memory_mgr.write(info_ptr, handle_count)) {
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

            uintptr_t info_ptr = reinterpret_cast<uintptr_t>(ProcessInformation);
            if (!memory_mgr.write(info_ptr, affinity_mask)) {
                return STATUS_ACCESS_VIOLATION;
            }

            if (ReturnLength) {
                uintptr_t ret_len_ptr = reinterpret_cast<uintptr_t>(ReturnLength);
                if (!memory_mgr.write(ret_len_ptr, sizeof(ULONG_PTR))) {
                    return STATUS_ACCESS_VIOLATION;
                }
            }

            return STATUS_SUCCESS;
        }
        case ProcessSessionInformation: {
            if (ProcessInformationLength < sizeof(ULONG)) {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            ULONG session_id = 0; // Default session

            uintptr_t info_ptr = reinterpret_cast<uintptr_t>(ProcessInformation);
            if (!memory_mgr.write(info_ptr, session_id)) {
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
        case ProcessWow64Information: {
            if (ProcessInformationLength < sizeof(PVOID)) {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            PVOID wow64_info = nullptr; // Not a WOW64 process

            uintptr_t info_ptr = reinterpret_cast<uintptr_t>(ProcessInformation);
            if (!memory_mgr.write(info_ptr, wow64_info)) {
                return STATUS_ACCESS_VIOLATION;
            }

            if (ReturnLength) {
                uintptr_t ret_len_ptr = reinterpret_cast<uintptr_t>(ReturnLength);
                if (!memory_mgr.write(ret_len_ptr, sizeof(PVOID))) {
                    return STATUS_ACCESS_VIOLATION;
                }
            }

            return STATUS_SUCCESS;
        }
        case ProcessImageFileName: {
            if (ProcessInformationLength < sizeof(UNICODE_STRING) + 1) {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            const std::u16string &image_path = g_processes[g_tls.process].image_path;
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
            uintptr_t info_ptr = reinterpret_cast<uintptr_t>(ProcessInformation);
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

            const std::u16string &image_path = g_processes[g_tls.process].image_path;
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

NTSTATUS NTAPI _NtCreateKey(
    ChildMemoryManager& memory_mgr,
    PHANDLE KeyHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG TitleIndex,
    PUNICODE_STRING Class,
    ULONG CreateOptions,
    PULONG Disposition) {

    trace("_NtCreateKey called");

    if (!KeyHandle || !ObjectAttributes) {
        return STATUS_INVALID_PARAMETER;
    }

    // Read ObjectAttributes from child memory
    auto obj_attr_ptr = reinterpret_cast<uintptr_t>(ObjectAttributes);
    auto obj_attr = memory_mgr.read<OBJECT_ATTRIBUTES>(obj_attr_ptr);
    if (!obj_attr) {
        return STATUS_ACCESS_VIOLATION;
    }

    std::string path;
    if (NTSTATUS status = parse_object_attributes(&obj_attr.value(), path); !NT_SUCCESS(status)) {
        return status;
    }

    std::wstring wpath = converter.from_bytes(path);

    bool created = false;
    HANDLE handle = g_registry_manager.create_key(wpath, created);

    if (!handle) {
        return STATUS_UNSUCCESSFUL;
    }

    // Write handle to child memory
    auto handle_ptr = reinterpret_cast<uintptr_t>(KeyHandle);
    if (!memory_mgr.write(handle_ptr, handle)) {
        g_registry_manager.close_key(handle);
        return STATUS_ACCESS_VIOLATION;
    }

    // Write disposition if requested
    if (Disposition) {
        ULONG disp = created ? REG_CREATED_NEW_KEY : REG_OPENED_EXISTING_KEY;
        auto disp_ptr = reinterpret_cast<uintptr_t>(Disposition);
        if (!memory_mgr.write(disp_ptr, disp)) {
            g_registry_manager.close_key(handle);
            return STATUS_ACCESS_VIOLATION;
        }
    }

    trace("Created/opened registry key: ", wpath, " (", (created ? "created" : "opened"), ")");
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI _NtOpenKey(
    ChildMemoryManager& memory_mgr,
    PHANDLE KeyHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes) {

    trace("_NtOpenKey called");

    if (!KeyHandle || !ObjectAttributes) {
        return STATUS_INVALID_PARAMETER;
    }

    uintptr_t obj_attr_ptr = reinterpret_cast<uintptr_t>(ObjectAttributes);
    auto obj_attr = memory_mgr.read<OBJECT_ATTRIBUTES>(obj_attr_ptr);
    if (!obj_attr) {
        return STATUS_ACCESS_VIOLATION;
    }

    std::string path;
    if (NTSTATUS status = parse_object_attributes(&obj_attr.value(), path); !NT_SUCCESS(status)) {
        return status;
    }

    std::wstring wpath = converter.from_bytes(path);
    HANDLE handle = g_registry_manager.open_key(wpath);

    if (!handle) {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    uintptr_t handle_ptr = reinterpret_cast<uintptr_t>(KeyHandle);
    if (!memory_mgr.write(handle_ptr, handle)) {
        g_registry_manager.close_key(handle);
        return STATUS_ACCESS_VIOLATION;
    }

    trace("Opened registry key: ", wpath);
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI _NtClose(
    ChildMemoryManager& memory_mgr,
    HANDLE Handle) {

    trace("_NtClose called with handle ", Handle);

    if (!Handle) {
        return STATUS_INVALID_HANDLE;
    }

    // Try different handle types
    if (g_registry_manager.close_key(Handle)) {
        return STATUS_SUCCESS;
    }

    std::shared_lock lock(g_processes[g_tls.process].process_mutex);
    if (g_processes[g_tls.process].device_handles.erase(Handle) ||
        g_processes[g_tls.process].events.erase(Handle) ||
        g_processes[g_tls.process].threads.erase(Handle) ||
        g_processes[g_tls.process].completion_ports.erase(Handle) ||
        g_processes[g_tls.process].file_mappings.erase(Handle)) {
        return STATUS_SUCCESS;
    }

    return STATUS_INVALID_HANDLE;
}

NTSTATUS NTAPI _NtDeleteKey(
    ChildMemoryManager& memory_mgr,
    HANDLE KeyHandle) {

    trace("_NtDeleteKey called");

    auto key = g_registry_manager.get_key(KeyHandle);
    if (!key) {
        return STATUS_INVALID_HANDLE;
    }

    if (g_registry_manager.delete_key(key->path)) {
        g_registry_manager.close_key(KeyHandle);
        return STATUS_SUCCESS;
    }

    return STATUS_UNSUCCESSFUL;
}

NTSTATUS NTAPI _NtFlushKey(
    ChildMemoryManager& memory_mgr,
    HANDLE KeyHandle) {

    trace("_NtFlushKey called");

    if (!g_registry_manager.get_key(KeyHandle)) {
        return STATUS_INVALID_HANDLE;
    }

    g_registry_manager.flush_key(KeyHandle);
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI _NtSetValueKey(
    ChildMemoryManager& memory_mgr,
    HANDLE KeyHandle,
    PUNICODE_STRING ValueName,
    ULONG TitleIndex,
    ULONG Type,
    PVOID Data,
    ULONG DataSize) {

    trace("_NtSetValueKey called");

    auto key = g_registry_manager.get_key(KeyHandle);
    if (!key) {
        return STATUS_INVALID_HANDLE;
    }

    // Read value name
    uintptr_t name_ptr = reinterpret_cast<uintptr_t>(ValueName);
    auto unicode_str = memory_mgr.read<UNICODE_STRING>(name_ptr);
    if (!unicode_str) {
        return STATUS_ACCESS_VIOLATION;
    }

    std::wstring value_name;
    if (unicode_str->Length > 0 && unicode_str->Buffer) {
        auto wname = memory_mgr.read_wstring(
            reinterpret_cast<uintptr_t>(unicode_str->Buffer),
            unicode_str->Length / sizeof(WCHAR));
        if (!wname) {
            return STATUS_ACCESS_VIOLATION;
        }
        for (char16_t c : *wname) value_name.push_back(static_cast<wchar_t>(c));
    }

    // Read data
    std::vector<uint8_t> data_bytes(DataSize);
    uintptr_t data_ptr = reinterpret_cast<uintptr_t>(Data);
    for (ULONG i = 0; i < DataSize; i += sizeof(long)) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, memory_mgr.child_, data_ptr + i, NULL);
        if (word == -1 && errno != 0) {
            return STATUS_ACCESS_VIOLATION;
        }
        size_t chunk_size = min(sizeof(long), static_cast<size_t>(DataSize - i));
        memcpy(data_bytes.data() + i, &word, chunk_size);
    }

    std::unique_lock lock(key->key_mutex);
    key->values[value_name] = std::move(data_bytes);
    key->value_types[value_name] = Type;
    key->update_write_time();

    trace("Set registry value: ", key->path, "\\", value_name);
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI _NtQueryValueKey(
    ChildMemoryManager& memory_mgr,
    HANDLE KeyHandle,
    PUNICODE_STRING ValueName,
    KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    PVOID KeyValueInformation,
    ULONG Length,
    PULONG ResultLength) {

    trace("_NtQueryValueKey called");

    auto key = g_registry_manager.get_key(KeyHandle);
    if (!key) {
        return STATUS_INVALID_HANDLE;
    }

    // Read value name
    uintptr_t name_ptr = reinterpret_cast<uintptr_t>(ValueName);
    auto unicode_str = memory_mgr.read<UNICODE_STRING>(name_ptr);
    if (!unicode_str) {
        return STATUS_ACCESS_VIOLATION;
    }

    std::wstring value_name;
    if (unicode_str->Length > 0 && unicode_str->Buffer) {
        auto wname = memory_mgr.read_wstring(
            reinterpret_cast<uintptr_t>(unicode_str->Buffer),
            unicode_str->Length / sizeof(WCHAR));
        if (!wname) {
            return STATUS_ACCESS_VIOLATION;
        }
        for (char16_t c : *wname) value_name.push_back(static_cast<wchar_t>(c));
    }

    std::shared_lock lock(key->key_mutex);

    if (!key->values.contains(value_name)) {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    const auto& data = key->values[value_name];
    DWORD type = key->value_types[value_name];

    ULONG required_length = sizeof(KEY_VALUE_PARTIAL_INFORMATION) + data.size();

    if (ResultLength) {
        uintptr_t result_ptr = reinterpret_cast<uintptr_t>(ResultLength);
        if (!memory_mgr.write(result_ptr, required_length)) {
            return STATUS_ACCESS_VIOLATION;
        }
    }

    if (Length < required_length) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    KEY_VALUE_PARTIAL_INFORMATION info;
    info.TitleIndex = 0;
    info.Type = type;
    info.DataLength = data.size();

    // Write info structure
    uintptr_t info_ptr = reinterpret_cast<uintptr_t>(KeyValueInformation);
    if (!memory_mgr.write(info_ptr, info)) {
        return STATUS_ACCESS_VIOLATION;
    }

    // Write data
    for (size_t i = 0; i < data.size(); i += sizeof(long)) {
        long word = 0;
        size_t chunk_size = min(sizeof(long), data.size() - i);
        memcpy(&word, data.data() + i, chunk_size);

        if (ptrace(PTRACE_POKEDATA, memory_mgr.child_,
                  info_ptr + offsetof(KEY_VALUE_PARTIAL_INFORMATION, Data) + i, word) == -1) {
            return STATUS_ACCESS_VIOLATION;
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS NTAPI _NtDeleteValueKey(
    ChildMemoryManager& memory_mgr,
    HANDLE KeyHandle,
    PUNICODE_STRING ValueName) {

    trace("_NtDeleteValueKey called");

    auto key = g_registry_manager.get_key(KeyHandle);
    if (!key) {
        return STATUS_INVALID_HANDLE;
    }

    uintptr_t name_ptr = reinterpret_cast<uintptr_t>(ValueName);
    auto unicode_str = memory_mgr.read<UNICODE_STRING>(name_ptr);
    if (!unicode_str) {
        return STATUS_ACCESS_VIOLATION;
    }

    std::wstring value_name;
    if (unicode_str->Length > 0 && unicode_str->Buffer) {
        auto wname = memory_mgr.read_wstring(
            reinterpret_cast<uintptr_t>(unicode_str->Buffer),
            unicode_str->Length / sizeof(WCHAR));
        if (!wname) {
            return STATUS_ACCESS_VIOLATION;
        }
        for (char16_t c : *wname) value_name.push_back(static_cast<wchar_t>(c));
    }

    std::unique_lock lock(key->key_mutex);

    if (key->values.erase(value_name) > 0) {
        key->value_types.erase(value_name);
        key->update_write_time();
        return STATUS_SUCCESS;
    }

    return STATUS_OBJECT_NAME_NOT_FOUND;
}

NTSTATUS NTAPI _NtEnumerateKey(
    ChildMemoryManager& memory_mgr,
    HANDLE KeyHandle,
    ULONG Index,
    KEY_INFORMATION_CLASS KeyInformationClass,
    PVOID KeyInformation,
    ULONG Length,
    PULONG ResultLength) {

    trace("_NtEnumerateKey called with index ", Index);

    auto key = g_registry_manager.get_key(KeyHandle);
    if (!key) {
        return STATUS_INVALID_HANDLE;
    }

    std::shared_lock lock(key->key_mutex);

    if (Index >= key->subkeys.size()) {
        return STATUS_NO_MORE_ENTRIES;
    }

    // Get the nth subkey
    auto it = key->subkeys.begin();
    std::advance(it, Index);
    const auto& [subkey_name, subkey] = *it;

    ULONG required_length = sizeof(KEY_BASIC_INFORMATION) +
                           (subkey_name.length() + 1) * sizeof(WCHAR);

    if (ResultLength) {
        uintptr_t result_ptr = reinterpret_cast<uintptr_t>(ResultLength);
        if (!memory_mgr.write(result_ptr, required_length)) {
            return STATUS_ACCESS_VIOLATION;
        }
    }

    if (Length < required_length) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    KEY_BASIC_INFORMATION info;
    info.LastWriteTime = subkey->last_write_time;
    info.TitleIndex = 0;
    info.NameLength = subkey_name.length() * sizeof(WCHAR);

    uintptr_t info_ptr = reinterpret_cast<uintptr_t>(KeyInformation);
    if (!memory_mgr.write(info_ptr, info)) {
        return STATUS_ACCESS_VIOLATION;
    }

    // Write name
    for (size_t i = 0; i < subkey_name.length(); i++) {
        WCHAR ch = subkey_name[i];
        uintptr_t char_ptr = info_ptr + offsetof(KEY_BASIC_INFORMATION, Name) + i * sizeof(WCHAR);
        if (ptrace(PTRACE_POKEDATA, memory_mgr.child_, char_ptr, ch) == -1) {
            return STATUS_ACCESS_VIOLATION;
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS NTAPI _NtEnumerateValueKey(
    ChildMemoryManager& memory_mgr,
    HANDLE KeyHandle,
    ULONG Index,
    KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    PVOID KeyValueInformation,
    ULONG Length,
    PULONG ResultLength) {

    trace("_NtEnumerateValueKey called with index ", Index);

    auto key = g_registry_manager.get_key(KeyHandle);
    if (!key) {
        return STATUS_INVALID_HANDLE;
    }

    std::shared_lock lock(key->key_mutex);

    if (Index >= key->values.size()) {
        return STATUS_NO_MORE_ENTRIES;
    }

    auto it = key->values.begin();
    std::advance(it, Index);
    const auto& [value_name, value_data] = *it;

    DWORD value_type = key->value_types[value_name];

    ULONG required_length = sizeof(KEY_VALUE_BASIC_INFORMATION) +
                           (value_name.length() + 1) * sizeof(WCHAR);

    if (ResultLength) {
        uintptr_t result_ptr = reinterpret_cast<uintptr_t>(ResultLength);
        if (!memory_mgr.write(result_ptr, required_length)) {
            return STATUS_ACCESS_VIOLATION;
        }
    }

    if (Length < required_length) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    KEY_VALUE_BASIC_INFORMATION info;
    info.TitleIndex = 0;
    info.Type = value_type;
    info.NameLength = value_name.length() * sizeof(WCHAR);

    uintptr_t info_ptr = reinterpret_cast<uintptr_t>(KeyValueInformation);
    if (!memory_mgr.write(info_ptr, info)) {
        return STATUS_ACCESS_VIOLATION;
    }

    // Write name
    for (size_t i = 0; i < value_name.length(); i++) {
        WCHAR ch = value_name[i];
        uintptr_t char_ptr = info_ptr + offsetof(KEY_VALUE_BASIC_INFORMATION, Name) + i * sizeof(WCHAR);
        if (ptrace(PTRACE_POKEDATA, memory_mgr.child_, char_ptr, ch) == -1) {
            return STATUS_ACCESS_VIOLATION;
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS NTAPI _NtQueryKey(
    ChildMemoryManager& memory_mgr,
    HANDLE KeyHandle,
    KEY_INFORMATION_CLASS KeyInformationClass,
    PVOID KeyInformation,
    ULONG Length,
    PULONG ResultLength) {

    trace("_NtQueryKey called");

    auto key = g_registry_manager.get_key(KeyHandle);
    if (!key) {
        return STATUS_INVALID_HANDLE;
    }

    std::shared_lock lock(key->key_mutex);

    if (KeyInformationClass == KeyBasicInformation) {
        ULONG required_length = sizeof(KEY_BASIC_INFORMATION) +
                               (key->path.length() + 1) * sizeof(WCHAR);

        if (ResultLength) {
            uintptr_t result_ptr = reinterpret_cast<uintptr_t>(ResultLength);
            if (!memory_mgr.write(result_ptr, required_length)) {
                return STATUS_ACCESS_VIOLATION;
            }
        }

        if (Length < required_length) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        KEY_BASIC_INFORMATION info;
        info.LastWriteTime = key->last_write_time;
        info.TitleIndex = 0;
        info.NameLength = key->path.length() * sizeof(WCHAR);

        uintptr_t info_ptr = reinterpret_cast<uintptr_t>(KeyInformation);
        if (!memory_mgr.write(info_ptr, info)) {
            return STATUS_ACCESS_VIOLATION;
        }

        return STATUS_SUCCESS;
    }

    return STATUS_INVALID_INFO_CLASS;
}

NTSTATUS NTAPI _NtAddAtom(
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
    const auto name = memory_mgr.read_wstring(name_ptr, Length / sizeof(WCHAR));
    if (!name) {
        return STATUS_ACCESS_VIOLATION;
    }
    RTL_ATOM &atom = g_atom_table[*name];
    if (atom == 0) {
        atom = ++g_next_atom_value;
    }
    if (const auto atom_ptr = reinterpret_cast<uintptr_t>(Atom); !memory_mgr.write(atom_ptr, atom)) {
        return STATUS_ACCESS_VIOLATION;
    }
    trace("Added atom: ", converter.from_bytes(converter16.to_bytes(*name)), " with value ", atom);
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI _NtFindAtom(
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
    const auto name = memory_mgr.read_wstring(name_ptr, Length / sizeof(WCHAR));
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

NTSTATUS NTAPI _NtDeleteAtom(
    ChildMemoryManager& memory_mgr,
    RTL_ATOM Atom) {

    trace("NtDeleteAtom called");
    for (auto it = g_atom_table.begin(); it != g_atom_table.end(); ++it) {
        if (it->second == Atom) {
            trace("Deleted atom: ", converter.from_bytes(converter16.to_bytes(it->first)), " with value ", Atom);
            g_atom_table.erase(it);
            return STATUS_SUCCESS;
        }
    }
    return STATUS_INVALID_PARAMETER;
}

class WindowsPELoader {
private:
    void initialize_function_tracking() {
        if (syscall_monitor && syscall_monitor->is_enabled()) {
            syscall_monitor->initialize_function_resolver(module_by_address);
        }
    }

    std::shared_ptr<EnhancedProcessManager> process_manager;  // NEW

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
        std::wstring ntdll_path = find_dll_file(ntdll_name);
        if (ntdll_path.empty()) {
            warn("Could not find ntdll.dll - this may cause issues");
            return false;
        }

        // Parse ntdll.dll
        std::string ntdll_path_str = converter.to_bytes(ntdll_path);
        std::shared_ptr<LIEF::PE::Binary> pe_binary(
            LIEF::PE::Parser::parse(ntdll_path_str).release());

        if (!pe_binary) {
            warn("Failed to parse ntdll.dll");
            return false;
        }

        // Get preferred base and size
        uintptr_t preferred_base = pe_binary->optional_header().imagebase();
        size_t image_size = pe_binary->optional_header().sizeof_image();
        image_size = (image_size + 4095) & ~4095; // Align to page size

        trace("ntdll.dll preferred base: 0x", std::hex, preferred_base, std::dec);
        trace("ntdll.dll image size: ", image_size, " bytes");

        // Try to allocate at preferred base with high priority
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

    void initialize_multithreading() {
        ProcessContext* current_process = &g_processes[g_tls.process];
    }
public:
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
        std::construct_at(&g_processes[g_tls.process]);
        g_processes[g_tls.process].process_hmodule = reinterpret_cast<HMODULE>(base_addr);

        if (!g_current_teb || !g_current_peb) {
            error("Current TEB or PEB not initialized");
            return 1;
        }

        if (const long ret = syscall(SYS_arch_prctl, ARCH_SET_GS, reinterpret_cast<uintptr_t>(g_current_teb)); ret != 0) {
            error("arch_prctl failed: ", strerror(errno));
            return 1;
        }

        initialize_function_tracking();
        initialize_multithreading();

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

                FunctionExecutor::call_windows_function_safe(entry_point, base_addr, 0, 0, 0);
                exit(0);
            } else {
                int status;
                waitpid(child, &status, 0);
                if (WIFSTOPPED(status)) {
                    syscall_monitor->trace_child_execution(child, L"Main execution");
                }
            }
        } else {
            FunctionExecutor::call_windows_function_safe(
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
        syscall_monitor = std::make_shared<SystemCallManager>(monitor_syscalls);

        import_resolver->set_function_tracing(trace_functions);

        const std::vector<std::string> candidates = {
            "10.0.19041.1-AMD64.json",
            "apisetschema.spec",
            "./apiset/10.0.19041.1-AMD64.json",
            "./apiset/apisetschema.spec"
        };

        api_resolver.load_multiple_files(candidates);

        CrashHandler::setup_crash_handler();
        initialize_shared_data();
        api_resolver.populate_peb_api_set_map();
        process_manager = std::make_shared<EnhancedProcessManager>();
        initialize_enhanced_managers();
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

        cleanup_shared_data();
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
private:
    void initialize_shared_data() {
        initialize_nt_emulation();
    }

    void cleanup_shared_data() {}

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

                FunctionExecutor::call_windows_function_safe(
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
            FunctionExecutor::call_dll_main(module, reason);
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