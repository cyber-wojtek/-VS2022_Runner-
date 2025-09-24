#include <LIEF/LIEF.hpp>
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
#include <fcntl.h>
#include <poll.h>
#include "log.h"

#include <linux/hdreg.h>
#include <linux/cdrom.h>
// for sg_io_hdr_t
#include <scsi/sg.h>

#include <condition_variable>
#define USE_WS_PREFIX
#include <nlohmann/json.hpp>

#include "winternl.h"
#include "winioctl.h"
#include "ws2def.h"
#include "ntstatus.h"
#include "ntddcdrm.h"
#include "ntddstor.h"
#include "afd.h"
#include "winbase.h"

#include <sys/ioctl.h>

#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <netdb.h>
#include <mutex>
#include <execinfo.h>
#include <ucontext.h>

#define SD_RECEIVE                 0x00
#define SD_SEND                    0x01
#define SD_BOTH                    0x02

struct afd_poll_info;
class DeviceHandle;
class Event;
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/ipc.h>
#include <unistd.h>
#include <cstring>
#include <capstone/capstone.h>

class SharedMemoryManager {
private:
    static int shm_counter;

public:
    static void* allocate_shared_executable_memory(size_t size, const std::string& name_suffix = "") {
        std::string shm_name = "/pe_loader_" + std::to_string(getpid()) + "_" +
                              std::to_string(shm_counter++) + name_suffix;

        // Create shared memory object
        int shm_fd = shm_open(shm_name.c_str(), O_CREAT | O_RDWR | O_EXCL, 0600);
        if (shm_fd == -1) {
            perror("shm_open");
            return nullptr;
        }

        // Set the size
        if (ftruncate(shm_fd, size) == -1) {
            perror("ftruncate");
            close(shm_fd);
            shm_unlink(shm_name.c_str());
            return nullptr;
        }

        // Map as shared, readable, writable, executable
        void* addr = mmap(nullptr, size,
                         PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_SHARED, shm_fd, 0);

        if (addr == MAP_FAILED) {
            perror("mmap shared");
            close(shm_fd);
            shm_unlink(shm_name.c_str());
            return nullptr;
        }

        // Close fd (mapping remains)
        close(shm_fd);

        // Unlink so it's cleaned up when all processes exit
        shm_unlink(shm_name.c_str());

        trace("Allocated shared executable memory: ", size, " bytes at ", addr);
        return addr;
    }

    static void* allocate_shared_executable_memory_at(size_t size, uintptr_t preferred_addr) {
        std::string shm_name = "/pe_loader_" + std::to_string(getpid()) + "_" +
                              std::to_string(shm_counter++);

        int shm_fd = shm_open(shm_name.c_str(), O_CREAT | O_RDWR | O_EXCL, 0600);
        if (shm_fd == -1) {
            return nullptr;
        }

        if (ftruncate(shm_fd, size) == -1) {
            close(shm_fd);
            shm_unlink(shm_name.c_str());
            return nullptr;
        }

        // Try to map at preferred address
        void* addr = mmap(reinterpret_cast<void*>(preferred_addr), size,
                         PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_SHARED | MAP_FIXED_NOREPLACE, shm_fd, 0);

        if (addr == MAP_FAILED) {
            // Fall back to any address
            addr = mmap(nullptr, size,
                       PROT_READ | PROT_WRITE | PROT_EXEC,
                       MAP_SHARED, shm_fd, 0);
        }

        close(shm_fd);
        shm_unlink(shm_name.c_str());

        return (addr == MAP_FAILED) ? nullptr : addr;
    }
};

int SharedMemoryManager::shm_counter = 0;

namespace fs = std::filesystem;

// ReSharper disable ONCE CppDeprecatedEntity
std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;

struct WSK_SOCKET_CONTEXT {
    int socket_type;      // SOCK_STREAM, SOCK_DGRAM, etc.
    int protocol;         // IPPROTO_TCP, IPPROTO_UDP, etc.
    int family;           // AF_INET, AF_INET6, etc.
    bool is_listening;
    bool is_connected;
    bool is_nonblocking;
    bool is_bound;        // Add this

    // Event selection fields
    Event* event;         // Add this
    INT event_mask;       // Add this
    HWND window;          // Add this
    UINT message;         // Add this
    WPARAM wparam;        // Add this
    INT pending_events;   // Add this
    DeviceHandle* deferred;  // Add this for IOCTL_AFD_WINE_DEFER
    bool poll_registered;
    ULONG poll_flags;
    ULONG poll_events;
    DeviceHandle * deffered;
};

// Handle management for devices
class DeviceHandle {
public:
    int linux_fd;
    DEVICE_TYPE device_type;
    std::string device_path;
    // options
    ULONG options = 0;
    ULONG disposition = 0;
    ULONG access = 0;
    ULONG share_mode = 0;
    ULONG file_attributes = 0;
    ULONG file_position = 0; // For files
    // WSK socket context
    std::unique_ptr<WSK_SOCKET_CONTEXT> socket_context; // Add this

    DeviceHandle(const int fd, const DEVICE_TYPE type, std::string path, ULONG opts, ULONG disp = 0,
                 ULONG acc = 0, ULONG share = 0, ULONG file_attrs = 0)
        : linux_fd(fd), device_type(type), device_path(std::move(path)), options(opts), disposition(disp),
          access(acc), share_mode(share), file_attributes(file_attrs) {
        if (type == FILE_DEVICE_NETWORK) {
            socket_context = std::make_unique<WSK_SOCKET_CONTEXT>();
            socket_context->is_listening = false;
            socket_context->is_connected = false;
            socket_context->is_nonblocking = false;
            socket_context->is_bound = false; // Initialize is_bound
            socket_context->event = nullptr; // Initialize event
            socket_context->event_mask = 0; // Initialize event_mask
            socket_context->window = nullptr; // Initialize window
            socket_context->message = 0; // Initialize message
            socket_context->wparam = 0; // Initialize wparam
            socket_context->pending_events = 0; // Initialize pending_events
            socket_context->deferred = nullptr; // Initialize deferred
            socket_context->poll_registered = false;
            socket_context->poll_flags = 0;
            socket_context->poll_events = 0;
        }
    }

    ~DeviceHandle() {
        if (linux_fd >= 0) {
            close(linux_fd);
        }
    }
};

class Event {
public:
    std::mutex mtx_;
    std::condition_variable cv_;
    bool flag_ = false;
    bool manual_reset_ = false;

    Event() = default;
    Event(bool manual_reset, bool initial_state)
        : flag_(initial_state), manual_reset_(manual_reset) {}

    Event(const Event &other) {
        std::lock_guard lock(mtx_);
        flag_ = other.flag_;
        manual_reset_ = other.manual_reset_;
    }

    Event(Event &&other) noexcept {
        std::lock_guard lock(other.mtx_);
        flag_ = other.flag_;
        manual_reset_ = other.manual_reset_;
    }

    Event& operator=(const Event &other) {
        if (this != &other) {
            std::lock_guard<std::mutex> lock(mtx_);
            flag_ = other.flag_;
            manual_reset_ = other.manual_reset_;
        }
        return *this;
    }

    Event& operator=(Event &&other) noexcept {
        if (this != &other) {
            std::lock_guard<std::mutex> lock(other.mtx_);
            flag_ = other.flag_;
            manual_reset_ = other.manual_reset_;
        }
        return *this;
    }

    void set() {
        std::lock_guard<std::mutex> lock(mtx_);
        flag_ = true;
        cv_.notify_all();
    }

    void clear() {
        std::lock_guard<std::mutex> lock(mtx_);
        flag_ = false;
    }

    void wait() {
        std::unique_lock<std::mutex> lock(mtx_);
        cv_.wait(lock, [this] { return flag_; });
    }

    bool is_set() {
        std::lock_guard<std::mutex> lock(mtx_);
        return flag_;
    }
};

static NTSTATUS errno_to_status( int err )
{
    trace("errno_to_status: errno = ", err);
    switch (err)
    {
        case EAGAIN:    return STATUS_SHARING_VIOLATION;
        case EBADF:     return STATUS_INVALID_HANDLE;
        case EBUSY:     return STATUS_DEVICE_BUSY;
        case ENOSPC:    return STATUS_DISK_FULL;
        case EPERM:
        case EROFS:
        case EACCES:    return STATUS_ACCESS_DENIED;
        case ENOTDIR:   return STATUS_OBJECT_PATH_NOT_FOUND;
        case ENOENT:    return STATUS_OBJECT_NAME_NOT_FOUND;
        case EISDIR:    return STATUS_INVALID_DEVICE_REQUEST;
        case EMFILE:
        case ENFILE:    return STATUS_TOO_MANY_OPENED_FILES;
        case EINVAL:    return STATUS_INVALID_PARAMETER;
        case ENOTEMPTY: return STATUS_DIRECTORY_NOT_EMPTY;
        case EPIPE:     return STATUS_PIPE_DISCONNECTED;
        case EIO:       return STATUS_DEVICE_NOT_READY;
#if ENOMEDIUM
        case ENOMEDIUM: return STATUS_NO_MEDIA_IN_DEVICE;
#endif
        case ENXIO:     return STATUS_NO_SUCH_DEVICE;
        case ENOTTY:
        case EOPNOTSUPP:return STATUS_NOT_SUPPORTED;
        case ECONNRESET:return STATUS_PIPE_DISCONNECTED;
        case EFAULT:    return STATUS_ACCESS_VIOLATION;
        case ESPIPE:    return STATUS_ILLEGAL_FUNCTION;
        case ELOOP:     return STATUS_REPARSE_POINT_NOT_RESOLVED;
#ifdef ETIME /* Missing on FreeBSD */
        case ETIME:     return STATUS_IO_TIMEOUT;
#endif
        case ENOEXEC:   /* ?? */
        case EEXIST:    /* ?? */
        default:
            fixme("errno_to_status: Unmapped errno %d\n", err );
            return STATUS_UNSUCCESSFUL;
    }
}

struct TLS {
    HANDLE thread{};
    HANDLE process{};
    std::vector<LPVOID> tls_data;
};

class ProcessThreadAPC {
public:
    PNTAPCFUNC func;
    ULONG_PTR arg1;
    ULONG_PTR arg2;
    ULONG_PTR arg3;
};

class ProcessThreadInfo {
public:
    bool is_suspended{};
    pthread_t thread{};
    pthread_attr_t attr{};
    void* arg{};
    void*(*start_routine)(void*){};
    DWORD last_error{};
    std::vector<ProcessThreadAPC> apc_queue;
};

struct ProcessInfo {
    std::unordered_map<HANDLE, ProcessThreadInfo> threads;
    std::unordered_map<DWORD, HANDLE> std_handles = {
        { STD_INPUT_HANDLE, reinterpret_cast<HANDLE>(-10) },
        { STD_OUTPUT_HANDLE, reinterpret_cast<HANDLE>(-11) },
        { STD_ERROR_HANDLE, reinterpret_cast<HANDLE>(-12) }
    };
    std::unordered_map<HANDLE, Event> events;
    std::vector<pollfd> active_polls;
    std::unordered_map<int, HANDLE> fd_to_handle;
    std::unordered_map<HANDLE, afd_poll_info*> handle_to_poll_info;
    bool poll_in_progress{};
    HMODULE process_hmodule = nullptr;
    pthread_t process_thread = 0;
    std::unordered_map<HANDLE, std::unique_ptr<DeviceHandle>> device_handles;

    ProcessInfo() {
        // Store options for standard handles (none by default)
        device_handles[reinterpret_cast<HANDLE>(-10)] = std::move(std::make_unique<DeviceHandle>(0, FILE_DEVICE_CONSOLE, std::string("CONIN$"), 0, 0, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE));
        device_handles[reinterpret_cast<HANDLE>(-11)] = std::move(std::make_unique<DeviceHandle>(1, FILE_DEVICE_CONSOLE, std::string("CONOUT$"), 0, 0, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE));
        device_handles[reinterpret_cast<HANDLE>(-12)] = std::move(std::make_unique<DeviceHandle>(2, FILE_DEVICE_CONSOLE, std::string("CONERR$"), 0, 0, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE));
    }
};

std::unordered_map<HANDLE, ProcessInfo> processes;
thread_local TLS tls;
auto next_handle = reinterpret_cast<HANDLE>(2);

// Add these helper functions:
DeviceHandle* get_device_handle(HANDLE process, HANDLE h) {
    auto& proc_info = processes[process];
    auto it = proc_info.device_handles.find(h);
    return (it != proc_info.device_handles.end()) ? it->second.get() : nullptr;
}

HANDLE create_network_socket(HANDLE process, int domain, int type, int protocol, ULONG options, ULONG disposition, ULONG access, ULONG share_mode, ULONG file_attributes) {
    int flags = 0;
    if (options & FILE_FLAG_OVERLAPPED) {
        flags |= O_NONBLOCK;
    }
    int sock_fd = socket(domain, type | flags, protocol);
    if (sock_fd < 0) {
        return nullptr;
    }
    auto handle = std::make_unique<DeviceHandle>(sock_fd, FILE_DEVICE_NETWORK, std::string("SOCKET"), options, disposition, access, share_mode, file_attributes);
    if (handle->socket_context) {
        handle->socket_context->socket_type = type;
        handle->socket_context->protocol = protocol;
        handle->socket_context->family = domain;
        handle->socket_context->is_listening = false;
        handle->socket_context->is_connected = false;
        handle->socket_context->is_nonblocking = (flags & O_NONBLOCK) != 0;
        handle->socket_context->is_bound = false; // Initialize is_bound
        handle->socket_context->event = nullptr; // Initialize event
        handle->socket_context->event_mask = 0; // Initialize event_mask
        handle->socket_context->window = nullptr; // Initialize window
        handle->socket_context->message = 0; // Initialize message
        handle->socket_context->wparam = 0; // Initialize wparam
        handle->socket_context->pending_events = 0; // Initialize pending_events
        handle->socket_context->deferred = nullptr; // Initialize deferred
        handle->socket_context->poll_registered = false;
        handle->socket_context->poll_flags = 0;
        handle->socket_context->poll_events = 0;
    }

    const auto h = reinterpret_cast<HANDLE>(handle.get());
    processes[process].device_handles[h] = std::move(handle);
    return h;
}

void close_device_handle(HANDLE process, HANDLE h) {
    processes[process].device_handles.erase(h);
}


struct afd_poll_info {
    SOCKET socket;
    ULONG flags;
    NTSTATUS status;
};

void notify_socket_events(HANDLE process, HANDLE socket_handle, ULONG events) {
    DeviceHandle* socket_dev = get_device_handle(process, socket_handle);
    if (!socket_dev || !socket_dev->socket_context) {
        return;
    }

    auto* sock_context = socket_dev->socket_context.get();
    sock_context->poll_events |= events;

    // Notify event if registered
    if (sock_context->event && (sock_context->event_mask & events)) {
        sock_context->event->set();
    }

    // Send window message if registered
    if (sock_context->window && sock_context->message && (sock_context->event_mask & events)) {
        // In a real implementation, you'd send the window message
        trace("Would send message ", sock_context->message, " to window ",
              sock_context->window, " with events 0x", std::hex, events);
    }
}

NTSTATUS NTAPI NtWorkerFactoryWorkerReady(HANDLE WorkerFactoryHandle) {
    // TODO: with threadpool implement this properly
    trace("NtWorkerFactoryWorkerReady called with hWorkerFactory = ", WorkerFactoryHandle);
    return STATUS_ALERTED;
}

NTSTATUS NTAPI NtSetEvent(HANDLE EventHandle, PLONG PreviousState) {
    trace("NtSetEvent called with EventHandle = ", EventHandle);
    auto& proc_info = processes[tls.process];
    auto it = proc_info.events.find(EventHandle);
    if (it == proc_info.events.end()) {
        error("NtSetEvent: Invalid event handle ", EventHandle);
        return STATUS_INVALID_HANDLE;
    }
    it->second.set();
    if (PreviousState) {
        *PreviousState = 0; // Not tracking previous state
    }
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI NtQueueApcThread(
    HANDLE ThreadHandle,
    PNTAPCFUNC ApcRoutine,
    ULONG_PTR ApcArgument1,
    ULONG_PTR ApcArgument2,
    ULONG_PTR ApcArgument3) {
    trace("NtQueueApcThread called with handle: ", ThreadHandle,
          ", ApcRoutine: ", reinterpret_cast<void*>(ApcRoutine),
          ", ApcArgument1: ", reinterpret_cast<void*>(ApcArgument1),
          ", ApcArgument2: ", reinterpret_cast<void*>(ApcArgument2),
          ", ApcArgument3: ", reinterpret_cast<void*>(ApcArgument3));
    ProcessThreadInfo &thread_info = processes[tls.process].threads[ThreadHandle];
    thread_info.apc_queue.emplace_back( ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3 );
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI NtMapUserPhysicalPagesScatter(
    PVOID* VirtualAddresses,
    ULONG_PTR NumberOfPages,
    PULONG_PTR UserPfnArray) {
    trace("NtMapUserPhysicalPagesScatter called with VirtualAddresses = ", VirtualAddresses,
          ", NumberOfPages = ", NumberOfPages,
          ", UserPfnArray = ", UserPfnArray);
    ret("NtMapUserPhysicalPagesScatter is not implemented - returning success");
    // stub.
    return STATUS_SUCCESS;
}

bool has_option(const DeviceHandle* device, DWORD option_flag) {
    return device && (device->options & option_flag) != 0;
}

NTSTATUS network_DeviceIoControl(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    IO_STATUS_BLOCK* IoStatusBlock,
    UINT IoControlCode,
    PVOID InputBuffer,
    ULONG InputBufferLength,
    PVOID OutputBuffer,
    UINT OutputBufferLength) {
    trace("network_DeviceIoControl called with FileHandle = ", FileHandle,
          ", IoControlCode = 0x", std::hex, IoControlCode,
          ", InputBufferLength = ", std::dec, InputBufferLength,
          ", OutputBufferLength = ", OutputBufferLength);

    NTSTATUS status = STATUS_SUCCESS;
    ULONG sz = 0;

    const auto dev = get_device_handle(tls.process, FileHandle);
    if (!dev) {
        error("network_DeviceIoControl: Invalid device handle ", FileHandle);
        return STATUS_INVALID_HANDLE;
    }

    auto* sock_context = dev->socket_context.get();
    if (!sock_context) {
        // Create default context for the socket
        dev->socket_context = std::make_unique<WSK_SOCKET_CONTEXT>();
        dev->socket_context->socket_type = SOCK_STREAM; // Default
        dev->socket_context->protocol = IPPROTO_TCP;    // Default
        dev->socket_context->is_listening = false;
        dev->socket_context->is_connected = false;
        dev->socket_context->is_nonblocking = false;

        sock_context = dev->socket_context.get();
    }

    switch (IoControlCode) {
        case IOCTL_AFD_WINE_CREATE: {
            trace("network_DeviceIoControl IOCTL_AFD_WINE_CREATE");
            auto *params = static_cast<w32::afd_create_params*>(InputBuffer);
            if (InputBufferLength < sizeof(w32::afd_create_params)) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }
            SOCKET fd = socket(params->family, params->type, params->protocol);
            if (fd < 0) {
                status = errno_to_status(errno);
                break;
            }
            // Update the existing device handle to use the new socket
            close(dev->linux_fd);
            dev->linux_fd = fd;
            // Preserve existing options when updating socket
            // dev->options remains unchanged
            sock_context->socket_type = params->type;
            sock_context->protocol = params->protocol;
            sock_context->is_listening = false;
            sock_context->is_connected = false;
            sock_context->is_nonblocking = true;

            // Apply options to the new socket
            if (dev->options & FILE_FLAG_OVERLAPPED) {
                sock_context->is_nonblocking = true;
                int flags = fcntl(fd, F_GETFL, 0);
                fcntl(fd, F_SETFL, flags | O_NONBLOCK);
            }

            sz = sizeof(w32::afd_create_params);
            status = STATUS_SUCCESS;
            break;
        }
        case IOCTL_AFD_WINE_ACCEPT: {
            trace("network_DeviceIoControl IOCTL_AFD_WINE_ACCEPT");
            if (InputBufferLength < sizeof(SOCKET_ADDRESS) || OutputBufferLength < sizeof(w32::WS_sockaddr_in)) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }
            sz = sizeof(SOCKET_ADDRESS);
            auto* out_addr = static_cast<w32::WS_sockaddr_in*>(OutputBuffer);
            socklen_t addrlen = sizeof(w32::WS_sockaddr_in);
            int client_fd = accept(dev->linux_fd, reinterpret_cast<sockaddr*>(out_addr), &addrlen);
            if (client_fd < 0) {
                status = errno_to_status(errno);
                break;
            }
            // Create a new DeviceHandle for the accepted socket
            auto client_handle = std::make_unique<DeviceHandle>(client_fd, FILE_DEVICE_NETWORK, "accepted_socket", dev->options);
            client_handle->socket_context = std::make_unique<WSK_SOCKET_CONTEXT>(*sock_context);
            client_handle->socket_context->is_connected = true;
            const auto h = reinterpret_cast<HANDLE>(client_handle.get());
            processes[tls.process].device_handles[h] = std::move(client_handle);
            // Return the new handle in the OutputBuffer
            if (OutputBufferLength >= sizeof(HANDLE)) {
                *static_cast<HANDLE*>(OutputBuffer) = h;
                sz = sizeof(HANDLE);
                status = STATUS_SUCCESS;
            } else {
                close(client_fd);
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }
            break;
        }

        case IOCTL_AFD_WINE_ACCEPT_INTO: {
            trace("network_DeviceIoControl IOCTL_AFD_WINE_ACCEPT_INTO");
            const auto *params = static_cast<const w32::afd_accept_into_params*>(InputBuffer);
            if (InputBufferLength < sizeof(w32::afd_accept_into_params)) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }
            sz = sizeof(w32::afd_accept_into_params);
            //params->accept_handle;
            //params->local_len;
            //params->recv_len;
            if (!params->accept_handle) {
                status = STATUS_INVALID_HANDLE;
                break;
            }
            const auto* accept_dev = get_device_handle(tls.process, reinterpret_cast<HANDLE>(params->accept_handle));
            if (!accept_dev) {
                status = STATUS_INVALID_HANDLE;
                break;
            }
            auto* accept_sock_context = accept_dev->socket_context.get();
            if (!accept_sock_context || !accept_sock_context->is_listening) {
                status = STATUS_INVALID_PARAMETER;
                break;
            }
            const socklen_t local_len = params->local_len;
            const socklen_t recv_len = params->recv_len;
            sockaddr *local_addr = nullptr;
            sockaddr *recv_addr = nullptr;
            if (local_len > 0) {
                local_addr = static_cast<sockaddr*>(malloc(local_len));
                if (!local_addr) {
                    status = STATUS_NO_MEMORY;
                    break;
                }
                memset(local_addr, 0, local_len);
            }
            if (recv_len > 0) {
                recv_addr = static_cast<sockaddr*>(malloc(recv_len));
                if (!recv_addr) {
                    if (local_addr) free(local_addr);
                    status = STATUS_NO_MEMORY;
                    break;
                }
                memset(recv_addr, 0, recv_len);
            }
            socklen_t recv_addrlen = recv_len;
            int client_fd = accept(accept_dev->linux_fd, recv_addr, &recv_addrlen);
            if (client_fd < 0) {
                if (local_addr) free(local_addr);
                if (recv_addr) free(recv_addr);
                status = errno_to_status(errno);
                break;
            }
            // Create a new DeviceHandle for the accepted socket
            auto client_handle = std::make_unique<DeviceHandle>(client_fd, FILE_DEVICE_NETWORK, "accepted_socket", accept_dev->options);
            client_handle->socket_context = std::make_unique<WSK_SOCKET_CONTEXT>(*accept_sock_context);
            client_handle->socket_context->is_connected = true;
            const auto h = reinterpret_cast<HANDLE>(client_handle.get());
            processes[tls.process].device_handles[h] = std::move(client_handle);
            // Return the new handle in the OutputBuffer
            if (OutputBufferLength >= sizeof(HANDLE)) {
                *static_cast<HANDLE*>(OutputBuffer) = h;
                sz = sizeof(HANDLE);
                status = STATUS_SUCCESS;
            } else {
                close(client_fd);
                if (local_addr) free(local_addr);
                if (recv_addr) free(recv_addr);
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }
            if (local_addr) free(local_addr);
            if (recv_addr) free(recv_addr);
            break;
        }
        case IOCTL_AFD_LISTEN: {
            trace("network_DeviceIoControl IOCTL_AFD_LISTEN");
            if (InputBufferLength < sizeof(w32::afd_listen_params)) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }
            w32::afd_listen_params *params;
            params = static_cast<w32::afd_listen_params *>(InputBuffer);
            if (params->backlog == 0) {
                params->backlog = SOMAXCONN;
            }
            sz = sizeof(w32::afd_listen_params);
            int ret = listen(dev->linux_fd, params->backlog);
            if (ret < 0) {
                status = errno_to_status(errno);
                break;
            }
            sock_context->is_listening = true;
            sz = 0;
            status = STATUS_SUCCESS;
            break;
        }
        case IOCTL_AFD_WINE_CONNECT: {
            trace("network_DeviceIoControl IOCTL_AFD_WINE_CONNECT");
            if (InputBufferLength < sizeof(SOCKET_ADDRESS)) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }
            sz = sizeof(SOCKET_ADDRESS);
            auto* addr = static_cast<SOCKET_ADDRESS*>(InputBuffer);
            int ret = connect(dev->linux_fd, reinterpret_cast<sockaddr *>(addr->lpSockaddr), addr->iSockaddrLength);
            if (ret < 0) {
                status = errno_to_status(errno);
                break;
            }
            sock_context->is_connected = true;
            status = STATUS_SUCCESS;
            break;
        }
        case IOCTL_AFD_WINE_SHUTDOWN: {
            trace("network_DeviceIoControl IOCTL_AFD_WINE_SHUTDOWN");
            UINT how;
            if (InputBufferLength < sizeof(UINT)) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }
            sz = sizeof(UINT);
            how = *static_cast<UINT*>(InputBuffer);
            int linux_how;
            if (how > SD_BOTH) {
                status = STATUS_INVALID_PARAMETER;
                break;
            }
            if (!sock_context->is_connected) {
                status = STATUS_INVALID_PARAMETER;
                break;
            }
            // Map Windows shutdown how to Linux how
            linux_how = (how == SD_RECEIVE) ? SHUT_RD : (how == SD_SEND) ? SHUT_WR : SHUT_RDWR;
            int ret = shutdown(dev->linux_fd, linux_how);
            status = errno_to_status(ret);
            break;
        }
        case IOCTL_AFD_WINE_ADDRESS_LIST_CHANGE: {
            trace("network_DeviceIoControl IOCTL_AFD_WINE_ADDRESS_LIST_CHANGE");
            int force_async;
            if (InputBufferLength < sizeof(int)) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }
            force_async = *static_cast<int*>(InputBuffer);

            sz = sizeof(int);
            status = STATUS_SUCCESS;
            break;
        }
        case IOCTL_AFD_WINE_FIONBIO: {
            trace("network_DeviceIoControl IOCTL_AFD_WINE_FIONBIO");
            UINT nonblocking;
            sz = 0;
            if (InputBufferLength < sizeof(UINT)) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }
            nonblocking = *static_cast<UINT*>(InputBuffer);
            int flags = fcntl(dev->linux_fd, F_GETFL, 0);
            if (nonblocking) {
                fcntl(dev->linux_fd, F_SETFL, flags | O_NONBLOCK);
                sock_context->is_nonblocking = true;
            } else {
                fcntl(dev->linux_fd, F_SETFL, flags & ~O_NONBLOCK);
                sock_context->is_nonblocking = false;
            }
            sz = sizeof(UINT);
            status = STATUS_SUCCESS;
            break;
        }
        case IOCTL_AFD_EVENT_SELECT: {
            trace("network_DeviceIoControl IOCTL_AFD_EVENT_SELECT");
            sz = 0;
            if (InputBufferLength < sizeof(w32::afd_event_select_params)) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }
            auto* params = static_cast<w32::afd_event_select_params*>(InputBuffer);
            HANDLE event = params->event;
            INT mask = params->mask;
            sock_context->event = event ? (processes[tls.process].events.contains(event) ? &processes[tls.process].events[event] : nullptr) : nullptr;
            sock_context->event_mask = mask;
            sock_context->window = nullptr;
            sock_context->message = 0;
            sock_context->wparam = 0;
            sock_context->is_nonblocking = true;

            if (event && (sock_context->pending_events & mask)) {
                // If there are pending events, signal the event immediately
                sock_context->event->set();
            }
            sz = sizeof(w32::afd_event_select_params);
            status = STATUS_SUCCESS;
            break;
        }
        case IOCTL_AFD_WINE_MESSAGE_SELECT: {
            trace("network_DeviceIoControl IOCTL_AFD_WINE_MESSAGE_SELECT");
            sz = 0;
            if (InputBufferLength < sizeof(w32::afd_message_select_params)) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }
            auto* params = static_cast<w32::afd_message_select_params*>(InputBuffer);
            sock_context->event = nullptr;
            sock_context->event_mask = params->mask;
            sock_context->window = reinterpret_cast<HWND>(params->window);
            sock_context->message = params->message;
            sock_context->wparam = params->handle;
            sock_context->is_nonblocking = true;
            sz = 0;
            status = STATUS_SUCCESS;
            sz = sizeof(w32::afd_message_select_params);
            break;
        }
        case IOCTL_AFD_BIND: {
            trace("network_DeviceIoControl IOCTL_AFD_BIND");
            sz = 0;
            const auto *params = static_cast<const w32::afd_bind_params*>(InputBuffer);
            if (InputBufferLength < sizeof(w32::afd_bind_params)) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }
            sockaddr bind_addr{};
            size_t in_sz;
            int v6only = 1;
            sz = sizeof(w32::afd_bind_params);
            if (sock_context->is_bound) {
                status = STATUS_ADDRESS_ALREADY_ASSOCIATED;
                break;
            }
            if (params->addr.sa_family == AF_INET) {
                in_sz = sizeof(sockaddr_in);
                memset(&bind_addr, 0, sizeof(bind_addr));
                memcpy(&bind_addr, &params->addr, sizeof (sockaddr_in));
            } else if (params->addr.sa_family == AF_INET6) {
                in_sz = sizeof(sockaddr_in6);
                memset(&bind_addr, 0, sizeof(bind_addr));
                memcpy(&bind_addr, &params->addr, sizeof (w32::WS_sockaddr));
                // Disable IPV6_V6ONLY to allow dual-stack
                setsockopt(dev->linux_fd, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<char *>(&v6only), sizeof(v6only));
            } else {
                status = STATUS_INVALID_PARAMETER;
                break;
            }
            if (bind(dev->linux_fd, &bind_addr, in_sz) < 0) {
                status = errno_to_status(errno);
                break;
            }
            sock_context->is_bound = true;
            // put into aoutput buffer the actual bound address
            if (OutputBufferLength >= sizeof(SOCKET_ADDRESS)) {
                auto* out_addr = static_cast<SOCKET_ADDRESS*>(OutputBuffer);
                socklen_t addrlen = sizeof(out_addr->iSockaddrLength);
                if (getsockname(dev->linux_fd, reinterpret_cast<sockaddr *>(out_addr->lpSockaddr), &addrlen) < 0) {
                    status = errno_to_status(errno);
                    break;
                }
                out_addr->iSockaddrLength = static_cast<INT>(addrlen);
                sz = sizeof(SOCKET_ADDRESS);
            } else {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }
            sz = 0;
            status = STATUS_SUCCESS;
            break;
        }
        case IOCTL_AFD_GETSOCKNAME: {
            trace("network_DeviceIoControl IOCTL_AFD_GETSOCKNAME");
            sz = 0;
            if (OutputBufferLength < sizeof(SOCKET_ADDRESS)) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }
            auto* out_addr = static_cast<SOCKET_ADDRESS*>(OutputBuffer);
            socklen_t addrlen = sizeof(out_addr->iSockaddrLength);
            if (getsockname(dev->linux_fd, reinterpret_cast<sockaddr *>(out_addr->lpSockaddr), &addrlen) < 0) {
                status = errno_to_status(errno);
                break;
            }
            out_addr->iSockaddrLength = static_cast<INT>(addrlen);
            sz = sizeof(SOCKET_ADDRESS);
            status = STATUS_SUCCESS;
            break;
        }
        case IOCTL_AFD_WINE_GETPEERNAME: {
            trace("network_DeviceIoControl IOCTL_AFD_WINE_GETPEERNAME");
            sz = 0;
            if (OutputBufferLength < sizeof(SOCKET_ADDRESS)) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }
            auto* out_addr = static_cast<SOCKET_ADDRESS*>(OutputBuffer);
            socklen_t addrlen = sizeof(out_addr->iSockaddrLength);
            if (getpeername(dev->linux_fd, reinterpret_cast<sockaddr *>(out_addr->lpSockaddr), &addrlen) < 0) {
                status = errno_to_status(errno);
                break;
            }
            out_addr->iSockaddrLength = static_cast<INT>(addrlen);
            sz = sizeof(SOCKET_ADDRESS);
            status = STATUS_SUCCESS;
            break;
        }
        case IOCTL_AFD_WINE_DEFER: {
            trace("network_DeviceIoControl IOCTL_AFD_WINE_DEFER");
            HANDLE handle = nullptr;
            if (InputBufferLength < sizeof(HANDLE)) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }
            handle = *static_cast<HANDLE*>(InputBuffer);
            auto acceptsock = get_device_handle(tls.process, handle);
            if (!acceptsock) {
                status = STATUS_INVALID_HANDLE;
                break;
            }
            sock_context->deffered = acceptsock;
            sz = sizeof(HANDLE);
            status = STATUS_SUCCESS;
            break;
        }
        case IOCTL_AFD_WINE_GET_INFO: {
            trace("network_DeviceIoControl IOCTL_AFD_WINE_GET_INFO");
            if (OutputBufferLength < sizeof(w32::afd_get_info_params)) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }
            auto* out_params = static_cast<w32::afd_get_info_params*>(OutputBuffer);
            out_params->type = sock_context->socket_type;
            out_params->protocol = sock_context->protocol;
            out_params->family = sock_context->family;
            sz = sizeof(w32::afd_get_info_params);
            status = STATUS_SUCCESS;
            break;
        }
        case IOCTL_AFD_WINE_GET_SO_ACCEPTCONN: {
            trace("network_DeviceIoControl IOCTL_AFD_WINE_GET_SO_ACCEPTCONN");
            if (OutputBufferLength < sizeof(BOOLEAN)) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }
            auto *is_listening = static_cast<BOOLEAN*>(OutputBuffer);
            *is_listening = sock_context->is_listening ? TRUE : FALSE;
            sz = sizeof(BOOLEAN);
            status = STATUS_SUCCESS;
            break;
        }
        case IOCTL_AFD_WINE_GET_SO_ERROR: {
            trace("network_DeviceIoControl IOCTL_AFD_WINE_GET_SO_ERROR");
            if (OutputBufferLength < sizeof(INT)) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }
            auto error = static_cast<INT*>(OutputBuffer);
            socklen_t optlen = sizeof(INT);
            if (getsockopt(dev->linux_fd, SOL_SOCKET, SO_ERROR, error, &optlen) < 0) {
                status = errno_to_status(errno);
                break;
            }
            sz = sizeof(INT);
            status = STATUS_SUCCESS;
            break;
        }
        case IOCTL_AFD_WINE_GET_SO_RCVBUF: {
            trace("network_DeviceIoControl IOCTL_AFD_WINE_GET_SO_RCVBUF");
            if (OutputBufferLength < sizeof(INT)) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }
            INT *rcvbuf = static_cast<INT*>(OutputBuffer);
            socklen_t optlen = sizeof(INT);
            if (getsockopt(dev->linux_fd, SOL_SOCKET, SO_RCVBUF, rcvbuf, &optlen) < 0) {
                status = errno_to_status(errno);
                break;
            }
            sz = sizeof(INT);
            status = STATUS_SUCCESS;
            break;
        }
        case IOCTL_AFD_WINE_SET_SO_RCVBUF: {
            trace("network_DeviceIoControl IOCTL_AFD_WINE_SET_SO_RCVBUF");
            if (InputBufferLength < sizeof(INT)) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }
            INT *rcvbuf = static_cast<INT*>(InputBuffer);
            if (setsockopt(dev->linux_fd, SOL_SOCKET, SO_RCVBUF, rcvbuf, sizeof(INT)) < 0) {
                status = errno_to_status(errno);
                break;
            }
            sz = sizeof(INT);
            status = STATUS_SUCCESS;
            break;
        }
        case IOCTL_AFD_WINE_GET_SO_RCVTIMEO: {
            trace("network_DeviceIoControl IOCTL_AFD_WINE_GET_SO_RCVTIMEO");
            if (OutputBufferLength < sizeof(INT)) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }
            auto rcvtimeo = static_cast<INT*>(OutputBuffer);
            socklen_t optlen = sizeof(INT);
            if (getsockopt(dev->linux_fd, SOL_SOCKET, SO_RCVTIMEO, rcvtimeo, &optlen) < 0) {
                status = errno_to_status(errno);
                break;
            }
            sz = sizeof(INT);
            status = STATUS_SUCCESS;
            break;
        }
        case IOCTL_AFD_WINE_SET_SO_RCVTIMEO: {
            trace("network_DeviceIoControl IOCTL_AFD_WINE_SET_SO_RCVTIMEO");
            if (InputBufferLength < sizeof(INT)) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }
            DWORD rcvtimeo = *static_cast<DWORD*>(InputBuffer);
            timeval tv{};
            tv.tv_sec = rcvtimeo / 1000;
            tv.tv_usec = (rcvtimeo % 1000) * 1000;
            if (setsockopt(dev->linux_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
                status = errno_to_status(errno);
                break;
            }
            sz = sizeof(DWORD);
            status = STATUS_SUCCESS;
            break;
        }
        case IOCTL_AFD_WINE_SET_SO_EXCLUSIVEADDRUSE: {
            trace("network_DeviceIoControl IOCTL_AFD_WINE_SET_SO_EXCLUSIVEADDRUSE");
            if (InputBufferLength < sizeof(BOOLEAN)) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }
            BOOLEAN exclusive = *static_cast<BOOLEAN*>(InputBuffer);
            int optval = exclusive ? 1 : 0;
            if (setsockopt(dev->linux_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
                status = errno_to_status(errno);
                break;
            }
            sz = sizeof(BOOLEAN);
            status = STATUS_SUCCESS;
            break;
        }
        case IOCTL_AFD_WINE_GET_SO_SNDBUF: {
            trace("network_DeviceIoControl IOCTL_AFD_WINE_GET_SO_SNDBUF");
            if (OutputBufferLength < sizeof(INT)) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }
            auto sndbuf = static_cast<INT*>(OutputBuffer);
            socklen_t optlen = sizeof(INT);
            if (getsockopt(dev->linux_fd, SOL_SOCKET, SO_SNDBUF, sndbuf, &optlen) < 0) {
                status = errno_to_status(errno);
                break;
            }
            sz = sizeof(INT);
            status = STATUS_SUCCESS;
            break;
        }
        case IOCTL_AFD_WINE_SET_SO_SNDBUF: {
            trace("network_DeviceIoControl IOCTL_AFD_WINE_SET_SO_SNDBUF");
            if (InputBufferLength < sizeof(INT)) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }
            INT sndbuf = *static_cast<INT*>(InputBuffer);
            if (setsockopt(dev->linux_fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(INT)) < 0) {
                status = errno_to_status(errno);
                break;
            }
            sz = sizeof(INT);
            status = STATUS_SUCCESS;
            break;
        }
        case IOCTL_AFD_WINE_GET_SO_SNDTIMEO: {
            trace("network_DeviceIoControl IOCTL_AFD_WINE_GET_SO_SNDTIMEO");
            if (OutputBufferLength < sizeof(INT)) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }
            auto sndtimeo = static_cast<INT*>(OutputBuffer);
            socklen_t optlen = sizeof(INT);
            if (getsockopt(dev->linux_fd, SOL_SOCKET, SO_SNDTIMEO, sndtimeo, &optlen) < 0) {
                status = errno_to_status(errno);
                break;
            }
            sz = sizeof(INT);
            status = STATUS_SUCCESS;
            break;
        }
        case IOCTL_AFD_WINE_SET_SO_SNDTIMEO: {
            trace("network_DeviceIoControl IOCTL_AFD_WINE_SET_SO_SNDTIMEO");
            if (InputBufferLength < sizeof(INT)) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }
            DWORD sndtimeo = *static_cast<DWORD*>(InputBuffer);
            timeval tv{};
            tv.tv_sec = sndtimeo / 1000;
            tv.tv_usec = (sndtimeo % 1000) * 1000;
            if (setsockopt(dev->linux_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
                status = errno_to_status(errno);
                break;
            }
            sz = sizeof(DWORD);
            status = STATUS_SUCCESS;
            break;
        }
        case IOCTL_AFD_WINE_GET_SO_CONNECT_TIME: {
            trace("network_DeviceIoControl IOCTL_AFD_WINE_GET_SO_CONNECT_TIME");
            if (OutputBufferLength < sizeof(DWORD)) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }
            // Not implemented, return 0
            auto *connect_time = static_cast<DWORD*>(OutputBuffer);
            *connect_time = 0;
            sz = sizeof(DWORD);
            status = STATUS_SUCCESS;
            break;
        }
        case IOCTL_AFD_WINE_GET_SO_REUSEADDR: {
            trace("network_DeviceIoControl IOCTL_AFD_WINE_GET_SO_REUSEADDR");
            if (OutputBufferLength < sizeof(BOOLEAN)) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }
            auto *reuseaddr = static_cast<BOOLEAN*>(OutputBuffer);
            int optval;
            socklen_t optlen = sizeof(optval);
            if (getsockopt(dev->linux_fd, SOL_SOCKET, SO_REUSEADDR, &optval, &optlen) < 0) {
                status = errno_to_status(errno);
                break;
            }
            *reuseaddr = optval ? TRUE : FALSE;
            sz = sizeof(BOOLEAN);
            status = STATUS_SUCCESS;
            break;
        }
        case IOCTL_AFD_WINE_GET_SO_EXCLUSIVEADDRUSE: {
            trace("network_DeviceIoControl IOCTL_AFD_WINE_GET_SO_EXCLUSIVEADDRUSE");
            if (OutputBufferLength < sizeof(BOOLEAN)) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }
            auto *exclusive = static_cast<BOOLEAN*>(OutputBuffer);
            int optval;
            socklen_t optlen = sizeof(optval);
            if (getsockopt(dev->linux_fd, SOL_SOCKET, SO_REUSEADDR, &optval, &optlen) < 0) {
                status = errno_to_status(errno);
                break;
            }
            *exclusive = optval ? FALSE : TRUE; // Inverse logic
            sz = sizeof(BOOLEAN);
            status = STATUS_SUCCESS;
            break;
        }
        case IOCTL_AFD_POLL: {
            trace("network_DeviceIoControl IOCTL_AFD_POLL");
            if (InputBufferLength < sizeof(w32::afd_poll_params_64)) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            auto* params = static_cast<w32::afd_poll_params_64*>(InputBuffer);
            auto* output_info = static_cast<afd_poll_info*>(OutputBuffer);

            if (params->count == 0) {
                status = STATUS_INVALID_PARAMETER;
                break;
            }

            const size_t required_input_size = sizeof(w32::afd_poll_params_64) +
                                              (params->count * sizeof(afd_poll_info));
            const size_t required_output_size = params->count * sizeof(afd_poll_info);

            if (InputBufferLength < required_input_size ||
                OutputBufferLength < required_output_size) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            std::vector<pollfd> pollfds;
            std::vector<HANDLE> handles;

            // Set up poll structures
            for (ULONG i = 0; i < params->count; i++) {
                auto socket_handle = reinterpret_cast<HANDLE>(params->sockets[i].socket);
                DeviceHandle* socket_dev = get_device_handle(tls.process, socket_handle);

                if (!socket_dev || socket_dev->device_type != FILE_DEVICE_NETWORK) {
                    output_info[i].socket = params->sockets[i].socket;
                    output_info[i].flags = 0;
                    output_info[i].status = STATUS_INVALID_HANDLE;
                    continue;
                }

                pollfd pfd = {};
                pfd.fd = socket_dev->linux_fd;
                pfd.events = 0;

                // Map AFD poll flags to Linux poll events
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
                if (afd_flags & AFD_POLL_CLOSE) {
                    pfd.events |= POLLHUP;
                }
                if (afd_flags & AFD_POLL_ACCEPT) {
                    // For listening sockets, we monitor for read events to detect incoming connections
                    auto* sock_context = socket_dev->socket_context.get();
                    if (sock_context && sock_context->is_listening) {
                        pfd.events |= POLLIN;
                    }
                }
                if (afd_flags & AFD_POLL_CONNECT) {
                    // For connect, we monitor for write events to detect connection completion
                    auto* sock_context = socket_dev->socket_context.get();
                    if (sock_context && !sock_context->is_connected) {
                        pfd.events |= POLLOUT;
                    }
                }
                if (afd_flags & AFD_POLL_HUP) {
                    pfd.events |= POLLHUP;
                }
                if (afd_flags & AFD_POLL_CONNECT_ERR) {
                    pfd.events |= POLLERR;
                }
                if (afd_flags & AFD_POLL_READ) {
                    pfd.events |= POLLIN;
                }
                if (afd_flags & AFD_POLL_WRITE) {
                    pfd.events |= POLLOUT;
                }
                if (afd_flags & AFD_POLL_RESET) {
                    // No direct equivalent, ignore
                }

                pollfds.push_back(pfd);
                handles.push_back(socket_handle);

                // Initialize output
                output_info[i].socket = params->sockets[i].socket;
                output_info[i].flags = 0;
                output_info[i].status = STATUS_SUCCESS;
            }

            if (pollfds.empty()) {
                status = STATUS_INVALID_PARAMETER;
                sz = 0;
                break;
            }

            // Convert timeout (100ns units to milliseconds)
            int timeout_ms;
            if (params->timeout == 0) {
                timeout_ms = 0; // Non-blocking
            } else if (params->timeout < 0) {
                timeout_ms = -1; // Infinite
            } else {
                timeout_ms = static_cast<int>(params->timeout / 10000); // Convert to ms
                if (timeout_ms == 0 && params->timeout > 0) {
                    timeout_ms = 1; // Minimum 1ms for positive timeouts
                }
            }

            // Perform the poll operation
            int poll_result = poll(pollfds.data(), pollfds.size(), timeout_ms);

            if (poll_result < 0) {
                status = errno_to_status(errno);
                sz = 0;
                break;
            }

            if (poll_result == 0) {
                // Timeout - no events
                status = STATUS_TIMEOUT;
                sz = required_output_size;
                break;
            }

            // Process results
            bool any_events = false;
            for (size_t i = 0; i < pollfds.size(); i++) {
                const pollfd& pfd = pollfds[i];
                HANDLE socket_handle = handles[i];
                DeviceHandle* socket_dev = get_device_handle(tls.process, socket_handle);
                auto* sock_context = socket_dev ? socket_dev->socket_context.get() : nullptr;

                ULONG result_flags = 0;

                if (pfd.revents & POLLIN) {
                    if (sock_context && sock_context->is_listening) {
                        result_flags |= AFD_POLL_ACCEPT;
                    } else {
                        result_flags |= AFD_POLL_READ;
                    }
                }

                if (pfd.revents & POLLOUT) {
                    if (sock_context && !sock_context->is_connected) {
                        result_flags |= AFD_POLL_CONNECT;
                        sock_context->is_connected = true;
                    } else {
                        result_flags |= AFD_POLL_WRITE;
                    }
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

                if (result_flags != 0) {
                    any_events = true;

                    // Update socket context with pending events
                    if (sock_context) {
                        sock_context->poll_events |= result_flags;

                        // Signal any registered event
                        if (sock_context->event && (sock_context->event_mask & result_flags)) {
                            sock_context->event->set();
                        }
                    }
                }
            }

            status = any_events ? STATUS_SUCCESS : STATUS_TIMEOUT;
            sz = required_output_size;
            break;
        }
        default:
            break;
    }

    if (!NT_ERROR(status)) {
        if (IoStatusBlock) {
            auto* ios = static_cast<IO_STATUS_BLOCK*>(IoStatusBlock);
            ios->Status = status;
            ios->Information = sz;
        }
        if (Event) {
            NtSetEvent(Event, nullptr);
        }
        if (ApcRoutine) {
            NtQueueApcThread(reinterpret_cast<HANDLE>(-2),
                           reinterpret_cast<PNTAPCFUNC>(ApcRoutine),
                           reinterpret_cast<ULONG_PTR>(ApcContext),
                           reinterpret_cast<ULONG_PTR>(IoStatusBlock),
                           reinterpret_cast<ULONG_PTR>(nullptr));
        }
    }
    trace("status=", std::hex, status, " sz=", sz);
    return status;
}

// partial support for cdrom's, mostly media handling (who uses cdrom's these days anyway?)
NTSTATUS cdrom_DeviceIoControl(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    IO_STATUS_BLOCK* IoStatusBlock,
    UINT IoControlCode,
    PVOID InputBuffer,
    ULONG InputBufferLength,
    PVOID OutputBuffer,
    UINT OutputBufferLength) {
    trace("cdrom_DeviceIoControl called with IoControlCode=", std::hex, IoControlCode,
          " InputBufferLength=", std::dec, InputBufferLength,
          " OutputBufferLength=", OutputBufferLength);
    NTSTATUS status = STATUS_SUCCESS;
    ULONG sz = 0;
    const auto dev = get_device_handle(tls.process, FileHandle);
    if (!dev) {
        ret("cdrom_DeviceIoControl: invalid device handle");
        return STATUS_INVALID_HANDLE;
    }

    switch (IoControlCode)
    {
        case IOCTL_CDROM_CHECK_VERIFY:
        case IOCTL_DISK_CHECK_VERIFY:
        case IOCTL_STORAGE_CHECK_VERIFY:
        case IOCTL_STORAGE_CHECK_VERIFY2: {
            trace("cdrom_DeviceIoControl: IOCTL_CDROM_CHECK_VERIFY");
            // check if media is present (either cdrom is inserted, or disk is present)
            int ret = ioctl(dev->linux_fd, CDROM_DRIVE_STATUS, CDSL_CURRENT);
            if (ret == CDS_NO_INFO || ret == CDS_NO_DISC) {
                status = STATUS_NO_MEDIA_IN_DEVICE;
            } else if (ret == CDS_TRAY_OPEN) {
                status = STATUS_DEVICE_NOT_READY;
            } else if (ret < 0) {
                status = STATUS_IO_DEVICE_ERROR;
            } else {
                status = errno_to_status(ret);
            }
            sz = 0;
            break;
        }
        case IOCTL_STORAGE_LOAD_MEDIA:
        case IOCTL_CDROM_LOAD_MEDIA: {
            trace("cdrom_DeviceIoControl: IOCTL_CDROM_LOAD_MEDIA");
            // Load the media (close the tray for cdrom, do nothing for disk)
            int ret = ioctl(dev->linux_fd, CDROM_LOCKDOOR, 0);
            status = errno_to_status(ret);
            sz = 0;
            break;
        }

        case IOCTL_STORAGE_EJECT_MEDIA: {
            trace("cdrom_DeviceIoControl: IOCTL_CDROM_EJECT_MEDIA");
            // Eject the media (open the tray for cdrom, eject for disk)
            int ret = ioctl(dev->linux_fd, CDROM_LOCKDOOR, 1);
            sz = 0;
            if (ret < 0) {
                status = STATUS_IO_DEVICE_ERROR;
            } else {
                ret = ioctl(dev->linux_fd, CDROMEJECT, 1);
                status = errno_to_status(ret);
            }
        }

        case IOCTL_CDROM_MEDIA_REMOVAL:
        case IOCTL_DISK_MEDIA_REMOVAL:
        case IOCTL_STORAGE_MEDIA_REMOVAL:
        case IOCTL_STORAGE_EJECTION_CONTROL: {
            trace("cdrom_DeviceIoControl: IOCTL_CDROM_MEDIA_REMOVAL");
            // Prevent or allow media removal (lock or unlock the tray for cdrom, do nothing for disk)
            if (InputBufferLength < sizeof(BOOLEAN)) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }
            sz = sizeof(BOOLEAN);
            BOOLEAN prevent = *static_cast<BOOLEAN*>(InputBuffer);
            int ret = ioctl(dev->linux_fd, CDROM_LOCKDOOR, prevent ? 1 : 0);
            status = errno_to_status(ret);
            sz = 0;
            break;
        }

        case IOCTL_DISK_GET_MEDIA_TYPES:
        case IOCTL_STORAGE_GET_MEDIA_TYPES:
        case IOCTL_STORAGE_GET_MEDIA_TYPES_EX: {
            trace("cdrom_DeviceIoControl: IOCTL_STORAGE_GET_MEDIA_TYPES");
            // Get media types supported by the device
            if (OutputBufferLength < sizeof(GET_MEDIA_TYPES)) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }
            sz = sizeof(GET_MEDIA_TYPES);
            auto* media_types = static_cast<GET_MEDIA_TYPES*>(OutputBuffer);
            memset(media_types, 0, OutputBufferLength);
            media_types->DeviceType = dev->device_type;
            media_types->MediaInfoCount = 1;

            unsigned char drive_config[8];
            unsigned char get_config_cmd[10] = { GPCMD_GET_CONFIGURATION, 0, 0xff, 0xff,
                                                 0, 0, 0, 0, sizeof(drive_config), 0 };
            sg_io_hdr_t iocmd = {
                .interface_id = 'S',
                .dxfer_direction = SG_DXFER_FROM_DEV,
                .cmd_len = sizeof(get_config_cmd),
                .dxfer_len = sizeof(drive_config),
                .dxferp = drive_config,
                .cmdp = get_config_cmd,
                .timeout = 2000,
            };
            int err;
            if ((err = ioctl(dev->linux_fd, SG_IO, &iocmd)) < 0) {
                status = errno_to_status(err);
                break;
            }
            if (iocmd.status == 0 && (drive_config[6] || drive_config[7] >= 0x10)) {
                // DVD drive
                media_types->DeviceType = FILE_DEVICE_DVD;
            }
            break;
        }

        case IOCTL_STORAGE_GET_DEVICE_NUMBER: {
            trace("cdrom_DeviceIoControl: IOCTL_STORAGE_GET_DEVICE_NUMBER");
            // Get device number (not implemented)
            if (OutputBufferLength < sizeof(STORAGE_DEVICE_NUMBER)) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }
            sz = sizeof(STORAGE_DEVICE_NUMBER);
            auto* dev_num = static_cast<STORAGE_DEVICE_NUMBER*>(OutputBuffer);
            dev_num->DeviceType = dev->device_type;
            dev_num->DeviceNumber = 1; // Not implemented
            dev_num->PartitionNumber = 1; // Not implemented
            sz = sizeof(STORAGE_DEVICE_NUMBER);
            break;
        }

        case IOCTL_STORAGE_RESET_DEVICE: {
            trace("cdrom_DeviceIoControl: IOCTL_STORAGE_RESET_DEVICE");
            // Reset the device
            int ret = ioctl(dev->linux_fd, CDROMRESET);
            status = errno_to_status(ret);
            sz = 0;
            break;
        }

        case IOCTL_CDROM_GET_CONTROL: {
            trace("cdrom_DeviceIoControl: IOCTL_CDROM_GET_CONTROL");
            // Get audio control information (only LogicalBlocksPerSecond is set)
            sz = sizeof(CDROM_AUDIO_CONTROL);
            if (OutputBufferLength < sizeof(CDROM_AUDIO_CONTROL)) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }
            auto* control = static_cast<CDROM_AUDIO_CONTROL*>(OutputBuffer);
            memset(control, 0, sizeof(*control));
            control->LogicalBlocksPerSecond = 75; // Standard for audio CDs
        }

        case IOCTL_CDROM_GET_DRIVE_GEOMETRY: {
            trace("cdrom_DeviceIoControl: IOCTL_CDROM_GET_DRIVE_GEOMETRY");
            sz = sizeof(DISK_GEOMETRY);
            if (OutputBufferLength < sizeof(DISK_GEOMETRY)) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }
            auto* geometry = static_cast<DISK_GEOMETRY*>(OutputBuffer);
            memset(geometry, 0, sizeof(*geometry));
            // first read filesize of the device
            off_t size = lseek(dev->linux_fd, 0, SEEK_END);
            if (size < 0) {
                status = errno_to_status(errno);
                break;
            }
            geometry->Cylinders.QuadPart = size / (512 * 255 * 63); // 512 * 255 * 63 bytes per cylinder because one sector is 512 bytes, 255 sectors per track, 63 tracks per cylinder
            geometry->MediaType = FixedMedia;
            geometry->TracksPerCylinder = 255;
            geometry->SectorsPerTrack = 63;
            geometry->BytesPerSector = 512;
            sz = sizeof(DISK_GEOMETRY);
        }

        case IOCTL_CDROM_DISK_TYPE: {
            trace("cdrom_DeviceIoControl: IOCTL_CDROM_DISK_TYPE");
            sz = sizeof(CDROM_DISK_DATA);
            if (OutputBufferLength < sizeof(CDROM_DISK_DATA) ) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }
            if (InputBuffer && InputBufferLength) {
                status = STATUS_INVALID_PARAMETER;
                break;
            }
            auto* disk_data = static_cast<CDROM_DISK_DATA*>(OutputBuffer);
            memset(disk_data, 0, sizeof(*disk_data));
            int ret = ioctl(dev->linux_fd, CDROM_DRIVE_STATUS, CDSL_CURRENT);
            status = errno_to_status(ret);
            disk_data->DiskData = 0;
            // read TOC to determine a disk type
            cdrom_tochdr tochdr{};
            ret = ioctl(dev->linux_fd, CDROMREADTOCHDR, &tochdr);
            if (ret < 0) {
                status = errno_to_status(ret);
                break;
            }
            for (int i = tochdr.cdth_trk0; i <= tochdr.cdth_trk1; i++) {
                cdrom_tocentry tocentry = {};
                tocentry.cdte_track = i;
                tocentry.cdte_format = CDROM_MSF;
                ret = ioctl(dev->linux_fd, CDROMREADTOCENTRY, &tocentry);
                if (ret < 0) {
                    status = errno_to_status(ret);
                    break;
                }
                if (tocentry.cdte_ctrl & CDROM_DATA_TRACK) {
                    disk_data->DiskData |= CDROM_DISK_DATA_TRACK; // Data track present
                } else {
                    disk_data->DiskData |= CDROM_DISK_AUDIO_TRACK; // Audio track present
                }
            }
            sz = sizeof(CDROM_DISK_DATA);
            break;
        }
        // TODO: more CD ioctls + DVDs

        default:
            status = STATUS_NOT_SUPPORTED;
    }
    if (!NT_ERROR(status))
    {
        if (IoStatusBlock)
        {
            auto* ios = static_cast<IO_STATUS_BLOCK*>(IoStatusBlock);
            ios->Status = status;
            ios->Information = sz;
        }
        if (Event) {
            NtSetEvent(Event, nullptr); // TODO: impl
        }
        if (ApcRoutine) {
            NtQueueApcThread(reinterpret_cast<HANDLE>(-2), reinterpret_cast<PNTAPCFUNC>(ApcRoutine), reinterpret_cast<ULONG_PTR>(ApcContext), reinterpret_cast<ULONG_PTR>(IoStatusBlock->Pointer), reinterpret_cast<ULONG_PTR>(nullptr)); // TODO: impl
        }
    }
    trace("status=", std::hex, status, " sz=", sz);
    return status;
}

// idc
NTSTATUS serial_DeviceIoControl(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    IO_STATUS_BLOCK* IoStatusBlock,
    UINT IoControlCode,
    PVOID InputBuffer,
    ULONG InputBufferLength,
    PVOID OutputBuffer,
    UINT OutputBufferLength) {
    trace("serial_DeviceIoControl IoControlCode=", std::hex, IoControlCode,
          " InputBufferLength=", std::dec, InputBufferLength,
          " OutputBufferLength=", OutputBufferLength);
    trace("status=STATUS_NOT_SUPPORTED");

    return STATUS_NOT_SUPPORTED; // TODO (in far future)
}

NTSTATUS tape_DeviceIoControl(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    IO_STATUS_BLOCK* IoStatusBlock,
    UINT IoControlCode,
    PVOID InputBuffer,
    ULONG InputBufferLength,
    PVOID OutputBuffer,
    UINT OutputBufferLength) {

    return STATUS_NOT_SUPPORTED; // TODO (in far future)
}

NTSTATUS NTAPI NtDeviceIoControlFile(
    HANDLE FileHandle,
    HANDLE Event,
    PVOID ApcRoutine,
    PVOID ApcContext,
    PVOID IoStatusBlock,
    ULONG IoControlCode,
    PVOID InputBuffer,
    ULONG InputBufferLength,
    PVOID OutputBuffer,
    ULONG OutputBufferLength) {

    const ULONG device = (IoControlCode >> 16);
    NTSTATUS status = STATUS_NOT_SUPPORTED;

    trace("NtDeviceIoControlFile called with handle: ", FileHandle,
          ", ioctl code: 0x", std::hex, IoControlCode, std::dec,
          ", input length: ", InputBufferLength,
          ", output length: ", OutputBufferLength);

    /* some broken applications call this frequently with INVALID_HANDLE_VALUE
     * and run slowly if we make a server call every time */
    if (HandleToLong(FileHandle) == ~0)
        return STATUS_INVALID_HANDLE;

    switch (device) {
        case FILE_DEVICE_BEEP:
        case FILE_DEVICE_NETWORK:
            trace("NtDeviceIoControlFile: routing to network_DeviceIoControl");
            status = network_DeviceIoControl(FileHandle, Event,
                                  reinterpret_cast<PIO_APC_ROUTINE>(ApcRoutine),
                                  ApcContext,
                                  static_cast<IO_STATUS_BLOCK*>(IoStatusBlock),
                                  IoControlCode, InputBuffer, InputBufferLength,
                                  OutputBuffer, OutputBufferLength);
            break;

        case FILE_DEVICE_DISK:
        case FILE_DEVICE_CD_ROM:
        case FILE_DEVICE_DVD:
        case FILE_DEVICE_CONTROLLER:
        case FILE_DEVICE_MASS_STORAGE:
            trace("NtDeviceIoControlFile: routing to cdrom_DeviceIoControl");
            status = cdrom_DeviceIoControl(FileHandle, Event,
                                         reinterpret_cast<PIO_APC_ROUTINE>(ApcRoutine),
                                         ApcContext,
                                         static_cast<IO_STATUS_BLOCK*>(IoStatusBlock),
                                         IoControlCode, InputBuffer, InputBufferLength,
                                         OutputBuffer, OutputBufferLength);
            break;

        case FILE_DEVICE_SERIAL_PORT:
            trace("NtDeviceIoControlFile: routing to serial_DeviceIoControl");
            status = serial_DeviceIoControl(FileHandle, Event,
                                          reinterpret_cast<PIO_APC_ROUTINE>(ApcRoutine),
                                          ApcContext,
                                          static_cast<IO_STATUS_BLOCK*>(IoStatusBlock),
                                          IoControlCode, InputBuffer, InputBufferLength,
                                          OutputBuffer, OutputBufferLength);
            break;

        case FILE_DEVICE_TAPE:
            trace("NtDeviceIoControlFile: routing to tape_DeviceIoControl");
            status = tape_DeviceIoControl(FileHandle, Event,
                                        reinterpret_cast<PIO_APC_ROUTINE>(ApcRoutine),
                                        ApcContext,
                                        static_cast<IO_STATUS_BLOCK*>(IoStatusBlock),
                                        IoControlCode, InputBuffer, InputBufferLength,
                                        OutputBuffer, OutputBufferLength);
            break;
        default:
            break;
    }

    if (NT_ERROR(status)) {
        warn("NtDeviceIoControlFile: Unsupported IOCTL 0x", std::hex, IoControlCode, std::dec,
             " for device type ", device);
    }

    ret("NtDeviceIoControlFile returning status 0x", std::hex, status, std::dec);
    return status;
}


// Related NT API functions that work with NtDeviceIoControlFile

NTSTATUS parse_object_attributes(PVOID ObjectAttributes, std::string& path) {
    if (!ObjectAttributes) {
        return STATUS_INVALID_PARAMETER;
    }

    auto* obj_attr = static_cast<OBJECT_ATTRIBUTES*>(ObjectAttributes);
    if (!obj_attr->ObjectName) {
        return STATUS_INVALID_PARAMETER;
    }

    auto* unicode_str = obj_attr->ObjectName;
    if (unicode_str->Length == 0 || !unicode_str->Buffer) {
        return STATUS_INVALID_PARAMETER;
    }

    for (size_t i = 0; i < unicode_str->Length / sizeof(WCHAR); i++) {
        path += static_cast<char>(unicode_str->Buffer[i] & 0xFF);
    }
    trace("Parsed object path: ", converter.from_bytes(path));

    return STATUS_SUCCESS;
}

HANDLE create_disk_handle(const std::string& linux_path, DEVICE_TYPE type, ULONG options = 0, ULONG disposition = 0, ULONG attributes = 0, ULONG access = GENERIC_ALL, ULONG share_access = 0) {
    trace("create_disk_handle called with path: ", converter.from_bytes(linux_path),
          ", type: ", type, ", options: 0x", std::hex, options, std::dec);
    int flags = O_RDWR | O_CLOEXEC;
    if (options & FILE_NON_DIRECTORY_FILE) {
        flags |= O_NOFOLLOW;
    }
    if (options & FILE_SYNCHRONOUS_IO_ALERT || options & FILE_SYNCHRONOUS_IO_NONALERT) {
        flags |= O_SYNC;
    }
    if (options & FILE_RANDOM_ACCESS) {
        // No direct equivalent, ignore
    }
    if (options & FILE_SEQUENTIAL_ONLY) {
        // No direct equivalent, ignore
    }
    if (options & FILE_NO_INTERMEDIATE_BUFFERING) {
        // No direct equivalent, ignore
    }
    if (options & FILE_WRITE_THROUGH) {
        flags |= O_DSYNC;
    }
    if (options & FILE_DELETE_ON_CLOSE) {
        // No direct equivalent, ignore
    }
    if (options & FILE_OPEN_FOR_BACKUP_INTENT) {
        // No direct equivalent, ignore
    }
    if (options & FILE_OPEN_BY_FILE_ID) {
        // No direct equivalent, ignore
    }
    if (options & FILE_OPEN_FOR_FREE_SPACE_QUERY) {
        // No direct equivalent, ignore
    }
    if (disposition == FILE_CREATE) {
        flags |= O_CREAT | O_EXCL;
    } else if (disposition == FILE_OPEN_IF) {
        flags |= O_CREAT;
    } else if (disposition == FILE_OVERWRITE) {
        flags |= O_TRUNC;
    } else if (disposition == FILE_OVERWRITE_IF) {
        flags |= O_CREAT | O_TRUNC;
    } else if (disposition == FILE_SUPERSEDE) {
        flags |= O_CREAT | O_TRUNC;
    } else if (disposition == FILE_OPEN) {
        // Default is open only, do nothing
    } else {
        warn("create_disk_handle: Unsupported disposition 0x", std::hex, disposition, std::dec);
        return nullptr;
    }
    if (attributes & FILE_ATTRIBUTE_READONLY) {
        flags &= ~O_RDWR;
        flags |= O_RDONLY;
    }
    if (attributes & FILE_ATTRIBUTE_HIDDEN) {
        // No direct equivalent, ignore
    }
    if (attributes & FILE_ATTRIBUTE_SYSTEM) {
        // No direct equivalent, ignore
    }
    if (attributes & FILE_ATTRIBUTE_DIRECTORY) {
        flags |= O_DIRECTORY;
    }
    if (attributes & FILE_ATTRIBUTE_ARCHIVE) {
        // No direct equivalent, ignore
    }
    if (attributes & FILE_ATTRIBUTE_NORMAL) {
        // No direct equivalent, ignore
    }
    if (attributes & FILE_ATTRIBUTE_TEMPORARY) {
        // No direct equivalent, ignore
    }
    if (attributes & FILE_ATTRIBUTE_OFFLINE) {
        // No direct equivalent, ignore
    }
    if (attributes & FILE_ATTRIBUTE_NOT_CONTENT_INDEXED) {
        // No direct equivalent, ignore
    }
    if (attributes & FILE_ATTRIBUTE_ENCRYPTED) {
        // No direct equivalent, ignore
    }
    if (share_access & FILE_SHARE_READ) {
        flags &= ~O_EXCL; // Allow others to open the file
    }
    if (share_access & FILE_SHARE_WRITE) {
        flags &= ~O_EXCL; // Allow others to open the file
    }
    if (share_access & FILE_SHARE_DELETE) {
        flags &= ~O_EXCL; // Allow others to open the file
    }
    if (access & GENERIC_READ) {
        flags |= O_RDONLY;
    }
    if (access & GENERIC_WRITE) {
        flags |= O_WRONLY;
    }
    if (access & GENERIC_ALL) {
        flags |= O_RDWR;
    }
    if ((access & (GENERIC_READ | GENERIC_WRITE)) == (GENERIC_READ | GENERIC_WRITE)) {
        flags |= O_RDWR;
    }
    if (access & GENERIC_EXECUTE) {
        flags |= O_RDONLY; // No direct equivalent, treat as read
    }
    int fd = open(linux_path.c_str(), flags);
    if (fd < 0) return nullptr;

    auto device = std::make_unique<DeviceHandle>(fd, type, linux_path, options, disposition, access, share_access, attributes);
    HANDLE h = device.get();
    processes[tls.process].device_handles[h] = std::move(device);
    return h;
}

struct DiskInfo {
    std::string linux_path;
    std::vector<std::string> partitions;
};

NTSTATUS NTAPI NtCreateFile(
    HANDLE* FileHandle,
    ULONG DesiredAccess,
    PVOID ObjectAttributes,
    PVOID IoStatusBlock,
    int64_t* AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength) {
    trace("NtCreateFile called with FileHandle: ", FileHandle,
          ", DesiredAccess: 0x", std::hex, DesiredAccess,
          ", ObjectAttributes: ", ObjectAttributes,
          ", IoStatusBlock: ", IoStatusBlock,
          ", AllocationSize: ", AllocationSize,
          ", FileAttributes: 0x", FileAttributes,
          ", ShareAccess: 0x", ShareAccess,
          ", CreateDisposition: 0x", CreateDisposition,
          ", CreateOptions: 0x", CreateOptions,
          ", EaBuffer: ", EaBuffer,
          ", EaLength: ", EaLength, std::dec);

    if (!FileHandle || !ObjectAttributes) return STATUS_INVALID_PARAMETER;

    std::string path;
    NTSTATUS status = parse_object_attributes(ObjectAttributes, path);
    if (!NT_SUCCESS(status)) return status;

    // Network sockets
    if (path.starts_with(R"(\Device\Afd\)")) {
        trace("NtCreateFile: Creating AFD socket with path ", converter.from_bytes(path));
        int family = AF_INET, type = SOCK_STREAM, protocol = IPPROTO_TCP;

        std::string afd_params = path.substr(12);
        size_t first = afd_params.find('_'), second = afd_params.find('_', first + 1);
        if (first != std::string::npos && second != std::string::npos) {
            try {
                family = std::stoi(afd_params.substr(0, first));
                type = std::stoi(afd_params.substr(first + 1, second - first - 1));
                protocol = std::stoi(afd_params.substr(second + 1));
            } catch (...) {}
        }

        SOCKET sockfd = socket(family, type, protocol);

        if (sockfd < 0) return errno_to_status(errno);

        auto device = std::make_unique<DeviceHandle>(sockfd, FILE_DEVICE_NETWORK, "afd_socket", CreateOptions, CreateDisposition, DesiredAccess, ShareAccess, FileAttributes);
        device->socket_context = std::make_unique<WSK_SOCKET_CONTEXT>();
        device->socket_context->family = family;
        device->socket_context->socket_type = type;
        device->socket_context->protocol = protocol;
        *FileHandle = reinterpret_cast<HANDLE>(device.get());
        processes[tls.process].device_handles[*FileHandle] = std::move(device);

        if (IoStatusBlock) {
            auto* ios = static_cast<IO_STATUS_BLOCK*>(IoStatusBlock);
            ios->Status = STATUS_SUCCESS;
            ios->Information = 0;
        }
        ret("NtCreateFile: Created AFD socket with handle ", *FileHandle, " successfully");
        return STATUS_SUCCESS;
    }

    // Only file access, no raw disk/partition access for *now* (also as a precaution to make sure it does not destroy the host system), also no cdroms, tapes, serial ports etc.
    if (!path.starts_with(R"(\??\)")) {
        ret("NtCreateFile: Unsupported path prefix in ", converter.from_bytes(path));
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }
    path = path.substr(4); // Remove \??\
    // replace \ with /
    std::ranges::replace(path, '\\', '/');
    // prepend "." (relative to the current working directory)
    if (path.starts_with('/')) path = "." + path;
    else path = "./" + path;
    trace("NtCreateFile: Translated path: ", converter.from_bytes(path));
    if (HANDLE handle = create_disk_handle(path, FILE_DEVICE_DISK, CreateOptions, CreateDisposition, FileAttributes, DesiredAccess, ShareAccess); !handle) {
        ret("NtCreateFile: Failed to create disk handle for ", converter.from_bytes(path));
        return errno_to_status(errno);
    } else {
        *FileHandle = handle;
        if (IoStatusBlock) {
            auto* ios = static_cast<IO_STATUS_BLOCK*>(IoStatusBlock);
            ios->Status = STATUS_SUCCESS;
            ios->Information = 0;
        }
        ret("NtCreateFile: Created disk handle ", *FileHandle, " for ", converter.from_bytes(path), " successfully");
        return STATUS_SUCCESS;
    }

    // Everything else unsupported
    return STATUS_OBJECT_NAME_NOT_FOUND;
}
NTSTATUS NTAPI NtClose(HANDLE Handle) {
    trace("NtClose called with handle: ", Handle);
    const DeviceHandle* device = get_device_handle(tls.process, Handle);
    if (!device) {
        ret("NtClose: Invalid handle ", Handle);
        return STATUS_INVALID_HANDLE;
    }
    close(device->linux_fd);
    processes[tls.process].device_handles.erase(Handle);
    ret("NtClose: Closed handle ", Handle, " successfully");
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI NtReadFile(HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine,
                          PVOID ApcContext, PVOID IoStatusBlock, PVOID Buffer,
                          ULONG Length, int64_t* ByteOffset, PVOID Key) {
    trace("NtReadFile called with handle: ", FileHandle,
          ", Buffer: ", Buffer,
          ", Length: ", Length,
          ", ByteOffset: ", ByteOffset);

    const DeviceHandle* device = get_device_handle(tls.process, FileHandle);
    if (!device) {
        ret("NtReadFile: Invalid handle ", FileHandle);
        return STATUS_INVALID_HANDLE;
    }

    trace("NtReadFile: Device options = 0x", std::hex, device->options, std::dec);

    // Handle FILE_FLAG_NO_BUFFERING - requires sector alignment
    if (device->options & FILE_FLAG_NO_BUFFERING) {
        if (const auto buffer_addr = reinterpret_cast<uintptr_t>(Buffer); buffer_addr % 512 != 0 || Length % 512 != 0) {
            ret("NtReadFile: Buffer or length not sector-aligned for unbuffered I/O");
            return STATUS_INVALID_PARAMETER;
        }
        if (ByteOffset && (*ByteOffset % 512 != 0)) {
            ret("NtReadFile: Offset not sector-aligned for unbuffered I/O");
            return STATUS_INVALID_PARAMETER;
        }
    }

    // Handle overlapped I/O
    if (device->options & FILE_FLAG_OVERLAPPED) {
        if (!IoStatusBlock) {
            ret("NtReadFile: IoStatusBlock required for overlapped I/O");
            return STATUS_INVALID_PARAMETER;
        }
        // Set socket/file to non-blocking if not already
        if (const int flags = fcntl(device->linux_fd, F_GETFL, 0); !(flags & O_NONBLOCK)) {
            fcntl(device->linux_fd, F_SETFL, flags | O_NONBLOCK);
        }
    }

    ssize_t bytes;
    if (ByteOffset && *ByteOffset != -1) {
        bytes = pread(device->linux_fd, Buffer, Length, *ByteOffset);
    } else {
        bytes = read(device->linux_fd, Buffer, Length);
    }

    if (bytes < 0) {
        if ((errno == EAGAIN || errno == EWOULDBLOCK) && (device->options & FILE_FLAG_OVERLAPPED)) {
            // For overlapped I/O, return pending status
            auto* ios = static_cast<IO_STATUS_BLOCK*>(IoStatusBlock);
            ios->Status = STATUS_PENDING;
            ios->Information = 0;
            ret("NtReadFile: Overlapped I/O pending");
            return STATUS_PENDING;
        }
        ret("NtReadFile: Read error on handle ", FileHandle, ": ", strerror(errno));
        return errno_to_status(errno);
    }

    if (IoStatusBlock) {
        auto* ios = static_cast<IO_STATUS_BLOCK*>(IoStatusBlock);
        ios->Status = STATUS_SUCCESS;
        ios->Information = bytes;
    }

    // Signal event for overlapped completion
    if ((device->options & FILE_FLAG_OVERLAPPED) && Event) {
        NtSetEvent(Event, nullptr);
    }

    // Queue APC for overlapped completion
    if ((device->options & FILE_FLAG_OVERLAPPED) && ApcRoutine) {
        NtQueueApcThread(reinterpret_cast<HANDLE>(-2),
                       reinterpret_cast<PNTAPCFUNC>(ApcRoutine),
                       reinterpret_cast<ULONG_PTR>(ApcContext),
                       reinterpret_cast<ULONG_PTR>(IoStatusBlock),
                       reinterpret_cast<ULONG_PTR>(nullptr));
    }

    ret("NtReadFile: Read ", bytes, " bytes from handle ", FileHandle, " successfully");
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI NtWriteFile(HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine,
                           PVOID ApcContext, PVOID IoStatusBlock, PVOID Buffer,
                           ULONG Length, int64_t* ByteOffset, PVOID Key) {

    const DeviceHandle* device = get_device_handle(tls.process, FileHandle);
    if (!device) return STATUS_INVALID_HANDLE;

    const ssize_t bytes = write(device->linux_fd, Buffer, Length);
    if (bytes < 0) return errno_to_status(errno);

    if (IoStatusBlock) {
        auto* ios = static_cast<IO_STATUS_BLOCK*>(IoStatusBlock);
        ios->Status = STATUS_SUCCESS;
        ios->Information = bytes;
    }
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI NtFlushBuffersFile(HANDLE FileHandle, PVOID IoStatusBlock) {
    trace("NtFlushBuffersFile called with handle: ", FileHandle);

    const DeviceHandle* device = get_device_handle(tls.process, FileHandle);
    if (!device) {
        ret("NtFlushBuffersFile: Invalid handle ", FileHandle);
        return STATUS_INVALID_HANDLE;
    }

    if (fsync(device->linux_fd) < 0) {
        ret("NtFlushBuffersFile: fsync error on handle ", FileHandle, ": ", strerror(errno));
        return errno_to_status(errno);
    }

    if (IoStatusBlock) {
        auto* ios = static_cast<IO_STATUS_BLOCK*>(IoStatusBlock);
        ios->Status = STATUS_SUCCESS;
        ios->Information = 0;
    }
    ret("NtFlushBuffersFile: Flushed buffers for handle ", FileHandle, " successfully");
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI NtFlushBuffersFileEx(HANDLE FileHandle, ULONG Flags, PVOID IoStatusBlock) {
    trace("NtFlushBuffersFileEx called with handle: ", FileHandle, ", Flags: 0x", std::hex, Flags, std::dec);

    const DeviceHandle* device = get_device_handle(tls.process, FileHandle);
    if (!device) {
        ret("NtFlushBuffersFileEx: Invalid handle ", FileHandle);
        return STATUS_INVALID_HANDLE;
    }
    {
        if (fsync(device->linux_fd) < 0) {
            ret("NtFlushBuffersFileEx: fsync error on handle ", FileHandle, ": ", strerror(errno));
            return errno_to_status(errno);
        }
    }
    if (IoStatusBlock) {
        auto* ios = static_cast<IO_STATUS_BLOCK*>(IoStatusBlock);
        ios->Status = STATUS_SUCCESS;
        ios->Information = 0;
    }
    ret("NtFlushBuffersFileEx: Flushed buffers for handle ", FileHandle, " successfully");
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI NtWriteFileGather(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    FILE_SEGMENT_ELEMENT* SegmentArray,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key) {
    trace("NtWriteFileGather called with handle: ", FileHandle,
         ", Event: ", Event,
         ", ApcRoutine: ", ApcRoutine,
         ", ApcContext: ", ApcContext,
         ", IoStatusBlock: ", IoStatusBlock,
         ", SegmentArray: ", SegmentArray,
         ", Length: ", Length,
         ", ByteOffset: ", ByteOffset,
         ", Key: ", Key);
    if (!SegmentArray) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Length  == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Length % PAGE_SIZE != 0) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!IoStatusBlock) {
        return STATUS_INVALID_PARAMETER;
    }
    const auto *device = get_device_handle(tls.process, FileHandle);
    if (!device) {
        return STATUS_INVALID_HANDLE;
    }
    if (device->device_type != FILE_DEVICE_DISK) {
        return STATUS_INVALID_PARAMETER;
    }
    std::vector<iovec> iovecs;
    iovecs.reserve(Length / PAGE_SIZE);
    for (ULONG i = 0; i < Length / PAGE_SIZE; i++) {
        if (SegmentArray[i].Buffer == nullptr) {
            ret("NtWriteFileGather: NULL buffer in segment array");
            return STATUS_INVALID_PARAMETER;
        }
        iovecs.push_back({SegmentArray[i].Buffer, PAGE_SIZE});
    }
    ssize_t bytes;
    if (ByteOffset && ByteOffset->QuadPart != -1) {
        bytes = pwritev(device->linux_fd, iovecs.data(), iovecs.size(), ByteOffset->QuadPart);
    } else {
        bytes = writev(device->linux_fd, iovecs.data(), iovecs.size());
    }
    if (bytes < 0) {
        return errno_to_status(errno);
    }
    IoStatusBlock->Status = STATUS_SUCCESS;
    IoStatusBlock->Information = bytes;
    if (Event) {
        NtSetEvent(Event, nullptr);
    }
    if (ApcRoutine) {
        NtQueueApcThread(reinterpret_cast<HANDLE>(-2),
                         reinterpret_cast<PNTAPCFUNC>(ApcRoutine),
                         reinterpret_cast<ULONG_PTR>(ApcContext),
                         reinterpret_cast<ULONG_PTR>(IoStatusBlock),
                         reinterpret_cast<ULONG_PTR>(nullptr));
    }
    ret("NtWriteFileGather: Wrote ", bytes, " bytes to handle ", FileHandle, " successfully");
    return STATUS_SUCCESS;
}

// WINDOWS 10 22H2. MAKE SURE THAT DLLS COME FROM WINDOWS 10 22H2 AS WELL, OTHERWISE SYSCALL NUMBERS WILL NOT MATCH!
static const std::unordered_set<unsigned long long> windows_syscalls = {
    0x1,  // NTSTATUS NTAPI NtWorkerFactoryWorkerReady(_In_ HANDLE hWorkerFactory);
    0x3,  // NTSTATUS NTAPI NtMapUserPhysicalPagesScatter(
          //     _In_ PVOID *VirtualAddresses,
          //     _In_ ULONG NumberOfPages,
          //     _In_reads_opt_(NumberOfPages) PULONG_PTR UserPfnArray
          // );
    0x1B, // NTSTATUS NTAPI NtWriteFileGather(
          //     _In_ HANDLE FileHandle,
          //     _In_opt_ HANDLE Event,
          //     _In_opt_ PIO_APC_ROUTINE ApcRoutine,
          //     _In_opt_ PVOID ApcContext,
          //     _Out_ PIO_STATUS_BLOCK IoStatusBlock,
          //     _In_reads_(Length) FILE_SEGMENT_ELEMENT SegmentArray[],
          //     _In_ ULONG Length,
          //     _In_opt_ PLARGE_INTEGER ByteOffset,
          //     _In_opt_ PULONG Key
          // );
    0xE7, // NTSTATUS NTAPI NtFlushBuffersFileEx(
          //     _In_ HANDLE FileHandle,
          //     _In_ ULONG Flags,
          //     _Out_ PIO_STATUS_BLOCK IoStatusBlock
          // );
};

struct LoadedModule {
    std::wstring name;
    uintptr_t base_address;
    size_t size;
    std::unique_ptr<LIEF::PE::Binary> pe_binary;
    bool is_dll;
    uintptr_t entry_point;

    LoadedModule(std::wstring n, const uintptr_t base, const size_t sz,
                 std::unique_ptr<LIEF::PE::Binary> pe, const bool DLL = false)
        : name(std::move(n)), base_address(base), size(sz), pe_binary(std::move(pe)),
          is_dll(DLL), entry_point(0) {
        if (pe_binary && pe_binary->optional_header().addressof_entrypoint() != 0) {
            entry_point = base_address + pe_binary->optional_header().addressof_entrypoint();
        }
    }
};

class ApiSetResolver {
private:
    std::unordered_map<std::string, std::string> api_mapping;
    bool is_loaded = false;

public:
    bool load_apiset_json(const std::string& json_file) {
        try {
            std::ifstream file(json_file);
            if (!file.is_open()) {
                trace("Could not open API set JSON file: ", converter.from_bytes(json_file));
                return false;
            }

            nlohmann::json data;
            file >> data;

            api_mapping.clear();
            for (const auto& ns : data["namespaces"]) {
                std::string name = ns["name"];
                std::string host = ns["host"];
                std::ranges::transform(name, name.begin(), ::tolower);
                api_mapping[name] = host;
            }

            is_loaded = true;
            trace("Loaded ", api_mapping.size(), " API set mappings from ", converter.from_bytes(json_file));
            return true;
        } catch (const std::exception& e) {
            trace("Error loading API set JSON: ", e.what());
            return false;
        }
    }

    std::string resolve_dll(const std::string& dll_name) const {
        if (!is_loaded) {
            return dll_name;
        }

        std::string lower_name = dll_name;
        std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);

        auto it = api_mapping.find(lower_name);
        if (it != api_mapping.end()) {
            trace("API set resolved: ", converter.from_bytes(dll_name), " -> ", converter.from_bytes(it->second));
            return it->second;
        }

        return dll_name;
    }

    bool is_api_set(const std::string& dll_name) const {
        return dll_name.starts_with("api-ms-") || dll_name.starts_with("ext-ms-");
    }
};

// Function tracing infrastructure
struct FunctionWrapper {
    void* original_func;
    void* wrapper_func;
    std::string func_name;
    std::string dll_name;
};

static std::unordered_map<void*, FunctionWrapper> function_wrappers;
static std::unordered_map<std::string, void*> original_functions;

// Assembly wrapper generation - creates a trampoline that logs then jumps to original
class AssemblyWrapperGenerator {
private:
    static constexpr size_t WRAPPER_SIZE = 128; // Size per wrapper function

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
        // Allocate executable memory for the wrapper
        void* wrapper_mem = mmap(nullptr, WRAPPER_SIZE,
                               PROT_READ | PROT_WRITE | PROT_EXEC,
                               MAP_SHARED | MAP_ANONYMOUS, -1, 0);

        return original_func;

        if (wrapper_mem == MAP_FAILED) {
            return nullptr;
        }

        if (!original_func) {
            //create a thin wrapper that just logs and returns
            auto *data = new WrapperData{nullptr, func_name, dll_name};
            auto code = static_cast<uint8_t*>(wrapper_mem);
            size_t offset = 0;

            // Save all caller-saved registers
            // push %rax
            code[offset++] = 0x50;
            // push %rcx
            code[offset++] = 0x51;
            // push %rdx
            code[offset++] = 0x52;
            // push %rsi
            code[offset++] = 0x56;
            // push %rdi
            code[offset++] = 0x57;
            // push %r8
            code[offset++] = 0x41; code[offset++] = 0x50;
            // push %r9
            code[offset++] = 0x41; code[offset++] = 0x51;
            // push %r10
            code[offset++] = 0x41; code[offset++] = 0x52;
            // push %r11
            code[offset++] = 0x41; code[offset++] = 0x53;
            // Set up parameters for log_function_call(dll_name, func_name, original_func)
            // mov $data->dll_name, %rdi (1st parameter)
            code[offset++] = 0x48; code[offset++] = 0xbf;
            *reinterpret_cast<uintptr_t*>(&code[offset]) = reinterpret_cast<uintptr_t>(data->dll_name);
            offset += 8;
            // mov $data->func_name, %rsi (2nd parameter)
            code[offset++] = 0x48; code[offset++] = 0xbe;
            *reinterpret_cast<uintptr_t*>(&code[offset]) = reinterpret_cast<uintptr_t>(data->func_name);
            offset += 8;
            // mov $data->original_func, %rdx (3rd parameter)
            code[offset++] = 0x48; code[offset++] = 0xba;
            *reinterpret_cast<uintptr_t*>(&code[offset]) = reinterpret_cast<uintptr_t>(data->original_func);
            offset += 8;
            // Call log_function_call
            // mov $log_function_call, %rax
            code[offset++] = 0x48; code[offset++] = 0xb8;
            *reinterpret_cast<uintptr_t*>(&code[offset]) = reinterpret_cast<uintptr_t>(&log_function_call);
            offset += 8;
            // call *%rax
            code[offset++] = 0xff; code[offset++] = 0xd0;
            // restore all caller-saved registers in reverse order
            // pop %r11
            code[offset++] = 0x41; code[offset++] = 0x5b;
            // pop %r10
            code[offset++] = 0x41; code[offset++] = 0x5a;
            // pop %r9
            code[offset++] = 0x41; code[offset++] = 0x59;
            // pop %r8
            code[offset++] = 0x41; code[offset++] = 0x58;
            // pop %rdi
            code[offset++] = 0x5f;
            // pop %rsi
            code[offset++] = 0x5e;
            // pop %rdx
            code[offset++] = 0x5a;
            // pop %rcx
            code[offset++] = 0x59;
            // pop %rax
            code[offset++] = 0x58;
            // ret
            code[offset++] = 0xc3;
        }

        // Create wrapper data structure
        WrapperData* data = new WrapperData{original_func, func_name, dll_name};

        // Generate assembly wrapper
        uint8_t* code = static_cast<uint8_t*>(wrapper_mem);
        size_t offset = 0;

        // Save all caller-saved registers
        // push %rax
        code[offset++] = 0x50;
        // push %rcx
        code[offset++] = 0x51;
        // push %rdx
        code[offset++] = 0x52;
        // push %rsi
        code[offset++] = 0x56;
        // push %rdi
        code[offset++] = 0x57;
        // push %r8
        code[offset++] = 0x41; code[offset++] = 0x50;
        // push %r9
        code[offset++] = 0x41; code[offset++] = 0x51;
        // push %r10
        code[offset++] = 0x41; code[offset++] = 0x52;
        // push %r11
        code[offset++] = 0x41; code[offset++] = 0x53;

        // Set up parameters for log_function_call(dll_name, func_name, original_func)
        // mov $data->dll_name, %rdi (1st parameter)
        code[offset++] = 0x48; code[offset++] = 0xbf;
        *reinterpret_cast<uintptr_t*>(&code[offset]) = reinterpret_cast<uintptr_t>(data->dll_name);
        offset += 8;

        // mov $data->func_name, %rsi (2nd parameter)
        code[offset++] = 0x48; code[offset++] = 0xbe;
        *reinterpret_cast<uintptr_t*>(&code[offset]) = reinterpret_cast<uintptr_t>(data->func_name);
        offset += 8;

        // mov $data->original_func, %rdx (3rd parameter)
        code[offset++] = 0x48; code[offset++] = 0xba;
        *reinterpret_cast<uintptr_t*>(&code[offset]) = reinterpret_cast<uintptr_t>(data->original_func);
        offset += 8;

        // Call log_function_call
        // mov $log_function_call, %rax
        code[offset++] = 0x48; code[offset++] = 0xb8;
        *reinterpret_cast<uintptr_t*>(&code[offset]) = reinterpret_cast<uintptr_t>(&log_function_call);
        offset += 8;

        // call *%rax
        code[offset++] = 0xff; code[offset++] = 0xd0;

        // Restore all caller-saved registers in reverse order
        // pop %r11
        code[offset++] = 0x41; code[offset++] = 0x5b;
        // pop %r10
        code[offset++] = 0x41; code[offset++] = 0x5a;
        // pop %r9
        code[offset++] = 0x41; code[offset++] = 0x59;
        // pop %r8
        code[offset++] = 0x41; code[offset++] = 0x58;
        // pop %rdi
        code[offset++] = 0x5f;
        // pop %rsi
        code[offset++] = 0x5e;
        // pop %rdx
        code[offset++] = 0x5a;
        // pop %rcx
        code[offset++] = 0x59;
        // pop %rax
        code[offset++] = 0x58;

        // Jump to original function (tail call)
        // mov $original_func, %r11
        code[offset++] = 0x49; code[offset++] = 0xbb;
        *reinterpret_cast<uintptr_t*>(&code[offset]) = reinterpret_cast<uintptr_t>(original_func);
        offset += 8;

        // jmp *%r11
        code[offset++] = 0x41; code[offset++] = 0xff; code[offset++] = 0xe3;

        // Make memory read-only and executable
        mprotect(wrapper_mem, WRAPPER_SIZE, PROT_READ | PROT_EXEC);

        return wrapper_mem;
    }

    static void cleanup_wrapper(void* wrapper_mem) {
        if (wrapper_mem) {
            munmap(wrapper_mem, WRAPPER_SIZE);
        }
    }
};

std::unordered_map<uintptr_t, LoadedModule*> module_by_address;

class WindowsPELoader {
private:
    std::vector<std::unique_ptr<LoadedModule>> loaded_modules;
    std::unordered_map<std::wstring, LoadedModule*> module_by_name;
    std::vector<std::wstring> dll_search_paths;
    bool enable_syscall_monitoring;
    ApiSetResolver api_resolver;  // Add this member

    static void fatal(const char* what) {
        perror(what);
        exit(1);
    }

    static void sigsegv_handler(int sig, siginfo_t *si, void *unused) {
        const ucontext_t *uc = static_cast<ucontext_t *>(unused);

        trace("\n=== SIGSEGV DEBUG INFO ===");
        trace("Signal: ", sig);
        trace("Fault address: 0x", std::hex, reinterpret_cast<uintptr_t>(si->si_addr), std::dec);
        trace("Error code: ", si->si_code);

        // Print register state at a crash
        trace("Register state at crash:");
        trace("  RIP: 0x", std::hex, uc->uc_mcontext.gregs[REG_RIP], std::dec);
        trace("  RSP: 0x", std::hex, uc->uc_mcontext.gregs[REG_RSP], std::dec);
        trace("  RBP: 0x", std::hex, uc->uc_mcontext.gregs[REG_RBP], std::dec);
        trace("  RAX: 0x", std::hex, uc->uc_mcontext.gregs[REG_RAX], std::dec);
        trace("  RCX: 0x", std::hex, uc->uc_mcontext.gregs[REG_RCX], std::dec);
        trace("  RDX: 0x", std::hex, uc->uc_mcontext.gregs[REG_RDX], std::dec);
        trace("  R8:  0x", std::hex, uc->uc_mcontext.gregs[REG_R8], std::dec);
        trace("  R9:  0x", std::hex, uc->uc_mcontext.gregs[REG_R9], std::dec);

        // Check which module the crash occurred in
        const uintptr_t crash_addr = uc->uc_mcontext.gregs[REG_RIP];
        trace("Crash occurred at: 0x", std::hex, crash_addr, std::dec);

        // Find which module this address belongs to
        bool found_module = false;
        for (const auto& [base_addr, module] : module_by_address) {
            if (crash_addr >= base_addr && crash_addr < base_addr + module->size) {
                const uintptr_t offset = crash_addr - base_addr;
                trace("Crash in module: ", module->name);
                trace("  Base: 0x", std::hex, base_addr, std::dec);
                trace("  Offset: 0x", std::hex, offset, std::dec);
                found_module = true;

                // Try to disassemble a few bytes at crash location
                trace("Bytes at crash location:");
                const uint8_t* crash_ptr = reinterpret_cast<uint8_t*>(crash_addr);
                for (int i = -8; i < 16; i++) {
                    if (crash_addr + i >= base_addr && crash_addr + i < base_addr + module->size) {
                        trace("  [", std::hex, crash_addr + i, "] = 0x",
                              std::hex, std::setw(2), std::setfill<wchar_t>('0'),
                              static_cast<int>(crash_ptr[i]), std::dec);
                    }
                }
                break;
            }
        }

        if (!found_module) {
            trace("Crash occurred outside loaded modules - invalid memory access");
        }

        // Print stack trace
        trace("\nStack trace:");
        void *array[20];
        const size_t size = backtrace(array, 20);
        char **strings = backtrace_symbols(array, size);
        for (size_t i = 0; i < size; i++) {
            trace("  ", i, ": ", strings[i]);
        }
        free(strings);

        trace("========================\n");
        exit(1);
    }

    // Setup detailed crash handler
    static void setup_crash_handler() {
        struct sigaction sa{};
        sa.sa_flags = SA_SIGINFO;
        sigemptyset(&sa.sa_mask);
        sa.sa_sigaction = sigsegv_handler;

        if (sigaction(SIGSEGV, &sa, NULL) == -1) {
            perror("sigaction");
            exit(1);
        }

        // Also catch other signals that might indicate issues
        sigaction(SIGFPE, &sa, NULL);   // Floating point exception
        sigaction(SIGILL, &sa, NULL);   // Illegal instruction
        sigaction(SIGBUS, &sa, NULL);   // Bus error
    }

    // Validate memory before calling
    static bool is_memory_readable(void* addr, const size_t size) {
        return true;
    }

    static bool validate_function_address(const uintptr_t func_addr) {
        // Check if address is in a loaded module
        for (const auto& [base_addr, module] : module_by_address) {
            if (func_addr >= base_addr && func_addr < base_addr + module->size) {
                // Check if it's in an executable section
                for (const auto& section : module->pe_binary->sections()) {
                    const uintptr_t section_start = base_addr + section.virtual_address();

                    if (const uintptr_t section_end = section_start + section.virtual_size(); func_addr >= section_start && func_addr < section_end) {
                        const auto characteristics = section.characteristics();
                        const bool is_executable = (characteristics &
                            static_cast<uint32_t>(LIEF::PE::Section::CHARACTERISTICS::MEM_EXECUTE)) != 0;

                        trace("Function at 0x", std::hex, func_addr, std::dec,
                              " is in section ", converter.from_bytes(section.name()),
                              " (executable: ", (is_executable ? "YES" : "NO"), ")");

                        return is_executable;
                    }
                }
            }
        }

        trace("Function at 0x", std::hex, func_addr, std::dec, " not found in any loaded module");
        return false;
    }

    // Updated function call with validation
    static int call_windows_function_safe(uintptr_t func_addr, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3, uintptr_t arg4) {
        {
            trace("Attempting to call function at 0x", std::hex, func_addr, std::dec);
            trace("Arguments: 0x", std::hex, arg1, ", 0x", arg2, ", 0x", arg3, ", 0x", arg4, std::dec);

            // Validate function address
            if (!validate_function_address(func_addr)) {
                trace("ERROR: Invalid function address");
                return -1;
            }

            // Check if we can read the first few bytes of the function
            if (!is_memory_readable(reinterpret_cast<void*>(func_addr), 16)) {
                trace("ERROR: Cannot read function memory");
                return -1;
            }

            // Print first few bytes of function for debugging
            auto func_bytes = reinterpret_cast<uint8_t*>(func_addr);
            trace("Function bytes: ");
            for (int i = 0; i < 64; i++) {
                trace(std::hex, std::setw(2), std::setfill<wchar_t>('0'), static_cast<int>(func_bytes[i]), " ");
            }
            trace(std::dec);

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

        // CRITICAL: Stop and wait for parent
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


    static void print_syscall_info(unsigned long long syscall_nr, const struct user_regs_struct& regs, const std::wstring& context = L"") {
        trace("\n=== WINDOWS SYSCALL INTERCEPTED ===");

        if (!context.empty()) {
            trace("Context: ", context);
        }

        // here is the code to print syscall number and arguments
        // print disassembly of 16 bytes at RIP (-8, +8)
        //trace("Disassembly around RIP:");
        //const auto* rip_ptr = reinterpret_cast<const uint8_t*>(regs.rip);
        /*for (int i = -8; i < 16; i++) {
            trace("  [", std::hex, regs.rip + i, "] = 0x",
                  std::hex, std::setw(2), std::setfill<wchar_t>('0'),
                  static_cast<int>(rip_ptr[i]), std::dec);
        }*/
        trace("Syscall number: 0x", std::hex, syscall_nr, std::dec);
        trace("Arguments:");
        trace("  RAX (syscall number): 0x", std::hex, regs.rax, std::dec);
        trace("  RBX : 0x", std::hex, regs.rbx, std::dec);
        trace("  RCX (~arg1): 0x", std::hex, regs.rcx, std::dec);
        trace("  R10 (arg1): 0x", std::hex, regs.r10, std::dec);
        trace("  RDX (arg2): 0x", std::hex, regs.rdx, std::dec);
        trace("  R8  (arg3): 0x", std::hex, regs.r8, std::dec);
        trace("  R9  (arg4): 0x", std::hex, regs.r9, std::dec);
        trace("  RDI : 0x", std::hex, regs.rdi, std::dec);
        trace("  RSI : 0x", std::hex, regs.rsi, std::dec);
        trace("  RIP (next instruction): 0x", std::hex, regs.rip, std::dec);
        trace("  RSP (stack pointer): 0x", std::hex, regs.rsp, std::dec);

        trace("===================================");

        if (const auto it = windows_syscalls.find(syscall_nr); it != windows_syscalls.end()) {
            switch (syscall_nr) {
                case 0x1: // NtWorkerFactoryWorkerReady
                    trace("NtWorkerFactoryWorkerReady called with:");
                    trace("  hWorkerFactory: 0x", std::hex, regs.r10, std::dec);
                    return;
                case 0x3: // NtMapUserPhysicalPagesScatter
                    trace("NtMapUserPhysicalPagesScatter called with:");
                    trace("  VirtualAddresses: 0x", std::hex, regs.r10, std::dec);
                    trace("  NumberOfPages: 0x", std::hex, regs.rdx, std::dec);
                    trace("  UserPfnArray: 0x", std::hex, regs.r8, std::dec);
                    return;
                case 0x1B: // NtWriteFileGather
                    trace("NtWriteFileGather called with:");
                    trace("  FileHandle: 0x", std::hex, regs.r10, std::dec);
                    trace("  Event: 0x", std::hex, regs.rdx, std::dec);
                    trace("  ApcRoutine: 0x", std::hex, regs.r8, std::dec);
                    trace("  ApcContext: 0x", std::hex, regs.r9, std::dec);
                    // next args on the stack
                    {
                        const auto stack64 = reinterpret_cast<const uint64_t*>(regs.rsp);
                        trace("  IoStatusBlock: 0x", std::hex, stack64[4], std::dec);
                        trace("  SegmentArray: 0x", std::hex, stack64[5], std::dec);
                        trace("  Length: 0x", std::hex, stack64[6], std::dec);
                        trace("  ByteOffset: 0x", std::hex, stack64[7], std::dec);
                        trace("  Key: 0x", std::hex, stack64[8], std::dec);
                    }
                    return;
                case 0xE7: // NtFlushBuffersFileEx
                    trace("NtFlushBuffersFileEx called with:");
                    trace("  FileHandle: 0x", std::hex, regs.r10, std::dec);
                    trace("  Flags: 0x", std::hex, regs.rdx, std::dec);
                    trace("  IoStatusBlock: 0x", std::hex, regs.r8, std::dec);
                    return;
                default:
                    trace("Unhandled Windows syscall: 0x", std::hex, syscall_nr, std::dec);
                    break;
            }
        } else {
            trace("Unknown syscall: 0x", std::hex, syscall_nr, std::dec);
        }

        // Exit immediately after the first unknown Windows syscall
        trace("Terminating to prevent system damage.");
        exit(0);
    }

    static std::string find_function_at_address(uintptr_t address) {
        // Find which module this address belongs to
        LoadedModule* target_module = nullptr;
        for (const auto& [base_addr, module] : module_by_address) {
            if (address >= base_addr && address < base_addr + module->size) {
                target_module = module;
                break;
            }
        }

        if (!target_module) {
            return "UNKNOWN_MODULE";
        }

        const uintptr_t rva = address - target_module->base_address;

        // Try to find the function in exports first (most accurate)
        if (target_module->pe_binary->has_exports()) {
            const LIEF::PE::Export* export_table = target_module->pe_binary->get_export();

            // Find the closest export that's before or at this RVA
            std::string closest_export;
            uint32_t closest_rva = 0;
            uint32_t closest_distance = UINT32_MAX;

            for (const LIEF::PE::ExportEntry& entry : export_table->entries()) {
                uint32_t export_rva = static_cast<uint32_t>(entry.address());

                if (export_rva <= rva) {
                    uint32_t distance = rva - export_rva;
                    if (distance < closest_distance) {
                        closest_distance = distance;
                        closest_rva = export_rva;
                        closest_export = entry.name();
                    }
                }
            }

            if (!closest_export.empty()) {
                if (closest_distance == 0) {
                    return closest_export; // Exact match
                } else if (closest_distance < 0x1000) { // Within 4KB, likely same function
                    return closest_export + "+0x" +
                           std::to_string(closest_distance) +
                           std::string("h");
                }
            }
        }

        // Try to find function in imports (IAT calls)
        if (target_module->pe_binary->has_imports()) {
            for (const LIEF::PE::Import& import : target_module->pe_binary->imports()) {
                for (const LIEF::PE::ImportEntry& entry : import.entries()) {
                    if (entry.iat_address() == rva) {
                        return std::string("IAT_") + entry.name() + "@" + import.name();
                    }
                }
            }
        }

        // Check if we're in a known section
        std::string section_info;
        for (const auto& section : target_module->pe_binary->sections()) {
            const uintptr_t section_start = section.virtual_address();
            const uintptr_t section_end = section_start + section.virtual_size();

            if (rva >= section_start && rva < section_end) {
                const uintptr_t section_offset = rva - section_start;
                section_info = section.name() + "+0x" +
                              std::to_string(section_offset) + "h";
                break;
            }
        }

        // Return module name + RVA + section info
        std::string module_name = converter.to_bytes(target_module->name);
        if (module_name.ends_with(".dll") || module_name.ends_with(".exe")) {
            module_name = module_name.substr(0, module_name.find_last_of('.'));
        }

        std::string result = module_name + "!0x" + std::to_string(rva) + "h";
        if (!section_info.empty()) {
            result += " (" + section_info + ")";
        }

        return result;
    }


    static void print_step_info(pid_t child, const struct user_regs_struct& regs, const std::wstring& context = L"") {
        if (!context.empty()) {
            trace("Context: ", context);
        }

        // Find and print function information
        std::string function_info = find_function_at_address(regs.rip);
        trace("Current function: ", converter.from_bytes(function_info));

        // Safe instruction reading using ptrace
        trace("Bytes at RIP:");
        errno = 0;
        char buffer[sizeof(long) * 2] = {};
        for (size_t i = 0; i < sizeof(buffer); i += sizeof(long)) {
            errno = 0;
            long word = ptrace(PTRACE_PEEKDATA, child, regs.rip + i, NULL);
            if (word == -1 && errno != 0) {
                trace("Failed to read memory at 0x", std::hex, regs.rip + i, std::dec);
                break;
            }
            // print  bytes in hex
            for (size_t j = 0; j < sizeof(long); j++) {
                if (i + j < sizeof(buffer)) {
                    trace("  [", std::hex, regs.rip + i + j, "] = 0x",
                          std::hex, std::setw(2), std::setfill<wchar_t>('0'),
                          static_cast<int>((word >> (j * 8)) & 0xFF), std::dec);
                }
            }
            std::memcpy(buffer + i, &word, sizeof(long));
        }

        // Print register state
        trace("Register state:");
        trace("  RAX: 0x", std::hex, regs.rax, std::dec);
        trace("  RDI: 0x", std::hex, regs.rdi, std::dec);
        trace("  RSI: 0x", std::hex, regs.rsi, std::dec);
        trace("  RDX: 0x", std::hex, regs.rdx, std::dec);
        trace("  R10: 0x", std::hex, regs.r10, std::dec);
        trace("  R8: 0x", std::hex, regs.r8, std::dec);
        trace("  R9: 0x", std::hex, regs.r9, std::dec);
        trace("  RIP: 0x", std::hex, regs.rip, std::dec);
        trace("  RSP: 0x", std::hex, regs.rsp, std::dec);

        // Determine which module the RIP belongs to (use global module tracking)
        for (const auto& [base_addr, module] : module_by_address) {
            if (regs.rip >= base_addr && regs.rip < base_addr + module->size) {
                uintptr_t offset = regs.rip - base_addr;
                trace("Current instruction is in module: ", module->name,
                      " (base: 0x", std::hex, base_addr,
                      ", size: 0x", module->size,
                      ", offset: 0x", offset, ")", std::dec);
                break;
            }
        }

        csh handle;
        cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
        cs_insn *insn;
        size_t count = cs_disasm(handle, reinterpret_cast<const uint8_t*>(buffer), sizeof(buffer),
                                 regs.rip, 0, &insn);

        if (count > 0) {
            trace("Disassembly at RIP:");
            for (size_t j = 0; j < count; j++) {
                trace("0x", std::hex, insn[j].address, ": ", insn[j].mnemonic, " ", insn[j].op_str, std::dec);
            }
            cs_free(insn, count);
        } else {
            trace("Failed to disassemble at RIP");
        }
        cs_close(&handle);
        errno = 0;
    }

    void trace_child_execution(pid_t child, const std::wstring& context = L"Main execution") {
        int status;

        // Set trace options
        if (ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD) == -1) {
            // Continue anyway
        }

        // Continue until next syscall
        if (ptrace(/*PTRACE_SYSCALL*/ PTRACE_SINGLESTEP, child, 0, 0) == -1) {
            // do not fatal here, exit since the process might have exited
            trace("Failed to set PTRACE_SYSCALL, child might have exited.");
            return;
        }

        bool in_syscall = false;
        trace("Started syscall monitoring for: ", context);

        while (true) {
            pid_t w = waitpid(child, &status, 0);
            if (w == -1) fatal("waitpid");

            if (WIFEXITED(status)) {
                trace(context, " - Child exited with code ", std::hex, WEXITSTATUS(status), std::dec);
                break;
            }

            if (WIFSIGNALED(status)) {
                trace(context, " - Child terminated by signal ", std::hex, WTERMSIG(status), std::dec);
                break;
            }

            if (WIFSTOPPED(status)) {
                const int sig = WSTOPSIG(status);

                if (bool is_syscall_stop = (sig == (SIGTRAP | 0x80)) || (sig == SIGTRAP)) {
                    user_regs_struct regs{};
                    if (ptrace(PTRACE_GETREGS, child, NULL, &regs) == -1) {
                        fatal("ptrace GETREGS");
                    }
                    auto stack_ptr = reinterpret_cast<uint8_t*>(regs.rsp);
                    print_step_info(child, regs, context);
                    /*if (!in_syscall) {
                        // Syscall entry
                        const unsigned long long syscall_nr = regs.orig_rax; // orig_rax is the syscall numbe, rax is the return value

                        // Check if this looks like a Windows syscall
                        //print_syscall_info(syscall_nr, regs, context);
                        trace("[", context, "] [SYSCALL ENTRY] ", syscall_nr
                                 , " (0x", std::hex, syscall_nr, std::dec, ")");
                        // execute the syscall
                        switch (syscall_nr) {
                            case 0x1: // NtWorkerFactoryWorkerReady
                                regs.rax = NtWorkerFactoryWorkerReady(reinterpret_cast<HANDLE>(regs.r10) // first argument
                                                                );
                                if (ptrace(PTRACE_SETREGS, child, NULL, &regs) == -1) {
                                    fatal("ptrace SETREGS");
                                }
                                break;
                            case 0x3: // NtMapUserPhysicalPagesScatter
                                regs.rax = NtMapUserPhysicalPagesScatter(reinterpret_cast<PVOID*>(regs.r10), // first argument
                                                                static_cast<ULONG>(regs.rdx), // second argument
                                                                reinterpret_cast<PULONG_PTR>(regs.r8) // third argument
                                                            );
                                if (ptrace(PTRACE_SETREGS, child, NULL, &regs) == -1) {
                                    fatal("ptrace SETREGS");
                                }
                            case 0x1B: // NtWriteFileGather
                                {
                                    const auto *stack64 = reinterpret_cast<uint64_t*>(regs.rsp);

                                    const auto hFile        = reinterpret_cast<HANDLE>(regs.r10); // arg1
                                    const auto hEvent       = reinterpret_cast<HANDLE>(regs.rdx); // arg2
                                    const auto apc = reinterpret_cast<PIO_APC_ROUTINE>(regs.r8); // arg3
                                    const auto apcCtx        = reinterpret_cast<PVOID>(regs.r9);  // arg4
                                    const auto iosb  = reinterpret_cast<PIO_STATUS_BLOCK>(stack64[4]); // arg5 @ rsp+0x20
                                    const auto segs = reinterpret_cast<FILE_SEGMENT_ELEMENT*>(stack64[5]); // arg6 @ rsp+0x28
                                    const auto length        = static_cast<ULONG>(stack64[6]); // arg7 @ rsp+0x30
                                    const auto byteOff = reinterpret_cast<PLARGE_INTEGER>(stack64[7]); // arg8 @ rsp+0x38
                                    const auto key          = reinterpret_cast<PULONG>(stack64[8]); // arg9 @ rsp+0x40

                                    regs.rax = NtWriteFileGather(hFile, hEvent, apc, apcCtx,
                                                                 iosb, segs, length, byteOff, key);

                                    if (ptrace(PTRACE_SETREGS, child, NULL, &regs) == -1)
                                        fatal("ptrace SETREGS");
                                    break;
                                }
                            case 0xE7: // NtFlushBuffersFileEx
                                regs.rax = NtFlushBuffersFileEx(reinterpret_cast<HANDLE>(regs.r10), // first argument
                                                                static_cast<ULONG>(regs.rdx), // second argument
                                                                reinterpret_cast<PIO_STATUS_BLOCK>(regs.r8) // third argument
                                                            );
                                if (ptrace(PTRACE_SETREGS, child, NULL, &regs) == -1) {
                                    fatal("ptrace SETREGS");
                                }
                                break;
                            default:
                                // Unknown syscall, just log it
                                break;
                        }
                        in_syscall = true;
                        // avoid further processing of the syscall by the kernel
                        regs.orig_rax = -1; // invalid syscall number
                        if (ptrace(PTRACE_SETREGS, child, NULL, &regs) == -1) {
                            fatal("ptrace SETREGS");
                        }
                    } else {
                        // Syscall exit
                        const unsigned long long retval = regs.rax;
                        trace("[", context, "] [SYSCALL EXIT] return = 0x", std::hex, retval, std::dec);
                        in_syscall = false;
                    }*/
                } else {
                    // Forward other signals
                    trace("Forwarding signal ", sig, " to child");
                    if (ptrace(PTRACE_SINGLESTEP, child, 0, sig) == -1) {
                        fatal("ptrace SYSCALL (deliver sig)");
                    }
                    continue;
                }
            }

            // Continue tracing
            if (ptrace(/*PTRACE_SYSCALL*/ PTRACE_SINGLESTEP, child, 0, 0) == -1) {
                fatal("ptrace SYSCALL (continue)");
            }
        }
    }

    void* allocate_executable_memory(size_t size, uintptr_t preferred_addr = 0) {
        if (preferred_addr != 0) {
            // Try to map at exact address with MAP_FIXED
            void* addr = mmap(reinterpret_cast<void*>(preferred_addr), size,
                             PROT_READ | PROT_WRITE | PROT_EXEC,
                             MAP_SHARED | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
            if (addr != MAP_FAILED && addr == reinterpret_cast<void*>(preferred_addr)) {
                return addr;
            }
        }

        // Fall back to any address but ensure it's truly shared
        return mmap(nullptr, size,
                    PROT_READ | PROT_WRITE | PROT_EXEC,
                    MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    }

    void apply_relocations(const LIEF::PE::Binary& pe, void* mem, uintptr_t base_addr) {
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

        trace("Applying relocations with delta: 0x", std::hex, delta, std::dec, "(", delta, ")");

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
                        trace("Unsupported relocation type: "
                                 , static_cast<uint16_t>(entry.type()));
                        break;
                }
            }
        }
        trace("Applied ", reloc_count, " relocations");
    }

    std::wstring find_dll_file(const std::wstring& dll_name) const {
        std::wstring dll_to_search = dll_name;

        // Try the resolved/original name in the current directory first
        if (fs::exists(dll_to_search)) {
            return dll_to_search;
        }

        // Try with .dll extension if not present
        std::wstring dll_with_ext = dll_to_search;
        if (!dll_with_ext.ends_with(L".dll") && !dll_with_ext.ends_with(L".DLL")) {
            dll_with_ext += L".dll";
            if (fs::exists(dll_with_ext)) {
                return dll_with_ext;
            }
        }

        // Search in DLL search paths
        for (const auto& path : dll_search_paths) {
            if (fs::path full_path = fs::path(path) / dll_with_ext; fs::exists(full_path)) {
                return full_path.wstring();
            }
        }

        return L"";
    }

    std::pair<bool, LoadedModule*> load_pe_dll(const std::wstring& dll_name) {
        // Check if already loaded
        std::wstring dll_lower = dll_name;
        std::ranges::transform(dll_lower, dll_lower.begin(), ::tolower);

        if (const auto it = module_by_name.find(dll_lower); it != module_by_name.end()) {
            trace("DLL ", dll_name, " already loaded");
            return { true, it->second };
        }

        // Use JSON-based API set resolution
        std::wstring actual_dll_name = dll_name;

        bool is_api_set = false;

        if (const std::string dll_name_str = converter.to_bytes(dll_name); api_resolver.is_api_set(dll_name_str)) {
            if (const std::string resolved = api_resolver.resolve_dll(dll_name_str); resolved != dll_name_str) {
                actual_dll_name = converter.from_bytes(resolved);
                trace("API set ", dll_name, " resolved to: ", actual_dll_name);
                is_api_set = true;
                // Check if the resolved DLL is already loaded
                std::wstring resolved_lower = actual_dll_name;
                std::ranges::transform(resolved_lower, resolved_lower.begin(), ::tolower);
                if (const auto it = module_by_name.find(resolved_lower); it != module_by_name.end()) {
                    trace("Base DLL ", actual_dll_name, " already loaded, reusing for API set ", dll_name);
                    module_by_name[dll_lower] = it->second;
                    return { false, it->second };
                }
            }
        }

        // Continue with the rest of the function using actual_dll_name instead of dll_name
        // Find a DLL file
        const std::wstring dll_path = find_dll_file(actual_dll_name);
        if (dll_path.empty()) {
            trace("Could not find DLL: ", actual_dll_name, " (requested as: ", dll_name, ")");
            return { false, nullptr };
        }

        trace("Loading PE DLL: ", dll_path, " (for request: ", dll_name, ")");

        const std::string dll_path_str = converter.to_bytes(dll_path);

        // Parse PE DLL
        std::unique_ptr<LIEF::PE::Binary> pe_binary(LIEF::PE::Parser::parse(dll_path_str).release());
        if (!pe_binary) {
            trace("Failed to parse PE DLL: ", dll_path);
            return { false, nullptr };
        }

        // Check if it's actually a DLL
        auto characteristics = pe_binary->header().characteristics();
        bool is_dll = (characteristics & static_cast<uint32_t>(LIEF::PE::Header::CHARACTERISTICS::DLL)) != 0;

        if (!is_dll) {
            trace("Warning: ", dll_name, " is not marked as a DLL");
        }

        // Calculate memory requirements
        size_t image_size = pe_binary->optional_header().sizeof_image();
        image_size = (image_size + 4095) & ~4095; // Page align

        // Allocate memory for DLL
        uintptr_t preferred_base = pe_binary->optional_header().imagebase();
        void* memory = allocate_executable_memory(image_size, preferred_base);
        if (!memory) {
            trace("Failed to allocate memory for DLL: ", dll_name);
            return { false, nullptr };;
        }

        uintptr_t base_addr = reinterpret_cast<uintptr_t>(memory);
        trace("Allocated DLL memory at: 0x", std::hex, base_addr, std::dec);

        // Clear memory
        memset(memory, 0, image_size);


        // Map sections
        for (const auto& section : pe_binary->sections()) {
            uint32_t virtual_addr = section.virtual_address();
            auto raw_data = section.content();

            if (virtual_addr + raw_data.size() <= image_size) {
                memcpy(reinterpret_cast<void*>(base_addr + virtual_addr),
                       raw_data.data(), raw_data.size());

                trace("Mapped DLL section ", converter.from_bytes(section.name())
                         , " at RVA 0x", std::hex, virtual_addr
                         , std::dec, ", size ", raw_data.size());
            }
        }

        // apply section permissions
        apply_section_permissions(*pe_binary, memory, base_addr);

        // Create loaded module entry
        auto module = std::make_unique<LoadedModule>(dll_lower, base_addr, image_size, std::move(pe_binary), true);
        LoadedModule* module_ptr = module.get();

        // Add to tracking structures
        loaded_modules.push_back(std::move(module));
        module_by_name[dll_lower] = module_ptr;
        module_by_address[base_addr] = module_ptr;

        // Apply relocations
        apply_relocations(*module_ptr->pe_binary, memory, base_addr);

        // Recursively load dependencies first
        if (module_ptr->pe_binary->has_imports()) {
            for (const auto& import : module_ptr->pe_binary->imports()) {
                if (import.name().empty()) {
                    continue;
                    trace("Skipping unnamed import");
                }
                trace("Import descriptor for: ", converter.from_bytes(import.name()));
                std::wstring dep_name = converter.from_bytes(import.name());
                std::ranges::transform(dep_name, dep_name.begin(), ::tolower);
                trace("DLL ", dll_name, " depends on ", dep_name);
                if (dep_name != dll_lower) { // Avoid circular dependencies
                    load_pe_dll(dep_name);
                }
            }
        }

        trace("All dependencies for ", dll_name, " loaded");
        // Now resolve imports for this DLL
        resolve_imports(*module_ptr->pe_binary, base_addr);

        // Call DllMain if present (with syscall monitoring if enabled)
        if (module_ptr->entry_point != 0 && !is_api_set /* don't call DllMain for API sets */) {
            call_dll_main_monitored(module_ptr, 1); // DLL_PROCESS_ATTACH
        }

        trace("Successfully loaded PE DLL: ", dll_name);
        return { false, module_ptr };
    }

    // New function to call DLL entry point with syscall monitoring
   void call_dll_main_monitored(LoadedModule* module, uint32_t reason) {
        if (!module || !module->is_dll || module->entry_point == 0) {
            return;
        }

        const std::wstring reason_str = (reason == 1) ? L"DLL_PROCESS_ATTACH" :
                                      (reason == 0) ? L"DLL_PROCESS_DETACH" :
                                      (reason == 2) ? L"DLL_THREAD_ATTACH" :
                                      (reason == 3) ? L"DLL_THREAD_DETACH" : L"UNKNOWN";

        std::wstring context = L"DllMain(" + module->name + L", " + reason_str + L")";

        if (enable_syscall_monitoring) {
            trace("Calling DLL entry point with syscall monitoring for ", module->name
                     , " at 0x", std::hex, module->entry_point, std::dec
                     , " (reason: ", reason_str, ")");

            pid_t child = fork();
            if (child == -1) {
                fatal("fork for DLL monitoring");
            }

            if (child == 0) {
                // Child process - set up tracing and call DLL entry point
                if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
                    fatal("ptrace TRACEME for DLL");
                }

                // Call the DLL entry point
                call_windows_function_safe(
                    module->entry_point,
                    module->base_address,
                    reason,
                    0,
                    0
                );
                trace("DLL entry point returned for ", module->name);
                exit(0);
            } else {
                // Parent process - wait for child to stop, then trace
                int status;
                waitpid(child, &status, 0);

                if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP) {
                    // Set up tracing options
                    if (ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD) == -1) {
                        fatal("ptrace SETOPTIONS for DLL");
                    }
                    trace_child_execution(child, context);
                }
            }
        } else {
            call_dll_main(module, reason);
        }
    }

    void call_dll_main(LoadedModule* module, DWORD reason) {
        if (!module || !module->is_dll || module->entry_point == 0) {
            return;
        }

        call_windows_function_safe(
            module->entry_point,
            module->base_address,
            reason,
            0,
            0
        );
    }

    void* find_export(LoadedModule* module, const std::wstring& func_name) {
        if (!module || !module->pe_binary->has_exports()) {
            return nullptr;
        }

        const LIEF::PE::Export *export_table = module->pe_binary->get_export();

        // Try by name first
        for (const LIEF::PE::ExportEntry& entry : export_table->entries()) {
            if (converter.from_bytes(entry.name()) == func_name) {
                const uint32_t rva = entry.address();
                return reinterpret_cast<void*>(module->base_address + rva);
            }
        }

        // Try by ordinal if it's a number
        try {
            auto ordinal = static_cast<uint16_t>(std::stoul(func_name));
            for (const auto& entry : export_table->entries()) {
                if (entry.ordinal() == ordinal) {
                    uint32_t rva = static_cast<uint32_t>(entry.address());
                    return reinterpret_cast<void*>(module->base_address + rva);
                }
            }
        } catch (...) {
            // Not a number, continue
        }

        return nullptr;
    }

    std::unordered_map<void*, void*> function_wrappers;
    bool enable_function_tracing;

    static void apply_section_permissions(const LIEF::PE::Binary& pe, void* mem, const uintptr_t base_addr) {
        for (const LIEF::PE::Section& section : pe.sections()) {
            const uint32_t virtual_addr = section.virtual_address();
            const size_t section_size = section.virtual_size();

            if (section_size == 0) continue;

            // Start with read permissions for all sections
            int prot = PROT_READ;
            const uint32_t characteristics = section.characteristics();

            if (characteristics & static_cast<uint32_t>(LIEF::PE::Section::CHARACTERISTICS::MEM_WRITE))
                prot |= PROT_WRITE;
            if (characteristics & static_cast<uint32_t>(LIEF::PE::Section::CHARACTERISTICS::MEM_EXECUTE))
                prot |= PROT_EXEC;

            // Ensure we don't remove read permissions from executable sections
            if (prot & PROT_EXEC) {
                prot |= PROT_READ;
            }

            void* section_addr = reinterpret_cast<void*>(base_addr + virtual_addr);
            trace("Setting section ", converter.from_bytes(section.name()),
                  " permissions: ", (prot & PROT_READ ? "R" : "-"),
                  (prot & PROT_WRITE ? "W" : "-"), (prot & PROT_EXEC ? "X" : "-"));

            if (mprotect(section_addr, section_size, prot) != 0) {
                trace("Warning: Failed to set permissions for section ",
                      converter.from_bytes(section.name()), ": ", strerror(errno));
            }
        }
    }

    void* create_function_wrapper(void* original_func, const std::string& func_name, const std::string& dll_name) {
        if (!enable_function_tracing) {
            trace("Function tracing disabled, using original function for ", converter.from_bytes(func_name), " in ", converter.from_bytes(dll_name));
            return original_func;
        }
        trace("Creating wrapper for function ", converter.from_bytes(func_name), " in ", converter.from_bytes(dll_name));

        // Check if we already created a wrapper for this function
        if (const auto it = function_wrappers.find(original_func); it != function_wrappers.end()) {
            trace("Reusing existing wrapper for function ", converter.from_bytes(func_name), " in ", converter.from_bytes(dll_name)
                     , " at 0x", std::hex, it->second, std::dec);
            return it->second;
        }

        // use wrapper for now
        void* wrapper = AssemblyWrapperGenerator::create_wrapper(
            original_func,
            func_name.c_str(),
            dll_name.c_str()
        );

        if (wrapper) {
            trace("Created wrapper for function ", converter.from_bytes(func_name), " in ", converter.from_bytes(dll_name)
                     , " at 0x", std::hex, wrapper, std::dec);
            function_wrappers[original_func] = wrapper;
            return wrapper;
        }

        return original_func; // Fallback to original if wrapper creation fails
    }

    void resolve_imports(const LIEF::PE::Binary& pe, uintptr_t base_addr) {
        if (!pe.has_imports()) {
            return;
        }

        trace("Resolving imports...");

        for (const LIEF::PE::Import &import : pe.imports()) {
            std::wstring dll_name = converter.from_bytes(import.name());
            std::ranges::transform(dll_name, dll_name.begin(), ::tolower);
            trace("Processing imports from: ", dll_name);

            // Load the DLL if not already loaded
            auto dll_module = load_pe_dll(dll_name);

            if (dll_module.first) {
                trace("Skipping, DLL ", dll_name, " already loaded");
                continue;
            }

            for (const LIEF::PE::ImportEntry& entry : import.entries()) {
                if (entry.name().empty()) {
                    trace("  Skipping import");
                    continue; // Skip imports by ordinal for simplicity
                }
                trace("  Importing function: ", converter.from_bytes(entry.name()));

                const std::wstring& func_name = converter.from_bytes(entry.name());
                void* func_addr = nullptr;

                if (dll_module.second) {
                    func_addr = find_export(dll_module.second, func_name);
                }

                trace("  Resolved address: 0x", std::hex,
                      reinterpret_cast<uintptr_t>(func_addr), std::dec);
                trace("  Base address of ", dll_name, ": 0x", std::hex,
                      dll_module.second ? dll_module.second->base_address : 0, std::dec);

                // Get the IAT RVA directly - LIEF returns RVAs, not VAs
                uint64_t iat_rva = entry.iat_address();

                // Validate the RVA is within the image
                if (iat_rva >= pe.optional_header().sizeof_image() - sizeof(uintptr_t)) {
                    trace("  WARNING: Invalid IAT RVA 0x", std::hex, iat_rva, std::dec,
                          " for ", func_name, " in ", dll_name);
                    continue;
                }

                trace("  IAT RVA: 0x", std::hex, iat_rva, std::dec);

                // Calculate the actual IAT address in memory
                auto* iat_ptr = reinterpret_cast<uintptr_t*>(base_addr + iat_rva);

                if (!func_addr) {
                    trace("  WARNING: Could not resolve ", func_name
                             , " from ", dll_name, ", setting to NULL at RVA 0x"
                             , std::hex, iat_rva, std::dec);
                    if (iat_ptr >= reinterpret_cast<uintptr_t*>(base_addr) &&
                        iat_ptr < reinterpret_cast<uintptr_t*>(base_addr + pe.optional_header().sizeof_image())) {
                        //*iat_ptr = 0; // Set to NULL
                    } else {
                        trace("  WARNING: IAT pointer 0x", std::hex, reinterpret_cast<uintptr_t>(iat_ptr),
                              " is out of bounds (base: 0x", base_addr,
                              ", size: 0x", pe.optional_header().sizeof_image(), ")", std::dec);
                    }
                } else {
                    // Update IAT with the resolved function address
                    void* final_func = func_addr;
                    trace("  Original function address: 0x", std::hex,
                          reinterpret_cast<uintptr_t>(func_addr), std::dec, ", iat_ptr: 0x", std::hex, reinterpret_cast<uintptr_t>(iat_ptr), std::dec);
                    // check if iat_ptr is within a mapped page
                    if (reinterpret_cast<uintptr_t>(iat_ptr) < base_addr ||
                        reinterpret_cast<uintptr_t>(iat_ptr) >= base_addr + pe.optional_header().sizeof_image()) {
                        trace("  WARNING: IAT pointer 0x", std::hex, reinterpret_cast<uintptr_t>(iat_ptr),
                              " is out of bounds (base: 0x", base_addr,
                              ", size: 0x", pe.optional_header().sizeof_image(), ")", std::dec);
                        continue;
                    }
                    *iat_ptr = reinterpret_cast<uintptr_t>(final_func);
                    trace("  Resolved ", func_name, " to address 0x", std::hex,
                          reinterpret_cast<uintptr_t>(final_func), std::dec,
                          " (IAT RVA: 0x", std::hex, iat_rva, std::dec, ")");
                }
            }
        }
    }

public:
    explicit WindowsPELoader(bool monitor_syscalls = true, bool trace_functions = true)
    : enable_syscall_monitoring(monitor_syscalls), enable_function_tracing(trace_functions) {
        // Add default DLL search paths
        dll_search_paths.emplace_back(L".");
        dll_search_paths.emplace_back(L"./dlls");

        // Try to load API set mappings from common locations
        std::vector<std::string> json_candidates = {
            "10.0.19041.1-AMD64.json",
            "apiset.json",
            "./apiset/10.0.19041.1-AMD64.json"
        };

        for (const auto& json_file : json_candidates) {
            if (api_resolver.load_apiset_json(json_file)) {
                break;
            }
        }
    }

    bool load_api_mappings(const std::string& json_file) {
        return api_resolver.load_apiset_json(json_file);
    }

    void set_function_tracing(bool enable) {
        enable_function_tracing = enable;
    }

    ~WindowsPELoader() {
        // Clean up function wrappers
        for (auto& [orig, wrapper] : function_wrappers) {
            AssemblyWrapperGenerator::cleanup_wrapper(wrapper);
        }

        // Clean up memory (in a real implementation)
        for (auto& module : loaded_modules) {
            if (module->base_address && module->size > 0) {
                munmap(reinterpret_cast<void*>(module->base_address), module->size);
            }
        }
    }

    void add_dll_search_path(const std::wstring& path) {
        dll_search_paths.push_back(path);
    }

    void set_syscall_monitoring(bool enable) {
        enable_syscall_monitoring = enable;
    }

    int load_and_execute(const std::wstring& pe_path, int argc, char* argv[]) {
        trace("Loading PE file: ", pe_path);
        trace("Syscall monitoring ", (enable_syscall_monitoring ? "ENABLED" : "DISABLED"));

        // Parse PE file with LIEF (common for both paths)
        std::unique_ptr<LIEF::PE::Binary> pe_binary(LIEF::PE::Parser::parse(converter.to_bytes(pe_path)).release());
        if (!pe_binary) {
            error("Failed to parse PE file: ", pe_path);
            return 1;
        }

        trace("PE file parsed successfully");
        trace("Entry point RVA: 0x", std::hex
                 , pe_binary->optional_header().addressof_entrypoint(), std::dec);

        // Calculate the required memory size
        size_t image_size = pe_binary->optional_header().sizeof_image();
        image_size = (image_size + 4095) & ~4095; // Page align

        trace("Image size: ", image_size, " bytes");

        // Allocate memory
        const uintptr_t preferred_base = pe_binary->optional_header().imagebase();
        void* memory = allocate_executable_memory(image_size, preferred_base);
        if (!memory) {
            error("Failed to allocate memory");
            return 1;
        }

        auto base_addr = reinterpret_cast<uintptr_t>(memory);
        trace("Allocated memory at: 0x", std::hex, base_addr, std::dec);

        // Clear memory
        memset(memory, 0, image_size);

        // Map sections
        for (const auto& section : pe_binary->sections()) {
            uint32_t virtual_addr = section.virtual_address();
            auto raw_data = section.content();

            if (virtual_addr + raw_data.size() <= image_size) {
                memcpy(reinterpret_cast<void*>(base_addr + virtual_addr),
                       raw_data.data(), raw_data.size());

                trace("Mapped section ", converter.from_bytes(section.name())
                         , " at RVA 0x", std::hex, virtual_addr
                         , std::dec, ", size ", raw_data.size());
            }
        }

        // Create the main module entry
        auto main_module = std::make_unique<LoadedModule>(pe_path, base_addr, image_size, std::move(pe_binary), false);
        LoadedModule* main_module_ptr = main_module.get();

        loaded_modules.push_back(std::move(main_module));
        module_by_address[base_addr] = main_module_ptr;

        // Apply relocations
        apply_relocations(*main_module_ptr->pe_binary, memory, base_addr);

        // initialize global vars
        tls.process = reinterpret_cast<HANDLE>(1); // main process handle
        tls.thread = reinterpret_cast<HANDLE>(0); // main thread handle is also invalid handle
        std::construct_at(&processes[tls.process]);
        processes[tls.process].process_hmodule = /* base addr */ reinterpret_cast<HMODULE>(base_addr);

        // Resolve imports (this will load required DLLs and call their entry points with monitoring)
        resolve_imports(*main_module_ptr->pe_binary, base_addr);

        // apply section permissions
        apply_section_permissions(*main_module_ptr->pe_binary, memory, base_addr);

        // Get entry point
        const uintptr_t entry_rva = main_module_ptr->pe_binary->optional_header().addressof_entrypoint();
        if (entry_rva == 0) {
            error("No entry point found");
            return 1;
        }

        const uintptr_t entry_point = base_addr + entry_rva;
        trace("Entry point: 0x", std::hex, entry_point, std::dec, "(" , entry_point, ")");

        // Always fork for main execution, regardless of monitoring setting
        if (enable_syscall_monitoring) {
            const pid_t child = fork();
            if (child == -1) {
                fatal("fork for main execution monitoring");
            }

            if (child == 0) {
                // Child process
                if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
                    fatal("ptrace TRACEME for main execution");
                }

                trace("Child: About to execute PE entry point...");
                call_windows_function_safe(
                    entry_point,
                    base_addr,
                    0,
                    0,
                    0
                );
                trace("Child: PE execution completed.");
                exit(0);
            } else {
                // Parent process - wait for the child to stop, then trace
                int status;
                waitpid(child, &status, 0);
                if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP) {
                    // Set up tracing options
                    if (ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD) == -1) {
                        perror("ptrace SETOPTIONS");
                    }
                    trace_child_execution(child, L"Main execution");
                }
            }
        } else {
            // No monitoring - execute directly
            trace("Executing PE entry point directly...");
            call_windows_function_safe(
                entry_point,
                base_addr,
                argc,
                reinterpret_cast<uintptr_t>(argv),
                0
            );
            trace("PE execution completed.");
        }

        return 0;
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
};

int main(int argc, char* argv[]) {
    if (argc < 2) {
        trace("Usage: ", argv[0], " <pe_file> [--no-monitoring] [--no-tracing] [--apiset json_file] [dll_search_path...]");
        trace("Example: ", argv[0], " program.exe ./dlls /path/to/wine/dlls");
        trace("         ", argv[0], " program.exe --apiset 10.0.19041.1-AMD64.json ./dlls");
        trace("Options:");
        trace("  --no-monitoring  Disable syscall monitoring for DLL entry points and main execution");
        trace("  --no-tracing     Disable function call tracing");
        trace("  --apiset file    Load API set mappings from JSON file");
        return 1;
    }

    try {
        bool enable_monitoring = true;
        bool enable_tracing = true;
        int path_start_idx = 2;

        WindowsPELoader loader(enable_monitoring, enable_tracing);

        // Parse command line options
        for (int i = 2; i < argc; i++) {
            std::string arg = argv[i];
            if (arg == "--no-monitoring") {
                enable_monitoring = false;
                trace("Syscall monitoring disabled");
                path_start_idx = i + 1;
            } else if (arg == "--no-tracing") {
                enable_tracing = false;
                trace("Function call tracing disabled");
                path_start_idx = i + 1;
            } else if (arg == "--apiset" && i + 1 < argc) {
                if (std::string json_file = argv[i + 1]; loader.load_api_mappings(json_file)) {
                    trace("Loaded API set mappings from: ", converter.from_bytes(json_file));
                } else {
                    trace("Failed to load API set mappings from: ", converter.from_bytes(json_file));
                }
                i++; // Skip the filename argument
                path_start_idx = i + 1;
            } else {
                break; // Start of DLL paths
            }
        }

        // Add additional DLL search paths from the command line
        for (int i = path_start_idx; i < argc; i++) {
            loader.add_dll_search_path(converter.from_bytes(argv[i]));
            trace("Added DLL search path: ", argv[i]);
        }

        int result = loader.load_and_execute(converter.from_bytes(argv[1]), argc - 1, argv + 1);

        // Print summary of loaded modules
        loader.print_loaded_modules();

        return result;
    } catch (const std::exception& e) {
        error("Error: ", e.what());
        return 1;
    }
}