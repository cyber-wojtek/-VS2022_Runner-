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
#include <condition_variable>
#include <future>

#include <linux/hdreg.h>
#include <linux/cdrom.h>
#include <scsi/sg.h>
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
#include <execinfo.h>
#include <ucontext.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <asm/prctl.h>
#include <sys/shm.h>
#include <sys/ipc.h>
#include <capstone/capstone.h>
#include <sys/stat.h>
#include <sched.h>
#include <pthread.h>
#include <sys/eventfd.h>
#include <sys/signalfd.h>
#include <sys/timerfd.h>

// The ONE. True. Converter.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
#pragma GCC diagnostic pop

// Constants
#define KUSER_SHARED_DATA_ADDRESS 0x7FFE0000
#define KUSER_SHARED_DATA_SIZE 0x1000
#define PROCESSOR_FEATURE_MAX 64

// Forward declarations
class ProcessContext;
class ThreadContext;
class ProcessManager;
class ThreadManager;

// ============================================================================
// ENHANCED THREAD AND PROCESS SYNCHRONIZATION
// ============================================================================

struct APCEntry {
    PNTAPCFUNC function;
    ULONG_PTR arg1;
    ULONG_PTR arg2;
    ULONG_PTR arg3;
    bool user_mode;
};

// Thread-safe event with process-aware functionality
class CrossProcessEvent {
private:
    mutable std::mutex mtx_;
    std::condition_variable cv_;
    std::atomic<bool> flag_;
    bool manual_reset_;
    pid_t owner_process_;
    int eventfd_;
    std::string shared_name_;

public:
    CrossProcessEvent(bool manual_reset = false, bool initial_state = false, const std::string& name = "")
        : flag_(initial_state), manual_reset_(manual_reset), owner_process_(getpid()),
          eventfd_(-1), shared_name_(name) {

        // Create eventfd for cross-process signaling
        eventfd_ = eventfd(initial_state ? 1 : 0, EFD_CLOEXEC | EFD_SEMAPHORE);
        if (eventfd_ == -1) {
            warn("Failed to create eventfd: ", strerror(errno));
        }

        trace("Created cross-process event '", converter.from_bytes(name), "' with fd ", eventfd_);
    }

    ~CrossProcessEvent() {
        if (eventfd_ >= 0) {
            close(eventfd_);
        }
    }

    void set() {
        std::lock_guard<std::mutex> lock(mtx_);
        flag_ = true;

        // Signal via eventfd for cross-process notification
        if (eventfd_ >= 0) {
            uint64_t val = 1;
            if (write(eventfd_, &val, sizeof(val)) == -1) {
                trace("Failed to write to eventfd: ", strerror(errno));
            }
        }

        cv_.notify_all();
        trace("Event '", converter.from_bytes(shared_name_), "' set");
    }

    void reset() {
        std::lock_guard<std::mutex> lock(mtx_);
        flag_ = false;

        // Clear eventfd
        if (eventfd_ >= 0) {
            uint64_t val;
            while (read(eventfd_, &val, sizeof(val)) > 0) {
                // Drain all pending events
            }
        }

        trace("Event '", converter.from_bytes(shared_name_), "' reset");
    }

    bool wait_for(DWORD milliseconds) {
        std::unique_lock<std::mutex> lock(mtx_);
        bool result;

        if (milliseconds == INFINITE) {
            cv_.wait(lock, [this] { return flag_.load(); });
            result = true;
        } else {
            result = cv_.wait_for(lock, std::chrono::milliseconds(milliseconds),
                                [this] { return flag_.load(); });
        }

        if (result && !manual_reset_) {
            flag_ = false;
        }

        return result;
    }

    bool wait_for_cross_process(DWORD milliseconds) {
        if (eventfd_ < 0) {
            return wait_for(milliseconds);
        }

        pollfd pfd;
        pfd.fd = eventfd_;
        pfd.events = POLLIN;
        pfd.revents = 0;

        int timeout = (milliseconds == INFINITE) ? -1 : static_cast<int>(milliseconds);
        int result = poll(&pfd, 1, timeout);

        if (result > 0 && (pfd.revents & POLLIN)) {
            uint64_t val;
            if (read(eventfd_, &val, sizeof(val)) > 0) {
                std::lock_guard<std::mutex> lock(mtx_);
                flag_ = true;
                if (!manual_reset_) {
                    flag_ = false;
                }
                return true;
            }
        }

        return result > 0;
    }

    bool is_set() const {
        std::lock_guard<std::mutex> lock(mtx_);
        return flag_;
    }

    int get_eventfd() const { return eventfd_; }
    const std::string& get_name() const { return shared_name_; }
    pid_t get_owner() const { return owner_process_; }
};

// Enhanced thread-local storage with cross-process awareness
class EnhancedTLS {
public:
    HANDLE thread_handle;
    HANDLE process_handle;
    std::vector<LPVOID> tls_data;
    DWORD last_error;
    std::unique_ptr<TEB> teb;
    std::atomic<bool> is_suspended;
    std::atomic<bool> is_alertable;
    std::queue<PNTAPCFUNC> apc_queue;
    std::mutex apc_mutex;
    std::condition_variable apc_cv;
    pthread_t native_thread;
    pid_t process_id;
    DWORD thread_id;
    uintptr_t stack_base;
    size_t stack_size;
    std::chrono::steady_clock::time_point creation_time;

    EnhancedTLS() : thread_handle(nullptr), process_handle(nullptr), last_error(0),
                   is_suspended(false), is_alertable(false),
                   native_thread(pthread_self()), process_id(getpid()),
                   thread_id(static_cast<DWORD>(syscall(SYS_gettid))),
                   stack_base(0), stack_size(0),
                   creation_time(std::chrono::steady_clock::now()) {
        tls_data.resize(64); // Standard TLS slots
        initialize_teb();
        get_stack_info();
    }

private:
    void initialize_teb() {
        teb = std::make_unique<TEB>();
        memset(teb.get(), 0, sizeof(TEB));

        teb->ClientId.UniqueProcess = process_handle;
        teb->ClientId.UniqueThread = thread_handle;
        teb->LastErrorValue = last_error;
        teb->Tib.ExceptionList = reinterpret_cast<EXCEPTION_REGISTRATION_RECORD*>(-1);
        teb->Tib.Self = &teb->Tib;
    }

    void get_stack_info() {
        pthread_attr_t attr;
        if (pthread_getattr_np(native_thread, &attr) == 0) {
            void* stack_addr;
            if (pthread_attr_getstack(&attr, &stack_addr, &stack_size) == 0) {
                stack_base = reinterpret_cast<uintptr_t>(stack_addr) + stack_size;
                teb->Tib.StackBase = reinterpret_cast<void*>(stack_base);
                teb->Tib.StackLimit = stack_addr;
            }
            pthread_attr_destroy(&attr);
        }
    }
};

// Thread-local storage
static thread_local std::unique_ptr<EnhancedTLS> g_enhanced_tls;

// ============================================================================
// ENHANCED THREAD CONTEXT MANAGEMENT
// ============================================================================

class ThreadContext {
private:
    mutable std::shared_mutex context_mutex_;
    std::atomic<bool> is_valid_;

public:
    pthread_t native_thread_id;
    HANDLE windows_thread_handle;
    HANDLE parent_process_handle;
    DWORD thread_id;
    DWORD last_error;
    std::vector<LPVOID> tls_data;
    std::unique_ptr<TEB> current_teb;
    bool is_main_thread;
    std::atomic<bool> is_suspended;
    std::atomic<bool> is_terminated;
    std::atomic<bool> is_alertable;
    DWORD exit_code;
    DWORD priority_class;
    DWORD affinity_mask;
    CONTEXT thread_context;
    bool context_valid;

    // Thread synchronization
    std::queue<struct APCEntry> apc_queue;
    mutable std::mutex apc_mutex;
    std::condition_variable apc_cv;
    std::unique_ptr<CrossProcessEvent> suspend_event;
    std::unique_ptr<CrossProcessEvent> resume_event;
    std::unique_ptr<CrossProcessEvent> terminate_event;

    // Stack information
    uintptr_t stack_base;
    size_t stack_size;
    uintptr_t stack_limit;

    // Thread timing
    std::chrono::steady_clock::time_point creation_time;
    std::chrono::steady_clock::time_point last_run_time;
    std::chrono::nanoseconds cpu_time;

    ThreadContext(HANDLE process_handle, bool main_thread = false)
        : native_thread_id(pthread_self()),
          windows_thread_handle(nullptr),
          parent_process_handle(process_handle),
          thread_id(static_cast<DWORD>(syscall(SYS_gettid))),
          last_error(0),
          is_main_thread(main_thread),
          is_suspended(false),
          is_terminated(false),
          is_alertable(false),
          exit_code(STILL_ACTIVE),
          priority_class(NORMAL_PRIORITY_CLASS),
          affinity_mask(0xFFFFFFFF),
          context_valid(false),
          stack_base(0),
          stack_size(0),
          stack_limit(0),
          creation_time(std::chrono::steady_clock::now()),
          last_run_time(creation_time),
          cpu_time(std::chrono::nanoseconds::zero()),
          is_valid_(true) {

        tls_data.resize(64);
        create_thread_teb();
        get_stack_information();
        create_synchronization_objects();
    }

    ~ThreadContext() {
        is_valid_ = false;
        cleanup_thread_teb();
    }

    bool is_valid() const {
        return is_valid_;
    }

    void suspend() {
        std::unique_lock lock(context_mutex_);
        is_suspended = true;
        if (suspend_event) {
            suspend_event->set();
        }
        trace("Thread ", thread_id, " suspended");
    }

    void resume() {
        std::unique_lock lock(context_mutex_);
        is_suspended = false;
        if (resume_event) {
            resume_event->set();
        }
        trace("Thread ", thread_id, " resumed");
    }

    void terminate(DWORD exit_status) {
        std::unique_lock lock(context_mutex_);
        is_terminated = true;
        exit_code = exit_status;
        if (terminate_event) {
            terminate_event->set();
        }
        trace("Thread ", thread_id, " terminated with code ", exit_status);
    }

    void queue_apc(PNTAPCFUNC function, ULONG_PTR arg1, ULONG_PTR arg2, ULONG_PTR arg3, bool user_mode = true) {
        std::lock_guard<std::mutex> lock(apc_mutex);
        apc_queue.emplace(function, arg1, arg2, arg3, user_mode);
        apc_cv.notify_one();
        trace("Queued APC for thread ", thread_id);
    }

    bool process_apcs() {
        std::lock_guard<std::mutex> lock(apc_mutex);
        bool processed = false;

        while (!apc_queue.empty() && is_alertable) {
            APCEntry apc = apc_queue.front();
            apc_queue.pop();

            // Execute APC (this would need proper context switching in real implementation)
            trace("Processing APC for thread ", thread_id);
            // apc.function(apc.arg1, apc.arg2, apc.arg3);
            processed = true;
        }

        return processed;
    }

    void update_cpu_time() {
        auto now = std::chrono::steady_clock::now();
        if (last_run_time < now) {
            cpu_time += std::chrono::duration_cast<std::chrono::nanoseconds>(now - last_run_time);
            last_run_time = now;
        }
    }

private:
    void create_thread_teb() {
        current_teb = std::make_unique<TEB>();
        memset(current_teb.get(), 0, sizeof(TEB));

        current_teb->ClientId.UniqueProcess = parent_process_handle;
        current_teb->ClientId.UniqueThread = windows_thread_handle;
        current_teb->LastErrorValue = last_error;
        current_teb->Tib.ExceptionList = reinterpret_cast<EXCEPTION_REGISTRATION_RECORD*>(-1);
        current_teb->Tib.Self = &current_teb->Tib;
        current_teb->Tib.StackBase = reinterpret_cast<void*>(stack_base);
        current_teb->Tib.StackLimit = reinterpret_cast<void*>(stack_limit);
    }

    void cleanup_thread_teb() {
        current_teb.reset();
    }

    void get_stack_information() {
        pthread_attr_t attr;
        if (pthread_getattr_np(native_thread_id, &attr) == 0) {
            void* stack_addr;
            if (pthread_attr_getstack(&attr, &stack_addr, &stack_size) == 0) {
                stack_base = reinterpret_cast<uintptr_t>(stack_addr) + stack_size;
                stack_limit = reinterpret_cast<uintptr_t>(stack_addr);
            }
            pthread_attr_destroy(&attr);
        }
    }

    void create_synchronization_objects() {
        std::string thread_name = "thread_" + std::to_string(thread_id);
        suspend_event = std::make_unique<CrossProcessEvent>(false, false, thread_name + "_suspend");
        resume_event = std::make_unique<CrossProcessEvent>(false, false, thread_name + "_resume");
        terminate_event = std::make_unique<CrossProcessEvent>(false, false, thread_name + "_terminate");
    }
};

// ============================================================================
// ENHANCED PROCESS CONTEXT MANAGEMENT
// ============================================================================

class ProcessContext {
private:
    mutable std::shared_mutex process_mutex_;
    std::atomic<bool> is_valid_;
    std::atomic<bool> is_terminating_;

public:
    pid_t native_process_id;
    HANDLE windows_process_handle;
    DWORD process_id;
    std::unique_ptr<PEB> current_peb;

    // Thread management
    std::unordered_map<pthread_t, std::unique_ptr<ThreadContext>> threads;
    std::unordered_map<HANDLE, pthread_t> handle_to_thread;
    ThreadContext* main_thread;
    std::atomic<size_t> thread_count;

    // Handle management
    std::unordered_map<HANDLE, std::unique_ptr<class DeviceHandle>> device_handles;
    std::unordered_map<HANDLE, std::unique_ptr<CrossProcessEvent>> events;
    std::unordered_map<HANDLE, std::unique_ptr<class CompletionPort>> completion_ports;
    std::unordered_map<HANDLE, std::unique_ptr<class FileMapping>> file_mappings;

    // Process synchronization
    std::unique_ptr<CrossProcessEvent> process_ready_event;
    std::unique_ptr<CrossProcessEvent> process_exit_event;
    std::condition_variable_any thread_exit_cv;

    // Process information
    DWORD exit_code;
    DWORD priority_class;
    std::chrono::steady_clock::time_point creation_time;
    std::wstring image_path;
    std::wstring command_line;
    std::wstring current_directory;
    WCHAR* environment_block;

    // Child process management
    std::vector<pid_t> child_processes;
    std::mutex child_process_mutex;

    // Memory management
    std::vector<class HeapInfo> heaps;
    class HeapInfo* default_heap;

    ProcessContext() : is_valid_(true),
                      is_terminating_(false),
                      native_process_id(getpid()),
                      windows_process_handle(nullptr),
                      process_id(static_cast<DWORD>(getpid())),
                      main_thread(nullptr),
                      thread_count(0),
                      exit_code(STILL_ACTIVE),
                      priority_class(NORMAL_PRIORITY_CLASS),
                      creation_time(std::chrono::steady_clock::now()),
                      environment_block(nullptr),
                      default_heap(nullptr) {

        create_process_peb();
        create_synchronization_objects();
        initialize_heaps();
        initialize_environment();
    }

    ~ProcessContext() {
        is_valid_ = false;
        cleanup_process();
    }

    bool is_valid() const { return is_valid_; }
    bool is_terminating() const { return is_terminating_; }

    ThreadContext* get_current_thread() {
        const pthread_t current = pthread_self();
        std::shared_lock lock(process_mutex_);
        const auto it = threads.find(current);
        return (it != threads.end()) ? it->second.get() : nullptr;
    }

    ThreadContext* create_thread_context(bool is_main = false) {
        pthread_t current = pthread_self();
        std::unique_lock lock(process_mutex_);

        auto thread_ctx = std::make_unique<ThreadContext>(windows_process_handle, is_main);
        ThreadContext* ptr = thread_ctx.get();

        threads[current] = std::move(thread_ctx);
        thread_count++;

        if (is_main) {
            main_thread = ptr;
        }

        return ptr;
    }

    void remove_thread(pthread_t thread_id) {
        std::unique_lock lock(process_mutex_);

        if (auto it = threads.find(thread_id); it != threads.end()) {
            if (it->second.get() == main_thread) {
                main_thread = nullptr;
            }
            threads.erase(it);
            thread_count--;
            trace("Removed thread from process context, remaining threads: ", thread_count.load());
        }

        // Notify waiting threads
        thread_exit_cv.notify_all();
    }

    void terminate_process(DWORD exit_status) {
        std::unique_lock lock(process_mutex_);
        is_terminating_ = true;
        exit_code = exit_status;

        // Terminate all threads
        for (auto& [tid, thread_ctx] : threads) {
            thread_ctx->terminate(exit_status);
        }

        // Signal process exit
        if (process_exit_event) {
            process_exit_event->set();
        }

        trace("Process ", process_id, " terminated with code ", exit_status);
    }

    void wait_for_all_threads() {
        std::shared_lock lock(process_mutex_);
        thread_exit_cv.wait(lock, [this] { return thread_count == 0 || is_terminating_; });
    }

    void add_child_process(pid_t child_pid) {
        std::lock_guard lock(child_process_mutex);
        child_processes.push_back(child_pid);
        trace("Added child process ", child_pid, " to parent ", process_id);
    }

    void remove_child_process(pid_t child_pid) {
        std::lock_guard lock(child_process_mutex);
        auto it = std::find(child_processes.begin(), child_processes.end(), child_pid);
        if (it != child_processes.end()) {
            child_processes.erase(it);
            trace("Removed child process ", child_pid, " from parent ", process_id);
        }
    }

private:
    void create_process_peb() {
        current_peb = std::make_unique<PEB>();
        memset(current_peb.get(), 0, sizeof(PEB));

        current_peb->NumberOfProcessors = sysconf(_SC_NPROCESSORS_ONLN);
        current_peb->OSMajorVersion = 10;
        current_peb->OSMinorVersion = 0;
        current_peb->OSBuildNumber = 19045;
        current_peb->OSPlatformId = VER_PLATFORM_WIN32_NT;
    }

    void create_synchronization_objects() {
        std::string proc_name = "process_" + std::to_string(process_id);
        process_ready_event = std::make_unique<CrossProcessEvent>(false, false, proc_name + "_ready");
        process_exit_event = std::make_unique<CrossProcessEvent>(false, false, proc_name + "_exit");
    }

    void initialize_heaps() {
        // Initialize default heap
        // Implementation would create actual heap structures
    }

    void initialize_environment() {
        // Create basic Windows environment
        constexpr char env_template[] = "SystemRoot=C:\\Windows\0TEMP=C:\\Temp\0TMP=C:\\Temp\0PATH=C:\\Windows\\System32\0\0";
        constexpr size_t env_size = sizeof(env_template);
        environment_block = static_cast<WCHAR*>(malloc(env_size * sizeof(WCHAR)));
        for (size_t i = 0; i < env_size; ++i) {
            environment_block[i] = static_cast<WCHAR>(env_template[i]);
        }
    }

    void cleanup_process() {
        if (environment_block) {
            free(environment_block);
            environment_block = nullptr;
        }

        // Cleanup child processes
        std::lock_guard lock(child_process_mutex);
        for (pid_t child : child_processes) {
            kill(child, SIGTERM);
            // Don't wait here to avoid blocking
        }
        child_processes.clear();
    }
};

// ============================================================================
// GLOBAL CONTEXT MANAGER WITH ADVANCED FEATURES
// ============================================================================

class AdvancedContextManager {
private:
    static thread_local std::unique_ptr<ThreadContext> current_thread_context;
    static std::unordered_map<pid_t, std::unique_ptr<ProcessContext>> processes;
    static std::shared_mutex global_mutex;
    static std::atomic<bool> shutdown_requested;
    static std::thread cleanup_thread;
    static std::condition_variable_any cleanup_cv;

    // Process hierarchy tracking
    static std::unordered_map<pid_t, pid_t> parent_child_map;
    static std::unordered_map<pid_t, std::vector<pid_t>> children_map;

public:
    static ProcessContext* get_current_process() {
        pid_t pid = getpid();
        std::shared_lock lock(global_mutex);
        auto it = processes.find(pid);
        return (it != processes.end()) ? it->second.get() : nullptr;
    }

    static ProcessContext* get_process_by_id(pid_t pid) {
        std::shared_lock lock(global_mutex);
        auto it = processes.find(pid);
        return (it != processes.end()) ? it->second.get() : nullptr;
    }

    static ProcessContext* create_process_context() {
        pid_t pid = getpid();
        std::unique_lock lock(global_mutex);

        auto proc_ctx = std::make_unique<ProcessContext>();
        ProcessContext* ptr = proc_ctx.get();
        processes[pid] = std::move(proc_ctx);

        trace("Created process context for PID ", pid);
        return ptr;
    }

    static ThreadContext* get_current_thread() {
        if (!current_thread_context) {
            ProcessContext* proc = get_current_process();
            if (!proc) {
                proc = create_process_context();
            }
            current_thread_context.reset(new ThreadContext(proc->windows_process_handle));
            proc->threads[pthread_self()] = std::unique_ptr<ThreadContext>(current_thread_context.get());
        }
        return current_thread_context.get();
    }

    static void register_process_hierarchy(pid_t parent, pid_t child) {
        std::unique_lock lock(global_mutex);
        parent_child_map[child] = parent;
        children_map[parent].push_back(child);
        trace("Registered process hierarchy: ", parent, " -> ", child);
    }

    static std::vector<pid_t> get_child_processes(pid_t parent) {
        std::shared_lock lock(global_mutex);
        auto it = children_map.find(parent);
        return (it != children_map.end()) ? it->second : std::vector<pid_t>();
    }

    static void cleanup_process(pid_t pid) {
        std::unique_lock lock(global_mutex);

        // Cleanup children first
        if (auto it = children_map.find(pid); it != children_map.end()) {
            for (pid_t child : it->second) {
                cleanup_process(child);
            }
            children_map.erase(it);
        }

        // Remove from parent's children list
        if (auto parent_it = parent_child_map.find(pid); parent_it != parent_child_map.end()) {
            pid_t parent = parent_it->second;
            if (auto children_it = children_map.find(parent); children_it != children_map.end()) {
                auto& children = children_it->second;
                children.erase(std::remove(children.begin(), children.end(), pid), children.end());
            }
            parent_child_map.erase(parent_it);
        }

        processes.erase(pid);
        trace("Cleaned up process context for PID ", pid);
    }

    static void initialize_cleanup_system() {
        shutdown_requested = false;
        cleanup_thread = std::thread(cleanup_worker);
    }

    static void shutdown_cleanup_system() {
        shutdown_requested = true;
        cleanup_cv.notify_all();
        if (cleanup_thread.joinable()) {
            cleanup_thread.join();
        }
    }

    static void request_process_cleanup(pid_t pid) {
        // This would be called asynchronously to clean up terminated processes
        cleanup_cv.notify_all();
    }

private:
    static void cleanup_worker() {
        while (!shutdown_requested) {
            std::unique_lock lock(global_mutex);
            cleanup_cv.wait(lock, [] { return shutdown_requested.load(); });

            if (shutdown_requested) break;

            // Check for terminated processes and clean them up
            std::vector<pid_t> to_cleanup;
            for (const auto& [pid, proc_ctx] : processes) {
                if (!proc_ctx->is_valid() || proc_ctx->is_terminating()) {
                    to_cleanup.push_back(pid);
                }
            }

            lock.unlock();

            for (pid_t pid : to_cleanup) {
                cleanup_process(pid);
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
};

// Static member definitions
thread_local std::unique_ptr<ThreadContext> AdvancedContextManager::current_thread_context;
std::unordered_map<pid_t, std::unique_ptr<ProcessContext>> AdvancedContextManager::processes;
std::shared_mutex AdvancedContextManager::global_mutex;
std::atomic<bool> AdvancedContextManager::shutdown_requested{false};
std::thread AdvancedContextManager::cleanup_thread;
std::condition_variable_any AdvancedContextManager::cleanup_cv;
std::unordered_map<pid_t, pid_t> AdvancedContextManager::parent_child_map;
std::unordered_map<pid_t, std::vector<pid_t>> AdvancedContextManager::children_map;

// ============================================================================
// ENHANCED THREAD AND PROCESS MANAGEMENT
// ============================================================================


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
    bool write(const uintptr_t addr, const T& data) const {
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


class ThreadManager {
private:
    std::unordered_map<HANDLE, std::unique_ptr<ThreadContext>> managed_threads;
    std::unordered_map<pthread_t, HANDLE> native_to_handle_map;
    std::shared_mutex thread_map_mutex;
    std::atomic<HANDLE> next_thread_handle{reinterpret_cast<HANDLE>(0x2000)};

public:
    HANDLE create_thread(HANDLE process_handle, LPTHREAD_START_ROUTINE start_routine,
                        LPVOID parameter, DWORD creation_flags, LPDWORD thread_id) {

        const auto thread_handle = reinterpret_cast<HANDLE>(reinterpret_cast<uintptr_t>(next_thread_handle.load()) + 1);

        auto thread_ctx = std::make_unique<ThreadContext>(process_handle, false);
        thread_ctx->windows_thread_handle = thread_handle;

        // Create actual pthread
        pthread_attr_t attr;
        pthread_attr_init(&attr);

        if (creation_flags & CREATE_SUSPENDED) {
            thread_ctx->suspend();
        }

        // Thread creation parameters
        struct ThreadParams {
            LPTHREAD_START_ROUTINE start_routine;
            LPVOID parameter;
            ThreadContext* context;
            std::promise<void> ready_promise;
        };

        auto params = std::make_unique<ThreadParams>();
        params->start_routine = start_routine;
        params->parameter = parameter;
        params->context = thread_ctx.get();
        auto ready_future = params->ready_promise.get_future();

        pthread_t native_thread;
        int result = pthread_create(&native_thread, &attr, thread_wrapper, params.release());

        if (result != 0) {
            pthread_attr_destroy(&attr);
            trace("Failed to create thread: ", strerror(result));
            return nullptr;
        }

        // Wait for thread to be ready
        ready_future.wait();

        thread_ctx->native_thread_id = native_thread;
        if (thread_id) {
            *thread_id = thread_ctx->thread_id;
        }

        std::unique_lock lock(thread_map_mutex);
        managed_threads[thread_handle] = std::move(thread_ctx);
        native_to_handle_map[native_thread] = thread_handle;

        pthread_attr_destroy(&attr);

        trace("Created thread with handle ", thread_handle,
              " and native thread ", native_thread);

        return thread_handle;
    }

    bool suspend_thread(HANDLE thread_handle, LPDWORD suspend_count) {
        std::shared_lock lock(thread_map_mutex);
        auto it = managed_threads.find(thread_handle);

        if (it == managed_threads.end()) {
            return false;
        }

        ThreadContext* ctx = it->second.get();
        DWORD prev_count = ctx->is_suspended ? 1 : 0;

        ctx->suspend();

        // Send signal to native thread to suspend
        pthread_kill(ctx->native_thread_id, SIGUSR1);

        if (suspend_count) {
            *suspend_count = prev_count;
        }

        return true;
    }

    bool resume_thread(HANDLE thread_handle, LPDWORD suspend_count) {
        std::shared_lock lock(thread_map_mutex);
        auto it = managed_threads.find(thread_handle);

        if (it == managed_threads.end()) {
            return false;
        }

        ThreadContext* ctx = it->second.get();
        DWORD prev_count = ctx->is_suspended ? 1 : 0;

        ctx->resume();

        // Send signal to native thread to resume
        pthread_kill(ctx->native_thread_id, SIGUSR2);

        if (suspend_count) {
            *suspend_count = prev_count;
        }

        return true;
    }

    bool terminate_thread(HANDLE thread_handle, DWORD exit_code) {
        std::unique_lock lock(thread_map_mutex);
        auto it = managed_threads.find(thread_handle);

        if (it == managed_threads.end()) {
            return false;
        }

        ThreadContext* ctx = it->second.get();
        ctx->terminate(exit_code);

        // Cancel the pthread
        pthread_cancel(ctx->native_thread_id);

        // Clean up
        native_to_handle_map.erase(ctx->native_thread_id);
        managed_threads.erase(it);

        return true;
    }

    ThreadContext* get_thread_context(HANDLE thread_handle) {
        std::shared_lock lock(thread_map_mutex);
        auto it = managed_threads.find(thread_handle);
        return (it != managed_threads.end()) ? it->second.get() : nullptr;
    }

    HANDLE get_thread_handle(pthread_t native_thread) {
        std::shared_lock lock(thread_map_mutex);
        auto it = native_to_handle_map.find(native_thread);
        return (it != native_to_handle_map.end()) ? it->second : nullptr;
    }

private:
    static void* thread_wrapper(void* param) {
        std::unique_ptr<ThreadParams> params(static_cast<ThreadParams*>(param));

        // Set up thread-local storage
        if (!g_enhanced_tls) {
            g_enhanced_tls = std::make_unique<EnhancedTLS>();
        }

        g_enhanced_tls->thread_handle = params->context->windows_thread_handle;
        g_enhanced_tls->process_handle = params->context->parent_process_handle;

        // Set up signal handlers for suspend/resume
        signal(SIGUSR1, suspend_signal_handler);
        signal(SIGUSR2, resume_signal_handler);

        params->ready_promise.set_value();

        // Wait if created suspended
        while (params->context->is_suspended) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }

        trace("Thread starting execution");

        DWORD result = 0;
        try {
            result = reinterpret_cast<DWORD>(params->start_routine(params->parameter));
        } catch (const std::exception& e) {
            error("Thread exception: ", e.what());
            result = 1;
        }

        params->context->terminate(result);
        trace("Thread finished with result ", result);

        return reinterpret_cast<void*>(static_cast<uintptr_t>(result));
    }

    static void suspend_signal_handler(int sig) {
        if (sig == SIGUSR1) {
            // Suspend current thread
            sigset_t set;
            sigemptyset(&set);
            sigaddset(&set, SIGUSR2);

            int signal_received;
            sigwait(&set, &signal_received); // Wait for resume signal
        }
    }

    static void resume_signal_handler(int sig) {
        if (sig == SIGUSR2) {
            // Resume is handled by unblocking sigwait in suspend handler
            trace("Thread resume signal received");
        }
    }

    struct ThreadParams {
        LPTHREAD_START_ROUTINE start_routine;
        LPVOID parameter;
        ThreadContext* context;
        std::promise<void> ready_promise;
    };
};

class ProcessManager {
private:
    std::unordered_map<HANDLE, std::unique_ptr<ProcessContext>> managed_processes;
    std::unordered_map<pid_t, HANDLE> pid_to_handle_map;
    std::shared_mutex process_map_mutex;
    std::atomic<HANDLE> next_process_handle{reinterpret_cast<HANDLE>(0x3000)};
    std::unique_ptr<ThreadManager> thread_manager;

public:
    ProcessManager() : thread_manager(std::make_unique<ThreadManager>()) {}

    HANDLE create_process(const std::wstring& application_name,
                         const std::wstring& command_line,
                         LPSECURITY_ATTRIBUTES process_attributes,
                         LPSECURITY_ATTRIBUTES thread_attributes,
                         BOOL inherit_handles,
                         DWORD creation_flags,
                         LPVOID environment,
                         const std::wstring& current_directory,
                         LPSTARTUPINFOW startup_info,
                         LPPROCESS_INFORMATION process_information) {

        // Convert Windows paths and arguments to Unix format
        std::string app_name_str = converter.to_bytes(application_name);
        std::string cmd_line_str = converter.to_bytes(command_line);
        std::string current_dir_str = converter.to_bytes(current_directory);

        // Parse command line into arguments
        std::vector<std::string> args = parse_command_line(cmd_line_str);
        if (args.empty()) {
            trace("Invalid command line");
            return nullptr;
        }

        // Create process handle
        const auto process_handle = next_process_handle = reinterpret_cast<HANDLE>(reinterpret_cast<uintptr_t>(next_process_handle.load()) + 1);

        pid_t child_pid = fork();
        if (child_pid == -1) {
            error("Failed to fork process: ", strerror(errno));
            return nullptr;
        }

        if (child_pid == 0) {
            // Child process
            if (!current_dir_str.empty()) {
                chdir(current_dir_str.c_str());
            }

            // Convert args to char* array
            std::vector<char*> argv;
            for (auto& arg : args) {
                argv.push_back(const_cast<char*>(arg.c_str()));
            }
            argv.push_back(nullptr);

            // Set up environment if provided
            if (environment) {
                // Convert Windows environment block to Unix environ format
                // This is a simplified implementation
            }

            // Enable tracing if requested
            if (creation_flags & DEBUG_PROCESS) {
                ptrace(PTRACE_TRACEME, 0, NULL, NULL);
            }

            // Execute the program
            execv(argv[0], argv.data());

            // If we get here, exec failed
            error("Failed to exec: ", strerror(errno));
            exit(1);
        }

        // Parent process
        auto proc_ctx = std::make_unique<ProcessContext>();
        proc_ctx->native_process_id = child_pid;
        proc_ctx->windows_process_handle = process_handle;
        proc_ctx->process_id = static_cast<DWORD>(child_pid);
        proc_ctx->image_path = application_name;
        proc_ctx->command_line = command_line;
        proc_ctx->current_directory = current_directory;

        // Create main thread context for the child process
        HANDLE main_thread_handle = thread_manager->create_thread(
            process_handle, nullptr, nullptr, 0, nullptr);

        std::unique_lock lock(process_map_mutex);
        managed_processes[process_handle] = std::move(proc_ctx);
        pid_to_handle_map[child_pid] = process_handle;

        // Register in context manager
        AdvancedContextManager::register_process_hierarchy(getpid(), child_pid);

        if (process_information) {
            process_information->hProcess = process_handle;
            process_information->hThread = main_thread_handle;
            process_information->dwProcessId = static_cast<DWORD>(child_pid);
            process_information->dwThreadId = static_cast<DWORD>(child_pid); // Simplified
        }

        trace("Created process ", child_pid, " with handle ", process_handle);

        return process_handle;
    }

    bool terminate_process(HANDLE process_handle, UINT exit_code) {
        std::unique_lock lock(process_map_mutex);
        auto it = managed_processes.find(process_handle);

        if (it == managed_processes.end()) {
            return false;
        }

        ProcessContext* ctx = it->second.get();
        pid_t child_pid = ctx->native_process_id;

        // Terminate the process
        if (kill(child_pid, SIGTERM) != 0) {
            // Try SIGKILL if SIGTERM fails
            kill(child_pid, SIGKILL);
        }

        ctx->terminate_process(exit_code);

        // Wait for process to actually terminate
        int status;
        waitpid(child_pid, &status, WNOHANG);

        // Clean up
        pid_to_handle_map.erase(child_pid);
        managed_processes.erase(it);

        AdvancedContextManager::cleanup_process(child_pid);

        trace("Terminated process ", child_pid);
        return true;
    }

    DWORD wait_for_single_object(HANDLE handle, DWORD timeout_ms) {
        // Check if it's a process handle
        {
            std::shared_lock lock(process_map_mutex);
            auto proc_it = managed_processes.find(handle);
            if (proc_it != managed_processes.end()) {
                return wait_for_process(proc_it->second.get(), timeout_ms);
            }
        }

        // Check if it's a thread handle
        ThreadContext* thread_ctx = thread_manager->get_thread_context(handle);
        if (thread_ctx) {
            return wait_for_thread(thread_ctx, timeout_ms);
        }

        // Check for events, mutexes, etc.
        return wait_for_synchronization_object(handle, timeout_ms);
    }

    ProcessContext* get_process_context(HANDLE process_handle) {
        std::shared_lock lock(process_map_mutex);
        auto it = managed_processes.find(process_handle);
        return (it != managed_processes.end()) ? it->second.get() : nullptr;
    }

    ThreadManager* get_thread_manager() { return thread_manager.get(); }

private:
    DWORD wait_for_process(ProcessContext* ctx, DWORD timeout_ms) {
        if (ctx->is_terminating()) {
            return WAIT_OBJECT_0;
        }

        auto start_time = std::chrono::steady_clock::now();

        while (!ctx->is_terminating()) {
            if (timeout_ms != INFINITE) {
                auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - start_time);
                if (elapsed.count() >= timeout_ms) {
                    return WAIT_TIMEOUT;
                }
            }

            // Check if process is still alive
            if (kill(ctx->native_process_id, 0) != 0 && errno == ESRCH) {
                ctx->terminate_process(0);
                return WAIT_OBJECT_0;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }

        return WAIT_OBJECT_0;
    }

    DWORD wait_for_thread(ThreadContext* ctx, DWORD timeout_ms) {
        if (ctx->is_terminated) {
            return WAIT_OBJECT_0;
        }

        auto start_time = std::chrono::steady_clock::now();

        while (!ctx->is_terminated) {
            if (timeout_ms != INFINITE) {
                auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - start_time);
                if (elapsed.count() >= timeout_ms) {
                    return WAIT_TIMEOUT;
                }
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }

        return WAIT_OBJECT_0;
    }

    DWORD wait_for_synchronization_object(HANDLE handle, DWORD timeout_ms) {
        // This would handle events, mutexes, semaphores, etc.
        // Implementation depends on the specific object type
        return WAIT_FAILED;
    }

    std::vector<std::string> parse_command_line(const std::string& cmd_line) {
        std::vector<std::string> args;
        std::string current_arg;
        bool in_quotes = false;
        bool escape_next = false;

        for (char c : cmd_line) {
            if (escape_next) {
                current_arg += c;
                escape_next = false;
            } else if (c == '\\') {
                escape_next = true;
                current_arg += c;
            } else if (c == '"') {
                in_quotes = !in_quotes;
            } else if (c == ' ' && !in_quotes) {
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
};

// ============================================================================
// ENHANCED NT API IMPLEMENTATIONS WITH MULTITHREADING SUPPORT
// ============================================================================

// Global managers
static std::unique_ptr<ProcessManager> g_process_manager;
static std::unique_ptr<ThreadManager> g_thread_manager;

// Enhanced NT API functions
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

    trace("_NtCreateThread called");

    if (!ThreadHandle) {
        return STATUS_INVALID_PARAMETER;
    }

    // For now, only support creating threads in current process
    if (ProcessHandle && ProcessHandle != reinterpret_cast<HANDLE>(-1)) {
        ProcessContext* target_proc = g_process_manager->get_process_context(ProcessHandle);
        if (!target_proc) {
            return STATUS_INVALID_HANDLE;
        }
    }

    DWORD creation_flags = CreateSuspended ? CREATE_SUSPENDED : 0;
    DWORD thread_id;

    // Create a simple thread that just exits (for compatibility)
    // In a real implementation, this would set up proper thread context
    HANDLE thread_handle = g_thread_manager->create_thread(
        ProcessHandle ? ProcessHandle : reinterpret_cast<HANDLE>(-1),
        [](LPVOID) -> DWORD { return 0; },
        nullptr,
        creation_flags,
        &thread_id);

    if (!thread_handle) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Write thread handle to child memory
    uintptr_t handle_ptr = reinterpret_cast<uintptr_t>(ThreadHandle);
    if (!memory_mgr.write(handle_ptr, thread_handle)) {
        g_thread_manager->terminate_thread(thread_handle, 1);
        return STATUS_ACCESS_VIOLATION;
    }

    // Write ClientId if requested
    if (ClientId) {
        CLIENT_ID client_id;
        client_id.UniqueProcess = ProcessHandle ? ProcessHandle : reinterpret_cast<HANDLE>(-1);
        client_id.UniqueThread = thread_handle;

        uintptr_t client_id_ptr = reinterpret_cast<uintptr_t>(ClientId);
        if (!memory_mgr.write(client_id_ptr, client_id)) {
            g_thread_manager->terminate_thread(thread_handle, 1);
            return STATUS_ACCESS_VIOLATION;
        }
    }

    trace("Created thread with handle ", thread_handle);
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI _NtSuspendThread(
    const ChildMemoryManager& memory_mgr,
    HANDLE ThreadHandle,
    PULONG PreviousSuspendCount) {

    trace("_NtSuspendThread called with handle ", ThreadHandle);

    DWORD suspend_count = 0;
    bool success = g_thread_manager->suspend_thread(ThreadHandle, &suspend_count);

    if (!success) {
        return STATUS_INVALID_HANDLE;
    }

    if (PreviousSuspendCount) {
        uintptr_t count_ptr = reinterpret_cast<uintptr_t>(PreviousSuspendCount);
        if (!memory_mgr.write(count_ptr, static_cast<ULONG>(suspend_count))) {
            return STATUS_ACCESS_VIOLATION;
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS NTAPI _NtResumeThread(
    ChildMemoryManager& memory_mgr,
    HANDLE ThreadHandle,
    PULONG PreviousSuspendCount) {

    trace("_NtResumeThread called with handle ", ThreadHandle);

    DWORD suspend_count = 0;
    bool success = g_thread_manager->resume_thread(ThreadHandle, &suspend_count);

    if (!success) {
        return STATUS_INVALID_HANDLE;
    }

    if (PreviousSuspendCount) {
        uintptr_t count_ptr = reinterpret_cast<uintptr_t>(PreviousSuspendCount);
        if (!memory_mgr.write(count_ptr, static_cast<ULONG>(suspend_count))) {
            return STATUS_ACCESS_VIOLATION;
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS NTAPI _NtTerminateThread(
    ChildMemoryManager& memory_mgr,
    HANDLE ThreadHandle,
    NTSTATUS ExitStatus) {

    trace("_NtTerminateThread called with handle ", ThreadHandle,
          " and exit status ", ExitStatus);

    if (!ThreadHandle) {
        ThreadHandle = g_thread_manager->get_thread_handle(pthread_self());
    }

    bool success = g_thread_manager->terminate_thread(ThreadHandle, ExitStatus);

    if (!success) {
        return STATUS_INVALID_HANDLE;
    }

    // If terminating current thread, exit immediately
    if (ThreadHandle == g_thread_manager->get_thread_handle(pthread_self())) {
        pthread_exit(reinterpret_cast<void*>(static_cast<uintptr_t>(ExitStatus)));
    }

    return STATUS_SUCCESS;
}

NTSTATUS NTAPI _NtCreateProcessEx(
    ChildMemoryManager& memory_mgr,
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ParentProcess,
    ULONG Flags,
    HANDLE SectionHandle,
    HANDLE DebugPort,
    HANDLE ExceptionPort,
    BOOLEAN InJob) {

    trace("_NtCreateProcessEx called");

    if (!ProcessHandle) {
        return STATUS_INVALID_PARAMETER;
    }

    // Read ObjectAttributes for image path
    std::wstring image_path;
    if (ObjectAttributes) {
        uintptr_t obj_attr_ptr = reinterpret_cast<uintptr_t>(ObjectAttributes);
        auto obj_attr = memory_mgr.read<OBJECT_ATTRIBUTES>(obj_attr_ptr);
        if (obj_attr && obj_attr->ObjectName) {
            auto unicode_str_ptr = reinterpret_cast<uintptr_t>(obj_attr->ObjectName);
            auto unicode_str = memory_mgr.read<UNICODE_STRING>(unicode_str_ptr);
            if (unicode_str && unicode_str->Buffer) {
                auto wpath = memory_mgr.read_wstring(
                    reinterpret_cast<uintptr_t>(unicode_str->Buffer),
                    unicode_str->Length / sizeof(WCHAR));
                if (wpath) {
                    image_path = std::wstring(wpath->begin(), wpath->end());
                }
            }
        }
    }

    if (image_path.empty()) {
        return STATUS_INVALID_PARAMETER;
    }

    // Create the process
    PROCESS_INFORMATION proc_info;
    STARTUPINFOW startup_info = {};
    startup_info.cb = sizeof(STARTUPINFOW);

    HANDLE process_handle = g_process_manager->create_process(
        image_path, image_path,
        nullptr, nullptr,
        (Flags & PROCESS_CREATE_FLAGS_INHERIT_HANDLES) != 0,
        Flags,
        nullptr,
        L".",
        &startup_info,
        &proc_info);

    if (!process_handle) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Write process handle to child memory
    uintptr_t handle_ptr = reinterpret_cast<uintptr_t>(ProcessHandle);
    if (!memory_mgr.write(handle_ptr, process_handle)) {
        g_process_manager->terminate_process(process_handle, 1);
        return STATUS_ACCESS_VIOLATION;
    }

    trace("Created process with handle ", process_handle);
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI _NtTerminateProcess(
    ChildMemoryManager& memory_mgr,
    HANDLE ProcessHandle,
    NTSTATUS ExitStatus) {

    trace("_NtTerminateProcess called with handle ", ProcessHandle,
          " and exit status ", ExitStatus);

    if (!ProcessHandle) {
        // Terminate current process
        exit(static_cast<int>(ExitStatus));
    }

    bool success = g_process_manager->terminate_process(ProcessHandle, ExitStatus);

    if (!success) {
        return STATUS_INVALID_HANDLE;
    }

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

    DWORD result = g_process_manager->wait_for_single_object(Handle, timeout_ms);

    switch (result) {
        case WAIT_OBJECT_0:
            return STATUS_SUCCESS;
        case WAIT_TIMEOUT:
            return STATUS_TIMEOUT;
        case WAIT_FAILED:
        default:
            return STATUS_INVALID_HANDLE;
    }
}

// ============================================================================
// INTEGRATION WITH EXISTING SYSCALL SYSTEM
// ============================================================================

// Enhanced syscall handlers map with thread/process management
const std::unordered_map<unsigned long long, std::pair<std::string, NTSTATUS (*)(ChildMemoryManager&, const user_regs_struct&)>> enhanced_syscall_handlers = {
    // ... (include all previous syscall handlers)

    // Thread management syscalls
    {0xA5, {"NtCreateThread", [](ChildMemoryManager& mgr, const user_regs_struct& regs) {
        const SyscallParameterReader reader(mgr, regs);
        return _NtCreateThread(
            mgr,
            reinterpret_cast<PHANDLE>(regs.r10),
            static_cast<ACCESS_MASK>(regs.rdx),
            reinterpret_cast<POBJECT_ATTRIBUTES>(regs.r8),
            reinterpret_cast<HANDLE>(regs.r9),
            reader.get_stack_param<PCLIENT_ID>(5).value(),
            reader.get_stack_param<PCONTEXT>(6).value(),
            reader.get_stack_param<PINITIAL_TEB>(7).value(),
            reader.get_stack_param<BOOLEAN>(8).value()
        );
    }}},

    {0x17D, {"NtSuspendThread", [](ChildMemoryManager& mgr, const user_regs_struct& regs) {
        return _NtSuspendThread(
            mgr,
            reinterpret_cast<HANDLE>(regs.r10),
            reinterpret_cast<PULONG>(regs.rdx)
        );
    }}},

    {0x14D, {"NtResumeThread", [](ChildMemoryManager& mgr, const user_regs_struct& regs) {
        return _NtResumeThread(
            mgr,
            reinterpret_cast<HANDLE>(regs.r10),
            reinterpret_cast<PULONG>(regs.rdx)
        );
    }}},

    {0x177, {"NtTerminateThread", [](ChildMemoryManager& mgr, const user_regs_struct& regs) {
        return _NtTerminateThread(
            mgr,
            reinterpret_cast<HANDLE>(regs.r10),
            static_cast<NTSTATUS>(regs.rdx)
        );
    }}},

    // Process management syscalls
    {0xBA, {"NtCreateProcessEx", [](ChildMemoryManager& mgr, const user_regs_struct& regs) {
        const SyscallParameterReader reader(mgr, regs);
        return _NtCreateProcessEx(
            mgr,
            reinterpret_cast<PHANDLE>(regs.r10),
            static_cast<ACCESS_MASK>(regs.rdx),
            reinterpret_cast<POBJECT_ATTRIBUTES>(regs.r8),
            reinterpret_cast<HANDLE>(regs.r9),
            reader.get_stack_param<ULONG>(5).value(),
            reader.get_stack_param<HANDLE>(6).value(),
            reader.get_stack_param<HANDLE>(7).value(),
            reader.get_stack_param<HANDLE>(8).value(),
            reader.get_stack_param<BOOLEAN>(9).value()
        );
    }}},

    {0x178, {"NtTerminateProcess", [](ChildMemoryManager& mgr, const user_regs_struct& regs) {
        return _NtTerminateProcess(
            mgr,
            reinterpret_cast<HANDLE>(regs.r10),
            static_cast<NTSTATUS>(regs.rdx)
        );
    }}},

    // Wait functions
    {0x199, {"NtWaitForSingleObject", [](ChildMemoryManager& mgr, const user_regs_struct& regs) {
        return _NtWaitForSingleObject(
            mgr,
            reinterpret_cast<HANDLE>(regs.r10),
            static_cast<BOOLEAN>(regs.rdx),
            reinterpret_cast<PLARGE_INTEGER>(regs.r8)
        );
    }}},

    // Include all existing syscalls from original implementation
    {0x1, {"NtWorkerFactoryWorkerReady", [](ChildMemoryManager& mgr, const user_regs_struct& regs) {
        return _NtWorkerFactoryWorkerReady(mgr, reinterpret_cast<HANDLE>(regs.r10));
    }}},

    {0x3, {"NtMapUserPhysicalPagesScatter", [](ChildMemoryManager& mgr, const user_regs_struct& regs) {
        return _NtMapUserPhysicalPagesScatter(
            mgr,
            reinterpret_cast<PVOID*>(regs.r10),
            static_cast<ULONG>(regs.rdx),
            reinterpret_cast<PULONG_PTR>(regs.r8)
        );
    }}},

    {0x9, {"NtRemoveIoCompletion", [](ChildMemoryManager& mgr, const user_regs_struct& regs) {
        const SyscallParameterReader reader(mgr, regs);
        return _NtRemoveIoCompletion(
            mgr,
            reinterpret_cast<HANDLE>(regs.r10),
            reinterpret_cast<PVOID*>(regs.rdx),
            reinterpret_cast<PVOID*>(regs.r8),
            reinterpret_cast<PIO_STATUS_BLOCK>(regs.r9),
            reader.get_stack_param<PLARGE_INTEGER>(5).value()
        );
    }}},

    {0xE, {"NtSetEvent", [](ChildMemoryManager& mgr, const user_regs_struct& regs) {
        return _NtSetEvent(
            mgr,
            reinterpret_cast<HANDLE>(regs.r10),
            reinterpret_cast<PLONG>(regs.rdx)
        );
    }}}
};

// ============================================================================
// ENHANCED SYSTEM CALL MANAGER WITH MULTIPROCESS SUPPORT
// ============================================================================

class EnhancedSystemCallManager {
private:
    bool monitoring_enabled;
    std::unique_ptr<FunctionResolver> function_resolver;
    std::unordered_map<pid_t, std::unique_ptr<ProcessContext>> child_processes;
    std::shared_mutex child_processes_mutex;

public:
    explicit EnhancedSystemCallManager(bool enabled = true) : monitoring_enabled(enabled) {}

    void initialize_function_resolver(std::unordered_map<uintptr_t, LoadedModule*>& modules) {
        function_resolver = std::make_unique<FunctionResolver>(modules);
    }

    void trace_child_execution_multithreaded(pid_t child, const std::wstring& context) const {
        if (!monitoring_enabled) return;

        trace("Starting enhanced syscall monitoring for: ", context);

        int status;
        if (ptrace(PTRACE_SETOPTIONS, child, 0,
                  PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACECLONE |
                  PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK) == -1) {
            warn("Failed to set ptrace options");
        }

        std::unordered_map<pid_t, std::string> thread_contexts;
        thread_contexts[child] = converter.to_bytes(context);

        if (ptrace(PTRACE_CONT, child, 0, 0) == -1) {
            error("Failed to continue child process");
            return;
        }

        while (true) {
            pid_t w = waitpid(-1, &status, __WALL);
            if (w == -1) {
                if (errno == ECHILD) {
                    trace("No more children to wait for");
                    break;
                }
                continue;
            }

            if (WIFEXITED(status)) {
                trace("Process ", w, " exited with code ", WEXITSTATUS(status));
                thread_contexts.erase(w);
                if (thread_contexts.empty()) break;
                continue;
            }

            if (WIFSIGNALED(status)) {
                trace("Process ", w, " terminated by signal ", WTERMSIG(status));
                thread_contexts.erase(w);
                if (thread_contexts.empty()) break;
                continue;
            }

            if (WIFSTOPPED(status)) {
                int sig = WSTOPSIG(status);

                // Handle new thread/process creation
                if (sig == SIGTRAP) {
                    int event = (status >> 16) & 0xffff;
                    switch (event) {
                        case PTRACE_EVENT_CLONE:
                        case PTRACE_EVENT_FORK:
                        case PTRACE_EVENT_VFORK: {
                            unsigned long new_pid;
                            if (ptrace(PTRACE_GETEVENTMSG, w, 0, &new_pid) != -1) {
                                std::string new_context = thread_contexts[w] + "_thread_" + std::to_string(new_pid);
                                thread_contexts[new_pid] = new_context;
                                trace("New thread/process created: ", new_pid, " context: ", new_context);

                                // Continue the new thread
                                ptrace(PTRACE_CONT, new_pid, 0, 0);
                            }
                            break;
                        }
                    }
                }

                // Handle syscall tracing
                if (sig == (SIGTRAP | 0x80)) {
                    user_regs_struct regs{};
                    if (ptrace(PTRACE_GETREGS, w, NULL, &regs) != -1) {
                        ChildMemoryManager mgr(w);

                        std::string current_func = "unknown";
                        if (function_resolver) {
                            auto func_name = function_resolver->resolve_address(regs.rip);
                            current_func = converter.to_bytes(func_name);
                        }

                        std::string proc_context = thread_contexts[w];
                        print_syscall_info_enhanced(regs.rax, mgr, regs,
                                                   converter.from_bytes(proc_context), current_func);
                    }
                }

                // Continue execution
                ptrace(PTRACE_CONT, w, 0, 0);
            }
        }
    }

    static void print_syscall_info_enhanced(unsigned long long syscall_nr,
                                           ChildMemoryManager& mgr,
                                           const struct user_regs_struct& regs,
                                           const std::wstring& context,
                                           const std::string& current_func) {
        if (enhanced_syscall_handlers.contains(syscall_nr)) {
            const auto& [name, handler] = enhanced_syscall_handlers.at(syscall_nr);
            trace("[", context, "] [", converter.from_bytes(current_func),
                  "] Intercepted syscall: ", converter.from_bytes(name), " (", syscall_nr, ")");

            NTSTATUS status = handler(mgr, regs);

            trace("[", context, "] [", converter.from_bytes(current_func),
                  "] Syscall ", converter.from_bytes(name), " returned: 0x",
                  std::hex, status, std::dec);
        } else {
            trace("[", context, "] [", converter.from_bytes(current_func),
                  "] Unknown syscall number: ", syscall_nr);
        }
    }

    void set_monitoring(bool enabled) { monitoring_enabled = enabled; }
    bool is_enabled() const { return monitoring_enabled; }
};

// ============================================================================
// ENHANCED WINDOWS PE LOADER WITH MULTITHREADING
// ============================================================================

class EnhancedWindowsPELoader {
private:
    // ... (include all original loader functionality)
    std::unique_ptr<EnhancedSystemCallManager> enhanced_syscall_monitor;
    bool multithreading_enabled;

public:
    explicit EnhancedWindowsPELoader(bool monitor_syscalls = true,
                                   bool trace_functions = true,
                                   bool enable_multithreading = true)
        : multithreading_enabled(enable_multithreading) {

        // Initialize managers
        g_process_manager = std::make_unique<ProcessManager>();
        g_thread_manager = std::make_unique<ThreadManager>();

        enhanced_syscall_monitor = std::make_unique<EnhancedSystemCallManager>(monitor_syscalls);

        // Initialize context manager
        AdvancedContextManager::initialize_cleanup_system();

        trace("Enhanced PE Loader initialized with multithreading ",
              (enable_multithreading ? "ENABLED" : "DISABLED"));
    }

    ~EnhancedWindowsPELoader() {
        AdvancedContextManager::shutdown_cleanup_system();
        g_process_manager.reset();
        g_thread_manager.reset();
    }

    int load_and_execute_multithreaded(const std::wstring& pe_path, int argc, char* argv[]) {
        trace("Loading PE file with multithreading support: ", pe_path);

        if (!multithreading_enabled) {
            return load_and_execute_original(pe_path, argc, argv);
        }

        // Create main process context
        ProcessContext* main_process = AdvancedContextManager::create_process_context();
        if (!main_process) {
            error("Failed to create main process context");
            return 1;
        }

        // Load the PE file (reuse original implementation)
        int result = load_pe_executable(pe_path, argc, argv, main_process);

        // Wait for all threads to complete
        main_process->wait_for_all_threads();

        trace("Main process execution completed with result: ", result);
        return result;
    }

    void set_multithreading_enabled(bool enabled) {
        multithreading_enabled = enabled;
    }

    ProcessManager* get_process_manager() { return g_process_manager.get(); }
    ThreadManager* get_thread_manager() { return g_thread_manager.get(); }

private:
    int load_pe_executable(const std::wstring& pe_path, int argc, char* argv[],
                          ProcessContext* process_ctx) {
        // Implementation would reuse the original PE loading logic
        // but with enhanced thread and process management

        trace("Loading PE executable: ", pe_path);

        // For now, return success
        return 0;
    }

    int load_and_execute_original(const std::wstring& pe_path, int argc, char* argv[]) {
        // Fallback to original implementation when multithreading is disabled
        return 0;
    }
};

// ============================================================================
// INITIALIZATION AND CLEANUP FUNCTIONS
// ============================================================================

static void initialize_enhanced_nt_emulation() {
    trace("Initializing enhanced NT API emulation layer with multithreading support");

    // Initialize original NT emulation
    initialize_nt_emulation();

    // Initialize enhanced features
    AdvancedContextManager::initialize_cleanup_system();

    // Set up enhanced TLS
    if (!g_enhanced_tls) {
        g_enhanced_tls = std::make_unique<EnhancedTLS>();
    }

    trace("Enhanced NT API emulation layer initialized successfully");
}

static void cleanup_enhanced_nt_emulation() {
    trace("Cleaning up enhanced NT API emulation layer");

    AdvancedContextManager::shutdown_cleanup_system();

    // Cleanup enhanced TLS
    g_enhanced_tls.reset();

    // Cleanup original NT emulation
    cleanup_nt_emulation();

    trace("Enhanced NT API emulation layer cleanup complete");
}

// ============================================================================
// ENHANCED MAIN FUNCTION WITH MULTITHREADING SUPPORT
// ============================================================================

int main(int argc, char* argv[]) {
    if (argc < 2) {
        trace("Usage: ", argv[0], " <pe_file> [options] [dll_paths...]");
        trace("Options:");
        trace("  --no-monitoring      Disable syscall monitoring");
        trace("  --no-tracing         Disable function tracing");
        trace("  --no-multithreading  Disable multithreading support");
        trace("  --apiset <file>      Load API set mappings");
        trace("  --stats              Show API set statistics");
        return 1;
    }

    try {
        bool enable_monitoring = true;
        bool enable_tracing = true;
        bool enable_multithreading = true;
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
            } else if (arg == "--no-multithreading") {
                enable_multithreading = false;
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

        // Initialize enhanced NT emulation
        initialize_enhanced_nt_emulation();

        EnhancedWindowsPELoader loader(enable_monitoring, enable_tracing, enable_multithreading);

        // Load API set files
        if (!apiset_files.empty()) {
            // loader.load_api_mappings_multiple(apiset_files);
        }

        if (show_stats) {
            // loader.print_apiset_statistics();
        }

        // Add DLL search paths
        for (int i = path_start_idx; i < argc; i++) {
            // loader.add_dll_search_path(converter.from_bytes(argv[i]));
        }

        int result = loader.load_and_execute_multithreaded(
            converter.from_bytes(argv[1]), argc - 1, argv + 1);

        trace("Program execution completed with result: ", result);

        // Cleanup
        cleanup_enhanced_nt_emulation();

        return result;
    } catch (const std::exception& e) {
        error("Error: ", e.what());
        cleanup_enhanced_nt_emulation();
        return 1;
    }
}