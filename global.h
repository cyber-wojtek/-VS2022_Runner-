//
// Created by wojtek on 9/10/25.
//

#ifndef _VS2022_RUNNER__GLOBAL_H
#define _VS2022_RUNNER__GLOBAL_H

#include <mutex>
#include <condition_variable>
#include <chrono>
#include <cstring>
#include <pthread.h>
#include <deque>
#include <dirent.h>
#include <fcntl.h>
#include <functional>
#include <string>
#include <utility>
#include "win_types.h"
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <semaphore.h>


class DynamicTLSObject {
public:
    std::string name;
};

class FindState {
public:
    std::string directory_path;
    std::string search_pattern;
    DIR* dir_handle{};
    bool first_call{};

    // Add these new fields:
    bool case_sensitive{};
    FINDEX_SEARCH_OPS search_op;
    bool basic_info{};

    FindState() = default;

    FindState(std::string dir, std::string pattern)
        : directory_path(std::move(dir)), search_pattern(std::move(pattern)),
          dir_handle(nullptr), first_call(true), case_sensitive(false),
          search_op(FindExSearchNameMatch), basic_info(false) {}

    // copy constructor
    FindState(const FindState& other)
        : directory_path(other.directory_path),
          search_pattern(other.search_pattern),
          dir_handle(other.dir_handle ? opendir(other.directory_path.c_str()) : nullptr),
          first_call(other.first_call),
          case_sensitive(other.case_sensitive),
          search_op(other.search_op),
          basic_info(other.basic_info) {}

    // move constructor
    FindState(FindState&& other) noexcept
        : directory_path(std::move(other.directory_path)),
          search_pattern(std::move(other.search_pattern)),
          dir_handle(other.dir_handle),
          first_call(other.first_call),
          case_sensitive(other.case_sensitive),
          search_op(other.search_op),
          basic_info(other.basic_info) {
        other.dir_handle = nullptr;
    }

    ~FindState() {
        if (dir_handle) {
            closedir(dir_handle);
        }
    }

    // copy assign
    FindState& operator=(const FindState& other) {
        if (this != &other) {
            directory_path = other.directory_path;
            search_pattern = other.search_pattern;
            if (dir_handle) {
                closedir(dir_handle);
            }
            dir_handle = other.dir_handle ? opendir(other.directory_path.c_str()) : nullptr;
            first_call = other.first_call;
            case_sensitive = other.case_sensitive;
            search_op = other.search_op;
            basic_info = other.basic_info;
        }
        return *this;
    }

    // move assign
    FindState& operator=(FindState&& other) noexcept {
        if (this != &other) {
            directory_path = std::move(other.directory_path);
            search_pattern = std::move(other.search_pattern);
            if (dir_handle) {
                closedir(dir_handle);
            }
            dir_handle = other.dir_handle;
            first_call = other.first_call;
            case_sensitive = other.case_sensitive;
            search_op = other.search_op;
            basic_info = other.basic_info;
            other.dir_handle = nullptr;
        }
        return *this;
    }
};

struct TLS {
    uint32_t last_error;
    HANDLE thread;
    HANDLE process;
};

class ProcessMemoryInfo {
public:
    void *mem;
    size_t size;
    DWORD protect;
    DWORD state;
    DWORD type;
};

class ProcessModuleInfo {
public:
    std::unordered_map<std::string, HMODULE> exports; // function name -> address
    uintptr_t base_address;
    char path[260];
    char name[260];
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
            std::lock_guard lock(mtx_);
            flag_ = other.flag_;
            manual_reset_ = other.manual_reset_;
        }
        return *this;
    }

    Event& operator=(Event &&other) noexcept {
        if (this != &other) {
            std::lock_guard lock(mtx_);
            flag_ = other.flag_;
            manual_reset_ = other.manual_reset_;
        }
        return *this;
    }

    // Set the event (wake up all waiting threads)
    void set() {
        std::lock_guard<std::mutex> lock(mtx_);
        flag_ = true;
        cv_.notify_all();
    }

    // Clear the event (reset to unsignaled)
    void clear() {
        std::lock_guard<std::mutex> lock(mtx_);
        flag_ = false;
    }

    // Wait until the event is set
    void wait() {
        std::unique_lock<std::mutex> lock(mtx_);
        cv_.wait(lock, [this] { return flag_; });
    }

    // Wait with timeout, returns true if the event was set
    bool is_set() {
        std::unique_lock<std::mutex> lock(mtx_);
        return flag_;
    }
};

class CRITICAL_SECTION {
public:
    std::mutex mtx_;
    std::condition_variable cv_;
    bool in_session_ = false;
    bool is_removed_ = false;

    void enter() {
        std::unique_lock lock(mtx_);
        if (is_removed_) {
            return; // If removed, do not enter
        }
        cv_.wait(lock, [this] { return !in_session_; });
        in_session_ = true;
    }

    void leave() {
        std::lock_guard lock(mtx_);
        if (is_removed_) {
            return; // If removed, do nothing
        }
        in_session_ = false;
        cv_.notify_all();
    }

    void remove() {
        std::lock_guard lock(mtx_);
        if (is_removed_) {
            return; // Already removed
        }
        is_removed_ = true;
        cv_.notify_all();
    }

    bool try_enter() {
        std::lock_guard lock(mtx_);
        if (is_removed_ || in_session_) {
            return false;
        }
        in_session_ = true;
        return true;
    }

    bool is_removed() const {
        return is_removed_;
    }
};

using LPCRITICAL_SECTION = CRITICAL_SECTION*;

inline thread_local TLS tls;

class HeapAllocInfo {
public:
    void* ptr;
    size_t size;
    DWORD flags;
};

class HeapInfo {
public:
    std::unordered_map<void*, HeapAllocInfo> alloc_info; // pointer -> allocation info
    DWORD flags;
};

class ProcessInfo {
public:
    std::unordered_map<HANDLE, ProcessMemoryInfo> memory_map; // the key is the base address
    std::unordered_map<HANDLE, ProcessModuleInfo> modules; // handle -> module info
    std::unordered_map<HANDLE, pthread_t> threads; // handle -> pthread
    std::unordered_map<HANDLE, Event> events;
    std::unordered_map<HANDLE, std::mutex> mutexes;
    std::unordered_map<HANDLE, int32_t> files; // handle -> file descriptor (i.e. the thing returned by open())
    std::unordered_map<HANDLE, std::string> registry_key_handles = {
        {reinterpret_cast<HANDLE>(0x80000001), "HKEY_CLASSES_ROOT"},
        {reinterpret_cast<HANDLE>(0x80000002), "HKEY_CURRENT_USER"},
        {reinterpret_cast<HANDLE>(0x80000003), "HKEY_LOCAL_MACHINE"},
        {reinterpret_cast<HANDLE>(0x80000004), "HKEY_USERS"},
        {reinterpret_cast<HANDLE>(0x80000005), "HKEY_PERFORMANCE_DATA"},
        {reinterpret_cast<HANDLE>(0x80000006), "HKEY_CURRENT_CONFIG"},
        {reinterpret_cast<HANDLE>(0x80000007), "HKEY_DYN_DATA"},
        // example: {0x2137, "HKEY_CURRENT_USER/somekey123"}
    };
    // later add registry handles
    std::unordered_map<HANDLE, std::deque<std::function<void()>>> apc_queues; // one queue per thread
    std::unordered_map<HANDLE, FindState> finds;
    // semaphore objects
    std::unordered_map<HANDLE, sem_t> semaphores;
    std::unordered_map<HANDLE, HeapInfo> heaps;
    std::wstring command_line;
    std::string current_directory;
    HMODULE process_hmodule = nullptr; // handle to the main module (base address)
    pthread_t process_thread = 0; // thread of the main process
    // console control handlers (CTRL+C, etc.)
    std::unordered_set<PHANDLER_ROUTINE> console_control_handlers;
    std::array<HANDLE, 3> std_handles = {reinterpret_cast<HANDLE>(-10), reinterpret_cast<HANDLE>(-11), reinterpret_cast<HANDLE>(-12)}; // stdin, stdout, stderr
};


inline auto next_handle = reinterpret_cast<HANDLE>(1); // next handle for all the objects
inline std::unordered_map<HANDLE, ProcessInfo> process_info;
inline std::unordered_map<std::string, std::string> environment;

#endif //_VS2022_RUNNER__GLOBAL_H