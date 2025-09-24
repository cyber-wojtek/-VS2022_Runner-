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
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <array>
#include <algorithm>
#include <string_view>
#include <ranges>

#include "win_types.h"
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <semaphore.h>
#include <LIEF/PE/OptionalHeader.hpp>

#define _UPPER        0x0001  /* C1_UPPER */
#define _LOWER        0x0002  /* C1_LOWER */
#define _DIGIT        0x0004  /* C1_DIGIT */
#define _SPACE        0x0008  /* C1_SPACE */
#define _PUNCT        0x0010  /* C1_PUNCT */
#define _CONTROL      0x0020  /* C1_CNTRL */
#define _BLANK        0x0040  /* C1_BLANK */
#define _HEX          0x0080  /* C1_XDIGIT */
#define _LEADBYTE     0x8000
#define _ALPHA       (0x0100|_UPPER|_LOWER)  /* (C1_ALPHA|_UPPER|_LOWER) */


constexpr WORD _C_      = _CONTROL;
constexpr WORD _S_      = _SPACE;    /* space, tab, carriage return, newline, */
                                    /* vertical tab, form feed */
constexpr WORD _P_      = _PUNCT;
constexpr WORD _D_      = _DIGIT;    /* 0-9 */
constexpr WORD _B_      = _BLANK;    /* space and tab */
constexpr WORD _U_      = _UPPER;    /* A-Z */
constexpr WORD _L_      = _LOWER;    /* a-z */
constexpr WORD _H_      = _HEX;      /* A-F, a-f, 0-9 */

constexpr WORD B110 = 0;
constexpr WORD D120 = 4;
constexpr WORD S140 = _SPACE;
constexpr WORD L140 = _LOWER | 0x100;
constexpr WORD C140 = _CONTROL;

// Forward declaration
class ExceptionHandlingRegistry {
public:
    void register_module_exception_table(uintptr_t base_address,
                                                const std::vector<RUNTIME_FUNCTION>& exception_table);
    PRUNTIME_FUNCTION find_function_entry(uintptr_t base_address, uint32_t rva);

    PRUNTIME_FUNCTION lookup_function_entry(uintptr_t address, uintptr_t* image_base);

    std::mutex registry_mutex;
    std::unordered_map<uintptr_t, std::vector<RUNTIME_FUNCTION>> exception_tables;
    std::unordered_map<uintptr_t, UNWIND_HISTORY_TABLE> unwind_history;
    PRUNTIME_FUNCTION find_in_table(uintptr_t base_address, uint32_t rva);
};

class FindState {
public:
    std::string directory_path;
    std::string search_pattern;
    DIR* dir_handle{};
    bool first_call{};
    bool case_sensitive{};
    FINDEX_SEARCH_OPS search_op{};
    bool basic_info{};

    FindState() = default;

    FindState(std::string dir, std::string pattern)
        : directory_path(std::move(dir)), search_pattern(std::move(pattern)),
          dir_handle(nullptr), first_call(true), case_sensitive(false),
          search_op(FindExSearchNameMatch), basic_info(false) {}

    FindState(const FindState& other)
        : directory_path(other.directory_path),
          search_pattern(other.search_pattern),
          dir_handle(other.dir_handle ? opendir(other.directory_path.c_str()) : nullptr),
          first_call(other.first_call),
          case_sensitive(other.case_sensitive),
          search_op(other.search_op),
          basic_info(other.basic_info) {}

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

    FindState& operator=(const FindState& other) {
        if (this != &other) {
            directory_path = other.directory_path;
            search_pattern = other.search_pattern;
            if (dir_handle) closedir(dir_handle);
            dir_handle = other.dir_handle ? opendir(other.directory_path.c_str()) : nullptr;
            first_call = other.first_call;
            case_sensitive = other.case_sensitive;
            search_op = other.search_op;
            basic_info = other.basic_info;
        }
        return *this;
    }

    FindState& operator=(FindState&& other) noexcept {
        if (this != &other) {
            directory_path = std::move(other.directory_path);
            search_pattern = std::move(other.search_pattern);
            if (dir_handle) closedir(dir_handle);
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
    uint32_t last_error{};
    HANDLE thread{};
    HANDLE process{};
    std::vector<LPVOID> tls_data;
    EXCEPTION_POINTERS xcptinfoptrs{};
    _invalid_parameter_handler invalid_parameter_handler = nullptr;
    _tls_callback_type tls_atexit_callback = nullptr;
    UINT commode;
    INT fmode;
    _wchar_t* locale_name;

    TLS() : commode(0), fmode(0), locale_name(new _wchar_t[20]) {
        std::memcpy(locale_name, L"C", 2 * sizeof(_wchar_t));
    }

    ~TLS() {
        delete[] locale_name;
    }

    lconv locale_info{};
};

class ProcessMemoryInfo {
public:
    void* mem;
    size_t size;
    DWORD protect;
    DWORD state;
    DWORD type;
};

class ProcessModuleInfo {
public:
    std::unordered_map<std::string, HMODULE> exports;
    uintptr_t base_address;
    size_t size;
    char path[260]{};
    char name[260]{};
    std::vector<RUNTIME_FUNCTION> exception_table;
    bool has_exception_table = false;

    PRUNTIME_FUNCTION find_function_entry(uint32_t rva) {
        if (!has_exception_table || exception_table.empty()) return nullptr;

        const auto it = std::lower_bound(exception_table.begin(), exception_table.end(), rva,
            [](const RUNTIME_FUNCTION& func, uint32_t target_rva) {
                return func.EndAddress <= target_rva;
            });

        if (it != exception_table.end() && rva >= it->BeginAddress && rva < it->EndAddress) {
            return &(*it);
        }
        return nullptr;
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

class CRITICAL_SECTION {
public:
    std::mutex mtx_;
    std::condition_variable cv_;
    bool in_session_ = false;
    bool is_removed_ = false;

    void enter() {
        std::unique_lock lock(mtx_);
        if (is_removed_) return;
        cv_.wait(lock, [this] { return !in_session_; });
        in_session_ = true;
    }

    void leave() {
        std::lock_guard lock(mtx_);
        if (is_removed_) return;
        in_session_ = false;
        cv_.notify_all();
    }

    void remove() {
        std::lock_guard lock(mtx_);
        if (!is_removed_) {
            is_removed_ = true;
            cv_.notify_all();
        }
    }

    bool try_enter() {
        std::lock_guard lock(mtx_);
        if (is_removed_ || in_session_) return false;
        in_session_ = true;
        return true;
    }

    bool removed() const {
        return is_removed_;
    }
};

using LPCRITICAL_SECTION = CRITICAL_SECTION*;

extern thread_local TLS tls;

class HeapAllocInfo {
public:
    void* ptr;
    size_t size;
    DWORD flags;
};

class HeapInfo {
public:
    std::unordered_map<void*, HeapAllocInfo> alloc_info;
    DWORD flags;
};

class ProcessThreadInfo {
public:
    bool is_suspended;
    pthread_t thread;
    pthread_attr_t attr;
    void* arg;
    void*(*start_routine)(void*);
};

struct ProcessAlignedMemInfo {
    size_t size = 0;
    size_t alignment = 0;
};

struct ProcessCMemInfo {
    size_t size = 0;
};

class ProcessInfo {
public:
    std::unordered_map<HANDLE, ProcessMemoryInfo> memory_map;
    std::unordered_map<HMODULE, ProcessModuleInfo> modules;
    std::unordered_map<HANDLE, ProcessThreadInfo> threads;
    std::unordered_map<HANDLE, Event> events;
    std::unordered_map<HANDLE, std::mutex> mutexes;
    std::unordered_map<HANDLE, int32_t> files {
        // default console devices (nul, conin$, conout$, conerr$)
        {reinterpret_cast<HANDLE>(0x80000000), open("/dev/null", O_RDWR)}, // NUL
        {reinterpret_cast<HANDLE>(0x80000001), 0}, // CONIN$
        {reinterpret_cast<HANDLE>(0x80000002), 0}, // CONOUT$
        {reinterpret_cast<HANDLE>(0x80000003), 0}  // CONERR$
    };
    std::unordered_map<HANDLE, std::string> registry_key_handles = {
        {reinterpret_cast<HANDLE>(0x80000001), "HKEY_CLASSES_ROOT"},
        {reinterpret_cast<HANDLE>(0x80000002), "HKEY_CURRENT_USER"},
        {reinterpret_cast<HANDLE>(0x80000003), "HKEY_LOCAL_MACHINE"},
        {reinterpret_cast<HANDLE>(0x80000004), "HKEY_USERS"},
        {reinterpret_cast<HANDLE>(0x80000005), "HKEY_PERFORMANCE_DATA"},
        {reinterpret_cast<HANDLE>(0x80000006), "HKEY_CURRENT_CONFIG"},
        {reinterpret_cast<HANDLE>(0x80000007), "HKEY_DYN_DATA"},
    };
    std::unordered_map<HANDLE, std::deque<std::function<void()>>> apc_queues;
    std::unordered_map<HANDLE, FindState> finds;
    std::unordered_map<HANDLE, sem_t> semaphores;
    std::unordered_map<HANDLE, HeapInfo> heaps;
    HANDLE default_heap = reinterpret_cast<HANDLE>(1);
    std::unordered_map<void*, ProcessAlignedMemInfo> aligned_mem;
    std::unordered_map<void*, ProcessCMemInfo> c_mem; // malloc/free mem kind for msize implementation (ye this wasteful ik)
    std::wstring command_line; // no "w" here
    std::string command_line_a; // see "a" here
    _wchar_t *cmdline_w = nullptr; // see "w" here
    char *cmdline = nullptr; // see no "a" here ?
    // :)
    std::string current_directory;
    HMODULE process_hmodule = nullptr;
    size_t image_size = 0;
    pthread_t process_thread = 0;
    std::unordered_set<PHANDLER_ROUTINE> console_control_handlers;
    std::unordered_map<DWORD, HANDLE> std_handles = {
        { STD_INPUT_HANDLE, reinterpret_cast<HANDLE>(-10) },
        { STD_OUTPUT_HANDLE, reinterpret_cast<HANDLE>(-11) },
        { STD_ERROR_HANDLE, reinterpret_cast<HANDLE>(-12) }
    };
    ExceptionHandlingRegistry exception_registry;
    int argc;
    char** argv;
    _wchar_t **wargv;
    std::wstring wpgmptr_s;
    _wchar_t* wpgmptr = nullptr;
    std::string pgmptr_s;
    char* pgmptr = nullptr;
    std::vector<void(*)()> atexit_functions;
    _onexit_table_t onexit_functions;
    std::vector<void(*)()> at_quick_exit_functions;
    terminate_function terminate_handler = nullptr;
    unexpected_function unexpected_handler = nullptr;
    _invalid_parameter_handler invalid_parameter_handler = nullptr;
    LIEF::PE::OptionalHeader::SUBSYSTEM subsystem;
    ucrt_matherr_func ucrt_matherr_handler = nullptr;
    int error_mode;
    _PNH new_handler = nullptr;
    bool is_locale_per_thread = true;
    int new_mode = 0;

    ~ProcessInfo() {
        free(cmdline_w);
        free(wpgmptr);
    }
};

extern HANDLE next_handle;
extern std::unordered_map<HANDLE, ProcessInfo> process_info;
//std::unordered_map<std::string, std::string> environment;
extern std::vector<std::string> environment_vector;
extern std::vector<std::wstring> environment_vector_w;
extern char** environment_narrow;
extern _wchar_t** environment_wide;
extern unsigned short _ctype[257];

extern unsigned short _wctype[257];

struct EmulatedExport {
    std::wstring name;
    uintptr_t address;
    bool is_function;  // true for functions, false for variables/data
    size_t size; // for data exports

    EmulatedExport() = default;

    EmulatedExport(const std::wstring& name, uintptr_t address, bool is_function, size_t size)
        : name(name), address(address), is_function(is_function), size(size) {}
};

#endif //_VS2022_RUNNER__GLOBAL_H
