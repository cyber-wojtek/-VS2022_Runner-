//
// Created by wojtek on 9/10/25.
//

#ifndef _VS2022_RUNNER__GLOBAL_CPP
#define _VS2022_RUNNER__GLOBAL_CPP

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
#include "global.h"


inline void ExceptionHandlingRegistry::register_module_exception_table(uintptr_t base_address, const std::vector<RUNTIME_FUNCTION> &exception_table) {
    std::lock_guard lock(registry_mutex);
    exception_tables[base_address] = exception_table;
}

PRUNTIME_FUNCTION ExceptionHandlingRegistry::find_function_entry(uintptr_t base_address, uint32_t rva) {
    std::lock_guard lock(registry_mutex);
    return find_in_table(base_address, rva);
}


inline PRUNTIME_FUNCTION ExceptionHandlingRegistry::lookup_function_entry(uintptr_t address, uintptr_t *image_base) {
    std::lock_guard lock(registry_mutex);

    for (auto& proc_info : process_info | std::views::values) {
        if (proc_info.process_hmodule) {
            const auto base = reinterpret_cast<uintptr_t>(proc_info.process_hmodule);
            if (const uintptr_t end = base + proc_info.image_size; address >= base && address < end) {
                if (image_base) *image_base = base;
                return find_in_table(base, address - base);
            }
        }

        for (auto &module_info: proc_info.modules | std::views::values) {
            const uintptr_t base = module_info.base_address;
            if (const uintptr_t end = base + module_info.size; address >= base && address < end) {
                if (image_base) *image_base = base;
                if (module_info.has_exception_table) {
                    return module_info.find_function_entry(static_cast<uint32_t>(address - base));
                }
                return find_in_table(base, address - base);
            }
        }
    }

    return nullptr;
}

inline PRUNTIME_FUNCTION ExceptionHandlingRegistry::find_in_table(uintptr_t base_address, uint32_t rva) {
    const auto it = exception_tables.find(base_address);
    if (it == exception_tables.end()) return nullptr;

    const auto& functions = it->second;
    const auto func_it = std::lower_bound(functions.begin(), functions.end(), rva,
        [](const RUNTIME_FUNCTION& func, const uint32_t target_rva) {
            return func.EndAddress <= target_rva;
        });

    if (func_it != functions.end() &&
        rva >= func_it->BeginAddress &&
        rva < func_it->EndAddress) {
        return const_cast<PRUNTIME_FUNCTION>(&(*func_it));
    }

    return nullptr;
}

thread_local TLS tls;
HANDLE next_handle = reinterpret_cast<HANDLE>(2);
std::unordered_map<HANDLE, ProcessInfo> process_info;
//std::unordered_map<std::string, std::string> environment;
std::vector<std::string> environment_vector;
std::vector<std::wstring> environment_vector_w;
char** environment_narrow;
_wchar_t** environment_wide;
unsigned short _ctype[257] = {
    0, _C_, _C_, _C_, _C_, _C_, _C_, _C_, _C_, _C_, _S_|_C_, _S_|_C_,
    _S_|_C_, _S_|_C_, _S_|_C_, _C_, _C_, _C_, _C_, _C_, _C_, _C_, _C_,
    _C_, _C_, _C_, _C_, _C_, _C_, _C_, _C_, _C_, _C_, _S_|_BLANK,
    _P_, _P_, _P_, _P_, _P_, _P_, _P_, _P_, _P_, _P_, _P_, _P_, _P_, _P_,
    _P_, _D_|_H_, _D_|_H_, _D_|_H_, _D_|_H_, _D_|_H_, _D_|_H_, _D_|_H_,
    _D_|_H_, _D_|_H_, _D_|_H_, _P_, _P_, _P_, _P_, _P_, _P_, _P_, _U_|_H_,
    _U_|_H_, _U_|_H_, _U_|_H_, _U_|_H_, _U_|_H_, _U_, _U_, _U_, _U_, _U_,
    _U_, _U_, _U_, _U_, _U_, _U_, _U_, _U_, _U_, _U_, _U_, _U_, _U_, _U_,
    _U_, _P_, _P_, _P_, _P_, _P_, _P_, _L_|_H_, _L_|_H_, _L_|_H_, _L_|_H_,
    _L_|_H_, _L_|_H_, _L_, _L_, _L_, _L_, _L_, _L_, _L_, _L_, _L_, _L_,
    _L_, _L_, _L_, _L_, _L_, _L_, _L_, _L_, _L_, _L_, _P_, _P_, _P_, _P_,
    _C_, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

unsigned short _wctype[257] =
{
    0,
    /* 00 */
    0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0020,
    0x0020, 0x0028 | B110, 0x0028, 0x0028, 0x0028, 0x0028, 0x0020, 0x0020,
    /* 10 */
    0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0020,
    0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0020,
    /* 20 */
    0x0048, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010,
    0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010,
    /* 30 */
    0x0084, 0x0084, 0x0084, 0x0084, 0x0084, 0x0084, 0x0084, 0x0084,
    0x0084, 0x0084, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010,
    /* 40 */
    0x0010, 0x0181, 0x0181, 0x0181, 0x0181, 0x0181, 0x0181, 0x0101,
    0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101,
    /* 50 */
    0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101,
    0x0101, 0x0101, 0x0101, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010,
    /* 60 */
    0x0010, 0x0182, 0x0182, 0x0182, 0x0182, 0x0182, 0x0182, 0x0102,
    0x0102, 0x0102, 0x0102, 0x0102, 0x0102, 0x0102, 0x0102, 0x0102,
    /* 70 */
    0x0102, 0x0102, 0x0102, 0x0102, 0x0102, 0x0102, 0x0102, 0x0102,
    0x0102, 0x0102, 0x0102, 0x0010, 0x0010, 0x0010, 0x0010, 0x0020,
    /* 80 */
    0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0020 | S140, 0x0020, 0x0020,
    0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0020,
    /* 90 */
    0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0020,
    0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0020,
    /* a0 */
    0x0008 | B110, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010,
    0x0010, 0x0010, 0x0010 | L140, 0x0010, 0x0010, 0x0010 | C140, 0x0010, 0x0010,
    /* b0 */
    0x0010, 0x0010, 0x0010 | D120, 0x0010 | D120, 0x0010, 0x0010 | L140, 0x0010, 0x0010,
    0x0010, 0x0010 | D120, 0x0010 | L140, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010,
    /* c0 */
    0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101,
    0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101,
    /* d0 */
    0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0010,
    0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0101, 0x0102,
    /* e0 */
    0x0102, 0x0102, 0x0102, 0x0102, 0x0102, 0x0102, 0x0102, 0x0102,
    0x0102, 0x0102, 0x0102, 0x0102, 0x0102, 0x0102, 0x0102, 0x0102,
    /* f0 */
    0x0102, 0x0102, 0x0102, 0x0102, 0x0102, 0x0102, 0x0102, 0x0010,
    0x0102, 0x0102, 0x0102, 0x0102, 0x0102, 0x0102, 0x0102, 0x0102
};

#endif //_VS2022_RUNNER__GLOBAL_CPP