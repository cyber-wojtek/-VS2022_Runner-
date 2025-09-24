#include <cstdint>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <string>
#include <deque>
#include <fstream>
#include <filesystem>
#include <functional>
#include <thread>
#include <mutex>
#include <algorithm>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <ranges>
#include <sys/mman.h>
#include <csignal>
#include <list>
#include <openssl/sha.h>
#include <LIEF/PE.hpp>
#include <nlohmann/json.hpp>
// backtrace()
#include <execinfo.h>

#include "global.h"
#include "win_types.h"
#include "log.h"
#include "kernel32.hpp"
#include "ucrtbase.hpp"
#include "vcruntime140.hpp"

// DL*
#include <dlfcn.h>

// unwind
#include <cxxabi.h>
#include <unwind.h>
#define UNW_LOCAL_ONLY
#include <libunwind.h>

std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;

// Forward declarations for your existing classes
class WineLikeLoader;
// Enhanced export information structure (keep for compatibility)
struct ExportInfo {
    std::wstring name;
    uintptr_t address{};
    uint16_t ordinal{};
    bool is_function{};        // true for functions, false for variables/data
    bool is_forwarded{};
    std::wstring forward_dll;
    std::wstring forward_function;
    uint32_t rva{};
    std::wstring section_name;
};
struct DllInfo {
    std::wstring name;
    std::wstring path;
    uintptr_t base_address = 0;
    size_t size = 0;

    // NEW: Enhanced export table with function/data distinction
    std::unordered_map<std::wstring, ExportInfo> enhanced_exports;  // name -> export info

    // Enhanced export information (keep for compatibility)
    std::vector<ExportInfo> exports_detailed;
    std::unordered_map<std::wstring, ExportInfo> export_map;

    std::unordered_map<std::wstring, std::vector<std::wstring>> imports;
    std::unordered_set<std::wstring> dependencies;
    std::unordered_map<std::wstring, std::wstring> version_info;
    std::unordered_map<std::wstring, bool> security_flags;
    uint16_t pe_characteristics = 0;
    uint32_t timestamp = 0;
    uint32_t checksum = 0;
    std::wstring file_hash;
    bool is_native = true;
    std::unordered_map<std::wstring, uint32_t> export_table; // Keep for backward compatibility
    std::vector<uint8_t> memory_mapped;

    // NEW: Enhanced export access methods
    std::unordered_map<std::wstring, std::pair<bool, uintptr_t>> get_exports() const {
        std::unordered_map<std::wstring, std::pair<bool, uintptr_t>> result;
        for (const auto& [name, entry] : enhanced_exports) {
            if (!entry.is_forwarded) {  // Only include non-forwarded exports
                result[name] = std::make_pair(entry.is_function, entry.address);
            }
        }
        return result;
    }

    // Get only function exports
    std::unordered_map<std::wstring, uintptr_t> get_function_exports_map() const {
        std::unordered_map<std::wstring, uintptr_t> functions;
        for (const auto& [name, entry] : enhanced_exports) {
            if (entry.is_function && !entry.is_forwarded) {
                functions[name] = entry.address;
            }
        }
        return functions;
    }

    // Get only data exports
    std::unordered_map<std::wstring, uintptr_t> get_data_exports_map() const {
        std::unordered_map<std::wstring, uintptr_t> data;
        for (const auto& [name, entry] : enhanced_exports) {
            if (!entry.is_function && !entry.is_forwarded) {
                data[name] = entry.address;
            }
        }
        return data;
    }

    // Check if an export exists and get its info
    bool has_export(const std::wstring& name) const {
        return enhanced_exports.contains(name);
    }

    // Helper methods for export filtering (keep for compatibility)
    std::vector<ExportInfo> get_function_exports() const {
        std::vector<ExportInfo> functions;
        for (const auto& exp : exports_detailed) {
            if (exp.is_function && !exp.is_forwarded) {
                functions.push_back(exp);
            }
        }
        return functions;
    }

    std::vector<ExportInfo> get_variable_exports() const {
        std::vector<ExportInfo> variables;
        for (const auto& exp : exports_detailed) {
            if (!exp.is_function && !exp.is_forwarded) {
                variables.push_back(exp);
            }
        }
        return variables;
    }

    std::vector<ExportInfo> get_forwarded_exports() const {
        std::vector<ExportInfo> forwarded;
        for (const auto& exp : exports_detailed) {
            if (exp.is_forwarded) {
                forwarded.push_back(exp);
            }
        }
        return forwarded;
    }
};
struct LoadedDLL {
    DllInfo dll_info;
    uintptr_t base_address{};
    void* memory_map; // Raw pointer
    size_t allocated_size{}; // Track allocation size for cleanup
    LIEF::PE::Binary* pe_binary; // Raw pointer

    // NEW: Enhanced export addresses with function/data distinction
    std::unordered_map<std::wstring, std::pair<bool, uintptr_t>> enhanced_export_addresses;

    // Keep old export_addresses for compatibility
    std::unordered_map<std::wstring, uintptr_t> export_addresses;

    // Constructor
    LoadedDLL() : memory_map(nullptr), pe_binary(nullptr) {}

    // Destructor handles cleanup
    ~LoadedDLL() {
        cleanup();
    }

    // Move constructor
    LoadedDLL(LoadedDLL&& other) noexcept
        : dll_info(std::move(other.dll_info))
        , base_address(other.base_address)
        , memory_map(other.memory_map)
        , allocated_size(other.allocated_size)
        , pe_binary(other.pe_binary)
        , enhanced_export_addresses(std::move(other.enhanced_export_addresses))
        , export_addresses(std::move(other.export_addresses))
    {
        // Take ownership
        other.memory_map = nullptr;
        other.pe_binary = nullptr;
        other.allocated_size = 0;
    }

    // Move assignment
    LoadedDLL& operator=(LoadedDLL&& other) noexcept {
        if (this != &other) {
            cleanup(); // Clean up current resources

            dll_info = std::move(other.dll_info);
            base_address = other.base_address;
            memory_map = other.memory_map;
            allocated_size = other.allocated_size;
            pe_binary = other.pe_binary;
            enhanced_export_addresses = std::move(other.enhanced_export_addresses);
            export_addresses = std::move(other.export_addresses);

            // Take ownership
            other.memory_map = nullptr;
            other.pe_binary = nullptr;
            other.allocated_size = 0;
        }
        return *this;
    }

    // Delete copy operations to avoid double-free
    LoadedDLL(const LoadedDLL&) = delete;
    LoadedDLL& operator=(const LoadedDLL&) = delete;

    // NEW: Enhanced export lookup methods
    std::pair<bool, uintptr_t> get_export(const std::wstring& name) const {
        if (auto it = enhanced_export_addresses.find(name); it != enhanced_export_addresses.end()) {
            return it->second;
        }
        return std::make_pair(false, 0);  // Not found
    }

    bool has_export(const std::wstring& name) const {
        return enhanced_export_addresses.contains(name);
    }

    bool is_function_export(const std::wstring& name) const {
        if (auto it = enhanced_export_addresses.find(name); it != enhanced_export_addresses.end()) {
            return it->second.first;  // first = is_function
        }
        return false;
    }

    uintptr_t get_export_address(const std::wstring& name) const {
        if (auto it = enhanced_export_addresses.find(name); it != enhanced_export_addresses.end()) {
            return it->second.second;  // second = address
        }
        return 0;
    }

private:
    void cleanup() {
        if (memory_map && memory_map != MAP_FAILED && allocated_size > 0) {
            munmap(memory_map, allocated_size);
            memory_map = nullptr;
            allocated_size = 0;
        }
        if (pe_binary) {
            delete pe_binary;
            pe_binary = nullptr;
        }
    }
};

struct EmulatedModule {
    std::wstring name;
    uintptr_t base_address{};
    size_t size{};
    std::unordered_map<std::wstring, uintptr_t> function_exports;
    std::unordered_map<std::wstring, uintptr_t> data_exports;
    std::unordered_map<uintptr_t, std::wstring> address_to_name;
    bool is_emulated{};
};

struct PEModule {
    std::wstring name;
    uintptr_t base_address{};
    size_t size{};
    std::unordered_map<uintptr_t, std::wstring> rva_to_export;
    std::unordered_map<std::wstring, uintptr_t> export_to_address;
    std::vector<std::pair<std::wstring, std::pair<uintptr_t, uintptr_t>>> sections; // name, start, end
};

struct SymbolInfo {
    std::wstring function_name;
    std::wstring module_name;
    uintptr_t offset;
    uintptr_t base_address;
    std::wstring symbol_type; // "EMULATED_FUNC", "EMULATED_DATA", "PE_EXPORT", "PE_SECTION", "NATIVE"
    std::wstring section_name;
    bool is_emulated;
    bool is_pe_module;
};

static std::unordered_map<std::wstring, EmulatedModule> emulated_modules;
static std::unordered_map<std::wstring, PEModule> pe_modules;
static std::unordered_map<uintptr_t, std::wstring> address_to_module; // Quick lookup
// Add internal PE function tracking
static std::unordered_map<uintptr_t, std::wstring> internal_pe_functions;
static std::unordered_map<uintptr_t, std::pair<std::wstring, std::wstring>> address_to_internal_symbol; // addr -> {module, symbol}

// Add dynamic function tracking for runtime-generated code
static std::unordered_map<uintptr_t, std::wstring> dynamic_functions;

// Add memory region tracking
struct MemoryRegion {
    uintptr_t start;
    uintptr_t end;
    std::wstring type;  // "HEAP", "STACK", "MAPPED", "GUARD", etc.
    std::wstring description;
};
static std::vector<MemoryRegion> memory_regions;



// Enhanced backtrace system that understands PE modules and emulated functions
class EnhancedBacktrace {
private:
public:
    // Register emulated modules (Kernel32, UCRTBase, etc.)
    static void register_emulated_module(const std::wstring& name,
                                       const std::unordered_map<std::wstring, EmulatedExport>& exports) {
        EmulatedModule module;
        module.name = name;
        module.is_emulated = true;
        module.base_address = 0; // Emulated modules don't have a base
        module.size = 0;

        for (const auto& [export_name, info] : exports) {
            bool is_function = info.is_function;
            uintptr_t address = info.address;

            if (is_function) {
                module.function_exports[export_name] = address;
            } else {
                module.data_exports[export_name] = address;
            }
            module.address_to_name[address] = export_name;
            address_to_module[address] = name;
        }

        emulated_modules[name] = std::move(module);
        trace("Registered emulated module ", name.c_str(), " with ",
              std::to_wstring(exports.size()), " exports");
    }

    // Register PE modules with their export tables and sections
    static void register_pe_module(const std::wstring& name, uintptr_t base_address, size_t size,
                                 const LoadedDLL* loaded_dll = nullptr) {
        PEModule module;
        module.name = name;
        module.base_address = base_address;
        module.size = size;

        // Map all addresses in this module's range
        for (uintptr_t addr = base_address; addr < base_address + size; addr += 4096) {
            address_to_module[addr & ~0xFFF] = name;
        }

        // If we have the LoadedDLL, extract export information
        if (loaded_dll) {
            // Get enhanced exports
            for (const auto& [export_name, info] : loaded_dll->enhanced_export_addresses) {
                bool is_function = info.first;
                uintptr_t address = info.second;
                uint32_t rva = static_cast<uint32_t>(address - base_address);

                module.rva_to_export[rva] = export_name + (is_function ? L"()" : L"[data]");
                module.export_to_address[export_name] = address;
            }

            // Extract section information from PE binary if available
            if (loaded_dll->pe_binary) {
                for (const auto& section : loaded_dll->pe_binary->sections()) {
                    uintptr_t sect_start = base_address + section.virtual_address();
                    uintptr_t sect_end = sect_start + section.virtual_size();
                    module.sections.emplace_back(converter.from_bytes(section.name()),
                                                 std::make_pair(sect_start, sect_end));
                }
            }
        }

        pe_modules[name] = std::move(module);
        trace("Registered PE module ", name.c_str(), " at base 0x",
              std::to_wstring(base_address), " with ",
              std::to_wstring(module.rva_to_export.size()), " exports");
    }

    static void print_libunwind_backtrace() {
        unw_cursor_t cursor;
        unw_context_t context;

        unw_getcontext(&context);
        unw_init_local(&cursor, &context);

        int frame = 0;
        while (unw_step(&cursor) > 0 && frame < 32) {
            unw_word_t pc, offset;
            char symbol[256];

            unw_get_reg(&cursor, UNW_REG_IP, &pc);

            // Your existing symbol resolution
            SymbolInfo info = resolve_symbol(pc);

            // Enhanced with libunwind's symbol resolution
            if (unw_get_proc_name(&cursor, symbol, sizeof(symbol), &offset) == 0) {
                std::wcout << frame << ": 0x" << std::hex << pc
                          << " " << symbol << "+0x" << offset;

                // Combine with your PE-aware resolution
                if (!info.function_name.empty()) {
                    std::wcout << " [PE: " << info.module_name
                              << "!" << info.function_name << "]";
                }
                std::wcout << "\n";
            }
            frame++;
        }
    }

    // Main symbol resolution that understands your architecture
     // Enhanced symbol resolution with complete coverage
    static SymbolInfo resolve_symbol(uintptr_t address) {
        SymbolInfo info = {};
        info.base_address = address;
        std::wcout << L"Resolving symbol for address: 0x" << std::hex << address << L"\n";
        // 1. FIRST PRIORITY: Check emulated modules (most specific)
        for (const auto& [mod_name, module] : emulated_modules) {
            if (module.address_to_name.contains(address)) {
                info.function_name = module.address_to_name.at(address);
                info.module_name = mod_name;
                info.is_emulated = true;
                info.symbol_type = module.function_exports.contains(info.function_name) ?
                    L"EMULATED_FUNC" : L"EMULATED_DATA";
                info.offset = 0; // Exact match
                std::wcout << L"Found in emulated module: " << mod_name << L" function: " << info.function_name << L"\n";
                return info;
            }
        }

        std::wcout << L"Not found in emulated modules, checking PE modules...\n";
        // 2. Check for nearby emulated functions (within reasonable range)
        uintptr_t nearest_emulated_addr = 0;
        std::wstring nearest_emulated_name;
        std::wstring nearest_emulated_module;
        uint32_t min_emulated_distance = UINT32_MAX;

        for (const auto& [mod_name, module] : emulated_modules) {
            for (const auto& [addr, name] : module.address_to_name) {
                if (addr <= address) {
                    uint32_t distance = static_cast<uint32_t>(address - addr);
                    if (distance < min_emulated_distance && distance < 0x1000) { // Within 4KB
                        min_emulated_distance = distance;
                        nearest_emulated_addr = addr;
                        nearest_emulated_name = name;
                        nearest_emulated_module = mod_name;
                    }
                }
            }
        }
        std::wcout << L"Nearest emulated function distance: " << min_emulated_distance << L"\n";
        // 3. Check internal PE functions (NEW: functions defined within PE modules but not exported)
        if (address_to_internal_symbol.contains(address)) {
            const auto& [module_name, symbol_name] = address_to_internal_symbol[address];
            info.function_name = symbol_name;
            info.module_name = module_name;
            info.is_pe_module = true;
            info.symbol_type = L"PE_INTERNAL_FUNC";
            info.offset = 0;
            std::wcout << L"Found internal PE function: " << symbol_name << L" in module: " << module_name << L"\n";
            return info;
        }

        std::wcout << L"Not found in internal PE functions, checking PE modules...\n";

        // 4. Check PE modules with enhanced search
        uintptr_t page_addr = address & ~0xFFF;
        if (address_to_module.contains(page_addr)) {
            std::wstring mod_name = address_to_module[page_addr];
            if (pe_modules.contains(mod_name)) {
                const auto& module = pe_modules[mod_name];
                info.module_name = mod_name;
                info.is_pe_module = true;
                info.base_address = module.base_address;

                uint32_t rva = static_cast<uint32_t>(address - module.base_address);
                info.offset = rva;

                // Try to find exact export match
                if (module.rva_to_export.contains(rva)) {
                    info.function_name = module.rva_to_export.at(rva);
                    info.symbol_type = L"PE_EXPORT";
                    info.offset = 0; // Exact match
                } else {
                    // Enhanced nearest export search with better heuristics
                    std::wstring nearest_export;
                    uint32_t nearest_rva = 0;
                    uint32_t min_distance = UINT32_MAX;

                    for (const auto& [export_rva, export_name] : module.rva_to_export) {
                        if (export_rva <= rva) {
                            uint32_t distance = rva - export_rva;
                            if (distance < min_distance) {
                                min_distance = distance;
                                nearest_export = export_name;
                                nearest_rva = export_rva;
                            }
                        }
                    }

                    if (!nearest_export.empty() && min_distance < 0x2000) { // Increased range to 8KB
                        info.function_name = nearest_export;
                        info.symbol_type = L"PE_EXPORT";
                        info.offset = min_distance;
                    } else {
                        // NEW: Try to identify function prologue patterns
                        if (try_identify_function_at_address(address)) {
                            info.function_name = L"PE_Function_" + std::to_wstring(rva); // corrected to std::to_wstring;
                            info.symbol_type = L"PE_INFERRED_FUNC";
                            info.offset = 0;
                        } else {
                            info.function_name = L"PE_Unknown";
                            info.symbol_type = L"PE_SECTION";
                        }
                    }
                }

                // Find which section this address belongs to
                for (const auto& [sect_name, sect_bounds] : module.sections) {
                    if (address >= sect_bounds.first && address < sect_bounds.second) {
                        info.section_name = sect_name;
                        break;
                    }
                }
                std::wcout << L"Found in PE module: " << mod_name << L" function: " << info.function_name << L"\n";
                return info;
            }
        }

        std::wcout << L"Not found in PE modules, checking emulated nearby functions...\n";

        // 5. NEW: Check if we're near an emulated function (spillover/thunk)
        if (nearest_emulated_addr != 0 && min_emulated_distance < 0x1000) {
            info.function_name = nearest_emulated_name + L"+0x" + std::to_wstring(min_emulated_distance);
            info.module_name = nearest_emulated_module;
            info.is_emulated = true;
            info.symbol_type = L"EMULATED_NEARBY";
            info.offset = min_emulated_distance;
            std::wcout << L"Found nearby emulated function: " << nearest_emulated_name << L" in module: " << nearest_emulated_module << L"\n";
            return info;
        }
        std::wcout << L"Not found nearby emulated functions, checking dynamic functions...\n";
        // 6. NEW: Check dynamic/runtime-generated functions
        if (dynamic_functions.contains(address)) {
            info.function_name = dynamic_functions[address];
            info.module_name = L"RUNTIME";
            info.symbol_type = L"DYNAMIC_FUNC";
            info.offset = 0;
            std::wcout << L"Found dynamic function: " << info.function_name << L"\n";
            return info;
        }
        std::wcout << L"Not found in dynamic functions, checking memory regions...\n";
        // 7. NEW: Check memory regions to classify unknown addresses
        for (const auto& region : memory_regions) {
            if (address >= region.start && address < region.end) {
                info.function_name = L"Address_in_" + region.type;
                info.module_name = region.description;
                info.symbol_type = L"MEMORY_" + region.type;
                info.offset = static_cast<uint32_t>(address - region.start);
                std::wcout << L"Address found in memory region: " << region.type << L" (" << region.description << L")\n";
                return info;
            }
        }
        std::wcout << L"Not found in memory regions, attempting native symbol resolution...\n";
        // 8. Enhanced native symbol resolution with better error handling
        std::wcout << L"Attempting native symbol resolution for address: 0x" << std::hex << address << L"\n";
        // 9. NEW: Last resort - analyze the address itself
        info = analyze_unknown_address(address);
        std::wcout << L"Address classified as: " << info.symbol_type << L"\n";
        return info;
    }

private:
    // NEW: Try to identify function patterns at an address
    static bool try_identify_function_at_address(uintptr_t address) {
        uint8_t bytes[16];
        if (!safe_read_memory(reinterpret_cast<void*>(address), bytes, sizeof(bytes))) {
            return false;
        }

        // Common x86-64 function prologues
        // Standard frame setup: push rbp; mov rbp, rsp
        if (bytes[0] == 0x55 && bytes[1] == 0x48 && bytes[2] == 0x89 && bytes[3] == 0xE5) {
            return true;
        }

        // Frame setup with stack allocation: push rbp; mov rbp, rsp; sub rsp, imm
        if (bytes[0] == 0x55 && bytes[1] == 0x48 && bytes[2] == 0x89 && bytes[3] == 0xE5 &&
            bytes[4] == 0x48 && bytes[5] == 0x83 && bytes[6] == 0xEC) {
            return true;
        }

        // Direct stack allocation: sub rsp, imm
        if (bytes[0] == 0x48 && bytes[1] == 0x83 && bytes[2] == 0xEC) {
            return true;
        }

        // Simple push rbp
        if (bytes[0] == 0x55) {
            return true;
        }

        // Jump instructions (thunks/trampolines)
        if (bytes[0] == 0xE9 || bytes[0] == 0xEB || bytes[0] == 0xFF) {
            return true;
        }

        // No-frame functions that start with common instructions
        if (bytes[0] == 0x48 && (bytes[1] == 0x8B || bytes[1] == 0x89)) { // mov instructions
            return true;
        }

        return false;
    }

    // NEW: Analyze completely unknown addresses
    static SymbolInfo analyze_unknown_address(uintptr_t address) {
        SymbolInfo info = {};
        info.base_address = address;

        // Classify address ranges
        if (address < 0x1000) {
            info.function_name = L"NULL_DEREF";
            info.module_name = L"invalid";
            info.symbol_type = L"NULL_POINTER";
            info.offset = static_cast<uint32_t>(address);
        } else if (address >= 0x7F0000000000ULL) {
            info.function_name = L"HIGH_KERNEL_ADDR";
            info.module_name = L"kernel_space";
            info.symbol_type = L"KERNEL_ADDR";
        } else if (address >= 0x700000000000ULL) {
            info.function_name = L"HIGH_USER_ADDR";
            info.module_name = L"high_memory";
            info.symbol_type = L"HIGH_ADDR";
        } else {
            info.function_name = L"UNKNOWN";
            info.module_name = L"unknown";
            info.symbol_type = L"UNKNOWN";
        }

        return info;
    }

public:
    // NEW: Register internal PE functions (non-exported but identifiable)
    static void register_internal_pe_function(uintptr_t address, const std::wstring& module_name,
                                             const std::wstring& function_name) {
        address_to_internal_symbol[address] = std::make_pair(module_name, function_name);
    }

    // NEW: Register dynamic/runtime-generated functions
    static void register_dynamic_function(uintptr_t address, const std::wstring& name) {
        dynamic_functions[address] = name;
    }

    // NEW: Register memory regions for classification
    static void register_memory_region(uintptr_t start, uintptr_t end,
                                     const std::wstring& type, const std::wstring& description) {
        memory_regions.push_back({start, end, type, description});
    }

    // NEW: Scan PE module for internal functions using heuristics
    static void discover_internal_pe_functions(const std::wstring& module_name,
                                             uintptr_t base_addr, size_t size) {
        const uintptr_t end_addr = base_addr + size;

        // Scan for function prologue patterns
        for (uintptr_t addr = base_addr; addr < end_addr - 16; addr += 4) {
            if (try_identify_function_at_address(addr)) {
                // Generate a name for this internal function
                uint32_t rva = static_cast<uint32_t>(addr - base_addr);
                std::wstring func_name = L"internal_func_" + std::to_wstring(rva);
                register_internal_pe_function(addr, module_name, func_name);
            }
        }
    }

    // NEW: Enhanced safe memory reading with additional validation
    static bool safe_read_memory(const void* addr, void* buffer, size_t size) {
        if (addr == nullptr || buffer == nullptr || size == 0) {
            return false;
        }

        // Check for obviously invalid addresses
        uintptr_t address = reinterpret_cast<uintptr_t>(addr);
        if (address < 0x1000 || address >= 0x7FFF00000000ULL) {
            return false;
        }

        try {
            std::memcpy(buffer, addr, size);
            return true;
        } catch (...) {
            return false;
        }
    }

    // Enhanced backtrace printing
    static void print_enhanced_backtrace(const std::wstring& context = L"") {
        print_libunwind_backtrace();
        std::wcout << L"\n" << std::wstring(80, L'=') << L"\n";
        std::wcout << L"ENHANCED PE EMULATOR BACKTRACE\n";
        if (!context.empty()) {
            std::wcout << L"Context: " << context << L"\n";
        }
        std::wcout << std::wstring(80, L'=') << L"\n";

        // Get backtrace
        void* buffer[64];
        int nptrs = backtrace(buffer, 64);

        std::wcout << L"Stack trace (" << nptrs << L" frames):\n";

        for (int i = 0; i < nptrs; i++) {
            const auto addr = reinterpret_cast<uintptr_t>(buffer[i]);
            SymbolInfo info = resolve_symbol(addr);

            std::wcout << std::setw(2) << i << L": 0x" << std::hex << std::setw(16)
                     << std::setfill<wchar_t>('0') << addr << std::dec << L" ";

            // Color coding based on a symbol type
            std::wstring color_start, color_end = L"\033[0m";
            if (info.is_emulated) {
                color_start = L"\033[1;32m"; // Bright green for emulated
            } else if (info.is_pe_module) {
                color_start = L"\033[1;34m"; // Bright blue for PE
            } else {
                color_start = L"\033[1;37m"; // White for nativee

                std::wcout << color_start;

                // Module name with type indicator
                if (!info.module_name.empty()) {
                    std::wcout << "[" << info.module_name;
                    if (info.is_emulated) {
                        std::wcout << "*EMULATED*";
                    } else if (info.is_pe_module) {
                        std::wcout << "*PE*";
                    }
                    std::wcout << "]";

                    if (info.is_pe_module && info.offset > 0) {
                        std::wcout << "+0x" << std::hex << info.offset << std::dec;
                    }
                }

                // Function name with type
                if (!info.function_name.empty() && info.function_name != L"unknown" && info.function_name != L"???") {
                    std::wcout << " " << info.function_name;
                    if (info.offset > 0 && !info.is_emulated) {
                        std::wcout << "+0x" << std::hex << info.offset << std::dec;
                    }
                    std::wcout << " [" << info.symbol_type << "]";
                }

                // Section information for PE modules
                if (!info.section_name.empty()) {
                    std::wcout << " @" << info.section_name;
                }

                std::wcout << color_end << "\n";
            }

            std::wcout << "\nLegend:\n";
            std::wcout << "  \033[1;32m*EMULATED*\033[0m - Your emulated Windows APIs (Kernel32, UCRTBase, etc.)\n";
            std::wcout << "  \033[1;34m*PE*\033[0m - Loaded PE modules with exports/sections\n";
            std::wcout << "  Native - Host system libraries\n";
            std::wcout << std::wstring(80, '=') << "\n\n";
        }
    }

    // Signal handler that shows emulated context
    // Enhanced signal handler that provides detailed crash context
    static void enhanced_signal_handler(int signum, siginfo_t* info, void* context) {
        auto* ucontext = static_cast<ucontext_t*>(context);
        uintptr_t fault_addr = reinterpret_cast<uintptr_t>(info->si_addr);
        uintptr_t ip = 0;

    #if defined(__x86_64__)
        ip = ucontext->uc_mcontext.gregs[REG_RIP];
    #elif defined(__i386__)
        ip = ucontext->uc_mcontext.gregs[REG_EIP];
    #endif

        std::wcout << "\n" << std::wstring(80, L'=') << L"\n";
        std::wcout << L"FATAL SIGNAL IN PE EMULATOR: " << strsignal(signum) << L" (" << signum << L")\n";
        std::wcout << std::wstring(80, L'=') << L"\n";

        // Print signal-specific information
        switch (signum) {
            case SIGSEGV:
                std::wcout << L"Segmentation violation - ";
                switch (info->si_code) {
                    case SEGV_MAPERR:
                        std::wcout << L"Address not mapped to object\n";
                        break;
                    case SEGV_ACCERR:
                        std::wcout << L"Invalid permissions for mapped object\n";
                        break;
                    default:
                        std::wcout << L"Unknown segfault type (code: " << info->si_code << L")\n";
                }
                break;
            case SIGBUS:
                std::wcout << L"Bus error - Hardware alignment or access issue\n";
                break;
            case SIGILL:
                std::wcout << L"Illegal instruction\n";
                break;
            case SIGFPE:
                std::wcout << L"Floating point exception\n";
                break;
            default:
                break;
        }

        // Analyze the crash location (instruction pointer)
        std::wcout << L"\n";
        SymbolInfo crash_info = resolve_symbol(ip);
        std::wcout << L"\nCRASH LOCATION ANALYSIS:\n";
        std::wcout << L"Instruction pointer: 0x" << std::hex << ip << std::dec;

        if (crash_info.is_emulated) {
            std::wcout << L" [\033[1;31mEMULATED\033[0m] " << crash_info.module_name
                       << L"!" << crash_info.function_name;
            if (crash_info.offset > 0) {
                std::wcout << L"+0x" << std::hex << crash_info.offset << std::dec;
            }
            std::wcout << L"\n";
            std::wcout << L"  ➤ Crashed in emulated Windows API function\n";
        } else if (crash_info.is_pe_module) {
            std::wcout << L" [\033[1;34mPE MODULE\033[0m] " << crash_info.module_name;
            if (!crash_info.function_name.empty() && crash_info.function_name != L"PE_Unknown") {
                std::wcout << L"!" << crash_info.function_name;
                if (crash_info.offset > 0) {
                    std::wcout << L"+0x" << std::hex << crash_info.offset << std::dec;
                }
            }
            if (!crash_info.section_name.empty()) {
                std::wcout << L" in section " << crash_info.section_name;
            }
            std::wcout << L"\n";
            std::wcout << L"  ➤ Crashed in loaded PE module\n";
        } else {
            std::wcout << L" [\033[1;37mNATIVE\033[0m] " << crash_info.module_name
                       << L"!" << crash_info.function_name;
            if (crash_info.offset > 0) {
                std::wcout << L"+0x" << std::hex << crash_info.offset << std::dec;
            }
            std::wcout << L"\n";
            std::wcout << L"  ➤ Crashed in native system library\n";
        }

        // Analyze the fault address (what was being accessed)
        if (fault_addr != 0) {
            std::wcout << L"\nFAULT ADDRESS ANALYSIS:\n";
            std::wcout << L"Fault address: 0x" << std::hex << fault_addr << std::dec;

            SymbolInfo fault_info = resolve_symbol(fault_addr);
            if (fault_info.is_emulated) {
                std::wcout << L" [\033[1;32mEMULATED DATA\033[0m] " << fault_info.module_name
                           << L"!" << fault_info.function_name << L"\n";
                std::wcout << L"  ➤ Trying to access emulated API data/function\n";
            } else if (fault_info.is_pe_module) {
                std::wcout << L" [\033[1;34mPE DATA\033[0m] " << fault_info.module_name;
                if (!fault_info.section_name.empty()) {
                    std::wcout << L" in section " << fault_info.section_name;
                }
                std::wcout << L"\n";
                std::wcout << L"  ➤ Trying to access PE module memory\n";
            } else {
                // Check for common problematic addresses
                if (fault_addr < 0x1000) {
                    std::wcout << L" [\033[1;31mNULL/LOW\033[0m]\n";
                    std::wcout << L"  ➤ NULL pointer dereference or low address access\n";
                } else if (fault_addr == 0xDEADBEEF || fault_addr == 0xCCCCCCCC || fault_addr == 0xCDCDCDCD) {
                    std::wcout << L" [\033[1;31mDEBUG PATTERN\033[0m]\n";
                    std::wcout << L"  ➤ Accessing debug fill pattern - uninitialized memory\n";
                } else if (fault_addr >= 0x7FFF00000000ULL) {
                    std::wcout << L" [\033[1;37mHIGH ADDRESS\033[0m]\n";
                    std::wcout << L"  ➤ Very high address - possible corruption\n";
                } else {
                    std::wcout << L" [\033[1;37mUNKNOWN\033[0m]\n";
                    std::wcout << L"  ➤ Address not in known modules\n";
                }
            }

            // Try to read around the fault address to see if it's readable
            std::wcout << L"\nMEMORY ACCESSIBILITY CHECK:\n";
            for (int offset = -16; offset <= 16; offset += 8) {
                uintptr_t test_addr = fault_addr + offset;
                uint64_t test_value;
                bool readable = safe_read_memory(reinterpret_cast<void*>(test_addr), &test_value, sizeof(test_value));

                std::wcout << L"  0x" << std::hex << std::setw(16) << std::setfill<wchar_t>(L'0') << test_addr << L": ";
                if (readable) {
                    std::wcout << L"0x" << std::setw(16) << test_value << L" [\033[1;32mOK\033[0m]";
                } else {
                    std::wcout << L"???????????????? [\033[1;31mFAULT\033[0m]";
                }
                if (offset == 0) std::wcout << L" ← FAULT ADDRESS";
                std::wcout << L"\n" << std::dec;
            }
        }

        // Show register state
        std::wcout << L"\nREGISTER STATE:\n";
    #if defined(__x86_64__)
        std::wcout << L"RAX: 0x" << std::hex << std::setw(16) << std::setfill<wchar_t>(L'0')
                   << ucontext->uc_mcontext.gregs[REG_RAX] << L"  ";
        std::wcout << L"RBX: 0x" << std::setw(16) << ucontext->uc_mcontext.gregs[REG_RBX] << L"\n";
        std::wcout << L"RCX: 0x" << std::setw(16) << ucontext->uc_mcontext.gregs[REG_RCX] << L"  ";
        std::wcout << L"RDX: 0x" << std::setw(16) << ucontext->uc_mcontext.gregs[REG_RDX] << L"\n";
        std::wcout << L"RSI: 0x" << std::setw(16) << ucontext->uc_mcontext.gregs[REG_RSI] << L"  ";
        std::wcout << L"RDI: 0x" << std::setw(16) << ucontext->uc_mcontext.gregs[REG_RDI] << L"\n";
        std::wcout << L"RSP: 0x" << std::setw(16) << ucontext->uc_mcontext.gregs[REG_RSP] << L"  ";
        std::wcout << L"RBP: 0x" << std::setw(16) << ucontext->uc_mcontext.gregs[REG_RBP] << L"\n";
        std::wcout << L"RIP: 0x" << std::setw(16) << ucontext->uc_mcontext.gregs[REG_RIP] << L"\n" << std::dec;
    #elif defined(__i386__)
        std::wcout << L"EAX: 0x" << std::hex << std::setw(8) << std::setfill<wchar_t>(L'0')
                   << ucontext->uc_mcontext.gregs[REG_EAX] << L"  ";
        std::wcout << L"EBX: 0x" << std::setw(8) << ucontext->uc_mcontext.gregs[REG_EBX] << L"\n";
        std::wcout << L"ECX: 0x" << std::setw(8) << ucontext->uc_mcontext.gregs[REG_ECX] << L"  ";
        std::wcout << L"EDX: 0x" << std::setw(8) << ucontext->uc_mcontext.gregs[REG_EDX] << L"\n";
        std::wcout << L"ESI: 0x" << std::setw(8) << ucontext->uc_mcontext.gregs[REG_ESI] << L"  ";
        std::wcout << L"EDI: 0x" << std::setw(8) << ucontext->uc_mcontext.gregs[REG_EDI] << L"\n";
        std::wcout << L"ESP: 0x" << std::setw(8) << ucontext->uc_mcontext.gregs[REG_ESP] << L"  ";
        std::wcout << L"EBP: 0x" << std::setw(8) << ucontext->uc_mcontext.gregs[REG_EBP] << L"\n";
        std::wcout << L"EIP: 0x" << std::setw(8) << ucontext->uc_mcontext.gregs[REG_EIP] << L"\n" << std::dec;
    #endif

        // Analyze the stack around RSP/ESP
        std::wcout << L"\nSTACK ANALYSIS:\n";
        uintptr_t stack_ptr = 0;
    #if defined(__x86_64__)
        stack_ptr = ucontext->uc_mcontext.gregs[REG_RSP];
    #elif defined(__i386__)
        stack_ptr = ucontext->uc_mcontext.gregs[REG_ESP];
    #endif

        if (stack_ptr > 0x1000 && stack_ptr < 0x7FFF00000000ULL) {
            std::wcout << L"Stack pointer: 0x" << std::hex << stack_ptr << std::dec << L"\n";
            std::wcout << L"Stack content:\n";

            for (int i = -2; i <= 8; i++) {
                uintptr_t addr = stack_ptr + (i * 8);
                uintptr_t value;
                if (safe_read_memory(reinterpret_cast<void*>(addr), &value, sizeof(value))) {
                    std::wcout << L"  [" << std::dec << std::setw(3) << i << L"] 0x"
                               << std::hex << std::setw(16) << std::setfill<wchar_t>(L'0') << addr
                               << L": 0x" << std::setw(16) << value;

                    if (i == 0) std::wcout << L" ← RSP";

                    // Try to resolve what this stack value points to
                    SymbolInfo stack_symbol = resolve_symbol(value);
                    if (!stack_symbol.function_name.empty() && stack_symbol.function_name != L"unknown"
                        && stack_symbol.function_name != L"???") {
                        std::wcout << L" → " << stack_symbol.module_name << L"!" << stack_symbol.function_name;
                    }
                    std::wcout << L"\n" << std::dec;
                }
            }
        }

        // Show disassembly around crash point
        std::wcout << L"\nDISASSEMBLY CONTEXT:\n";
        std::wcout << L"Instructions around crash point:\n";
        for (int offset = -16; offset <= 16; offset += 4) {
            uintptr_t addr = ip + offset;
            uint32_t instruction;
            if (safe_read_memory(reinterpret_cast<void*>(addr), &instruction, sizeof(instruction))) {
                std::wcout << L"  ";
                if (offset == 0) std::wcout << L"→ ";
                else std::wcout << L"  ";

                std::wcout << L"0x" << std::hex << std::setw(16) << std::setfill<wchar_t>(L'0') << addr
                           << L": " << std::setw(8) << instruction << std::dec;

                if (offset == 0) std::wcout << L" ← CRASH HERE";
                std::wcout << L"\n";
            }
        }

        // Show the enhanced backtrace
        print_enhanced_backtrace(L"Signal " + std::to_wstring(signum) + L" at " +
                                 (crash_info.is_emulated ? L"EMULATED " :
                                  crash_info.is_pe_module ? L"PE " : L"NATIVE ") +
                                 crash_info.module_name + L"!" + crash_info.function_name);

        // Provide debugging suggestions based on the crash context
        std::wcout << L"\nDEBUGGING SUGGESTIONS:\n";
        if (crash_info.is_emulated) {
            std::wcout << L"• The crash occurred in an emulated Windows API function\n";
            std::wcout << L"• Check if the API parameters are valid\n";
            std::wcout << L"• Verify that required data structures are properly initialized\n";
            if (fault_addr < 0x1000) {
                std::wcout << L"• NULL pointer passed to API - check function arguments\n";
            }
        } else if (crash_info.is_pe_module) {
            std::wcout << L"• The crash occurred in PE module code\n";
            if (crash_info.function_name.empty() || crash_info.function_name == L"PE_Unknown") {
                std::wcout << L"• This appears to be internal PE code (not an exported function)\n";
                std::wcout << L"• Check if imports are properly resolved\n";
                std::wcout << L"• Verify relocations were applied correctly\n";
            }
            if (!crash_info.section_name.empty()) {
                if (crash_info.section_name == L".text") {
                    std::wcout << L"• Crash in code section - possible bad function call or corrupted code\n";
                } else if (crash_info.section_name == L".data" || crash_info.section_name == L".rdata") {
                    std::wcout << L"• Crash in data section - possible data corruption or invalid access\n";
                }
            }
        }

        if (fault_addr != 0 && fault_addr != ip) {
            if (fault_addr < 0x1000) {
                std::wcout << L"• Classic NULL pointer dereference\n";
            } else if (fault_addr == 0xDEADBEEF || fault_addr == 0xCCCCCCCC) {
                std::wcout << L"• Accessing debug fill pattern - using uninitialized pointer\n";
            }
        }

        std::wcout << std::wstring(80, L'=') << L"\n";
        exit(1);
    }

    // Setup enhanced signal handlers
    static void setup_enhanced_handlers() {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_sigaction = enhanced_signal_handler;
        sa.sa_flags = SA_SIGINFO | SA_RESTART;
        sigemptyset(&sa.sa_mask);

        sigaction(SIGSEGV, &sa, nullptr);
        sigaction(SIGBUS, &sa, nullptr);
        sigaction(SIGILL, &sa, nullptr);
        sigaction(SIGFPE, &sa, nullptr);
        sigaction(SIGTRAP, &sa, nullptr);
        sigaction(SIGABRT, &sa, nullptr);
    }

    // Debug helper: print all registered modules
    static void print_registered_modules() {
        std::wcout << "\nRegistered Emulated Modules:\n";
        for (const auto& [name, module] : emulated_modules) {
            std::wcout << "  " << name << ": " << module.function_exports.size()
                     << " functions, " << module.data_exports.size() << " data\n";
        }

        std::wcout << "\nRegistered PE Modules:\n";
        for (const auto& [name, module] : pe_modules) {
            std::wcout << "  " << name << " at 0x" << std::hex << module.base_address
                     << std::dec << " (" << module.rva_to_export.size() << " exports)\n";
        }
        std::wcout << "\n";
    }
};

namespace fs = std::filesystem;



// Enhanced DllInfo structure

struct ImportInfo {
    std::wstring dll_name;
    std::wstring function_name;
    uint16_t ordinal = 0;
    uintptr_t address = 0;
    bool is_resolved = false;
    bool is_emulated = false;
    bool is_function = false;  // NEW: Track if this is a function or data import
};

struct ForwardedExport {
    std::wstring original_name;
    std::wstring target_dll;
    std::wstring target_function;
    uintptr_t resolved_address = 0;
    bool is_resolved = false;
};

enum DLL_CHARACTERISTICS {
    DYNAMIC_BASE = 0x0040,
    NX_COMPAT = 0x0100,
    NO_SEH = 0x0400,
    GUARD_CF = 0x0004,
    HIGH_ENTROPY_VA = 0x0020,
    DYNAMIC_BASE_STRICT = 0x0080,
    FORCE_INTEGRITY = 0x0010,
    NX_COMPAT_STRICT = 0x0200,
    APPCONTAINER = 0x1000,
};

enum HEADER_CHARACTERISTICS {
    RELOCS_STRIPPED = 0x0001,
    EXECUTABLE_IMAGE = 0x0002,
    LINE_NUMS_STRIPPED = 0x0004,
    LOCAL_SYMS_STRIPPED = 0x0008,
    AGGRESSIVE_WS_TRIM = 0x0010,
    LARGE_ADDRESS_AWARE = 0x0020,
    BYTES_REVERSED_LO = 0x0080,
    MACHINE_32BIT = 0x0100,
    DEBUG_STRIPPED = 0x0200,
    REMOVABLE_RUN_FROM_SWAP = 0x0400,
    NET_RUN_FROM_SWAP = 0x0800,
    SYSTEM = 0x1000,
    DLL = 0x2000,
    UP_SYSTEM_ONLY = 0x4000,
    BYTES_REVERSED_HI = 0x8000,
};

// ============================================================
// PE Analyzer Class
// ============================================================
class PEAnalyzer {
public:
    std::unordered_map<std::wstring, DllInfo> analyzed_dlls;
    std::unordered_map<std::wstring, std::unordered_set<std::wstring>> dependency_graph;
    std::vector<fs::path> system_dll_paths;
    std::unordered_map<std::wstring, std::vector<ForwardedExport>> forwarded_exports; // dll_name -> forwards

    // NEW: Enhanced export extraction that builds both old and new structures
    static std::vector<ExportInfo> extract_detailed_exports(const LIEF::PE::Binary& pe, uintptr_t base_address = 0) {
        std::vector<ExportInfo> exports;

        try {
            if (!pe.has_exports()) {
                return exports;
            }

            const auto& export_dir = pe.get_export();
            if (!export_dir) {
                return exports;
            }

            for (const LIEF::PE::ExportEntry& entry : export_dir->entries()) {
                ExportInfo export_info;

                // Basic export information
                export_info.name = entry.name().empty() ?
                    L"Ordinal_" + std::to_wstring(entry.ordinal()) : converter.from_bytes(entry.name());
                export_info.ordinal = entry.ordinal();
                export_info.rva = static_cast<uint32_t>(entry.address());
                export_info.address = base_address != 0 ?
                    base_address + export_info.rva :
                    pe.optional_header().imagebase() + export_info.rva;

                // Check if this is a forwarded export
                export_info.is_forwarded = entry.is_forwarded();
                if (export_info.is_forwarded) {
                    export_info.forward_dll = converter.from_bytes(entry.forward_information().library) + L".DLL";
                    export_info.forward_function = converter.from_bytes(entry.forward_information().function);
                    export_info.is_function = true; // Assume forwarded exports are functions
                    export_info.section_name = L"FORWARDED";
                } else {
                    // Determine if this export is a function or variable
                    export_info.is_function = is_function_export(pe, export_info.rva);

                    // Get section name
                    if (const auto* section = pe.section_from_rva(export_info.rva)) {
                        export_info.section_name = converter.from_bytes(section->name()) ;
                    } else {
                        export_info.section_name = L"UNKNOWN";
                    }
                }

                exports.push_back(export_info);
            }
        } catch (const std::exception& e) {
            warn(L"Failed to extract detailed exports: " + converter.from_bytes(e.what()));
        }

        return exports;
    }

    // NEW: Build enhanced export map with function/data distinction
    static std::unordered_map<std::wstring, ExportInfo> build_enhanced_exports(const LIEF::PE::Binary& pe, uintptr_t base_address = 0)
    {

        std::unordered_map<std::wstring, ExportInfo> enhanced_exports;

        try {
            if (!pe.has_exports()) {
                return enhanced_exports;
            }

            const auto& export_dir = pe.get_export();
            if (!export_dir) {
                return enhanced_exports;
            }

            for (const LIEF::PE::ExportEntry& entry : export_dir->entries()) {
                ExportInfo export_entry;

                // Basic export information
                export_entry.name = entry.name().empty() ?
                    L"Ordinal_" + std::to_wstring(entry.ordinal()) : converter.from_bytes(entry.name());
                export_entry.ordinal = entry.ordinal();
                export_entry.rva = static_cast<uint32_t>(entry.address());
                export_entry.address = base_address != 0 ?
                    base_address + export_entry.rva :
                    pe.optional_header().imagebase() + export_entry.rva;

                // Check if this is a forwarded export
                export_entry.is_forwarded = entry.is_forwarded();
                if (export_entry.is_forwarded) {
                    export_entry.forward_dll = converter.from_bytes(entry.forward_information().library) + L".DLL";
                    export_entry.forward_function = converter.from_bytes(entry.forward_information().function);
                    export_entry.is_function = true; // Assume forwarded exports are functions
                    export_entry.section_name = L"FORWARDED";
                } else {
                    // Determine if this export is a function or variable
                    export_entry.is_function = is_function_export(pe, export_entry.rva);

                    // Get section name
                    if (const auto* section = pe.section_from_rva(export_entry.rva)) {
                        export_entry.section_name = converter.from_bytes(section->name());
                    } else {
                        export_entry.section_name = L"UNKNOWN";
                    }
                }

                enhanced_exports[export_entry.name] = export_entry;
            }
        } catch (const std::exception& e) {
            warn(L"Failed to build enhanced exports: " + converter.from_bytes(e.what()));
        }

        return enhanced_exports;
    }

    static bool is_function_export(const LIEF::PE::Binary& pe, uint32_t rva) {
        const auto* section = pe.section_from_rva(rva);
        if (!section) {
            return false; // Unknown section, assume variable
        }

        // Check section characteristics
        uint32_t characteristics = section->characteristics();

        // IMAGE_SCN_MEM_EXECUTE (0x20000000) - the section is executable
        const bool is_executable = (characteristics & 0x20000000) != 0;

        // IMAGE_SCN_CNT_CODE (0x00000020) - section contains code
        const bool contains_code = (characteristics & 0x00000020) != 0;

        // Additional heuristics for better detection
        std::wstring section_name = converter.from_bytes(section->name());
        std::ranges::transform(section_name, section_name.begin(), ::tolower);

        // Common code section names
        const bool is_code_section = (section_name == L".text" ||
                               section_name == L".code" ||
                               section_name.find(L"text") != std::wstring::npos);

        // Common data section names
        const bool is_data_section = (section_name == L".data" ||
                               section_name == L".rdata" ||
                               section_name == L".bss" ||
                               section_name == L".idata" ||
                               section_name.find(L"data") != std::wstring::npos);

        // If it's clearly a data section, it's a variable
        if (is_data_section && !is_executable) {
            return false;
        }

        // If it's executable or in a code section, it's likely a function
        if (is_executable || contains_code || is_code_section) {
            return true;
        }

        // For ambiguous cases, try to examine the memory content
        try {
            auto section_content = section->content();
            if (!section_content.empty() && rva >= section->virtual_address()) {
                uint32_t offset = rva - section->virtual_address();
                if (offset < section_content.size()) {
                    // Look for common function prologues
                    const uint8_t* data = section_content.data() + offset;
                    size_t remaining = section_content.size() - offset;

                    if (remaining >= 4) {
                        // Common x86/x64 function prologues
                        if ((data[0] == 0x55 && data[1] == 0x48 && data[2] == 0x89 && data[3] == 0xE5) ||
                            (data[0] == 0x48 && data[1] == 0x89 && data[2] == 0xE5) ||
                            (data[0] == 0x55) ||
                            (data[0] == 0x48 && data[1] == 0x83 && data[2] == 0xEC)) {
                            return true;
                        }

                        // Check for jump instructions (thunks)
                        if (data[0] == 0xE9 || data[0] == 0xEB || data[0] == 0xFF) {
                            return true;
                        }
                    }
                }
            }
        } catch (const std::exception&) {
            // Ignore errors in content analysis
        }

        // Default to variable if we can't determine
        return false;
    }

    // Add this method to parse forwarded exports
    static std::vector<ForwardedExport> extract_forwarded_exports(const LIEF::PE::Binary& pe) {
        std::vector<ForwardedExport> forwards;

        try {
            if (!pe.has_exports()) {
                return forwards;
            }
            for (const LIEF::PE::Export* export_dir = pe.get_export(); const LIEF::PE::ExportEntry& entry : export_dir->entries()) {
                if (entry.is_forwarded()) {
                    ForwardedExport export_;
                    export_.original_name = entry.name().empty() ?
                        L"Ordinal_" + std::to_wstring(entry.ordinal()) : converter.from_bytes(entry.name());
                    export_.target_dll = converter.from_bytes(entry.forward_information().library) + L".DLL";
                    export_.target_function = converter.from_bytes(entry.forward_information().function);
                    export_.is_resolved = false;
                    export_.resolved_address = 0;
                    forwards.push_back(export_);
                }
            }
        } catch (const std::exception& e) {
            warn(L"Failed to extract forwarded exports: " + converter.from_bytes(e.what()));
        }

        return forwards;
    }

    static std::vector<fs::path> get_system_dll_paths() {
        std::vector<fs::path> paths;
        paths.push_back(fs::current_path());
        // Add more system paths as needed
        return paths;
    }

    fs::path find_dll(const std::wstring& dll_name) const {
        // Try the exact name first
        for (const auto& search_path : system_dll_paths) {
            if (auto dll_path = search_path / dll_name; fs::exists(dll_path)) {
                return dll_path;
            }
        }

        // Try common variations
        std::vector<std::wstring> name_variations = {
            dll_name,
            to_lower(dll_name),
            to_upper(dll_name),
            dll_name.substr(0, dll_name.find_last_of('.')) + L".so",
            L"lib" + dll_name.substr(0, dll_name.find_last_of('.')) + L".so"
        };

        for (const auto& search_path : system_dll_paths) {
            for (const auto& variation : name_variations) {
                if (auto dll_path = search_path / variation; fs::exists(dll_path)) {
                    return dll_path;
                }
            }
        }
        return {};
    }

    static std::wstring calculate_file_hash(const fs::path& file_path) {
        try {
            std::ifstream file(file_path, std::ios::binary);
            if (!file) return L"";

            SHA256_CTX ctx;
            SHA256_Init(&ctx);

            char buffer[4096];
            while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0) {
                SHA256_Update(&ctx, buffer, file.gcount());
            }

            unsigned char hash[SHA256_DIGEST_LENGTH];
            SHA256_Final(hash, &ctx);

            std::wstringstream ss;
            for (unsigned char i : hash) {
                ss << std::hex << std::setw(2) << std::setfill<wchar_t>('0') << static_cast<unsigned int>(i);
            }
            return ss.str();
        } catch (const std::exception& e) {
            warn("Failed to calculate hash for " + file_path.string() + ": " + e.what());
            return L"";
        }
    }

    static std::unordered_map<std::wstring, std::wstring> extract_version_info(const LIEF::PE::Binary& pe) {
        std::unordered_map<std::wstring, std::wstring> version_info;
        try {
            if (pe.has_resources()) {
                // LIEF resource parsing is complex and version-dependent
                // This is a simplified placeholder - actual implementation would need
                // to parse the resource tree structure properly
                version_info[L"Version"] = L"Unknown";
                version_info[L"Description"] = L"PE File";
            }
        } catch (const std::exception& e) {
            warn(L"Failed to extract version info: " + converter.from_bytes(e.what()));
        }
        return version_info;
    }

    static std::unordered_map<std::wstring, bool> analyze_security_flags(const LIEF::PE::Binary& pe) {
        std::unordered_map<std::wstring, bool> security_flags;

        const auto& optional_header = pe.optional_header();

        // DLL characteristics - using correct LIEF enums
        const uint16_t dll_chars = optional_header.dll_characteristics();
        security_flags[L"ASLR"] = (dll_chars & static_cast<uint16_t>(DLL_CHARACTERISTICS::DYNAMIC_BASE)) != 0;
        security_flags[L"DEP"] = (dll_chars & static_cast<uint16_t>(DLL_CHARACTERISTICS::NX_COMPAT)) != 0;
        security_flags[L"SEH"] = (dll_chars & static_cast<uint16_t>(DLL_CHARACTERISTICS::NO_SEH)) == 0; // Inverted logic
        security_flags[L"CFG"] = (dll_chars & static_cast<uint16_t>(DLL_CHARACTERISTICS::GUARD_CF)) != 0;

        // File characteristics
        const uint16_t file_chars = pe.header().characteristics();
        security_flags[L"Executable"] = (file_chars & static_cast<uint16_t>(HEADER_CHARACTERISTICS::EXECUTABLE_IMAGE)) != 0;
        security_flags[L"DLL"] = (file_chars & static_cast<uint16_t>(HEADER_CHARACTERISTICS::DLL)) != 0;

        return security_flags;
    }

    static bool is_data_export(const LIEF::PE::Binary& pe, const uint32_t rva) {
        const auto* section = pe.section_from_rva(rva);
        if (!section) return false;
        // Check if a section is not executable (no IMAGE_SCN_MEM_EXECUTE)
        return !(section->characteristics() & 0x20000000);
    }

    static std::unordered_map<std::wstring, uint32_t> extract_export_table(const LIEF::PE::Binary& pe) {
        std::unordered_map<std::wstring, uint32_t> export_table;
        try {
            if (pe.has_exports()) {
                for (const LIEF::PE::Export *export_dir = pe.get_export(); const LIEF::PE::ExportEntry& entry : export_dir->entries()) {
                    if (!entry.name().empty()) {
                        export_table[converter.from_bytes(entry.name())] = static_cast<uint32_t>(entry.address());
                    } else if (entry.ordinal() > 0) {
                        export_table[L"Ordinal_" + std::to_wstring(entry.ordinal())] = static_cast<uint32_t>(entry.address());
                    }
                }
            }
        } catch (const std::exception& e) {
            warn(L"Failed to extract export table: " + converter.from_bytes(e.what()));
        }
        return export_table;
    }

    static DllInfo create_stub_dll_info(const fs::path& file_path, bool is_native) {
        const std::wstring dll_name = to_lower(file_path.filename().wstring());

        DllInfo info;
        info.name = dll_name;
        info.path = file_path.wstring();
        info.is_native = is_native;

        if (fs::exists(file_path)) {
            info.file_hash = calculate_file_hash(file_path);
        }

        return info;
    }

    static std::wstring to_lower(const std::wstring& str) {
        std::wstring result = str;
        std::ranges::transform(result, result.begin(), ::tolower);
        return result;
    }

    static std::wstring to_upper(const std::wstring& str) {
        std::wstring result = str;
        std::ranges::transform(result, result.begin(), ::toupper);
        return result;
    }

    PEAnalyzer() : system_dll_paths(get_system_dll_paths()) {}

    DllInfo analyze_pe_file(const fs::path& file_path, bool is_native = true) {
        std::wstring dll_name = to_lower(file_path.filename().wstring());
        if (auto it = analyzed_dlls.find(dll_name); it != analyzed_dlls.end()) {
            return it->second;
        }

        trace("Analyzing PE file: ", file_path.wstring());

        try {
            LIEF::PE::Binary* pe_binary = LIEF::PE::Parser::parse(file_path.string()).release();
            if (!pe_binary) {
                warn(file_path.string() + " is not a valid PE file, creating stub info");
                return create_stub_dll_info(file_path, is_native);
            }

            std::ifstream file(file_path, std::ios::binary);
            std::vector<uint8_t> memory_mapped((std::istreambuf_iterator<char>(file)),
                                               std::istreambuf_iterator<char>());

            DllInfo dll_info;
            dll_info.name = dll_name;
            dll_info.path = file_path.wstring();
            dll_info.base_address = pe_binary->optional_header().imagebase();
            dll_info.size = pe_binary->optional_header().sizeof_image();
            dll_info.version_info = extract_version_info(*pe_binary);
            dll_info.security_flags = analyze_security_flags(*pe_binary);
            dll_info.pe_characteristics = pe_binary->header().characteristics();
            dll_info.timestamp = pe_binary->header().time_date_stamp();
            dll_info.checksum = pe_binary->optional_header().checksum();
            dll_info.file_hash = calculate_file_hash(file_path);
            dll_info.is_native = is_native;
            dll_info.memory_mapped = std::move(memory_mapped);

            // NEW: Build enhanced exports map
            dll_info.enhanced_exports = build_enhanced_exports(*pe_binary, 0);

            // Extract detailed exports (keep for compatibility)
            dll_info.exports_detailed = extract_detailed_exports(*pe_binary);

            // Build export map for quick lookup
            for (const auto& exp : dll_info.exports_detailed) {
                dll_info.export_map[exp.name] = exp;
                // Keep backward compatibility
                if (!exp.is_forwarded) {
                    dll_info.export_table[exp.name] = exp.rva;
                }
            }

            // Store forwarded exports in the separate map
            std::vector<ForwardedExport> dll_forwards;
            for (const auto& exp : dll_info.exports_detailed) {
                if (exp.is_forwarded) {
                    ForwardedExport forward;
                    forward.original_name = exp.name;
                    forward.target_dll = exp.forward_dll;
                    forward.target_function = exp.forward_function;
                    forward.is_resolved = false;
                    forward.resolved_address = 0;
                    dll_forwards.push_back(forward);
                }
            }
            forwarded_exports[dll_name] = std::move(dll_forwards);

            // Analyze imports and dependencies (existing code)
            if (pe_binary->has_imports()) {
                for (const LIEF::PE::Import& import : pe_binary->imports()) {
                    std::wstring imported_dll = to_lower(converter.from_bytes(import.name()));
                    dll_info.dependencies.insert(imported_dll);
                    dll_info.imports[imported_dll] = {};
                    for (const LIEF::PE::ImportEntry& entry : import.entries()) {
                        if (!entry.name().empty()) {
                            dll_info.imports[imported_dll].push_back(converter.from_bytes(entry.name()));
                        } else if (entry.ordinal() > 0) {
                            dll_info.imports[imported_dll].push_back(L"Ordinal_" + std::to_wstring(entry.ordinal()));
                        }
                    }
                }
            }

            dependency_graph[dll_name] = dll_info.dependencies;
            analyzed_dlls[dll_name] = dll_info;
            delete pe_binary;

            // Enhanced logging
            size_t function_count = dll_info.get_function_exports().size();
            size_t variable_count = dll_info.get_variable_exports().size();
            size_t forwarded_count = dll_info.get_forwarded_exports().size();

            trace("Analyzed ", dll_name.c_str(), ": ",
                  std::to_wstring(function_count), " function exports, ",
                  std::to_wstring(variable_count), " variable exports, ",
                  std::to_wstring(forwarded_count), " forwarded exports, ",
                  std::to_wstring(dll_info.dependencies.size()), " dependencies");

            return dll_info;
        } catch (const std::exception& e) {
            error("Failed to analyze " + file_path.string() + ": " + e.what());
            return create_stub_dll_info(file_path, is_native);
        }
    }

    std::unordered_set<std::wstring> analyze_dependencies_recursive(const std::wstring& dll_name, const int max_depth = 10) {
        std::unordered_set<std::wstring> visited;
        std::deque<std::pair<std::wstring, int>> to_visit;
        to_visit.emplace_back(to_lower(dll_name), 0);

        while (!to_visit.empty()) {
            auto [current_dll, depth] = to_visit.front();
            to_visit.pop_front();

            if (visited.contains(current_dll) || depth > max_depth) {
                continue;
            }

            visited.insert(current_dll);

            // Try to find and analyze the DLL
            if (auto dll_path = find_dll(current_dll); !dll_path.empty()) {
                // Add dependencies to the queue
                for (auto dll_info = analyze_pe_file(dll_path); const auto& dep : dll_info.dependencies) {
                    if (!visited.contains(dep)) {
                        to_visit.emplace_back(dep, depth + 1);
                    }
                }
            } else {
                warn(L"Could not find DLL: " + current_dll);
            }
        }

        return visited;
    }

    std::vector<std::vector<std::wstring>> detect_circular_dependencies() {
        std::vector<std::vector<std::wstring>> cycles;
        std::unordered_set<std::wstring> visited;

        std::function<std::vector<std::wstring>(const std::wstring&, std::vector<std::wstring>&,
                                               std::unordered_set<std::wstring>&,
                                               std::unordered_set<std::wstring>&)> dfs;

        dfs = [&](const std::wstring& node, std::vector<std::wstring>& path,
                  std::unordered_set<std::wstring>& vis,
                  std::unordered_set<std::wstring>& rec_stack) -> std::vector<std::wstring> {
            vis.insert(node);
            rec_stack.insert(node);
            path.push_back(node);

            if (const auto it = dependency_graph.find(node); it != dependency_graph.end()) {
                for (const auto& neighbor : it->second) {
                    if (!vis.contains(neighbor)) {
                        if (auto cycle = dfs(neighbor, path, vis, rec_stack); !cycle.empty()) {
                            return cycle;
                        }
                    } else if (rec_stack.contains(neighbor)) {
                        // Found a cycle
                        const auto cycle_start = std::ranges::find(path, neighbor);
                        std::vector<std::wstring> cycle(cycle_start, path.end());
                        cycle.push_back(neighbor);
                        return cycle;
                    }
                }
            }

            path.pop_back();
            rec_stack.erase(node);
            return {};
        };

        for (const auto &DLL: dependency_graph | std::views::keys) {
            if (!visited.contains(DLL)) {
                std::vector<std::wstring> path;
                std::unordered_set<std::wstring> rec_stack;
                if (const auto cycle = dfs(DLL, path, visited, rec_stack); !cycle.empty()) {
                    cycles.push_back(cycle);
                }
            }
        }

        return cycles;
    }

    std::wstring generate_dependency_report() {
        std::wostringstream report;
        report << std::wstring(80, '=') << "\n";
        report << "ENHANCED PE DEPENDENCY ANALYSIS REPORT\n";
        report << std::wstring(80, '=') << "\n\n";

        // Summary with export type breakdown
        const size_t total_dlls = analyzed_dlls.size();
        size_t native_dlls = 0;
        size_t total_function_exports = 0;
        size_t total_variable_exports = 0;
        size_t total_forwarded_exports = 0;

        for (const auto &DLL: analyzed_dlls | std::views::values) {
            if (DLL.is_native) native_dlls++;
            total_function_exports += DLL.get_function_exports().size();
            total_variable_exports += DLL.get_variable_exports().size();
            total_forwarded_exports += DLL.get_forwarded_exports().size();
        }

        const size_t emulated_dlls = total_dlls - native_dlls;
        report << "SUMMARY:\n";
        report << "  Total DLLs analyzed: " << total_dlls << "\n";
        report << "  Native DLLs: " << native_dlls << "\n";
        report << "  Emulated DLLs: " << emulated_dlls << "\n";
        report << "  Total function exports: " << total_function_exports << "\n";
        report << "  Total variable exports: " << total_variable_exports << "\n";
        report << "  Total forwarded exports: " << total_forwarded_exports << "\n\n";

        // Detailed DLL information with export breakdown
        report << "DETAILED DLL ANALYSIS:\n";
        for (const auto& [dll_name, dll_info] : analyzed_dlls) {
            auto functions = dll_info.get_function_exports();
            auto variables = dll_info.get_variable_exports();
            auto forwarded = dll_info.get_forwarded_exports();

            report << "  " << dll_name << ":\n";
            report << "    Path: " << (dll_info.path.empty() ? L"Not found" : dll_info.path) << "\n";
            report << "    Type: " << (dll_info.is_native ? "Native" : "Emulated") << "\n";
            if (dll_info.base_address != 0) {
                report << "    Base Address: 0x" << std::hex << dll_info.base_address << std::dec << "\n";
            }
            report << "    Size: " << dll_info.size << " bytes\n";
            report << "    Function exports: " << functions.size() << "\n";
            report << "    Variable exports: " << variables.size() << "\n";
            report << "    Forwarded exports: " << forwarded.size() << "\n";
            report << "    Dependencies: " << dll_info.dependencies.size() << "\n";

            // Show sample exports by type
            if (!functions.empty()) {
                report << "    Sample functions: ";
                for (size_t i = 0; i < std::min(functions.size(), size_t(5)); ++i) {
                    if (i > 0) report << ", ";
                    report << functions[i].name << " (@" << functions[i].section_name << ")";
                }
                if (functions.size() > 5) report << "...";
                report << "\n";
            }

            if (!variables.empty()) {
                report << "    Sample variables: ";
                for (size_t i = 0; i < std::min(variables.size(), size_t(3)); ++i) {
                    if (i > 0) report << ", ";
                    report << variables[i].name << " (@" << variables[i].section_name << ")";
                }
                if (variables.size() > 3) report << "...";
                report << "\n";
            }

            if (!forwarded.empty()) {
                report << "    Sample forwards: ";
                for (size_t i = 0; i < std::min(forwarded.size(), size_t(3)); ++i) {
                    if (i > 0) report << ", ";
                    report << forwarded[i].name << " -> " << forwarded[i].forward_dll
                           << "!" << forwarded[i].forward_function;
                }
                if (forwarded.size() > 3) report << "...";
                report << "\n";
            }

            report << "\n";
        }

        return report.str();
    }

    static LIEF::PE::OptionalHeader::SUBSYSTEM detect_apptype(const LIEF::PE::Binary &pe) {
        return pe.optional_header().subsystem();
    }
};

// ============================================================
// Enhanced Loader
// ============================================================
class WineLikeLoader {
private:
    PEAnalyzer pe_analyzer;
    std::unordered_map<std::wstring, LoadedDLL*> loaded_modules; // Use raw pointer

    // Helper to allocate memory
    // Replace allocate_executable_memory with this:
    static void* allocate_executable_memory(size_t size, uintptr_t preferred_addr = 0) {
        void* addr = nullptr;

        if (preferred_addr != 0) {
            // Try to allocate at preferred address first
            addr = mmap(reinterpret_cast<void*>(preferred_addr), size,
                       PROT_READ | PROT_WRITE | PROT_EXEC,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);

            if (addr != MAP_FAILED && addr == reinterpret_cast<void*>(preferred_addr)) {
                trace("Allocated at preferred address 0x", std::to_wstring(preferred_addr));
                return addr;
            } else if (addr != MAP_FAILED) {
                munmap(addr, size);
            }
        }

        // Fallback to any available address
        addr = mmap(nullptr, size, PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

        if (addr == MAP_FAILED) {
            return nullptr;
        }

        trace("Allocated at address 0x", std::to_wstring(reinterpret_cast<uintptr_t>(addr)));
        return addr;
    }

    static void setup_seh() {
        auto handler = [](const int signum) {
            error("SEH: Caught signal ", std::to_wstring(signum));
            std::exit(1);
        };
        signal(SIGSEGV, handler);
    }

    // Fix the relocation function:
    static void apply_relocs_dll(const LIEF::PE::Binary& pe, void* mem, uintptr_t base_addr) {
        if (!pe.has_relocations()) {
            trace("No relocations found - this may cause RIP-relative addressing issues");
            return;
        }

        const uintptr_t original_base = pe.optional_header().imagebase();
        const int64_t delta = static_cast<int64_t>(base_addr) - static_cast<int64_t>(original_base);

        if (delta == 0) {
            trace("Loaded at preferred base - no relocations needed");
            return;
        }

        trace("Applying relocations with delta: 0x", std::to_wstring(delta));

        try {
            size_t reloc_count = 0;
            for (const LIEF::PE::Relocation &reloc_block : pe.relocations()) {
                for (const LIEF::PE::RelocationEntry &entry : reloc_block.entries()) {
                    const uint32_t rva = entry.position();

                    if (rva >= pe.optional_header().sizeof_image() - 8) {
                        continue;
                    }

                    const uintptr_t fix_addr = base_addr + rva;

                    switch (entry.type()) {
                        case LIEF::PE::RelocationEntry::BASE_TYPES::ABS:
                            // No relocation needed
                            break;
                        case LIEF::PE::RelocationEntry::BASE_TYPES::HIGH:
                            *reinterpret_cast<uint16_t*>(fix_addr) += static_cast<uint16_t>((delta >> 16)& 0xFFFF);
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
                            warn("Unsupported relocation type: ", std::to_wstring(static_cast<uint16_t>(entry.type())));
                            break;
                    }
                }
            }
            trace("Applied ", std::to_wstring(reloc_count), " relocations");

        } catch (const std::exception& e) {
            error("Failed to apply relocations: ", e.what());
            throw;
        }
    }

    // Add this validation function
    static bool validate_memory_layout(void* base, size_t size, const LIEF::PE::Binary& pe) {
        trace("Validating memory layout...");

        // Check if we can read/write the allocated memory
        auto test_ptr = static_cast<volatile char*>(base);

        try {
            // Test read access
            volatile char test_read = test_ptr[0];
            test_read = test_ptr[size - 1];

            // Test write access
            test_ptr[0] = 0x42;
            test_ptr[size - 1] = 0x43;

            trace("Memory allocation is valid and accessible");
        } catch (...) {
            error("Memory allocation is not accessible");
            return false;
        }

        // Validate section layout
        for (const auto& section : pe.sections()) {
            uintptr_t section_start = reinterpret_cast<uintptr_t>(base) + section.virtual_address();
            uintptr_t section_end = section_start + section.virtual_size();

            if (section_end > reinterpret_cast<uintptr_t>(base) + size) {
                error("Section " + section.name() + " extends beyond allocated memory");
                return false;
            }
        }

        return true;
    }

    // Add this safe memory reading function:
    bool safe_read_memory(const void* addr, void* buffer, size_t size) {
        if (addr == nullptr || buffer == nullptr || size == 0) {
            return false;
        }

        // Simple heuristic: check if the address is in a readable range
        // This is platform-dependent and may need to be adjusted
        uintptr_t address = reinterpret_cast<uintptr_t>(addr);

        // Attempt to read memory safely
        try {
            std::memcpy(buffer, addr, size);
            return true;
        } catch (...) {
            return false;
        }
    }

    void execute_pe_entry_point_fixed(uintptr_t entry_point_va, void* base_addr) {
        trace("Executing entry point at VA 0x", std::to_wstring(entry_point_va));

        // Install comprehensive signal handlers
        setup_comprehensive_signal_handlers();

        // Set up hang detection
        setup_hang_detection_enhanced(60);  // 60 second timeout

        // Verify entry point is still readable
        uint8_t entry_test[4];
        if (!safe_read_memory(reinterpret_cast<void*>(entry_point_va), entry_test, sizeof(entry_test))) {
            error("Entry point became unreadable before execution!");
            exit(1);
        }

        // Set up a controlled stack

        // Clear the stack area
        // Save current registers for debugging
        try {
            trace("=== CALLING ENTRY POINT NOW ===");
            using MainFunc = void(*)();
            const auto main_func = reinterpret_cast<MainFunc>(entry_point_va);
            main_func();
            trace("=== ENTRY POINT RETURNED ===");
        } catch (const std::exception& e) {
            error("C++ exception in entry point: ", e.what());
            EnhancedBacktrace::print_enhanced_backtrace(L"C++ Exception");
            exit(1);
        } catch (...) {
            error("Unknown exception in entry point");
            EnhancedBacktrace::print_enhanced_backtrace(L"Unknown Exception");
            exit(1);
        }
    }

    void setup_hang_detection_enhanced(int timeout_seconds = 30) {
        signal(SIGALRM, [](int) {
            error("=== HANG DETECTED ===");
            error("Program has been running for more than expected time");
            error("This suggests infinite loop or deadlock");

            EnhancedBacktrace::print_enhanced_backtrace(L"Hang Detection");
            exit(2);  // Exit with code 2 for hang
        });

        alarm(timeout_seconds);
    }

    // 7. Enhanced debugging function to manually trigger backtrace:
    void debug_print_backtrace(const std::wstring& context = L"") {
        EnhancedBacktrace::print_enhanced_backtrace(context);
    }

    // 4. ADD MEMORY PROTECTION CHECKING
    bool check_memory_protections(void* base_addr, size_t size) {
        trace("Checking memory protections for range 0x",
              std::to_wstring(reinterpret_cast<uintptr_t>(base_addr)),
              " - 0x",
              std::to_wstring(reinterpret_cast<uintptr_t>(base_addr) + size));

        // Try to read/write test at various points
        uintptr_t base = reinterpret_cast<uintptr_t>(base_addr);

        // Test points: start, middle, end-8
        std::vector<uintptr_t> test_points = {
            base,
            base + size / 2,
            base + size - 8
        };

        for (uintptr_t test_addr : test_points) {
            uint8_t test_byte;
            bool can_read = safe_read_memory(reinterpret_cast<void*>(test_addr), &test_byte, 1);
            trace("  Address 0x", std::to_wstring(test_addr),
                  " readable: ", (can_read ? "YES" : "NO"));

            if (!can_read) {
                error("Memory protection issue detected at 0x", std::to_wstring(test_addr));
                return false;
            }
        }

        return true;
    }

    void debug_import_table(const LIEF::PE::Binary& pe, uintptr_t base_addr) {
        trace("=== DEBUGGING IMPORT TABLE ===");

        if (!pe.has_imports()) {
            trace("No imports found");
            return;
        }

        for (const auto& import : pe.imports()) {
            trace("Import DLL:", import.name().c_str());

            for (const auto& entry : import.entries()) {
                if (entry.name().empty()) continue;

                uint64_t iat_va = entry.iat_address();
                if (iat_va >= pe.optional_header().imagebase()) {
                    uint32_t iat_rva = static_cast<uint32_t>(iat_va - pe.optional_header().imagebase());

                    if (iat_rva < pe.optional_header().sizeof_image() - 8) {
                        uintptr_t* iat_ptr = reinterpret_cast<uintptr_t*>(base_addr + iat_rva);
                        uintptr_t resolved_addr = *iat_ptr;

                        trace("  ", entry.name().c_str(),
                              " IAT[0x", std::to_wstring(iat_rva), "] = 0x", std::to_wstring(resolved_addr));

                        // Check if resolved address is valid
                        if (resolved_addr < 0x1000) {
                            error("  INVALID: Address too low!");
                        } else if (resolved_addr == 0xDEADBEEF || resolved_addr == 0) {
                            error("  UNRESOLVED: Address is placeholder or null");
                        }
                    }
                }
            }
        }
    }

    // 3. RELOCATION ISSUES - Verify relocations were applied correctly
    static void debug_relocations(const LIEF::PE::Binary& pe, void* mem, uintptr_t base_addr) {
        if (!pe.has_relocations()) {
            trace("No relocations to debug");
            return;
        }

        uintptr_t original_base = pe.optional_header().imagebase();
        int64_t delta = static_cast<int64_t>(base_addr) - static_cast<int64_t>(original_base);

        trace("=== DEBUGGING RELOCATIONS ===");
        trace("Original base: 0x", std::to_wstring(original_base));
        trace("Actual base: 0x", std::to_wstring(base_addr));
        trace("Delta: 0x", std::to_wstring(delta));

        size_t reloc_count = 0;
        for (const auto& reloc_block : pe.relocations()) {
            for (const auto& entry : reloc_block.entries()) {
                uint32_t rva = entry.position();

                if (rva >= pe.optional_header().sizeof_image() - 8) {
                    continue;
                }

                uintptr_t fix_addr = base_addr + rva;

                // Read the relocated value
                uint64_t relocated_value = 0;
                switch (entry.type()) {
                    case LIEF::PE::RelocationEntry::BASE_TYPES::DIR64:
                        relocated_value = *reinterpret_cast<uint64_t*>(fix_addr);
                        break;
                    case LIEF::PE::RelocationEntry::BASE_TYPES::HIGHLOW:
                        relocated_value = *reinterpret_cast<uint32_t*>(fix_addr);
                        break;
                    default:
                        continue;
                }

                // Check if the relocated value makes sense
                if (relocated_value < 0x1000) {
                    error("Suspicious relocation at RVA 0x", std::to_wstring(rva),
                          " resulted in low address: 0x", std::to_wstring(relocated_value));
                }

                reloc_count++;
                if (reloc_count > 10) break; // Don't spam too much
            }
        }
    }


    // Issue 6: Stack setup and calling convention issues
    // Add proper stack setup before calling entry point
    void setup_execution_environment() {
        // Set up floating point environment
        // Initialize x87 FPU control word
        uint16_t fpu_cw = 0x037F; // Standard Windows FPU control word
        asm volatile ("fldcw %0" : : "m" (fpu_cw));

        // Set up SSE control and status register
        uint32_t mxcsr = 0x1F80; // Standard Windows MXCSR
        asm volatile ("ldmxcsr %0" : : "m" (mxcsr));

        // Clear direction flag (required for string operations)
        asm volatile ("cld");
    }

    static void init_tls(const LIEF::PE::Binary& pe, void* mem, uintptr_t base_addr) {
        if (!pe.has_tls()) {
            trace("PE has no TLS, skipping TLS initialization");
            return;
        }

        try {
            const auto& tlsInfo = pe.tls();
            if (!tlsInfo) {
                if (pe.has_tls()) {
                    warn("PE has TLS directory but failed to retrieve TLS info");
                }
                return;
            }
            size_t callback_count = 0;

            // Initialize TLS data
            auto [fst, snd] = tlsInfo->addressof_raw_data();
            const uint64_t image_base = pe.optional_header().imagebase();

            if (fst != 0 && snd != 0) {
                if (const auto rva_start = static_cast<uint32_t>(fst - image_base); rva_start < pe.optional_header().sizeof_image()) {
                    const auto tls_data_dest = reinterpret_cast<void*>(base_addr + rva_start);
                    std::memcpy(tls_data_dest, reinterpret_cast<const void*>(base_addr + rva_start),
                                static_cast<size_t>(snd));
                    trace("Initialized TLS data of size ", std::to_wstring(snd), " bytes");
                }
            }

            trace("yeee");

            // Execute TLS callbacks
            for (const uint64_t callback_va : tlsInfo->callbacks()) {
                // just execute the callback
                if (callback_va == 0) {
                    continue;
                }
                trace("Executing TLS callback at VA 0x", std::to_wstring(callback_va));
                const uintptr_t callback_addr = callback_va;
                if (callback_addr < image_base || callback_addr >= image_base + pe.optional_header().sizeof_image()) {
                    warn("TLS callback address out of bounds: 0x" + std::to_string(callback_addr));
                    continue;
                }
                using TlsCallback = void(*)(void*, uint32_t, void*);
                const auto callback = reinterpret_cast<TlsCallback>(base_addr + (callback_addr - image_base));
                callback(mem, 1 /* DLL_PROCESS_ATTACH */, nullptr);
                callback_count++;
            }

            if (callback_count > 0) {
                trace("Executed ", std::to_wstring(callback_count), " TLS callbacks");
            }
        } catch (const std::exception& e) {
            error("Failed to initialize TLS: ", e.what());
        }
    }

    // Enhanced resolve_forwarded_export method - supports emulated DLLs
    uintptr_t resolve_forwarded_export(const std::wstring& dll_name, const std::wstring& func_name) {
        // Attempt to resolve a forwarded export (e.g. KERNEL32.DLL!HeapAlloc forwarded to NTDLL.DLL!RtlAllocateHeap)
        std::wstring dll_lower = dll_name;
        std::ranges::transform(dll_lower, dll_lower.begin(), ::tolower);

        // Check loaded native DLLs for forwarded exports
        if (const auto it = loaded_modules.find(dll_lower); it != loaded_modules.end()) {
            const auto* loaded_dll = it->second;
            // Check if this specific export is forwarded in the loaded DLL
            if (loaded_dll->dll_info.enhanced_exports.contains(func_name)) {
                const auto& export_info = loaded_dll->dll_info.enhanced_exports.at(func_name);
                if (export_info.is_forwarded) {
                    return get_proc_address(export_info.forward_dll, export_info.forward_function);
                }
            }
        }

        // Check PE analyzer's forwarded exports (existing logic)
        if (!pe_analyzer.forwarded_exports.contains(dll_lower)) {
            return 0;
        }

        for (const auto& forward : pe_analyzer.forwarded_exports[dll_lower]) {
            if (forward.original_name == func_name) {
                // Recursively resolve the target DLL/function
                return get_proc_address(forward.target_dll, forward.target_function);
            }
        }

        // Not found
        return 0;
    }

    // NEW: Enhanced get_proc_address method with function/data distinction
    std::pair<bool, uintptr_t> get_proc_address_enhanced(const std::wstring& dll_name, const std::wstring& func_name) {
        std::wstring dll_lower = dll_name;
        std::ranges::transform(dll_lower, dll_lower.begin(), ::tolower);
        trace("Getting enhanced proc address for ", dll_lower.c_str(), "!", func_name.c_str());

        std::wstring func_name_lower = func_name;
        std::ranges::transform(func_name_lower, func_name_lower.begin(), ::tolower);

        // Try specific emulated module APIs first
        trace("Checking specific emulated module APIs for \"", dll_lower.c_str(), "\"");
        if (dll_lower == L"kernel32.DLL") {
            auto kernel32_exports = Kernel32::get_exports_detailed();
            if (const auto it = kernel32_exports.find(func_name); it != kernel32_exports.end()) {
                trace("Found Kernel32 export using original case lookup: ", func_name.c_str());
                return std::make_pair(it->second.is_function, it->second.address);
            }
        }
        else if (dll_lower.contains(L"ucrtbase.DLL")) {
            auto ucrtbase_exports = UCRTBase::get_exports_detailed();
            if (const auto it = ucrtbase_exports.find(func_name_lower); it != ucrtbase_exports.end()) {
                trace("Found UCRTBase export using lowercase lookup: ", func_name_lower.c_str());
                return std::make_pair(it->second.is_function, it->second.address);
            }
            else {
                // Try original case if lowercase lookup failed
                if (const auto it_orig = ucrtbase_exports.find(func_name); it_orig != ucrtbase_exports.end()) {
                    trace("Found UCRTBase export using original case lookup: ", func_name.c_str());
                    return std::make_pair(it_orig->second.is_function, it_orig->second.address);
                }
                else {
                    trace("UCRTBase export not found: ", func_name.c_str());
                }
            }
        }
        else if (dll_lower == L"vcruntime140.DLL") {
            auto vcruntime_exports = VCRuntime140::get_exports_detailed();
            if (const auto it = vcruntime_exports.find(func_name); it != vcruntime_exports.end()) {
                trace("Found VCRuntime140 export using original case lookup: ", func_name.c_str());
                return std::make_pair(it->second.is_function, it->second.address);
            }
        }
        /*if (dll_lower == "vcruntime140.DLL") {
            auto vcruntime_exports = VCRuntime140::get_exports_detailed();
            if (auto it = vcruntime_exports.find(func_name); it != vcruntime_exports.end()) {
                return std::make_pair(it->second.is_function, it->second.address);
            }
        }*/

        // Try loaded native DLLs with enhanced export lookup
        if (const auto it = loaded_modules.find(dll_lower); it != loaded_modules.end()) {
            const auto* loaded_dll = it->second;
            auto export_info = loaded_dll->get_export(func_name);
            if (export_info.second != 0) {  // Found export
                return export_info;
            }
        }

        // Check for forwarded exports BEFORE attempting to load missing DLL
        if (const uintptr_t forwarded_addr = resolve_forwarded_export(dll_lower, func_name); forwarded_addr != 0) {
            return std::make_pair(true, forwarded_addr);  // Assume forwarded exports are functions
        }

        // If not found and not already analyzed, analyze the DLL first
        if (!pe_analyzer.analyzed_dlls.contains(dll_lower)) {
            if (const auto dll_path = pe_analyzer.find_dll(dll_lower); !dll_path.empty()) {
                trace("Analyzing missing DLL for get_proc_address: ", dll_lower.c_str());
                pe_analyzer.analyze_pe_file(dll_path, true);

                // After analysis, check forwarded exports again
                if (const uintptr_t forwarded_addr = resolve_forwarded_export(dll_lower, func_name); forwarded_addr != 0) {
                    return std::make_pair(true, forwarded_addr);
                }
            }
        }

        // Load the DLL if not found
        trace("Attempting to load missing DLL: ", dll_lower);
        if (const auto dll_path = pe_analyzer.find_dll(dll_lower); !dll_path.empty()) {
            if (auto* loaded_dll = load_dll_pe(dll_path); loaded_dll) {
                auto export_info = loaded_dll->get_export(func_name);
                if (export_info.second != 0) {
                    trace("Found export in newly loaded DLL: ", dll_lower.c_str(), "!", func_name.c_str());
                    return export_info;
                }

                // Check forwarded exports in newly loaded DLL
                if (const uintptr_t forwarded_addr = resolve_forwarded_export(dll_lower, func_name); forwarded_addr != 0) {
                    trace("Resolved forwarded export in newly loaded DLL: ", dll_lower.c_str(), "!", func_name.c_str());
                    return std::make_pair(true, forwarded_addr);
                }
                trace("Export not found in newly loaded DLL: ", dll_lower.c_str(), "!", func_name.c_str());
            }
        }

        return std::make_pair(false, 0);  // Not found
    }

    // Enhanced get_proc_address method using the emulated function registry:
    uintptr_t get_proc_address(const std::wstring& dll_name, const std::wstring& func_name) {
        auto [is_function, address] = get_proc_address_enhanced(dll_name, func_name);
        return address;
    }

    std::vector<ImportInfo> import_table;

    void resolve_imports(const LIEF::PE::Binary& pe, const uintptr_t base_addr) {
        if (!pe.has_imports()) {
            return;
        }

        try {
            size_t resolved_imports = 0;
            size_t emulated_imports = 0;
            size_t total_imports = 0;
            trace("Resolving imports...");
            for (const LIEF::PE::Import import : pe.imports()) {
                std::wstring dll_name = converter.from_bytes(import.name());
                std::ranges::transform(dll_name, dll_name.begin(), ::tolower);
                trace("Resolving imports from ", dll_name.c_str());

                for (const LIEF::PE::ImportEntry entry : import.entries()) {
                    total_imports++;
                    trace("  Import: ", entry.name().c_str(), " (ordinal ", std::to_wstring(entry.ordinal()), ") at IAT 0x",
                          std::to_wstring(entry.iat_address()));

                    if (entry.name().empty() && strlen(entry.name().c_str()) == 0 && entry.ordinal() == 0) {
                        warn("Import entry has neither name nor ordinal, skipping");
                        continue;
                    }

                    const std::wstring name = entry.name().empty() ? std::to_wstring(entry.ordinal()) : converter.from_bytes(entry.name());
                    // trace the name
                    trace("    Resolving ", dll_name.c_str(), "!", name.c_str());
                    // NEW: Use enhanced proc address resolution to get function/data info
                    auto [is_function, func_address] = get_proc_address_enhanced(dll_name, name);

                    if (func_address != 0) {
                        bool is_emulated = false;
                        // Check if it's emulated using get_exports_detailed
                        if (dll_name == L"kernel32.DLL") {
                            auto kernel32_exports = Kernel32::get_exports_detailed();
                            is_emulated = kernel32_exports.contains(name);
                        } else if (dll_name == L"ucrtbase.DLL") {

                            auto ucrtbase_exports = UCRTBase::get_exports_detailed();
                            is_emulated = ucrtbase_exports.contains(name);
                        }
                        else if (dll_name == L"vcruntime140.DLL") {
                            auto vcruntime_exports = VCRuntime140::get_exports_detailed();
                            is_emulated = vcruntime_exports.contains(name);
                        }

                        trace("Resolved ", dll_name.c_str(), "!", name.c_str(), " to 0x", reinterpret_cast<void*>(func_address),
                              is_emulated ? " (emulated)" : " (native)",
                              is_function ? " [FUNCTION]" : " [DATA]");
                        emulated_imports += is_emulated;

                        // Record import information with function/data distinction
                        ImportInfo import_info;
                        import_info.dll_name = dll_name;
                        import_info.function_name = name;
                        import_info.ordinal = entry.ordinal();
                        import_info.address = entry.iat_address();
                        import_info.is_resolved = true;
                        import_info.is_emulated = is_emulated;
                        import_info.is_function = is_function;  // NEW: Store function/data info
                        import_table.push_back(import_info);

                        // CRITICAL: Update IAT with proper handling for functions vs data
                        if (const uint64_t iat_va = entry.iat_address(); iat_va >= pe.optional_header().imagebase()) {
                            if (const auto iat_rva = static_cast<uint32_t>(iat_va - pe.optional_header().imagebase());
                                iat_rva < pe.optional_header().sizeof_image() - 8) {

                                const auto ptr = reinterpret_cast<uintptr_t*>(base_addr + iat_rva);
                                if (!func_address || func_address < 0x10000) {
                                    error("Attempting to write null address to IAT for ", dll_name, "!", name);
                                    continue;
                                }
                                else if (func_address == 0xDEADBEEF) {
                                    error("Attempting to write placeholder address to IAT for ", dll_name, "!", name);
                                    continue;
                                }
                                else if (func_address > pe.optional_header().sizeof_image() - 8) {
                                    warn("Warning: Unusually high function address for ", dll_name, "!", name);
                                }
                                if (is_function) {
                                    // For functions: store the function address directly
                                    *ptr = func_address;
                                    trace("    IAT[", std::to_wstring(iat_rva), "] = 0x",
                                          reinterpret_cast<void*>(func_address), " (function)");
                                } else {
                                    // For data: the address IS the data location, store it directly
                                    // The PE will dereference this to access the actual data
                                    *ptr = func_address;
                                    trace("    IAT[", std::to_wstring(iat_rva), "] = 0x",
                                          reinterpret_cast<void*>(func_address), " (data pointer)");
                                }

                                resolved_imports++;
                            } else {
                                error("IAT address out of bounds for ", dll_name, "!", name);
                            }
                        }
                    } else {
                        error("Failed to resolve ", dll_name, "!", name);
                        ImportInfo import_info;
                        import_info.dll_name = dll_name;
                        import_info.function_name = name;
                        import_info.ordinal = entry.ordinal();
                        import_info.address = entry.iat_address();
                        import_info.is_resolved = false;
                        import_info.is_emulated = false;
                        import_info.is_function = false;  // Default to false for unresolved
                        import_table.push_back(import_info);
                    }
                }
            }

            trace("Import resolution: ", std::to_wstring(resolved_imports), "/",
                  std::to_wstring(total_imports), " resolved, ",
                  std::to_wstring(emulated_imports), " emulated");

        } catch (const std::exception& e) {
            error("Failed to resolve imports: ", e.what());
        }
    }

public:
    WineLikeLoader() = default;

    // Destructor to clean up all loaded modules
    ~WineLikeLoader() {
        cleanup_modules();
        // munmap memory if needed
    }

    void cleanup_modules() {
        for (auto& [name, DLL] : loaded_modules) {
            delete DLL;
        }
        loaded_modules.clear();
    }

    // NEW: Enhanced load_dll_pe method with proper export table building
    LoadedDLL* load_dll_pe(const fs::path& dll_path) {
        std::wstring dll_name = dll_path.filename().wstring();
        std::ranges::transform(dll_name, dll_name.begin(), ::tolower);

        // Check if already loaded
        if (const auto it = loaded_modules.find(dll_name); it != loaded_modules.end()) {
            trace(dll_name.c_str(), " already loaded at 0x",
                  std::to_wstring(it->second->base_address));
            return it->second;
        }

        try {
            // Analyze DLL (this will populate forwarded_exports)
            const auto dll_info = pe_analyzer.analyze_pe_file(dll_path, true);
            LIEF::PE::Binary* pe_binary = LIEF::PE::Parser::parse(dll_path.string()).release();
            if (!pe_binary) {
                error("Failed to parse PE binary: " + dll_path.string());
                return nullptr;
            }

            // Calculate required size
            size_t size = pe_binary->optional_header().sizeof_image();
            if (size < 4096) {
                size = 4096;
            }
            size = (size + 4095) & ~4095; // Page align

            // Allocate memory
            void* memory_map = allocate_executable_memory(size);
            if (!memory_map) {
                error("Failed to allocate memory for DLL");
                delete pe_binary;
                return nullptr;
            }

            const auto base_addr = reinterpret_cast<uintptr_t>(memory_map);

            // Initialize memory
            memset(memory_map, 0, size);

            // Create LoadedDLL object
            auto* loaded_dll = new LoadedDLL();
            loaded_dll->dll_info = dll_info;
            loaded_dll->base_address = base_addr;
            loaded_dll->memory_map = memory_map;
            loaded_dll->pe_binary = pe_binary;
            loaded_dll->allocated_size = size;

            // Map sections
            for (const auto& section : loaded_dll->pe_binary->sections()) {
                const uint32_t sect_rva = section.virtual_address();
                const uintptr_t sect_va = base_addr + sect_rva;
                auto raw_data = section.content();

                if (sect_rva + raw_data.size() <= size) {
                    memcpy(reinterpret_cast<void*>(sect_va), raw_data.data(), raw_data.size());
                    trace("Mapped section ", section.name().c_str(), " at RVA 0x",
                          std::to_wstring(sect_rva), ", size ", std::to_wstring(raw_data.size()));
                } else {
                    error("Section " + section.name() + " would overflow allocated memory");
                    delete loaded_dll;
                    return nullptr;
                }
            }

            apply_relocs_dll(*loaded_dll->pe_binary, loaded_dll->memory_map, base_addr);
            loaded_modules[dll_name] = loaded_dll;

            // IMPROVED: Load ALL transitive dependencies recursively
            // First, get all dependencies of the current DLL (deps of deps...)
            std::unordered_set<std::wstring> all_transitive_deps = pe_analyzer.analyze_dependencies_recursive(dll_name, 15);

            // Remove self from dependencies
            all_transitive_deps.erase(dll_name);

            // Load dependencies in the proper order (depth-first to handle dependency chains)
            std::function<void(const std::wstring&, std::unordered_set<std::wstring>&)> load_deps_recursively;
            load_deps_recursively = [&](const std::wstring& current_dep, std::unordered_set<std::wstring>& visited_deps) {
                if (visited_deps.contains(current_dep) || loaded_modules.contains(current_dep)) {
                    return; // Already processed or loaded
                }

                visited_deps.insert(current_dep);

                // Find the DLL file
                auto dep_path = pe_analyzer.find_dll(current_dep);
                if (dep_path.empty()) {
                    warn("Dependency ", current_dep, " not found for ", dll_name);
                    return;
                }

                // Analyze this dependency to get its dependencies
                auto dep_info = pe_analyzer.analyze_pe_file(dep_path, true);

                // Load its dependencies first (depth-first)
                for (const auto& sub_dep : dep_info.dependencies) {
                    if (!visited_deps.contains(sub_dep) && !loaded_modules.contains(sub_dep)) {
                        load_deps_recursively(sub_dep, visited_deps);
                    }
                }

                // Now load this dependency itself
                if (!loaded_modules.contains(current_dep)) {
                    trace("Loading transitive dependency: ", current_dep.c_str(), " for ", dll_name.c_str());
                    load_dll_pe(dep_path);
                }
            };

            // Load all transitive dependencies
            std::unordered_set<std::wstring> visited_in_loading;
            for (const auto& dep : all_transitive_deps) {
                load_deps_recursively(dep, visited_in_loading);
            }

            // NEW: Build enhanced export table with function/data distinction
            if (loaded_dll->pe_binary->has_exports()) {
                auto enhanced_exports = PEAnalyzer::build_enhanced_exports(*loaded_dll->pe_binary, base_addr);

                for (const auto& [export_name, export_entry] : enhanced_exports) {
                    if (!export_entry.is_forwarded) {
                        // Store in enhanced export addresses with function/data distinction
                        loaded_dll->enhanced_export_addresses[export_name] =
                            std::make_pair(export_entry.is_function, export_entry.address);

                        // Also store in old format for backward compatibility
                        loaded_dll->export_addresses[export_name] = export_entry.address;
                    }
                }

                trace("Built enhanced export table with ", std::to_wstring(enhanced_exports.size()),
                      " total exports (including forwarded)");

                // Log export type breakdown
                size_t function_count = 0, data_count = 0, forwarded_count = 0;
                for (const auto& [name, entry] : enhanced_exports) {
                    if (entry.is_forwarded) {
                        forwarded_count++;
                    } else if (entry.is_function) {
                        function_count++;
                    } else {
                        data_count++;
                    }
                }
                trace("Export breakdown: ", std::to_wstring(function_count), " functions, ",
                      std::to_wstring(data_count), " data, ", std::to_wstring(forwarded_count), " forwarded");
            }

            // Resolve imports
            resolve_imports(*loaded_dll->pe_binary, base_addr);
            init_tls(*loaded_dll->pe_binary, loaded_dll->memory_map, base_addr);

            trace("Initialized TLS for ", dll_name.c_str());

            // Call DllMain if needed
            const bool is_dll = (loaded_dll->pe_binary->header().characteristics() &
                          static_cast<uint16_t>(HEADER_CHARACTERISTICS::DLL)) != 0;

            if (is_dll) {
                if (const uint32_t entry_rva = loaded_dll->pe_binary->optional_header().addressof_entrypoint(); entry_rva) {
                    if (entry_rva >= loaded_dll->pe_binary->optional_header().sizeof_image()) {
                        warn("Entry point RVA out of bounds for ", dll_name);
                        return loaded_dll;
                    }
                    try {
                        using DllMainFunc = BOOL(*)(HINSTANCE, DWORD, LPVOID);
                        const auto entry_point = reinterpret_cast<DllMainFunc>(base_addr + entry_rva);
                        trace("Calling DllMain for ", dll_name.c_str(), " at 0x",
                              std::to_wstring(reinterpret_cast<uintptr_t>(entry_point)));
                        const BOOL ret = entry_point(reinterpret_cast<HINSTANCE>(base_addr), DLL_PROCESS_ATTACH, nullptr);
                        trace("DllMain returned ", ret ? "TRUE" : "FALSE");
                    } catch (const std::exception& e) {
                        error("DllMain execution failed for ", dll_name, ": ", e.what());
                    }
                }
            }

            // Exception table registration code remains the same...
            if (loaded_dll && loaded_dll->base_address && loaded_dll->allocated_size > 0) {
                EnhancedBacktrace::register_pe_module(
                    dll_name,
                    loaded_dll->base_address,
                    loaded_dll->allocated_size,
                    loaded_dll  // Pass the LoadedDLL to extract export info
                );

                trace("Registered PE module ", dll_name.c_str(), " for enhanced backtrace");
            }

            return loaded_dll;

        } catch (const std::exception& e) {
            error("Failed to load DLL " + dll_path.string() + ": " + e.what());
            return nullptr;
        }
    }

    // NEW: Enhanced API to get export information with function/data distinction
    std::pair<bool, uintptr_t> get_dll_export(const std::wstring& dll_name, const std::wstring& export_name) {
        std::wstring dll_lower = dll_name;
        std::ranges::transform(dll_lower, dll_lower.begin(), ::tolower);

        if (const auto it = loaded_modules.find(dll_lower); it != loaded_modules.end()) {
            return it->second->get_export(export_name);
        }
        return std::make_pair(false, 0);
    }

    // NEW: Get all exports from a loaded DLL with function/data distinction
    std::unordered_map<std::wstring, std::pair<bool, uintptr_t>> get_dll_exports(const std::wstring& dll_name) {
        std::wstring dll_lower = dll_name;
        std::ranges::transform(dll_lower, dll_lower.begin(), ::tolower);

        if (const auto it = loaded_modules.find(dll_lower); it != loaded_modules.end()) {
            return it->second->enhanced_export_addresses;
        }
        return {};
    }

    // NEW: Check if a DLL export is a function
    bool is_dll_function_export(const std::wstring& dll_name, const std::wstring& export_name) {
        std::wstring dll_lower = dll_name;
        std::ranges::transform(dll_lower, dll_lower.begin(), ::tolower);

        if (const auto it = loaded_modules.find(dll_lower); it != loaded_modules.end()) {
            return it->second->is_function_export(export_name);
        }
        return false;
    }

    // Also improve the analyze_all_dependencies method:
    void analyze_all_dependencies(const fs::path& main_pe_path) {
        trace("Starting comprehensive dependency analysis...");

        // Analyze the main PE file
        auto main_info = pe_analyzer.analyze_pe_file(main_pe_path, false);

        // Get ALL dependencies recursively (this will include ucrtbase.DLL)
        std::unordered_set<std::wstring> all_deps;
        for (const auto& dep : main_info.dependencies) {
            auto recursive_deps = pe_analyzer.analyze_dependencies_recursive(dep);
            all_deps.insert(recursive_deps.begin(), recursive_deps.end());

            // Also add the direct dependency itself
            all_deps.insert(dep);
        }

        // Additionally, analyze dependencies of dependencies
        for (std::unordered_set<std::wstring> to_analyze = all_deps; const auto& dep : to_analyze) {
            if (auto dll_path = pe_analyzer.find_dll(dep); !dll_path.empty()) {
                for (auto dep_info = pe_analyzer.analyze_pe_file(dll_path, true); const auto& sub_dep : dep_info.dependencies) {
                    all_deps.insert(sub_dep);
                }
            }
        }

        trace("Dependency analysis complete: ", std::to_wstring(all_deps.size()), " total dependencies");

        // Generate and save a report
        auto report = pe_analyzer.generate_dependency_report();
        auto report_path = main_pe_path;
        report_path.replace_extension(".dependency_report.txt");

        try {
            if (std::wfstream report_file(report_path); report_file) {
                report_file << report;
                trace("Dependency report saved to: ", report_path.wstring());
            }
        } catch (const std::exception& e) {
            warn("Failed to save dependency report: ", converter.from_bytes(e.what()));
        }

        // Print summary to console
        std::wcout << "\n" << std::wstring(60, '=') << "\n";
        std::wcout << "DEPENDENCY ANALYSIS SUMMARY\n";
        std::wcout << std::wstring(60, '=') << "\n";
        std::wcout << "Main PE: " << main_pe_path.filename().wstring() << "\n";
        std::wcout << "Total dependencies: " << all_deps.size() << "\n";

        // Print all found dependencies for debugging
        std::wcout << "\nAll discovered dependencies:\n";
        for (const auto& dep : all_deps) {
            std::wcout << "  - " << dep << "\n";
        }

        size_t emulated_apis = 0, native_apis = 0, unresolved_apis = 0;
        for (const auto& import : import_table) {
            if (import.is_emulated) emulated_apis++;
            else if (import.is_resolved) native_apis++;
            else {
                unresolved_apis++;
            }
            trace("Unresolved import: ", import.dll_name.c_str(), "!", import.function_name.c_str());
        }

        std::wcout << "Emulated APIs: " << emulated_apis << "\n";
        std::wcout << "Native APIs: " << native_apis << "\n";
        std::wcout << "Unresolved APIs: " << unresolved_apis << "\n";

        // Show circular dependencies if any
        if (auto cycles = pe_analyzer.detect_circular_dependencies(); !cycles.empty()) {
            std::wcout << L"⚠️  Circular dependencies detected: " << cycles.size() << "\n";
            for (size_t i = 0; i < std::min(cycles.size(), static_cast<size_t>(3)); ++i) {
                std::wcout << "   ";
                for (size_t j = 0; j < cycles[i].size(); ++j) {
                    std::wcout << cycles[i][j];
                    if (j < cycles[i].size() - 1) std::wcout << " -> ";
                }
                std::wcout << "\n";
            }
        }

        std::wcout << "\nIMPORTED FUNCTIONS PER DLL:\n";
        for (const auto& [dll_name, dll_info] : pe_analyzer.analyzed_dlls) {
            if (dll_info.imports.empty()) continue;
            std::wcout << "  " << dll_name << " imports:\n";
            for (const auto& [dep, funcs] : dll_info.imports) {
                std::wcout << "    from " << dep << ":\n";
                for (const auto& func : funcs) {
                    std::wcout << "      - " << func << "\n";
                }
            }
        }

        std::wcout << L"📄 Full report: " << report_path.wstring() << "\n";
        std::wcout << std::wstring(60, '=') << "\n";
    }

    static std::vector<RUNTIME_FUNCTION> extract_exception_table(const LIEF::PE::Binary& pe) {
        std::vector<RUNTIME_FUNCTION> functions;

        if (!pe.data_directory(LIEF::PE::DataDirectory::TYPES::EXCEPTION_TABLE)) {
            return functions;
        }

        const auto& exception_dir = pe.data_directory(LIEF::PE::DataDirectory::TYPES::EXCEPTION_TABLE);
        if (exception_dir->RVA() == 0 || exception_dir->size() == 0) {
            return functions;
        }

        // Find section containing exception table and extract RUNTIME_FUNCTION entries
        if (const auto* section = pe.section_from_rva(exception_dir->RVA())) {
            const auto section_data = section->content();
            const uint32_t offset_in_section = exception_dir->RVA() - section->virtual_address();

            const size_t entry_count = exception_dir->size() / sizeof(RUNTIME_FUNCTION);
            const auto* runtime_functions = reinterpret_cast<const RUNTIME_FUNCTION*>(
                section_data.data() + offset_in_section
            );

            functions.assign(runtime_functions, runtime_functions + entry_count);
        }

        return functions;
    }

    static void setup_process_signal_handlers() {
        struct sigaction sa{};
        memset(&sa, 0, sizeof(sa));
        sa.sa_sigaction = [](int signum, siginfo_t* info, void* context) {
            auto* ucontext = static_cast<ucontext_t*>(context);
            uintptr_t fault_addr = reinterpret_cast<uintptr_t>(info->si_addr);
            uintptr_t ip = 0;
        };
        sa.sa_flags = SA_SIGINFO;
        sigemptyset(&sa.sa_mask);
        sigaction(SIGSEGV, &sa, nullptr);
        sigaction(SIGFPE, &sa, nullptr);
        sigaction(SIGILL, &sa, nullptr);
    }

    // Add this function to set proper section permissions
    static void set_section_permissions(void* base_addr, const LIEF::PE::Binary& pe) {
        for (const LIEF::PE::Section& section : pe.sections()) {
            uintptr_t section_start = reinterpret_cast<uintptr_t>(base_addr) + section.virtual_address();
            size_t section_size = std::max(section.virtual_size(), static_cast<uint32_t>(section.sizeof_raw_data()));

            // Ensure the section size is page-aligned
            section_size = (section_size + 4095) & ~4095;

            int prot = PROT_READ; // Always readable
            const uint32_t chars = section.characteristics();

            // Be more permissive initially for debugging
            if (chars & 0x20000000) prot |= PROT_EXEC;  // IMAGE_SCN_MEM_EXECUTE
            if (chars & 0x80000000) prot |= PROT_WRITE; // IMAGE_SCN_MEM_WRITE

            // For .text sections, ensure they're executable
            std::wstring section_name = converter.from_bytes(section.name());
            std::ranges::transform(section_name, section_name.begin(), ::tolower);
            if (section_name == L".text" || section_name.find(L"text") != std::wstring::npos) {
                prot |= PROT_EXEC;
            }

            if (mprotect(reinterpret_cast<void*>(section_start), section_size, prot) != 0) {
                error("Failed to set protection for section ", section.name().c_str(),
                      ": ", strerror(errno));
            } else {
                trace("Set protection for ", section.name().c_str(), ": ",
                      (prot & PROT_READ ? "R" : ""),
                      (prot & PROT_WRITE ? "W" : ""),
                      (prot & PROT_EXEC ? "X" : ""));
            }
        }
    }

    void* load_pe(const std::wstring& path, const int argc, char** argv) {
        const fs::path pe_path(path);
        trace("Loading PE file: ", pe_path.wstring());

        // Perform dependency analysis first
        analyze_all_dependencies(pe_path);

        LIEF::PE::Binary* pe_binary = LIEF::PE::Parser::parse(pe_path.string()).release();
        if (!pe_binary) {
            error("Invalid PE file: ", pe_path.wstring());
            return nullptr;
        }

        setup_seh();

        // Calculate memory requirements
        size_t size = pe_binary->virtual_size();
        if (size < 4096) {
            size = 4096;
        }
        size = (size + 4095) & ~4095; // Page align

        uintptr_t preferred_base = pe_binary->optional_header().imagebase();
        void* memory_map = allocate_executable_memory(size, preferred_base);

        if (!memory_map) {
            error("Failed to allocate memory");
            delete pe_binary;
            return nullptr;
        }

        const auto base_addr = reinterpret_cast<uintptr_t>(memory_map);

        // Validate the memory allocation
        if (!validate_memory_layout(memory_map, size, *pe_binary)) {
            munmap(memory_map, size);
            delete pe_binary;
            return nullptr;
        }

        // Clear memory
        memset(memory_map, 0, size);

        // Replace your section mapping code with this:
        try {
            for (const auto& section : pe_binary->sections()) {
                const uint32_t virtual_addr = section.virtual_address();
                const uint32_t virtual_size = section.virtual_size();
                const uint32_t raw_size = static_cast<uint32_t>(section.sizeof_raw_data());

                // Validate section bounds
                if (virtual_addr >= size || virtual_addr + virtual_size > size) {
                    error("Section " + section.name() + " exceeds image bounds");
                    continue;
                }

                const uintptr_t dest_addr = base_addr + virtual_addr;
                auto raw_data = section.content();

                trace("Mapping section ", section.name().c_str(),
                      " VA=0x", std::to_wstring(virtual_addr),
                      " VSize=", std::to_wstring(virtual_size),
                      " RawSize=", std::to_wstring(raw_size));

                // Clear the entire virtual section first
                memset(reinterpret_cast<void*>(dest_addr), 0, virtual_size);

                // Copy raw data if it exists
                if (!raw_data.empty() && raw_size > 0) {
                    size_t copy_size = std::min(static_cast<size_t>(raw_size), raw_data.size());
                    copy_size = std::min(copy_size, static_cast<size_t>(virtual_size));

                    memcpy(reinterpret_cast<void*>(dest_addr), raw_data.data(), copy_size);
                    trace("Copied ", std::to_wstring(copy_size), " bytes to section");
                }
            }

            // Apply section permissions AFTER mapping all sections
            set_section_permissions(memory_map, *pe_binary);

        } catch (const std::exception& e) {
            error("Section mapping failed: ",  converter.from_bytes(e.what()));
            return nullptr;
        }

        // Apply relocations
        try {
            apply_relocs_dll(*pe_binary, memory_map, base_addr);
            // After allocation, verify the claim:
            trace("Base address verification:");
            trace("  Requested preferred base: 0x", std::to_wstring(preferred_base));
            trace("  Actually allocated at: 0x", std::to_wstring(base_addr));
            trace("  Addresses match: ", (base_addr == preferred_base ? "YES" : "NO"));

            // Double-check by reading the PE header in memory
            if (base_addr == preferred_base) {
                // Verify the DOS header is intact
                if (const auto* dos_header = reinterpret_cast<const LIEF::PE::DosHeader*>(base_addr); dos_header->magic() != 0x5A4D) { // "MZ"
                    error("DOS header corrupted - magic = 0x", std::to_wstring(dos_header->magic()));
                } else {
                    trace("DOS header intact in loaded image");
                }
            }

            uint32_t entry_point_rva = pe_binary->optional_header().addressof_entrypoint();
            if (entry_point_rva != 0) {
                trace("Entry point found at RVA 0x", std::to_wstring(entry_point_rva));
            } else {
                error("No entry point found in PE file");
            }
            trace("Applied relocations for main executable");
        } catch (const std::exception& e) {
            error("Relocation failed: " ,  converter.from_bytes(e.what()));
            delete pe_binary;
            munmap(memory_map, size);
            return nullptr;
        }

        // Resolve imports
        try {
            resolve_imports(*pe_binary, base_addr);
            trace("Resolved imports for main executable");
        } catch (const std::exception& e) {
            error("Import resolution failed: " ,  converter.from_bytes(e.what()));
            delete pe_binary;
            munmap(memory_map, size);
            return nullptr;
        }

        // Initialize TLS
        try {
            init_tls(*pe_binary, memory_map, base_addr);
            trace("Initialized TLS for main executable");
        } catch (const std::exception& e) {
            error("TLS initialization failed: " ,  converter.from_bytes(e.what()));
            delete pe_binary;
            munmap(memory_map, size);
            return nullptr;
        }

        // Validate and prepare entry point
        uint32_t entry_point_rva = pe_binary->optional_header().addressof_entrypoint();
        if (entry_point_rva == 0) {
            error("No entry point found in PE file");
            delete pe_binary;
            munmap(memory_map, size);
            return nullptr;
        }

        if (entry_point_rva >= size) {
            error("Entry point RVA 0x" + std::to_string(entry_point_rva) +
                  " is outside allocated memory (size: 0x" + std::to_string(size) + ")");
            delete pe_binary;
            munmap(memory_map, size);
            return nullptr;
        }

        uintptr_t entry_point = base_addr + entry_point_rva;

        // Validate entry point is in executable section
        bool entry_valid = false;
        std::wstring entry_section_name;
        for (const auto& section : pe_binary->sections()) {
            uint32_t sect_start = section.virtual_address();
            uint32_t sect_end = sect_start + static_cast<uint32_t>(section.virtual_size());

            if (sect_start <= entry_point_rva && entry_point_rva < sect_end) {
                entry_section_name = converter.from_bytes(section.name());
                // Check if section is executable (IMAGE_SCN_MEM_EXECUTE = 0x20000000)
                if (section.characteristics() & 0x20000000) {
                    entry_valid = true;
                }
                break;
            }
        }

        if (!entry_valid) {
            if (entry_section_name.empty()) {
                error("Entry point 0x" ,  std::to_wstring(entry_point_rva), " is not within any section");
                delete pe_binary;
                munmap(memory_map, size);
                return nullptr;
            } else {
                warn("Entry point 0x", std::to_wstring(entry_point_rva),
                     " is in non-executable section: ", entry_section_name);
            }
        }

        trace("Entry point validated at RVA 0x", std::to_wstring(entry_point_rva),
              " (VA 0x", std::to_wstring(entry_point), ") in section: ", entry_section_name.c_str());

        // Initialize process globals
        tls.process = next_handle;
        tls.thread = next_handle;
        tls.last_error = 0;
        process_info[next_handle];
        process_info[next_handle].process_hmodule = memory_map;
        process_info[next_handle].process_thread = pthread_self();
        process_info[next_handle].image_size = size;
        process_info[next_handle].argc = argc;
        process_info[next_handle].argv = argv;
        // populate .wargv anyhow
        process_info[next_handle].wargv = new _wchar_t*[argc + 1];
        for (int i = 0; i < argc; ++i) {
            const size_t arg_len = strlen(argv[i]);
            process_info[next_handle].wargv[i] = new _wchar_t[arg_len + 1];
            for (size_t j = 0; j < arg_len; ++j) {
                process_info[next_handle].wargv[i][j] = static_cast<_wchar_t>(argv[i][j]);
            }
            process_info[next_handle].wargv[i][arg_len] = L'\0';
        }
        process_info[next_handle].wargv[argc] = nullptr;
        // populate .command_line (wstring)
        std::wstringstream cmdline_ss;
        for (int i = 0; i < argc; ++i) {
            if (i > 0) cmdline_ss << L" ";
            // Quote arguments with spaces
            if (std::wstring arg_wstr(argv[i], argv[i] + strlen(argv[i])); arg_wstr.find(L' ') != std::wstring::npos) {
                cmdline_ss << L"\"" << arg_wstr << L"\"";
            } else {
                cmdline_ss << arg_wstr;
            }
        }

        // populate .heaps with default heap
        process_info[next_handle].heaps[process_info[next_handle].default_heap] = HeapInfo{
            .flags = 0,
        };

        // populate .command_line_a
        std::stringstream cmdline_a_ss;
        for (int i = 0; i < argc; ++i) {
            if (i > 0) cmdline_a_ss << " ";
            // Quote arguments with spaces
            if (std::string arg_str(argv[i], argv[i] + strlen(argv[i])); arg_str.find(L' ') != std::string::npos) {
                cmdline_a_ss << "\"" << arg_str << "\"";
            } else {
                cmdline_a_ss << arg_str;
            }
        }
        process_info[next_handle].command_line_a = cmdline_a_ss.str();
        process_info[next_handle].cmdline = process_info[next_handle].command_line_a.data();
        process_info[next_handle].command_line = cmdline_ss.str();
        process_info[next_handle].cmdline_w = static_cast<_wchar_t *>(malloc(sizeof(_wchar_t) * (process_info[next_handle].command_line.size() + 1)));
        // copy deom wstring to _wchar_t*
        for (size_t i = 0; i < process_info[next_handle].command_line.size(); ++i) {
            process_info[next_handle].cmdline_w[i] = static_cast<_wchar_t>(process_info[next_handle].command_line[i]);
        }
        process_info[next_handle].wpgmptr_s = pe_path.wstring();
        process_info[next_handle].wpgmptr = static_cast<_wchar_t *>(malloc(sizeof(_wchar_t) * (process_info[next_handle].wpgmptr_s.size() + 1)));
        // copy wstring to _wchar_t*
        for (size_t i = 0; i < process_info[next_handle].wpgmptr_s.size(); ++i) {
            process_info[next_handle].wpgmptr[i] = static_cast<_wchar_t>(process_info[next_handle].wpgmptr_s[i]);
        }
        process_info[next_handle].pgmptr_s = pe_path.string();
        process_info[next_handle].pgmptr = process_info[next_handle].pgmptr_s.data();
        next_handle = reinterpret_cast<HANDLE>(static_cast<char*>(next_handle) + 1);

        process_info[tls.process].subsystem = PEAnalyzer::detect_apptype(*pe_binary);

        // Load environment variables
        load_environment_variables();

        // Setup signal handlers for process control
        setup_comprehensive_signal_handlers();

        // Store main executable memory for proper cleanup
        main_executable_memory = memory_map;
        main_executable_size = size;

        // Display execution info and wait for user confirmation
        std::wcout << "\n" << std::wstring(60, '=') << "\n";
        std::wcout << "READY TO EXECUTE: " << pe_path.filename().wstring() << "\n";
        std::wcout << std::wstring(60, '=') << "\n";
        std::wcout << "Base Address: 0x" << std::hex << base_addr << std::dec << "\n";
        std::wcout << "Image Size: " << size << " bytes\n";
        std::wcout << "Entry Point: 0x" << std::hex << entry_point << std::dec << "\n";
        std::wcout << "Dependencies: " << loaded_modules.size() << " DLLs loaded\n";

        size_t emulated_apis = 0, native_apis = 0, unresolved_apis = 0;
        for (const auto& import : import_table) {
            if (import.is_emulated) emulated_apis++;
            else if (import.is_resolved) native_apis++;
            else {
                unresolved_apis++;
                trace("Unresolved import: ", import.dll_name.c_str(), "!", import.function_name.c_str());
            }
        }

        std::wcout << "APIs: " << emulated_apis << " emulated, " << native_apis
                   << " native, " << unresolved_apis << " unresolved\n";
        std::wcout << std::wstring(60, '=') << "\n";
        std::wcout << "Press Enter to execute or Ctrl+C to abort...\n";

        try {
            std::cin.get();
        } catch (...) {
            std::wcout << "\nExecution aborted by user\n";
            delete pe_binary;
            munmap(memory_map, size);
            return nullptr;
        }

        if (!validate_and_execute_entry_point(entry_point, memory_map, size, *pe_binary)) {
            error("Entry point validation failed");
            delete pe_binary;
            munmap(memory_map, size);
            return nullptr;
        }

        // Set up execution environment
        setup_execution_environment();

        debug_import_table(*pe_binary, base_addr);
        debug_relocations(*pe_binary, memory_map, base_addr);

        // Execute with proper error handling
        trace("About to execute entry point at 0x", std::to_wstring(entry_point));

        EnhancedBacktrace::register_pe_module(
            pe_path.filename().wstring(),
            base_addr,
            size,
            nullptr  // Main PE doesn't have LoadedDLL structure
        );

        try {
            execute_pe_entry_point_fixed(entry_point, memory_map);
        } catch (...) {
            error("Fatal error during PE execution");
            exit(1);
        }

        // Should never reach here
        delete pe_binary;
        return reinterpret_cast<void*>(base_addr);
    }

    bool validate_and_execute_entry_point(uintptr_t entry_point, void* base_addr, size_t image_size, const LIEF::PE::Binary& pe) {
        trace("Validating entry point at 0x", std::to_wstring(entry_point));

        // Validate entry point is within bounds
        uintptr_t base = reinterpret_cast<uintptr_t>(base_addr);
        if (entry_point < base || entry_point >= base + image_size) {
            error("Entry point out of bounds");
            return false;
        }

        // Read and dump entry point bytes for debugging
        uint8_t entry_bytes[16];
        if (safe_read_memory(reinterpret_cast<const void*>(entry_point), entry_bytes, sizeof(entry_bytes))) {
            trace("First 16 bytes at entry point:");
            std::wstringstream hex_dump;
            for (unsigned char byte : entry_bytes) {
                hex_dump << std::hex << std::setw(2) << std::setfill<wchar_t>('0')
                         << static_cast<unsigned>(byte) << " ";
            }
            trace(hex_dump.str().c_str());
        } else {
            error("Cannot read memory at entry point");
            return false;
        }

        return true;
    }


    // Install the handler:
    void setup_comprehensive_signal_handlers() {
        // Register all emulated modules FIRST
        register_all_emulated_modules();

        // Then set up the enhanced handlers
        EnhancedBacktrace::setup_enhanced_handlers();
    }

    void register_all_emulated_modules() {
        // Register Kernel32 emulated functions
        const std::unordered_map<std::wstring, EmulatedExport> kernel32_exports = Kernel32::get_exports_detailed();
        EnhancedBacktrace::register_emulated_module(L"kernel32.DLL", kernel32_exports);

        // Register UCRTBase emulated functions
        auto ucrtbase_exports = UCRTBase::get_exports_detailed();
        EnhancedBacktrace::register_emulated_module(L"ucrtbase.DLL", ucrtbase_exports);

        // Register VCRuntime140 emulated functions
        auto vcruntime_exports = VCRuntime140::get_exports_detailed();
        EnhancedBacktrace::register_emulated_module(L"vcruntime140.DLL", vcruntime_exports);

        trace("Registered all emulated modules for enhanced backtrace");
    }

    // Add this function to help debug memory layout issues:
    void dump_memory_layout(void* base_addr, size_t total_size, const LIEF::PE::Binary& pe) {
        uintptr_t base = reinterpret_cast<uintptr_t>(base_addr);

        trace("=== MEMORY LAYOUT DEBUG ===");
        trace("Base address: 0x", std::to_wstring(base));
        trace("Total size: ", std::to_wstring(total_size));
        trace("End address: 0x", std::to_wstring(base + total_size));

        trace("PE sections:");
        for (const auto& section : pe.sections()) {
            uintptr_t sect_start = base + section.virtual_address();
            uintptr_t sect_end = sect_start + section.virtual_size();

            trace("  ", section.name().c_str(), ": 0x", std::to_wstring(sect_start),
                  " - 0x", std::to_wstring(sect_end),
                  " (RVA 0x", std::to_wstring(section.virtual_address()), ")",
                  " chars=0x", std::to_wstring(section.characteristics()));

            // Test if we can read from this section
            uint8_t test_byte;
            if (safe_read_memory(reinterpret_cast<void*>(sect_start), &test_byte, 1)) {
                trace("    Section is readable");
            } else {
                error("    Section is NOT readable");
            }
        }

        uint32_t entry_rva = pe.optional_header().addressof_entrypoint();
        uintptr_t calculated_entry = base + entry_rva;
        trace("Entry point RVA: 0x", std::to_wstring(entry_rva));
        trace("Calculated entry VA: 0x", std::to_wstring(calculated_entry));
        trace("=== END MEMORY LAYOUT ===");
    }

    // Add this validation before trying to read entry point bytes:
    bool validate_entry_point(uintptr_t entry_point, void* base_addr, size_t image_size, const LIEF::PE::Binary& pe) {
        trace("Validating entry point at 0x", std::to_wstring(entry_point));

        // Check if entry point is within allocated memory bounds
        uintptr_t base = reinterpret_cast<uintptr_t>(base_addr);
        if (entry_point < base || entry_point >= base + image_size) {
            error("Entry point 0x", std::to_wstring(entry_point), " is outside allocated memory range [0x",
                  std::to_wstring(base), " - 0x", std::to_wstring(base + image_size), "]");
            return false;
        }

        // Check if entry point is within a valid section
        uint32_t entry_rva = static_cast<uint32_t>(entry_point - base);
        bool found_in_section = false;

        for (const auto& section : pe.sections()) {
            uint32_t sect_start = section.virtual_address();
            uint32_t sect_end = sect_start + section.virtual_size();

            if (entry_rva >= sect_start && entry_rva < sect_end) {
                trace("Entry point found in section: ", section.name().c_str(),
                      " (RVA 0x", std::to_wstring(entry_rva), ")");

                // Check if section is executable
                if (!(section.characteristics() & 0x20000000)) {
                    warn("Entry point is in non-executable section: ", section.name().c_str());
                }

                found_in_section = true;
                break;
            }
        }

        if (!found_in_section) {
            error("Entry point RVA 0x", std::to_wstring(entry_rva), " is not within any section");
            return false;
        }

        return true;
    }

    // Store main executable memory for proper cleanup
    void* main_executable_memory = nullptr;
    size_t main_executable_size = 0;

    static void load_default_environment() {
        environment_vector.emplace_back("USERNAME=Administrator");
        environment_vector.emplace_back("USERDOMAIN=WORKGROUP");
        environment_vector.emplace_back("COMPUTERNAME=WORKSTATION");
        environment_vector.emplace_back("PROCESSOR_ARCHITECTURE=AMD64");
        environment_vector.emplace_back("PROCESSOR_IDENTIFIER=AMD64 Family 23 Model 1 Stepping 2, AuthenticAMD");
        environment_vector.emplace_back("PROCESSOR_LEVEL=6");
        environment_vector.emplace_back("PROCESSOR_REVISION=0002");
        environment_vector.emplace_back("NUMBER_OF_PROCESSORS=28");
        environment_vector.emplace_back("OS=Windows 10");
        environment_vector.emplace_back("SystemRoot=C:\\Windows");
        environment_vector.emplace_back("TEMP=C:\\Windows\\Temp");
        environment_vector.emplace_back("TMP=C:\\Windows\\Temp");
        environment_vector.emplace_back("USERPROFILE=C:\\Users\\Administrator");
        environment_vector.emplace_back("ProgramData=C:\\ProgramData");
        environment_vector.emplace_back("ALLUSERSPROFILE=C:\\ProgramData");
        environment_vector.emplace_back("CommonProgramFiles=C:\\Program Files\\Common Files");
        environment_vector.emplace_back("CommonProgramFiles(x86)=C:\\Program Files (x86)\\Common Files");
        environment_vector.emplace_back("ProgramFiles=C:\\Program Files");
        environment_vector.emplace_back("ProgramFiles(x86)=C:\\Program Files (x86)");
        environment_vector.emplace_back("WINDIR=C:\\Windows");
        for (auto& var : environment_vector) {
            environment_vector_w.emplace_back(converter.from_bytes(var));
        }
    }

    // Helper method to load environment variables
    static void load_environment_variables() {
        if (std::ifstream env_file("environment.json"); env_file) {
            try {
                nlohmann::json env_json;
                env_file >> env_json;

                for (const auto& item : env_json.items()) {
                    const std::string& key = item.key();
                    const std::string value = item.value();
                    //environment[key] = value;
                    environment_vector.emplace_back(key + "=" + value);
                    environment_vector_w.emplace_back(converter.from_bytes(key + "=" + value));
                }
                trace("Loaded environment variables from environment.json");
            } catch (const std::exception& e) {
                error("Failed to read environment file: " ,  converter.from_bytes(e.what()));
                load_default_environment();
            }
        } else {
            warn("environment.json not found, loading default environment");
            load_default_environment();
        }
        // make .environment_narrow and .environment_wide point to the vectors' data
        environment_narrow = new char*[environment_vector.size() + 1];
        for (size_t i = 0; i < environment_vector.size(); ++i) {
            environment_narrow[i] = environment_vector[i].data();
        }
        environment_narrow[environment_vector.size()] = nullptr;
        environment_wide = new _wchar_t*[environment_vector_w.size() + 1];
        for (size_t i = 0; i < environment_vector_w.size(); ++i) {
            environment_wide[i] = static_cast<_wchar_t *>(malloc(sizeof(_wchar_t) * (environment_vector_w[i].size() + 1)));
            // copy string to _wchar_t*
            for (size_t j = 0; j < environment_vector_w[i].size(); ++j) {
                environment_wide[i][j] = environment_vector_w[i][j];
            }
            environment_wide[environment_vector_w.size()] = nullptr;

            trace("Environment variables loaded");
        }
    }

    static void free_shit() {
        if (auto& proc = process_info[tls.process]; proc.wargv) {
            for (int i = 0; i < proc.argc; ++i) {
                delete[] proc.wargv[i];
            }
            delete[] proc.wargv;
            proc.wargv = nullptr;
        }

        delete[] environment_narrow;
        delete[] environment_wide;
    }
};

// ============================================================
// Usage Examples and Testing Functions
// ============================================================

// NEW: Enhanced export testing function
void test_enhanced_exports(WineLikeLoader& loader) {
    std::wcout << "\n=== Testing Enhanced Export System ===\n";

    // Test getting exports from a loaded DLL
    auto exports = loader.get_dll_exports(L"kernel32.DLL");

    std::wcout << "Kernel32.DLL exports (" << exports.size() << " total):\n";

    size_t function_count = 0;
    size_t data_count = 0;

    for (const auto& [name, info] : exports) {
        const bool is_function = info.first;
        const uintptr_t address = info.second;

        if (is_function) {
            function_count++;
            std::wcout << "  FUNC: " << name << " -> 0x" << std::hex << address << std::dec << "\n";
        } else {
            data_count++;
            std::wcout << "  DATA: " << name << " -> 0x" << std::hex << address << std::dec << "\n";
        }
    }

    std::wcout << "Summary: " << function_count << " functions, " << data_count << " data exports\n";
}

// ============================================================
// Main Function
// ============================================================
int main(const int argc, char* argv[]) {
    if (argc < 2) {
        std::wcout << "Usage: " << argv[0] << " <pe_file>\n";
        return 1;
    }

    const std::wstring pe_path = converter.from_bytes(argv[1]);

    try {
        WineLikeLoader loader;

        // Optional: Test the enhanced export system
        if (argc > 2 && std::wstring(argv[2], argv[2] + strlen(argv[2])) == L"--test-exports") {
            test_enhanced_exports(loader);
        }

        if (loader.load_pe(pe_path, argc - 1, argv + 1)) {
            trace("PE file executed successfully");
            WineLikeLoader::free_shit();
        } else {
            error("PE file execution failed");
            WineLikeLoader::free_shit();
            return 1;
        }
    } catch (const std::exception& e) {
        error("Execution failed: " ,  converter.from_bytes(e.what()));
        return 1;
    }

    return 0;
}