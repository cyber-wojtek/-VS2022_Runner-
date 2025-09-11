#include <cstdint>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <string>
#include <memory>
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
#include <openssl/sha.h>
#include <LIEF/PE.hpp>
#include <nlohmann/json.hpp>

#include "global.h"
#include "win_types.h"
#include "log.h"
#include "kernel32.hpp"

namespace fs = std::filesystem;

// ============================================================
// PE Analysis Structures
// ============================================================
struct DllInfo {
    std::string name;
    std::string path;
    uintptr_t base_address = 0;
    size_t size = 0;
    std::vector<std::string> exports;
    std::unordered_map<std::string, std::vector<std::string>> imports; // dll_name -> [function_names]
    std::unordered_set<std::string> dependencies;
    std::unordered_map<std::string, std::string> version_info;
    std::unordered_map<std::string, bool> security_flags;
    uint16_t pe_characteristics = 0;
    uint32_t timestamp = 0;
    uint32_t checksum = 0;
    std::string file_hash;
    bool is_native = true;
    std::unordered_map<std::string, uint32_t> export_table; // function_name -> RVA
    std::vector<uint8_t> memory_mapped;
};

struct ImportInfo {
    std::string dll_name;
    std::string function_name;
    uint16_t ordinal = 0;
    uintptr_t address = 0;
    bool is_resolved = false;
    bool is_emulated = false;
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

struct LoadedDLL {
    DllInfo dll_info;
    uintptr_t base_address{};
    void* memory_map{};
    std::shared_ptr<LIEF::PE::Binary> pe_binary;
    std::unordered_map<std::string, uintptr_t> export_addresses; // function_name -> virtual_address
};

// ============================================================
// PE Analyzer Class
// ============================================================
class PEAnalyzer {
public:
    std::unordered_map<std::string, DllInfo> analyzed_dlls;
    std::unordered_map<std::string, std::unordered_set<std::string>> dependency_graph;
    std::vector<fs::path> system_dll_paths;

    static std::vector<fs::path> get_system_dll_paths() {
        std::vector<fs::path> paths;
        paths.push_back(fs::current_path());
        // Add more system paths as needed
        return paths;
    }

    fs::path find_dll(const std::string& dll_name) const {
        // Try the exact name first
        for (const auto& search_path : system_dll_paths) {
            if (auto dll_path = search_path / dll_name; fs::exists(dll_path)) {
                return dll_path;
            }
        }

        // Try common variations
        std::vector<std::string> name_variations = {
            dll_name,
            to_lower(dll_name),
            to_upper(dll_name),
            dll_name.substr(0, dll_name.find_last_of('.')) + ".so",
            "lib" + dll_name.substr(0, dll_name.find_last_of('.')) + ".so"
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

    static std::string calculate_file_hash(const fs::path& file_path) {
        try {
            std::ifstream file(file_path, std::ios::binary);
            if (!file) return "";

            SHA256_CTX ctx;
            SHA256_Init(&ctx);

            char buffer[4096];
            while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0) {
                SHA256_Update(&ctx, buffer, file.gcount());
            }

            unsigned char hash[SHA256_DIGEST_LENGTH];
            SHA256_Final(hash, &ctx);

            std::stringstream ss;
            for (unsigned char i : hash) {
                ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned int>(i);
            }
            return ss.str();
        } catch (const std::exception& e) {
            warn("Failed to calculate hash for " + file_path.string() + ": " + e.what());
            return "";
        }
    }

    static std::unordered_map<std::string, std::string> extract_version_info(const LIEF::PE::Binary& pe) {
        std::unordered_map<std::string, std::string> version_info;
        try {
            if (pe.has_resources()) {
                // LIEF resource parsing is complex and version-dependent
                // This is a simplified placeholder - actual implementation would need
                // to parse the resource tree structure properly
                version_info["Version"] = "Unknown";
                version_info["Description"] = "PE File";
            }
        } catch (const std::exception& e) {
            warn("Failed to extract version info: " + std::string(e.what()));
        }
        return version_info;
    }

    static std::unordered_map<std::string, bool> analyze_security_flags(const LIEF::PE::Binary& pe) {
        std::unordered_map<std::string, bool> security_flags;

        const auto& optional_header = pe.optional_header();

        // DLL characteristics - using correct LIEF enums
        const uint16_t dll_chars = optional_header.dll_characteristics();
        security_flags["ASLR"] = (dll_chars & static_cast<uint16_t>(DLL_CHARACTERISTICS::DYNAMIC_BASE)) != 0;
        security_flags["DEP"] = (dll_chars & static_cast<uint16_t>(DLL_CHARACTERISTICS::NX_COMPAT)) != 0;
        security_flags["SEH"] = (dll_chars & static_cast<uint16_t>(DLL_CHARACTERISTICS::NO_SEH)) == 0; // Inverted logic
        security_flags["CFG"] = (dll_chars & static_cast<uint16_t>(DLL_CHARACTERISTICS::GUARD_CF)) != 0;

        // File characteristics
        const uint16_t file_chars = pe.header().characteristics();
        security_flags["Executable"] = (file_chars & static_cast<uint16_t>(HEADER_CHARACTERISTICS::EXECUTABLE_IMAGE)) != 0;
        security_flags["DLL"] = (file_chars & static_cast<uint16_t>(HEADER_CHARACTERISTICS::DLL)) != 0;

        return security_flags;
    }

    static std::unordered_map<std::string, uint32_t> extract_export_table(const LIEF::PE::Binary& pe) {
        std::unordered_map<std::string, uint32_t> export_table;
        try {
            if (pe.has_exports()) {
                for (const auto& export_dir = pe.get_export(); const auto& entry : export_dir->entries()) {
                    if (!entry.name().empty()) {
                        export_table[entry.name()] = static_cast<uint32_t>(entry.address());
                    } else if (entry.ordinal() > 0) {
                        export_table["Ordinal_" + std::to_string(entry.ordinal())] = static_cast<uint32_t>(entry.address());
                    }
                }
            }
        } catch (const std::exception& e) {
            warn("Failed to extract export table: " + std::string(e.what()));
        }
        return export_table;
    }

    static DllInfo create_stub_dll_info(const fs::path& file_path, bool is_native) {
        const std::string dll_name = to_lower(file_path.filename().string());

        DllInfo info;
        info.name = dll_name;
        info.path = file_path.string();
        info.is_native = is_native;

        if (fs::exists(file_path)) {
            info.file_hash = calculate_file_hash(file_path);
        }

        return info;
    }

    static std::string to_lower(const std::string& str) {
        std::string result = str;
        std::ranges::transform(result, result.begin(), ::tolower);
        return result;
    }

    static std::string to_upper(const std::string& str) {
        std::string result = str;
        std::ranges::transform(result, result.begin(), ::toupper);
        return result;
    }

    PEAnalyzer() : system_dll_paths(get_system_dll_paths()) {}

    DllInfo analyze_pe_file(const fs::path& file_path, bool is_native = true) {
        std::string dll_name = to_lower(file_path.filename().string());

        if (auto it = analyzed_dlls.find(dll_name); it != analyzed_dlls.end()) {
            return it->second;
        }

        trace("Analyzing PE file: ", file_path.wstring());

        try {
            auto pe_binary = LIEF::PE::Parser::parse(file_path.string());
            if (!pe_binary) {
                warn(file_path.string() + " is not a valid PE file, creating stub info");
                return create_stub_dll_info(file_path, is_native);
            }

            // Read raw file data
            std::ifstream file(file_path, std::ios::binary);
            std::vector<uint8_t> memory_mapped((std::istreambuf_iterator<char>(file)),
                                               std::istreambuf_iterator<char>());

            // Basic information
            DllInfo dll_info;
            dll_info.name = dll_name;
            dll_info.path = file_path.string();
            dll_info.base_address = pe_binary->optional_header().imagebase();
            dll_info.size = pe_binary->optional_header().sizeof_image();
            dll_info.version_info = extract_version_info(*pe_binary);
            dll_info.security_flags = analyze_security_flags(*pe_binary);
            dll_info.pe_characteristics = pe_binary->header().characteristics();
            dll_info.timestamp = pe_binary->header().time_date_stamp();
            dll_info.checksum = pe_binary->optional_header().checksum();
            dll_info.file_hash = calculate_file_hash(file_path);
            dll_info.is_native = is_native;
            dll_info.export_table = extract_export_table(*pe_binary);
            dll_info.memory_mapped = std::move(memory_mapped);

            // Analyze exports
            if (pe_binary->has_exports()) {
                for (const auto& export_dir = pe_binary->get_export(); const auto& entry : export_dir->entries()) {
                    if (!entry.name().empty()) {
                        dll_info.exports.push_back(entry.name());
                    } else if (entry.ordinal() > 0) {
                        dll_info.exports.push_back("Ordinal_" + std::to_string(entry.ordinal()));
                    }
                }
            }

            // Analyze imports and dependencies
            if (pe_binary->has_imports()) {
                for (const auto& import : pe_binary->imports()) {
                    std::string imported_dll = to_lower(import.name());
                    dll_info.dependencies.insert(imported_dll);
                    dll_info.imports[imported_dll] = {};

                    for (const auto& entry : import.entries()) {
                        if (!entry.name().empty()) {
                            dll_info.imports[imported_dll].push_back(entry.name());
                        } else if (entry.ordinal() > 0) {
                            dll_info.imports[imported_dll].push_back("Ordinal_" + std::to_string(entry.ordinal()));
                        }
                    }
                }
            }

            // Add to the dependency graph
            dependency_graph[dll_name] = dll_info.dependencies;

            // Cache analysis
            analyzed_dlls[dll_name] = dll_info;

            trace("Analyzed ", dll_name.c_str(), ": ", std::to_wstring(dll_info.exports.size()),
                  " exports, ", std::to_wstring(dll_info.dependencies.size()), " dependencies");

            return dll_info;

        } catch (const std::exception& e) {
            error("Failed to analyze " + file_path.string() + ": " + e.what());
            return create_stub_dll_info(file_path, is_native);
        }
    }

    std::unordered_set<std::string> analyze_dependencies_recursive(const std::string& dll_name, const int max_depth = 10) {
        std::unordered_set<std::string> visited;
        std::deque<std::pair<std::string, int>> to_visit;
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
                warn("Could not find DLL: " + current_dll);
            }
        }

        return visited;
    }

    std::vector<std::vector<std::string>> detect_circular_dependencies() {
        std::vector<std::vector<std::string>> cycles;
        std::unordered_set<std::string> visited;

        std::function<std::vector<std::string>(const std::string&, std::vector<std::string>&,
                                               std::unordered_set<std::string>&,
                                               std::unordered_set<std::string>&)> dfs;

        dfs = [&](const std::string& node, std::vector<std::string>& path,
                  std::unordered_set<std::string>& vis,
                  std::unordered_set<std::string>& rec_stack) -> std::vector<std::string> {
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
                        std::vector<std::string> cycle(cycle_start, path.end());
                        cycle.push_back(neighbor);
                        return cycle;
                    }
                }
            }

            path.pop_back();
            rec_stack.erase(node);
            return {};
        };

        for (const auto &dll: dependency_graph | std::views::keys) {
            if (!visited.contains(dll)) {
                std::vector<std::string> path;
                std::unordered_set<std::string> rec_stack;
                if (const auto cycle = dfs(dll, path, visited, rec_stack); !cycle.empty()) {
                    cycles.push_back(cycle);
                }
            }
        }

        return cycles;
    }

    std::string generate_dependency_report() {
        std::ostringstream report;
        report << std::string(80, '=') << "\n";
        report << "PE DEPENDENCY ANALYSIS REPORT\n";
        report << std::string(80, '=') << "\n\n";

        // Summary
        const size_t total_dlls = analyzed_dlls.size();
        size_t native_dlls = 0;
        for (const auto &dll: analyzed_dlls | std::views::values) {
            if (dll.is_native) native_dlls++;
        }
        const size_t emulated_dlls = total_dlls - native_dlls;

        report << "SUMMARY:\n";
        report << "  Total DLLs analyzed: " << total_dlls << "\n";
        report << "  Native DLLs: " << native_dlls << "\n";
        report << "  Emulated DLLs: " << emulated_dlls << "\n\n";

        // Security analysis
        report << "SECURITY ANALYSIS:\n";
        for (const auto& [dll_name, dll_info] : analyzed_dlls) {
            if (dll_info.security_flags.empty()) continue;

            report << "  " << dll_name << ":\n";
            for (const auto& [flag, enabled] : dll_info.security_flags) {
                report << "    " << flag << ": " << (enabled ? "✓" : "✗") << "\n";
            }
        }
        report << "\n";

        // Circular dependencies
        if (const auto cycles = detect_circular_dependencies(); !cycles.empty()) {
            report << "CIRCULAR DEPENDENCIES DETECTED:\n";
            for (size_t i = 0; i < cycles.size(); ++i) {
                report << "  Cycle " << (i + 1) << ": ";
                for (size_t j = 0; j < cycles[i].size(); ++j) {
                    report << cycles[i][j];
                    if (j < cycles[i].size() - 1) report << " -> ";
                }
                report << "\n";
            }
        } else {
            report << "No circular dependencies detected.\n";
        }
        report << "\n";

        // Detailed DLL information
        report << "DETAILED DLL ANALYSIS:\n";
        for (const auto& [dll_name, dll_info] : analyzed_dlls) {
            report << "  " << dll_name << ":\n";
            report << "    Path: " << (dll_info.path.empty() ? "Not found" : dll_info.path) << "\n";
            report << "    Type: " << (dll_info.is_native ? "Native" : "Emulated") << "\n";
            if (dll_info.base_address != 0) {
                report << "    Base Address: 0x" << std::hex << dll_info.base_address << std::dec << "\n";
            } else {
                report << "    Base Address: N/A\n";
            }
            report << "    Size: " << dll_info.size << " bytes\n";
            report << "    Exports: " << dll_info.exports.size() << "\n";
            report << "    Dependencies: " << dll_info.dependencies.size() << "\n";

            if (!dll_info.dependencies.empty()) {
                report << "      -> ";
                bool first = true;
                for (const auto& dep : dll_info.dependencies) {
                    if (!first) report << ", ";
                    report << dep;
                    first = false;
                }
                report << "\n";
            }

            if (!dll_info.file_hash.empty()) {
                report << "    SHA-256: " << dll_info.file_hash << "\n";
            }
            report << "\n";
        }

        report << "    IMPORTED FUNCTIONS PER DLL:\n";
        for (const auto& [dll_name, dll_info] : analyzed_dlls) {
            if (dll_info.imports.empty()) continue;
            report << "  " << dll_name << " imports:\n";
            for (const auto& [dep, funcs] : dll_info.imports) {
                report << "    from " << dep << ":\n";
                for (const auto& func : funcs) {
                    report << "      - " << func << "\n";
                }
            }
        }

        return report.str();
    }
};

// ============================================================
// Enhanced Loader
// ============================================================
class WineLikeLoader {
private:
    PEAnalyzer pe_analyzer;
    std::unordered_map<std::string, LoadedDLL> loaded_modules;
    std::vector<ImportInfo> import_table;

    static void setup_seh() {
        auto handler = [](const int signum) {
            error("SEH: Caught signal ", std::to_wstring(signum));
            std::exit(1);
        };
        signal(SIGSEGV, handler);
    }

    static void apply_relocs_dll(const LIEF::PE::Binary& pe, void* mem, uintptr_t base_addr) {
        if (!pe.has_relocations()) {
            return;
        }

        int64_t delta = static_cast<int64_t>(base_addr) - static_cast<int64_t>(pe.optional_header().imagebase());
        if (delta == 0) {
            return; // No relocation needed
        }

        try {
            size_t reloc_count = 0;
            for (const auto& reloc : pe.relocations()) {
                for (const auto& entry : reloc.entries()) {
                    uintptr_t addr = base_addr + entry.position();

                    // Validate address is within allocated memory
                    if (entry.position() >= pe.optional_header().sizeof_image()) {
                        continue;
                    }

                    // Use raw type values instead of potentially non-existent enums
                    if (auto reloc_type = static_cast<uint8_t>(entry.type()); reloc_type == 3) { // IMAGE_REL_BASED_HIGHLOW
                        auto* ptr = reinterpret_cast<uint32_t*>(addr);
                        *ptr = static_cast<uint32_t>(*ptr + delta);
                        reloc_count++;
                    } else if (reloc_type == 10) { // IMAGE_REL_BASED_DIR64
                        auto* ptr = reinterpret_cast<uint64_t*>(addr);
                        *ptr = static_cast<uint64_t>(*ptr + delta);
                        reloc_count++;
                    }
                }
            }
            trace("Applied ", std::to_wstring(reloc_count), " relocations for DLL with delta 0x",
                  std::to_wstring(delta));
        } catch (const std::exception& e) {
            error("Relocation failed: " + std::string(e.what()));
        }
    }

    static void init_tls(const LIEF::PE::Binary& pe, void* mem, uintptr_t base_addr) {
        if (!pe.has_tls()) {
            return;
        }

        try {
            const auto& tlsInfo = pe.tls();
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

            // Execute TLS callbacks
            for (const uint64_t callback_va : tlsInfo->callbacks()) {
                if (callback_va >= pe.optional_header().imagebase()) {
                    if (const auto callback_rva = static_cast<uint32_t>(callback_va - pe.optional_header().imagebase()); callback_rva < pe.optional_header().sizeof_image()) {
                        try {
                            // Create the function pointer and call it
                            // This is architecture-specific and would need proper implementation
                            const auto func = reinterpret_cast<void(*)()>(base_addr + callback_rva);
                            func();
                            callback_count++;
                            trace("Executed TLS callback ", std::to_wstring(callback_count),
                                  " at 0x", std::to_wstring(callback_va));
                        } catch (const std::exception& e) {
                            error("TLS callback 0x", std::to_wstring(callback_va), " failed: ", e.what());
                        }
                    }
                }
            }

            if (callback_count > 0) {
                trace("Executed ", std::to_wstring(callback_count), " TLS callbacks");
            }
        } catch (const std::exception& e) {
            error("TLS initialization failed: " + std::string(e.what()));
        }
    }

    uintptr_t get_proc_address(const std::string& dll_name, const std::string& func_name) {
        std::string dll_lower = dll_name;
        std::ranges::transform(dll_lower, dll_lower.begin(), ::tolower);

        // Try emulated APIs first (would need to implement Kernel32 and Advapi32 classes)
        // if (dll_lower == "kernel32.dll" && kernel32.exports.count(func_name)) {
        //     return reinterpret_cast<uintptr_t>(kernel32.exports[func_name]);
        // }
        if (dll_lower == "kernel32.dll" && Kernel32::get_exports().contains(func_name)) {
            return reinterpret_cast<uintptr_t>(Kernel32::get_exports().at(func_name));
        }

        // Try loaded native DLLs
        if (const auto it = loaded_modules.find(dll_lower); it != loaded_modules.end()) {
            if (const auto addr_it = it->second.export_addresses.find(func_name); addr_it != it->second.export_addresses.end()) {
                return addr_it->second;
            }
        }

        // Try to load the DLL if not already loaded
        if (const auto dll_path = pe_analyzer.find_dll(dll_name); !dll_path.empty()) {
            if (const auto loaded_dll = load_dll_pe(dll_path)) {
                if (const auto addr_it = loaded_dll->export_addresses.find(func_name); addr_it != loaded_dll->export_addresses.end()) {
                    return addr_it->second;
                }
            }
        }

        return 0;
    }

    void resolve_imports(const LIEF::PE::Binary& pe, const uintptr_t base_addr) {
        if (!pe.has_imports()) {
            return;
        }

        try {
            size_t resolved_imports = 0;
            size_t emulated_imports = 0;
            size_t total_imports = 0;
            for (const auto& import : pe.imports()) {
                std::string dll_name = import.name();
                std::ranges::transform(dll_name, dll_name.begin(), ::tolower);
                trace("Resolving imports from ", dll_name.c_str());

                for (const auto& entry : import.entries()) {
                    total_imports++;

                    if (entry.name().empty()) {
                        continue;
                    }

                    std::string name = entry.name();

                    if (const uintptr_t func_address = get_proc_address(dll_name, name); func_address != 0) {
                        bool is_emulated = false;
                        // Check if it's emulated (would need proper implementation)
                        // is_emulated = (dll_name == "kernel32.dll" && kernel32.exports.count(name));

                        // Record import information
                        ImportInfo import_info;
                        import_info.dll_name = dll_name;
                        import_info.function_name = name;
                        import_info.ordinal = entry.ordinal();
                        import_info.address = entry.iat_address();
                        import_info.is_resolved = true;
                        import_info.is_emulated = is_emulated;
                        import_table.push_back(import_info);

                        // Update IAT with bound checking
                        if (const uint64_t iat_va = entry.iat_address(); iat_va >= pe.optional_header().imagebase()) {
                            if (const auto iat_rva = static_cast<uint32_t>(iat_va - pe.optional_header().imagebase()); iat_rva < pe.optional_header().sizeof_image() - 8) {
                                const auto ptr = reinterpret_cast<uintptr_t*>(base_addr + iat_rva);
                                *ptr = func_address;
                                resolved_imports++;
                                trace("  ", dll_name.c_str(), "!", " -> 0x", reinterpret_cast<void*>(func_address), is_emulated ? " (emulated)" : " (native)");
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
                        import_table.push_back(import_info);
                    }
                }
            }

            trace("Import resolution: ", std::to_wstring(resolved_imports), "/",
                  std::to_wstring(total_imports), " resolved, ",
                  std::to_wstring(emulated_imports), " emulated");

        } catch (const std::exception& e) {
            error("Import resolution failed: " + std::string(e.what()));
        }
    }

public:
    std::shared_ptr<LoadedDLL> load_dll_pe(const fs::path& dll_path) {
        std::string dll_name = dll_path.filename().string();
        std::ranges::transform(dll_name, dll_name.begin(), ::tolower);

        if (const auto it = loaded_modules.find(dll_name); it != loaded_modules.end()) {
            trace(dll_name.c_str(), " already loaded at 0x", std::to_wstring(it->second.base_address));
            return std::make_shared<LoadedDLL>(it->second);
        }

        try {
            // 1. Analyze DLL
            const auto dll_info = pe_analyzer.analyze_pe_file(dll_path, true);
            auto pe_binary = LIEF::PE::Parser::parse(dll_path.string());
            if (!pe_binary) {
                error("Failed to parse PE binary: " + dll_path.string());
                return nullptr;
            }

            // Check if this is actually a DLL
            const bool is_dll = (pe_binary->header().characteristics() & static_cast<uint16_t>(HEADER_CHARACTERISTICS::DLL)) != 0;
            if (!is_dll) {
                warn(dll_name + " is not a DLL, skipping DllMain call");
            }

            size_t size = pe_binary->optional_header().sizeof_image();
            // Ensure minimum size alignment
            if (size < 4096) {
                size = 4096;
            }

            // Create memory mapping with proper permissions
            void* mem = mmap(nullptr, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (mem == MAP_FAILED) {
                error("Failed to allocate memory for DLL");
                return nullptr;
            }

            const auto base_addr = reinterpret_cast<uintptr_t>(mem);

            // Initialize memory to zero
            memset(mem, 0, size);

            // 2. Map sections with proper alignment
            for (const auto& section : pe_binary->sections()) {
                const uint32_t sect_rva = section.virtual_address();
                const uintptr_t sect_va = base_addr + sect_rva;
                auto raw_data = section.content();

                // Ensure we don't write beyond allocated memory
                if (sect_rva + raw_data.size() <= size) {
                    memcpy(reinterpret_cast<void*>(sect_va), raw_data.data(), raw_data.size());
                    trace("Mapped section ", section.name().c_str(), " at RVA 0x", std::to_wstring(sect_rva),
                          ", size ", std::to_wstring(raw_data.size()));
                } else {
                    error("Section " + section.name() + " would overflow allocated memory");
                    continue;
                }
            }

            // 3. Apply relocations
            apply_relocs_dll(*pe_binary, mem, base_addr);

            // 4. Recursively load dependencies first
            for (const auto& dep : dll_info.dependencies) {
                if (auto dep_path = pe_analyzer.find_dll(dep); !dep_path.empty()) {
                    load_dll_pe(dep_path);
                } else {
                    warn("Dependency ", dep, " not found for ", dll_name);
                }
            }

            // 5. Build export address table
            std::unordered_map<std::string, uintptr_t> export_addresses;
            if (pe_binary->has_exports()) {
                for (const auto& export_dir = pe_binary->get_export(); const auto& entry : export_dir->entries()) {
                    if (!entry.name().empty()) {
                        export_addresses[entry.name()] = base_addr + static_cast<uintptr_t>(entry.address());
                    } else if (entry.ordinal() > 0) {
                        export_addresses["Ordinal_" + std::to_string(entry.ordinal())] = base_addr + static_cast<uintptr_t>(entry.address());
                    }
                }
            }

            auto loaded_dll = std::make_shared<LoadedDLL>();
            loaded_dll->dll_info = dll_info;
            loaded_dll->base_address = base_addr;
            loaded_dll->memory_map = mem;
            loaded_dll->pe_binary = std::move(pe_binary);
            loaded_dll->export_addresses = std::move(export_addresses);

            loaded_modules[dll_name] = std::move(*loaded_dll);

            // 6. Resolve imports
            resolve_imports(*loaded_dll->pe_binary, base_addr);

            // 7. Initialize TLS
            init_tls(*loaded_dll->pe_binary, mem, base_addr);

            // 8. Call DllMain for PROCESS_ATTACH (only for actual DLLs)
            if (is_dll) {
                if (const uint32_t entry_rva = loaded_dll->pe_binary->optional_header().addressof_entrypoint(); entry_rva != 0) {
                    const uintptr_t entry_va = base_addr + entry_rva;

                    // Validate entry point is within loaded sections
                    bool valid_entry = false;
                    for (const auto& section : loaded_dll->pe_binary->sections()) {
                        const uint32_t sect_start = section.virtual_address();
                        if (const uint32_t sect_end = sect_start + static_cast<uint32_t>(section.virtual_size()); sect_start <= entry_rva && entry_rva < sect_end) {
                            valid_entry = true;
                            break;
                        }
                    }

                    if (valid_entry) {
                        try {
                            // Set up a proper calling convention
                            typedef BOOL (*DllMainProc)(HMODULE, DWORD, LPVOID);
                            const auto dll_main = reinterpret_cast<DllMainProc>(entry_va);

                            trace("Calling DllMain for ", dll_info.name.c_str(), " at 0x", std::to_wstring(entry_va));

                            // Call DllMain with PROCESS_ATTACH (1)
                            const BOOL ret = dll_main(reinterpret_cast<HMODULE>(base_addr), 1, nullptr);
                            trace("DllMain returned ", std::to_wstring(ret), " for ", dll_info.name.c_str());

                            if (!ret) {
                                warn("DllMain returned FALSE for ", dll_info.name);
                            }
                        } catch (const std::exception& e) {
                            error("DllMain execution failed for " + dll_info.name + ": " + e.what());
                        }
                    } else {
                        warn("Invalid entry point 0x", std::to_wstring(entry_rva), " for ", dll_info.name);
                    }
                } else {
                    trace("No entry point for ", dll_info.name.c_str());
                }
            } else {
                trace(dll_info.name.c_str(), " is not a DLL, skipping DllMain");
            }

            return loaded_dll;

        } catch (const std::exception& e) {
            error("Failed to load DLL " + dll_path.string() + ": " + e.what());
            return nullptr;
        }
    }

    void analyze_all_dependencies(const fs::path& main_pe_path) {
        trace("Starting comprehensive dependency analysis...");

        // Analyze the main PE file
        auto main_info = pe_analyzer.analyze_pe_file(main_pe_path, false);

        // Recursively analyze all dependencies
        std::unordered_set<std::string> all_deps;
        for (const auto& dep : main_info.dependencies) {
            auto deps = pe_analyzer.analyze_dependencies_recursive(dep);
            all_deps.insert(deps.begin(), deps.end());
        }

        trace("Dependency analysis complete: ", std::to_wstring(all_deps.size()), " total dependencies");

        // Generate and save a report
        auto report = pe_analyzer.generate_dependency_report();
        auto report_path = main_pe_path;
        report_path.replace_extension(".dependency_report.txt");

        try {
            if (std::ofstream report_file(report_path); report_file) {
                report_file << report;
                trace("Dependency report saved to: ", report_path.wstring());
            }
        } catch (const std::exception& e) {
            warn("Failed to save dependency report: " + std::string(e.what()));
        }

        // Print summary to console
        std::cout << "\n" << std::string(60, '=') << "\n";
        std::cout << "DEPENDENCY ANALYSIS SUMMARY\n";
        std::cout << std::string(60, '=') << "\n";
        std::wcout << "Main PE: " << main_pe_path.filename().wstring() << "\n";
        std::cout << "Total dependencies: " << all_deps.size() << "\n";

        size_t emulated_apis = 0, native_apis = 0, unresolved_apis = 0;
        for (const auto& import : import_table) {
            if (import.is_emulated) emulated_apis++;
            else if (import.is_resolved) native_apis++;
            else unresolved_apis++;
        }

        std::cout << "Emulated APIs: " << emulated_apis << "\n";
        std::cout << "Native APIs: " << native_apis << "\n";
        std::cout << "Unresolved APIs: " << unresolved_apis << "\n";

        // Show circular dependencies if any
        if (auto cycles = pe_analyzer.detect_circular_dependencies(); !cycles.empty()) {
            std::wcout << L"⚠️  Circular dependencies detected: " << cycles.size() << "\n";
            for (size_t i = 0; i < std::min(cycles.size(), static_cast<size_t>(3)); ++i) {
                std::cout << "   ";
                for (size_t j = 0; j < cycles[i].size(); ++j) {
                    std::cout << cycles[i][j];
                    if (j < cycles[i].size() - 1) std::cout << " -> ";
                }
                std::cout << "\n";
            }
        }

        // After dependency analysis summary in analyze_all_dependencies()
        std::cout << "\nIMPORTED FUNCTIONS PER DLL:\n";
        for (const auto& [dll_name, dll_info] : pe_analyzer.analyzed_dlls) {
            if (dll_info.imports.empty()) continue;
            std::cout << "  " << dll_name << " imports:\n";
            for (const auto& [dep, funcs] : dll_info.imports) {
                std::cout << "    from " << dep << ":\n";
                for (const auto& func : funcs) {
                    std::cout << "      - " << func << "\n";
                }
            }
        }

        std::wcout << L"📄 Full report: " << report_path.wstring() << "\n";
        std::cout << std::string(60, '=') << "\n";
    }

    void* load_pe(const std::string& path) {
        fs::path pe_path(path);
        trace("Loading PE file: ", pe_path.wstring());

        // Perform dependency analysis
        analyze_all_dependencies(pe_path);

        auto pe_binary = LIEF::PE::Parser::parse(pe_path.string());
        if (!pe_binary) {
            error("Invalid PE file: ", pe_path.wstring());
            return nullptr;
        }

        setup_seh();

        size_t size = pe_binary->optional_header().sizeof_image();
        // Ensure minimum size and alignment
        if (size < 4096) {
            size = 4096;
        }
        size = (size + 4095) & ~4095; // Page align

        void* mem = mmap(nullptr, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (mem == MAP_FAILED) {
            error("Failed to allocate memory");
            return nullptr;
        }

        auto base_addr = reinterpret_cast<uintptr_t>(mem);

        // Initialize memory
        memset(mem, 0, size);
        trace("Allocated ", std::to_wstring(size), " bytes at 0x", std::to_wstring(base_addr));

        // Load sections with validation
        try {
            size_t section_count = 0;
            for (const auto& section : pe_binary->sections()) {
                uint32_t sect_rva = section.virtual_address();
                uintptr_t sect_va = base_addr + sect_rva;
                auto raw_data = section.content();

                // Validate section bounds
                if (sect_rva + raw_data.size() > size) {
                    error("Section " + section.name() + " would overflow memory");
                    continue;
                }

                memcpy(reinterpret_cast<void*>(sect_va), raw_data.data(), raw_data.size());
                section_count++;
                trace("Loaded section ", section.name().c_str(), " at 0x", std::to_wstring(sect_va),
                      " size=", std::to_wstring(raw_data.size()));
            }
            trace("Loaded ", std::to_wstring(section_count), " sections");
        } catch (const std::exception& e) {
            error("Section loading failed: ", std::wstring(e.what(), e.what() + strlen(e.what())));
            munmap(mem, size);
            return nullptr;
        }

        // Apply transformations
        try {
            apply_relocs_dll(*pe_binary, mem, base_addr);
            resolve_imports(*pe_binary, base_addr);
            init_tls(*pe_binary, mem, base_addr);
        } catch (const std::exception& e) {
            error("PE preparation failed: ", std::wstring(e.what(), e.what() + strlen(e.what())));
            munmap(mem, size);
            return nullptr;
        }

        // Validate entry point
        uint32_t entry_point_rva = pe_binary->optional_header().addressof_entrypoint();
        if (entry_point_rva == 0) {
            error("No entry point found");
            munmap(mem, size);
            return nullptr;
        }

        if (entry_point_rva >= size) {
            error("Entry point 0x", std::to_wstring(entry_point_rva), " is outside allocated memory");
            munmap(mem, size);
            return nullptr;
        }

        uintptr_t entry_point = base_addr + entry_point_rva;

        // Validate entry point is in the executable section
        bool entry_valid = false;
        for (const auto& section : pe_binary->sections()) {
            if (section.virtual_address() <= entry_point_rva &&
                entry_point_rva < section.virtual_address() + static_cast<uint32_t>(section.virtual_size())) {
                if (section.characteristics() & 0x20000000) { // IMAGE_SCN_MEM_EXECUTE
                    entry_valid = true;
                    break;
                }
            }
        }

        if (!entry_valid) {
            warn("Entry point 0x", std::to_wstring(entry_point_rva), " may not be in executable section");
        }

        trace("Jumping to entry point at 0x", std::to_wstring(entry_point));

        std::wcout << "\n🚀 Ready to execute " << pe_path.filename().wstring() << "\n";
        std::wcout << "Press Enter to continue or Ctrl+C to abort...\n";

        try {
            std::cin.get();
        } catch (...) {
            std::cout << "\nExecution aborted by user\n";
            munmap(mem, size);
            return mem;
        }

        // initialize globals
        tls.process = next_handle;
        tls.thread = next_handle;
        tls.last_error = 0;
        process_info[next_handle] = ProcessInfo{};
        process_info[next_handle].process_hmodule = mem; // set hModule to base addr
        process_info[next_handle].process_thread = pthread_self();
        ++next_handle;

        // load environment from environment.json
        if (std::ifstream env_file("environment.json"); env_file) {
            try {
                nlohmann::json env_json;
                env_file >> env_json;

                for (const auto& item : env_json.items()) {

                    const std::string& key = item.key();
                    const std::string value = item.value();

                    environment[key] = value;
                }
            } catch (const std::exception& e) {
                error("Failed to read environment file: " + std::string(e.what()));
            }
        }
        else {
            error("Failed to read environment file: environment.json not found");
            // load default dummy values
            environment["USERNAME"] = "Administrator";
            environment["USERDOMAIN"] = "WORKGROUP";
            environment["COMPUTERNAME"] = "WORKSTATION";
            environment["PROCESSOR_ARCHITECTURE"] = "AMD64";
            environment["PROCESSOR_IDENTIFIER"] = "AMD64 Family 23 Model 1 Stepping 2, AuthenticAMD";
            environment["PROCESSOR_LEVEL"] = "6";
            environment["PROCESSOR_REVISION"] = "0002";
            environment["NUMBER_OF_PROCESSORS"] = "1";
            environment["OS"] = "Windows 10";
            environment["SystemRoot"] = "C:\\Windows";
            environment["TEMP"] = "C:\\Windows\\Temp";
            environment["TMP"] = "C:\\Windows\\Temp";
            environment["USERPROFILE"] = "C:\\Users\\Administrator";
            environment["ProgramData"] = "C:\\ProgramData";
            environment["ALLUSERSPROFILE"] = "C:\\ProgramData";
            environment["CommonProgramFiles"] = "C:\\Program Files\\Common Files";
            environment["CommonProgramFiles(x86)"] = "C:\\Program Files (x86)\\Common Files";
            environment["CommonProgramW6432"] = "C:\\Program Files\\Common Files";
            environment["CommonProgramW6432(x86)"] = "C:\\Program Files (x86)\\Common Files";
            environment["CommonDocuments"] = R"(C:\Users\Public\Documents)";
            environment["CommonStartMenu"] = R"(C:\ProgramData\Microsoft\Windows\Start Menu\Programs)";
            environment["CommonStartup"] = R"(C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup)";
            environment["CommonPrograms"] = R"(C:\ProgramData\Microsoft\Windows\Start Menu\Programs)";
            environment["CommonDesktopDirectory"] = R"(C:\Users\Public\Desktop)";
            environment["CommonTemplates"] = R"(C:\ProgramData\Microsoft\Windows\Templates)";
            environment["CommonVideos"] = R"(C:\Users\Public\Videos)";
            environment["CommonMusic"] = R"(C:\Users\Public\Music)";
            environment["CommonPictures"] = R"(C:\Users\Public\Pictures)";
            environment["CommonOemLinks"] = R"(C:\ProgramData\Microsoft\Windows\OEM Links)";
            environment["CommonAdminTools"] = R"(C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Administrative Tools)";
            environment["CommonAppdata"] = R"(C:\Users\Public\Application Data)";
        }

        // before executing, register handler to capture events like ctrl+c, ctrl+break, etc.
        signal(SIGINT, [](int signum) {
            // execute registered handlers
            for (const PHANDLER_ROUTINE& handler : process_info[tls.process].console_control_handlers) {
                if (handler) {
                    handler(CTRL_C_EVENT);
                }
            }
            std::exit(0);
        });
        signal(SIGTERM, [](int signum) {
            // execute registered handlers
            for (const PHANDLER_ROUTINE& handler : process_info[tls.process].console_control_handlers) {
                if (handler) {
                    handler(CTRL_CLOSE_EVENT);
                }
            }
            std::exit(0);
        });
        signal(SIGABRT, [](int signum) {
            // execute registered handlers
            for (const PHANDLER_ROUTINE& handler : process_info[tls.process].console_control_handlers) {
                if (handler) {
                    handler(CTRL_BREAK_EVENT);
                }
            }
            std::exit(0);
        });
        signal(SIGSEGV, [](int signum) {
            // execute registered handlers
            for (const PHANDLER_ROUTINE& handler : process_info[tls.process].console_control_handlers) {
                if (handler) {
                    handler(CTRL_SHUTDOWN_EVENT);
                }
            }
            std::exit(1);
        });
        signal(SIGFPE, [](int signum) {
            // execute registered handlers
            for (const PHANDLER_ROUTINE& handler : process_info[tls.process].console_control_handlers) {
                if (handler) {
                    handler(CTRL_LOGOFF_EVENT);
                }
            }
            std::exit(1);
        });
        // on console close, call handlers
        // this is platform dependent and may not work on all systems
        // on Linux, we can use atexit to register a function to be called on exit
        atexit([]() {
            for (const PHANDLER_ROUTINE& handler : process_info[tls.process].console_control_handlers) {
                if (handler) {
                    handler(CTRL_CLOSE_EVENT);
                }
            }
        });

        // Execute with better error handling
        try {
            typedef int (*EntryFunc)();
            const auto entry_func = reinterpret_cast<EntryFunc>(entry_point);
            const int ret = entry_func();
            trace("Program exited with code ", std::to_wstring(ret));
        } catch (const std::exception& e) {
            error("Execution failed: " + std::string(e.what()));
        }

        return mem;
    }
};

// ============================================================
// Main Function
// ============================================================
int main(const int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <pe_file>\n";
        return 1;
    }

    const std::string pe_path = argv[1];

    try {
        if (WineLikeLoader loader; loader.load_pe(pe_path)) {
            trace("PE file executed successfully");
        } else {
            error("PE file execution failed");
            return 1;
        }
    } catch (const std::exception& e) {
        error("Execution failed: " + std::string(e.what()));
        return 1;
    }

    return 0;
}