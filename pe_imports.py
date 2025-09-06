#!/usr/bin/env python3
# pe_imports.py
# Improved PE import parser for PE32+ (x64).
# - fixes pointer/stomping bugs when reading descriptors/thunks
# - handles RVA vs VA values in thunk entries
# - optional ordinal resolution by parsing DLL export tables (if DLL file found)

import struct
import sys
import os
import ctypes.util

IMAGE_DOS_SIGNATURE = b'MZ'
IMAGE_NT_SIGNATURE = b'PE\x00\x00'

SIZEOF_DOS_HEADER = 64
SIZEOF_FILE_HEADER = 20
SIZEOF_SECTION_HEADER = 40

IMPORT_DIRECTORY_INDEX = 1
IMAGE_ORDINAL_FLAG64 = 0x8000000000000000

def read_dos_header(f):
    f.seek(0)
    data = f.read(SIZEOF_DOS_HEADER)
    if data[0:2] != IMAGE_DOS_SIGNATURE:
        raise ValueError("Invalid DOS signature")
    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    return e_lfanew

def read_pe_header(f, offset):
    f.seek(offset)
    sig = f.read(4)
    if sig != IMAGE_NT_SIGNATURE:
        raise ValueError("Invalid PE signature")
    file_header = f.read(SIZEOF_FILE_HEADER)
    Machine, NumberOfSections, TimeDateStamp, PointerToSymbolTable, NumberOfSymbols, SizeOfOptionalHeader, Characteristics = struct.unpack('<HHIIIHH', file_header)
    optional_header = f.read(SizeOfOptionalHeader)
    OptionalHeaderMagic = struct.unpack_from('<H', optional_header, 0)[0]
    if OptionalHeaderMagic != 0x20B:
        raise ValueError("Not a PE32+ (x64) executable")

    # Offsets inside optional header (PE32+)
    AddressOfEntryPoint = struct.unpack_from('<I', optional_header, 16)[0]
    ImageBase = struct.unpack_from('<Q', optional_header, 24)[0]
    SizeOfImage = struct.unpack_from('<I', optional_header, 56)[0]

    # Data directories start at offset 112 in PE32+ optional header
    DataDirectoryStart = 112
    # Import directory
    ImportDirectoryRVA, ImportDirectorySize = struct.unpack_from('<II', optional_header, DataDirectoryStart + 8 * IMPORT_DIRECTORY_INDEX)

    section_headers_offset = offset + 4 + SIZEOF_FILE_HEADER + SizeOfOptionalHeader
    return {
        'NumberOfSections': NumberOfSections,
        'AddressOfEntryPoint': AddressOfEntryPoint,
        'ImageBase': ImageBase,
        'SizeOfImage': SizeOfImage,
        'ImportDirectoryRVA': ImportDirectoryRVA,
        'ImportDirectorySize': ImportDirectorySize,
        'SectionHeadersOffset': section_headers_offset,
        'SizeOfOptionalHeader': SizeOfOptionalHeader,
    }

def read_section_headers(f, offset, num_sections):
    f.seek(offset)
    sections = []
    for _ in range(num_sections):
        data = f.read(SIZEOF_SECTION_HEADER)
        Name = data[0:8].rstrip(b'\x00').decode(errors='ignore')
        VirtualSize = struct.unpack_from('<I', data, 8)[0]
        VirtualAddress = struct.unpack_from('<I', data, 12)[0]
        SizeOfRawData = struct.unpack_from('<I', data, 16)[0]
        PointerToRawData = struct.unpack_from('<I', data, 20)[0]
        sections.append({
            'Name': Name,
            'VirtualSize': VirtualSize,
            'VirtualAddress': VirtualAddress,
            'SizeOfRawData': SizeOfRawData,
            'PointerToRawData': PointerToRawData,
        })
    return sections

def rva_to_offset(rva, sections):
    """Map an RVA to a file offset. Return None when mapping is not possible."""
    if rva == 0:
        return None
    for sec in sections:
        start = sec['VirtualAddress']
        virt = sec['VirtualSize'] if sec['VirtualSize'] != 0 else sec['SizeOfRawData']
        raw = sec['SizeOfRawData']
        if start <= rva < start + virt:
            delta = rva - start
            if delta < raw:
                return sec['PointerToRawData'] + delta
            else:
                return None
    return None

def rva_or_va_to_offset(val, sections, image_base=None):
    """Try val as RVA; if fails and image_base provided, try val-image_base."""
    if val == 0:
        return None
    off = rva_to_offset(val, sections)
    if off is not None:
        return off
    if image_base is not None and val >= image_base:
        rva = val - image_base
        off = rva_to_offset(rva, sections)
        if off is not None:
            return off
    return None

def read_cstring_at_rva(f, rva, sections, image_base=None):
    off = rva_or_va_to_offset(rva, sections, image_base)
    if off is None:
        return None
    f.seek(off)
    b = bytearray()
    while True:
        c = f.read(1)
        if not c or c == b'\x00':
            break
        b.extend(c)
    try:
        return b.decode('ascii', errors='ignore')
    except Exception:
        return b.decode(errors='ignore')

# Caching export tables per DLL file path
_EXPORT_CACHE = {}

def parse_exports_from_file(path):
    """Return dict mapping ordinal -> name for exported functions in given PE file."""
    if not os.path.exists(path):
        return {}
    if path in _EXPORT_CACHE:
        return _EXPORT_CACHE[path]

    try:
        with open(path, 'rb') as f:
            e_lfanew = read_dos_header(f)
            header = read_pe_header(f, e_lfanew)
            # need to re-read optional header to get export directory (we'll replicate minimal reading)
            f.seek(e_lfanew + 4 + SIZEOF_FILE_HEADER)
            opt = f.read(header['SizeOfOptionalHeader'])
            # export dir is data directory index 0
            DataDirectoryStart = 112
            ExportRVA, ExportSize = struct.unpack_from('<II', opt, DataDirectoryStart + 0*8)
            if ExportRVA == 0:
                _EXPORT_CACHE[path] = {}
                return {}
            sections = read_section_headers(f, header['SectionHeadersOffset'], header['NumberOfSections'])
            exp_off = rva_to_offset(ExportRVA, sections)
            if exp_off is None:
                _EXPORT_CACHE[path] = {}
                return {}
            f.seek(exp_off)
            # IMAGE_EXPORT_DIRECTORY: 40 bytes
            edata = f.read(40)
            (Characteristics, TimeDateStamp, MajorVersion, MinorVersion, NameRVA,
             Base, NumberOfFunctions, NumberOfNames, AddressOfFunctions,
             AddressOfNames, AddressOfNameOrdinals) = struct.unpack('<IIHHIIIIIII', edata)

            # Read arrays
            ord_to_name = {}
            # Read names and ordinals
            for i in range(NumberOfNames):
                name_rva_off = rva_to_offset(AddressOfNames + i*4, sections)
                if name_rva_off is None:
                    continue
                f.seek(name_rva_off)
                entry_name_rva = struct.unpack('<I', f.read(4))[0]
                name = read_cstring_at_rva(f, entry_name_rva, sections, header['ImageBase'])
                # get ordinal index
                ord_idx_off = rva_to_offset(AddressOfNameOrdinals + i*2, sections)
                if ord_idx_off is None:
                    continue
                f.seek(ord_idx_off)
                ord_index = struct.unpack('<H', f.read(2))[0]
                real_ordinal = Base + ord_index
                ord_to_name[real_ordinal] = name
            _EXPORT_CACHE[path] = ord_to_name
            return ord_to_name
    except Exception:
        _EXPORT_CACHE[path] = {}
        return {}

def try_find_dll_on_disk(dll_name, search_paths=None):
    """Try to locate dll_name on disk. Returns path or None.
       You can pass search_paths (list) to try additional directories.
    """
    # normalize name
    base = dll_name
    if base.lower().endswith('.dll'):
        base = base
    else:
        base = base + '.dll'

    # user-provided dirs
    if search_paths:
        for d in search_paths:
            p = os.path.join(d, base)
            if os.path.exists(p):
                return p

    # same dir as analyzed exe (if present)
    # environment common locations (Windows)
    if os.name == 'nt':
        cands = [
            os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'System32', base),
            os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'SysWOW64', base),
            os.path.join(os.getcwd(), base)
        ]
        for p in cands:
            if os.path.exists(p):
                return p

    # try ctypes.find_library (might return 'advapi32' or path-like result)
    try:
        found = ctypes.util.find_library(os.path.splitext(base)[0])
        if found:
            # If find_library returned a path, use it; otherwise we may need to try common dirs
            if os.path.exists(found):
                return found
            # On Unix it may return 'advapi32' etc; try SystemRoot
            if os.name == 'nt':
                try_p = os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'System32', found)
                if os.path.exists(try_p):
                    return try_p
    except Exception:
        pass

    # last resort: current directory
    p = os.path.join(os.getcwd(), base)
    if os.path.exists(p):
        return p

    return None

def parse_import_table(f, import_rva, import_size, sections, image_base=None, dll_search_paths=None):
    """Return list of imports: { 'DLL': name, 'Functions': [names...] }"""
    if not import_rva:
        return []

    imports = []
    desc_size = 20
    dir_off = rva_to_offset(import_rva, sections)
    if dir_off is None:
        # maybe import_rva is provided as VA; try as VA
        if image_base and import_rva >= image_base:
            candidate = import_rva - image_base
            dir_off = rva_to_offset(candidate, sections)
        if dir_off is None:
            print("Import directory RVA not found in sections")
            return []

    idx = 0
    while True:
        entry_off = dir_off + idx * desc_size
        f.seek(entry_off)
        data = f.read(desc_size)
        if len(data) < desc_size:
            break
        OriginalFirstThunk, TimeDateStamp, ForwarderChain, NameRVA, FirstThunk = struct.unpack('<IIIII', data)
        if (OriginalFirstThunk | TimeDateStamp | ForwarderChain | NameRVA | FirstThunk) == 0:
            break  # end

        dll_name = read_cstring_at_rva(f, NameRVA, sections, image_base) or "<unknown>"

        # Choose lookup (INT) if present, otherwise fallback to IAT
        lookup_rva = OriginalFirstThunk if OriginalFirstThunk != 0 else FirstThunk
        funcs = []

        # Iterate thunks by computing explicit offsets so we never lose our place
        t_index = 0
        while True:
            thunk_rva = lookup_rva + t_index * 8  # 8 bytes per IMAGE_THUNK_DATA64
            thunk_off = rva_to_offset(thunk_rva, sections)
            # If pointer not in file, maybe lookup_rva was stored as VA; try convert to RVA with image_base
            if thunk_off is None and image_base is not None and lookup_rva >= image_base:
                thunk_rva_conv = (lookup_rva - image_base) + t_index * 8
                thunk_off = rva_to_offset(thunk_rva_conv, sections)
            if thunk_off is None:
                break
            f.seek(thunk_off)
            entry_data = f.read(8)
            if len(entry_data) < 8:
                break
            entry_val = struct.unpack('<Q', entry_data)[0]
            if entry_val == 0:
                break

            # Ordinal?
            if entry_val & IMAGE_ORDINAL_FLAG64:
                ordinal = entry_val & 0xffff
                # Try to resolve ordinal via on-disk DLL (optional)
                dll_path = try_find_dll_on_disk(dll_name, dll_search_paths)
                name = None
                if dll_path:
                    exports = parse_exports_from_file(dll_path)
                    name = exports.get(ordinal)
                funcs.append(name if name else f"Ordinal{ordinal}")
            else:
                # entry_val likely an RVA to IMAGE_IMPORT_BY_NAME; try to read it
                hintname_rva = entry_val
                func_name = read_cstring_at_rva(f, hintname_rva + 2, sections, image_base)  # skip WORD hint
                if func_name is None:
                    # try treat entry_val as VA
                    if image_base is not None and entry_val >= image_base:
                        func_name = read_cstring_at_rva(f, (entry_val - image_base) + 2, sections, image_base)
                funcs.append(func_name if func_name else "<unknown>")

            t_index += 1

        imports.append({'DLL': dll_name, 'Functions': funcs})
        idx += 1

    return imports

def load_pe_image(filename, dll_search_paths=None):
    with open(filename, 'rb') as f:
        e_lfanew = read_dos_header(f)
        header = read_pe_header(f, e_lfanew)
        NumberOfSections = header['NumberOfSections']
        EntryPoint = header['AddressOfEntryPoint']
        ImageBase = header['ImageBase']
        SizeOfImage = header['SizeOfImage']
        ImportDirectoryRVA = header['ImportDirectoryRVA']
        ImportDirectorySize = header['ImportDirectorySize']
        section_headers_offset = header['SectionHeadersOffset']

        sections = read_section_headers(f, section_headers_offset, NumberOfSections)

        print(f"Number of Sections: {NumberOfSections}")
        print(f"Entry Point RVA: 0x{EntryPoint:X}")
        print(f"Image Base: 0x{ImageBase:X}")
        print(f"Size of Image: 0x{SizeOfImage:X}")

        # Build in-memory image (optional)
        image = bytearray(SizeOfImage)
        for sec in sections:
            if sec['SizeOfRawData'] == 0:
                continue
            f.seek(sec['PointerToRawData'])
            data = f.read(sec['SizeOfRawData'])
            start = sec['VirtualAddress']
            end = start + len(data)
            print(f"Loading section {sec['Name']} at 0x{start:X} size 0x{len(data):X}")
            if end <= len(image):
                image[start:end] = data
            else:
                # defensive: append if necessary
                needed = end - len(image)
                image.extend(b'\x00' * needed)
                image[start:end] = data

        imports = parse_import_table(f, ImportDirectoryRVA, ImportDirectorySize, sections, ImageBase, dll_search_paths=dll_search_paths)
        print("Imports:")
        for imp in imports:
            print(f"  {imp['DLL']}")
            for fn in imp['Functions']:
                print(f"    {fn}")

        return image, EntryPoint, ImageBase, sections, imports, ImportDirectoryRVA, ImportDirectorySize

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <x64_windows_executable.exe> [--dlls=dir1{os.pathsep}dir2...]")
        sys.exit(1)

    dll_search_paths = None
    if len(sys.argv) >= 3 and sys.argv[2].startswith('--dlls='):
        dll_search_paths = sys.argv[2].split('=', 1)[1].split(os.pathsep)
        dll_search_paths = [p for p in dll_search_paths if p]

    in_file = sys.argv[1]
    image, entry_point, image_base, sections, imports, ImportDirectoryRVA, ImportDirectorySize = load_pe_image(in_file, dll_search_paths)
    entry_addr = image_base + entry_point
    print(f"Entry point address (VA): 0x{entry_addr:X}")
    print(f"Image Base: 0x{image_base:X}")
    print(f"Image Size (in-memory): 0x{len(image):X}")
    print(f"Import Directory RVA: 0x{ImportDirectoryRVA:X}")
    print(f"Import Directory Size: 0x{ImportDirectorySize:X}")
