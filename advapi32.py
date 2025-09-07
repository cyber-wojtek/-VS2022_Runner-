import random as rnd
import os
from log import *
from win_types import *
import ctypes as ct
import ctypes.wintypes as wt
import json
import glob
from pathlib import Path
from kernel32 import SetLastError

system_rnd = rnd.SystemRandom()

def CryptAcquireContextW(
        phProv: PHCRYPTPROV,
        szContainer: wt.LPCSTR,
        szProvider: wt.LPCSTR,
        dwProvType: wt.DWORD,
        dwFlags: wt.DWORD
) -> wt.BOOL:
    fixme(
        f"CryptAcquireContextW diserror-stub. phProv: {phProv}, szContainer: {szContainer}, szProvider: {szProvider}, dwProvType: {dwProvType}, dwFlags: {dwFlags}")
    phProv[0] = 0x2137
    SetLastError(wt.DWORD(0))  # ERROR_SUCCESS
    ret(f"  {wt.BOOL(1)}")  # Return TRUE for success
    return wt.BOOL(1)


def CryptGenRandom(
        hProv: HCRYPTPROV,
        dwLen: wt.DWORD,
        pbBuffer: wt.PBYTE
) -> wt.BOOL:
    fixme(f"CryptGenRandom diserror-stub. hProv: {hProv}, dwLen: {dwLen}, pbBuffer: {pbBuffer}")
    # Generate proper random bytes (0-255), not just 0-1
    for i in range(dwLen.value):
        pbBuffer[i] = system_rnd.randint(0, 255)
    SetLastError(wt.DWORD(0))
    ret(f"  {wt.BOOL(1)}")  # Return TRUE for success
    return wt.BOOL(1)


def CryptReleaseContext(
        hProv: HCRYPTPROV,
        dwFlags: wt.DWORD
) -> wt.BOOL:
    fixme("CryptReleaseContext diserror-stub. hProv: {hProv}, dwFlags: {dwFlags}")
    SetLastError(wt.DWORD(0))
    ret(f"  {wt.BOOL(1)}")  # Return TRUE for success
    return wt.BOOL(1)


def EventRegister(
        ProviderId: LPCGUID,
        EnableCallback: PENABLECALLNBACK,
        CallbackContext: wt.LPVOID,
        RegHandle: PREGHANDLE
) -> wt.ULONG:
    fixme("EventRegister diserror-stub. ProviderId: {ProviderId}, EnableCallback: {EnableCallback}, CallbackContext: {CallbackContext}, RegHandle: {RegHandle}")
    RegHandle[0] = 0x1337
    SetLastError(wt.DWORD(0))
    ret(f"  {wt.ULONG(0)}")  # ERROR_SUCCESS
    return wt.ULONG(0)


def EventWriteTransfer(
        RegHandle: REGHANDLE,
        EventDescriptor: PEVENT_DESCRIPTOR,
        ActivityId: LPCGUID,
        RelatedActivityId: LPCGUID,
        UserDataCount: wt.ULONG,
        UserData: PEVENT_DATA_DESCRIPTOR
) -> wt.ULONG:
    fixme(
        "EventWriteTransfer diserror-stub. RegHandle: {RegHandle}, EventDescriptor: {EventDescriptor}, ActivityId: {ActivityId}, RelatedActivityId: {RelatedActivityId}, UserDataCount: {UserDataCount}, UserData: {UserData}")
    SetLastError(wt.DWORD(0))
    ret(f"  {wt.ULONG(0)}")  # ERROR_SUCCESS
    return wt.ULONG(0)


REG_TYPE_MAP = {
    1: "REG_SZ",
    2: "REG_EXPAND_SZ",
    3: "REG_BINARY",
    4: "REG_DWORD",
    7: "REG_MULTI_SZ",
    11: "REG_QWORD",
}

REG_TYPE_REVERSE = {v: k for k, v in REG_TYPE_MAP.items()}

# Standard registry root keys mapping
regkey_map = {
    "HKEY_CLASSES_ROOT": HKEY(0x80000000),
    "HKEY_CURRENT_USER": HKEY(0x80000001),
    "HKEY_LOCAL_MACHINE": HKEY(0x80000002),
    "HKEY_USERS": HKEY(0x80000003),
    "HKEY_PERFORMANCE_DATA": HKEY(0x80000004),
    "HKEY_CURRENT_CONFIG": HKEY(0x80000005),
    "HKEY_DYN_DATA": HKEY(0x80000006),
}


def _store_value(key_dict, name, value, dwType):
    """Store value in-memory and JSON with type"""
    if isinstance(value, int):
        if dwType == 4:
            store = {"type": "REG_DWORD", "value": value}
        elif dwType == 11:
            store = {"type": "REG_QWORD", "value": value}
        else:
            raise ValueError("Invalid integer type")
    elif isinstance(value, str):
        if dwType == 1:
            store = {"type": "REG_SZ", "value": value}
        elif dwType == 2:
            store = {"type": "REG_EXPAND_SZ", "value": value}
        else:
            store = {"type": "REG_SZ", "value": value}
    elif isinstance(value, bytes):
        import base64
        store = {"type": "REG_BINARY", "value": base64.b64encode(value).decode()}
    elif isinstance(value, list) and all(isinstance(i, str) for i in value):
        store = {"type": "REG_MULTI_SZ", "value": value}
    else:
        raise ValueError("Unsupported value type")
    key_dict[name] = store
    _save_registry()


def _load_value(store):
    """Reconstruct Python value from stored JSON"""
    typ = store["type"]
    val = store["value"]
    if typ == "REG_DWORD" or typ == "REG_QWORD":
        return int(val)
    elif typ == "REG_SZ" or typ == "REG_EXPAND_SZ":
        return str(val)
    elif typ == "REG_BINARY":
        import base64
        return base64.b64decode(val)
    elif typ == "REG_MULTI_SZ":
        return list(val)
    else:
        raise ValueError(f"Unknown registry type {typ}")


# Persistent registry
registry_file = "registry.json"
if os.path.exists(registry_file):
    with open(registry_file, "r", encoding="utf-8") as f:
        registry = json.load(f)
else:
    registry = {k: {} for k in regkey_map}

# Dynamic handle map
_next_handle = 0x1000
_handle_map: dict[int, dict] = {}  # hKey -> key dict


def _alloc_handle(key_dict: dict) -> int:
    global _next_handle
    h = _next_handle
    _next_handle += 1
    _handle_map[h] = key_dict
    return h


def _save_registry():
    try:
        with open(registry_file, "w", encoding="utf-8") as f:
            json.dump(registry, f, indent=2, ensure_ascii=False)
    except Exception as e:
        trace(f"Failed to save registry: {e}")


# ----------------------------
# RegOpenKeyExW
# ----------------------------
def RegOpenKeyExW(
        hKey: HKEY,
        lpSubKey: wt.LPCWSTR,  # wide string
        ulOptions: wt.DWORD,
        samDesired: REGSAM,
        phKeyResult: PHKEY
) -> LSTATUS:
    trace("RegOpenKeyExW impl. hKey: {hKey}, lpSubKey: {lpSubKey}, ulOptions: {ulOptions}, samDesired: {samDesired}")

    # Map numeric hKey to string
    top_name = None
    for name, val in regkey_map.items():
        if val.value == hKey:
            top_name = name
            break

    # Handle case where hKey is already a dynamic handle
    if top_name is None and hKey in _handle_map:
        key_dict = _handle_map[hKey]
    elif top_name is None:
        SetLastError(wt.DWORD(6))  # ERROR_INVALID_HANDLE
        ret(f"  {wt.LONG(1)}")
        return wt.LONG(1)  # ERROR_INVALID_HANDLE
    else:
        key_dict = registry.get(top_name, {})

    # Navigate subkeys if provided
    if lpSubKey:
        # lpSubKey is already a Python string (UTF-16 decoded by ctypes)
        for part in lpSubKey.value.split("\\"):
            if not part:  # Skip empty parts
                continue
            if part not in key_dict:
                SetLastError(wt.DWORD(2))  # ERROR_FILE_NOT_FOUND
                ret(f"  {wt.LONG(2)}")
                return wt.LONG(2)  # ERROR_FILE_NOT_FOUND
            key_dict = key_dict[part]

    handle = _alloc_handle(key_dict)
    phKeyResult[0] = HKEY(handle)

    SetLastError(wt.DWORD(6))
    ret(f"  {wt.LONG(0)}")
    return wt.LONG(0)  # ERROR_SUCCESS


# ----------------------------
# RegGetValueW
# ----------------------------
def RegGetValueW(
        hKey: HKEY,
        lpSubKey: wt.LPCWSTR,  # wide string
        lpValue: wt.LPCWSTR,  # wide string
        dwFlags: wt.DWORD,
        pdwType: wt.PDWORD,
        pvData: wt.LPVOID,
        pcbData: wt.PDWORD
) -> LSTATUS:
    trace("RegGetValueW impl. hKey: {hKey}, lpSubKey: {lpSubKey}, lpValue: {lpValue}, dwFlags: {dwFlags}")

    if hKey.value not in _handle_map:
        ret(f"  {wt.LONG(1)}")
        return wt.LONG(1)  # ERROR_INVALID_HANDLE

    key_dict = _handle_map[hKey.value]

    if not key_dict:
        SetLastError(wt.DWORD(6))

    # Navigate subkey if provided
    if lpSubKey:
        for part in lpSubKey.split("\\"):
            if not part:
                continue
            if part not in key_dict:
                SetLastError(wt.DWORD(2))
                ret(f"  {wt.LONG(2)}")
                return wt.LONG(2)  # ERROR_FILE_NOT_FOUND
            key_dict = key_dict[part]

    if lpValue not in key_dict:
        SetLastError(wt.DWORD(2))
        ret(f"  {wt.LONG(2)}")
        return wt.LONG(2)  # ERROR_FILE_NOT_FOUND

    value_entry = key_dict[lpValue]

    # Handle both old format (direct values) and new format (stored objects)
    if isinstance(value_entry, dict) and "type" in value_entry:
        value = _load_value(value_entry)
        reg_type = REG_TYPE_REVERSE[value_entry["type"]]
    else:
        # Legacy support for direct values
        value = value_entry
        if isinstance(value, int):
            reg_type = 4  # REG_DWORD
        elif isinstance(value, str):
            reg_type = 1  # REG_SZ
        elif isinstance(value, bytes):
            reg_type = 3  # REG_BINARY
        else:
            SetLastError(wt.DWORD(13))
            ret(f"  {wt.LONG(13)}")
            return wt.LONG(13)  # ERROR_INVALID_DATA

    # Set type if requested
    if pdwType:
        pdwType[0] = wt.DWORD(reg_type)

    # Encode data based on type
    if reg_type == 4:  # REG_DWORD
        data = value.to_bytes(4, "little")
    elif reg_type == 11:  # REG_QWORD
        data = value.to_bytes(8, "little")
    elif reg_type in (1, 2):  # REG_SZ, REG_EXPAND_SZ
        data = value.encode("utf-16le") + b"\x00\x00"
    elif reg_type == 3:  # REG_BINARY
        data = value
    elif reg_type == 7:  # REG_MULTI_SZ
        data = "\x00".join(value).encode("utf-16le") + b"\x00\x00\x00\x00"
    else:
        ret(f"  {wt.LONG(13)}")
        return wt.LONG(13)  # ERROR_INVALID_DATA

    # Copy to buffer if provided
    if pvData and pcbData:
        buf_size = pcbData[0]
        n = min(len(data), buf_size)
        ct.memmove(pvData, data, n)
        pcbData[0] = wt.DWORD(len(data))
    elif pcbData:
        # Just return required size
        pcbData[0] = wt.DWORD(len(data))

    SetLastError(wt.DWORD(0))
    ret(f"  {wt.LONG(0)}")
    return wt.LONG(0)  # ERROR_SUCCESS


def RegCreateKeyExW(
        hKey: HKEY,
        lpSubKey: wt.LPCWSTR,
        Reserved: wt.DWORD,
        lpClass: wt.LPCWSTR,
        dwOptions: wt.DWORD,
        samDesired: REGSAM,
        lpSecurityAttributes,
        phKeyResult: PHKEY,
        lpdwDisposition
) -> LSTATUS:
    trace("RegCreateKeyExW impl. hKey: {hKey}, lpSubKey: {lpSubKey}, dwOptions: {dwOptions}")

    # Map numeric hKey to string
    top_name = None
    for name, val in regkey_map.items():
        if val.value == hKey.value:
            top_name = name
            break

    # Handle dynamic handles
    if top_name is None and hKey.value in _handle_map:
        key_dict = _handle_map[hKey.value]
        created_new = False
    elif top_name is None:
        SetLastError(wt.DWORD(6))  # ERROR_INVALID_HANDLE
        ret(f"  {wt.LONG(1)}")
        return wt.LONG(1)  # ERROR_INVALID_HANDLE
    else:
        key_dict = registry.setdefault(top_name, {})
        created_new = False

    if lpSubKey:
        for part in lpSubKey.value.split("\\"):
            if not part:
                continue
            if part not in key_dict:
                key_dict[part] = {}
                created_new = True
            key_dict = key_dict[part]

    handle = _alloc_handle(key_dict)
    phKeyResult[0] = HKEY(handle)

    if lpdwDisposition is not None:
        lpdwDisposition[0] = wt.DWORD(1 if created_new else 2)  # 1=REG_CREATED_NEW_KEY, 2=REG_OPENED_EXISTING_KEY

    _save_registry()
    SetLastError(wt.DWORD(0)) # ERROR_SUCCESS
    ret(f"  {wt.LONG(0)}")
    return wt.LONG(0)  # ERROR_SUCCESS


def RegSetValueExW(
        hKey: HKEY,
        lpValueName: wt.LPCWSTR,
        Reserved: wt.DWORD,
        dwType: wt.DWORD,
        lpData: wt.LPVOID,
        cbData: wt.DWORD
) -> LSTATUS:
    trace(f"RegSetValueExW impl. hKey={hKey}, lpValueName={lpValueName}, dwType={dwType}, cbData={cbData}")
    key_dict = _handle_map.get(hKey.value)
    if not key_dict:
        SetLastError(wt.DWORD(6))
        return wt.LONG(1)  # ERROR_INVALID_HANDLE

    # Convert lpData to Python value
    try:
        if dwType == 1 or dwType == 2:  # REG_SZ or REG_EXPAND_SZ
            # Handle null-terminated wide strings
            raw_data = ct.string_at(lpData, cbData.value)
            value = raw_data.decode("utf-16le").rstrip('\0')
        elif dwType == 3:  # REG_BINARY
            value = ct.string_at(lpData, cbData.value)
        elif dwType == 4:  # REG_DWORD
            value = int.from_bytes(ct.string_at(lpData, 4), "little")
        elif dwType == 7:  # REG_MULTI_SZ
            raw_bytes = ct.string_at(lpData, cbData.value)
            decoded = raw_bytes.decode("utf-16le")
            # Split on null chars and filter empty strings (except final empty from double-null)
            value = [s for s in decoded.split("\x00") if s]
        elif dwType == 11:  # REG_QWORD
            value = int.from_bytes(ct.string_at(lpData, 8), "little")
        else:
            SetLastError(wt.DWORD(13))
            return wt.LONG(13)  # ERROR_INVALID_DATA
    except Exception as e:
        error(f"  Error converting registry data: {e}")
        SetLastError(wt.DWORD(13))
        ret(f"  {wt.LONG(13)}")
        return wt.LONG(13)  # ERROR_INVALID_DATA

    _store_value(key_dict, lpValueName, value, dwType)
    SetLastError(wt.DWORD(0))
    ret(f"  {wt.LONG(0)}")
    return wt.LONG(0)  # ERROR_SUCCESS


def RegCloseKey(
        hKey: HKEY
) -> LSTATUS:
    trace("RegCloseKey impl. hKey: {hKey}")

    if hKey.value in _handle_map:
        del _handle_map[hKey.value]
        SetLastError(wt.DWORD(0))
        ret(f"  {wt.LONG(0)}")
        return wt.LONG(0)  # ERROR_SUCCESS
    SetLastError(wt.DWORD(6))  # ERROR_INVALID_HANDLE
    ret(f"  {wt.LONG(1)}")
    return wt.LONG(1)  # ERROR_INVALID_HANDLE


def RegQueryValueExW(
        hKey: HKEY,
        lpValueName: wt.LPCWSTR,
        lpReserved: wt.LPDWORD,
        pdwType: wt.PDWORD,
        pvData: wt.LPVOID,
        pcbData: wt.PDWORD
) -> LSTATUS:
    trace(f"RegQueryValueExW impl. hKey={hKey}, lpValueName={lpValueName}")

    key_dict = _handle_map.get(hKey.value)
    if not key_dict:
        return wt.LONG(1)  # ERROR_INVALID_HANDLE
    if lpValueName not in key_dict:
        return wt.LONG(2)  # ERROR_FILE_NOT_FOUND

    value_entry = key_dict[lpValueName]

    # Handle both stored format and legacy direct values
    if isinstance(value_entry, dict) and "type" in value_entry:
        value = _load_value(value_entry)
        reg_type = REG_TYPE_REVERSE[value_entry["type"]]
    else:
        # Legacy direct value
        value = value_entry
        if isinstance(value, int):
            reg_type = 4
        elif isinstance(value, str):
            reg_type = 1
        elif isinstance(value, bytes):
            reg_type = 3
        else:
            SetLastError(wt.DWORD(13))
            return wt.LONG(13)  # ERROR_INVALID_DATA

    if pdwType:
        pdwType[0] = wt.DWORD(reg_type)

    # Encode data for output
    if reg_type in (1, 2):  # REG_SZ, REG_EXPAND_SZ
        data_bytes = value.encode("utf-16le") + b"\x00\x00"
    elif reg_type == 7:  # REG_MULTI_SZ
        data_bytes = "\x00".join(value).encode("utf-16le") + b"\x00\x00\x00\x00"
    elif reg_type == 4:  # REG_DWORD
        data_bytes = value.to_bytes(4, "little")
    elif reg_type == 11:  # REG_QWORD
        data_bytes = value.to_bytes(8, "little")
    elif reg_type == 3:  # REG_BINARY
        data_bytes = value
    else:
        SetLastError(wt.DWORD(13))
        return wt.LONG(13)  # ERROR_INVALID_DATA

    # Copy to buffer if provided
    if pvData and pcbData:
        max_len = pcbData[0]
        n = min(len(data_bytes), max_len)
        ct.memmove(pvData, data_bytes, n)
        pcbData[0] = wt.DWORD(len(data_bytes))
    elif pcbData:
        pcbData[0] = wt.DWORD(len(data_bytes))

    SetLastError(wt.DWORD(0))
    ret(f"  {wt.LONG(0)}")
    return wt.LONG(0)  # ERROR_SUCCESS