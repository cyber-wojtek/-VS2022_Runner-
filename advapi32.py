# advapi32.py
from log import *
import globals as g
import json
import base64
from win_types import *
import random as rnd

# ----------------------------
# Registry constants
# ----------------------------
REG_TYPE_MAP = {
    1: "REG_SZ",
    2: "REG_EXPAND_SZ",
    3: "REG_BINARY",
    4: "REG_DWORD",
    7: "REG_MULTI_SZ",
    11: "REG_QWORD",
}
REG_TYPE_REVERSE = {v: k for k, v in REG_TYPE_MAP.items()}

REGKEY_MAP = {
    "HKEY_CLASSES_ROOT": wt.HKEY(0x80000000),
    "HKEY_CURRENT_USER": wt.HKEY(0x80000001),
    "HKEY_LOCAL_MACHINE": wt.HKEY(0x80000002),
    "HKEY_USERS": wt.HKEY(0x80000003),
    "HKEY_PERFORMANCE_DATA": wt.HKEY(0x80000004),
    "HKEY_CURRENT_CONFIG": wt.HKEY(0x80000005),
    "HKEY_DYN_DATA": wt.HKEY(0x80000006),
}

# ----------------------------
# Helpers
# ----------------------------
def _save_registry():
    try:
        trace(f"Saving registry to {g.registry_file}")
        with open(g.registry_file, "w", encoding="utf-8") as f:
            json.dump(g.registry, f, indent=2, ensure_ascii=False)
        trace("Registry saved successfully")
    except Exception as e:
        error(f"Failed to save registry: {e}")


def _store_value(key_dict, name, value, dwType):
    trace(f"Storing value [{name=}, {value=}, {dwType=}]")
    if isinstance(value, int):
        if dwType == 4:
            store = {"type": "REG_DWORD", "value": value}
        elif dwType == 11:
            store = {"type": "REG_QWORD", "value": value}
        else:
            raise ValueError(f"Invalid integer type {dwType}")
    elif isinstance(value, str):
        if dwType == 1:
            store = {"type": "REG_SZ", "value": value}
        elif dwType == 2:
            store = {"type": "REG_EXPAND_SZ", "value": value}
        else:
            store = {"type": "REG_SZ", "value": value}
    elif isinstance(value, bytes):
        store = {"type": "REG_BINARY", "value": base64.b64encode(value).decode()}
    elif isinstance(value, list) and all(isinstance(i, str) for i in value):
        store = {"type": "REG_MULTI_SZ", "value": value}
    else:
        raise ValueError(f"Unsupported value type {type(value)}")
    key_dict[name] = store
    _save_registry()


def _load_value(store):
    trace(f"Loading value {store}")
    typ = store["type"]
    val = store["value"]
    if typ in ("REG_DWORD", "REG_QWORD"):
        return int(val)
    elif typ in ("REG_SZ", "REG_EXPAND_SZ"):
        return str(val)
    elif typ == "REG_BINARY":
        return base64.b64decode(val)
    elif typ == "REG_MULTI_SZ":
        return list(val)
    else:
        raise ValueError(f"Unknown registry type {typ}")


def _alloc_registry_handle() -> int:
    h = g.next_registry_handle
    g.next_registry_handle += 1
    trace(f"Allocating registry handle {h}")
    g.registry_handles[h] = {}
    return h


# ----------------------------
# Advapi32 class
# ----------------------------
class Advapi32:
    def __init__(self):
        self.exports = {
            "RegOpenKeyExW": self.RegOpenKeyExW,
            "RegGetValueW": self.RegGetValueW,
            "RegCreateKeyExW": self.RegCreateKeyExW,
            "RegSetValueExW": self.RegSetValueExW,
            "RegCloseKey": self.RegCloseKey,
            "RegQueryValueExW": self.RegQueryValueExW,
            "CryptAcquireContextW": self.CryptAcquireContextW,
            "CryptGenRandom": self.CryptGenRandom,
            "CryptReleaseContext": self.CryptReleaseContext,
            "EventRegister": self.EventRegister,
            "EventWriteTransfer": self.EventWriteTransfer,
        }

    # ----------------------------
    # Registry APIs
    # ----------------------------
    @staticmethod
    def RegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired, phKeyResult):
        trace(f"RegOpenKeyExW called [{hKey=}, {lpSubKey=}, {ulOptions=}, {samDesired=}]")
        top_name = None
        for name, val in REGKEY_MAP.items():
            if val.value == hKey:
                top_name = name
                break
        if top_name:
            trace(f"Top-level key: {top_name}")
            key_dict = g.registry.setdefault(top_name, {})
        else:
            if hKey in g.registry_handles:
                key_dict = g.registry_handles[hKey]
                trace(f"Using dynamic handle {hKey}")
            else:
                from kernel32 import Kernel32
                error(f"Invalid registry handle {hKey}")
                Kernel32.SetLastError(wt.DWORD(6))
                return wt.LONG(1)
        if lpSubKey:
            for part in lpSubKey.value.split("\\"):
                if not part:
                    continue
                if part not in key_dict:
                    from kernel32 import Kernel32
                    error(f"Subkey not found: {lpSubKey.value}")
                    Kernel32.SetLastError(wt.DWORD(2))
                    return wt.LONG(2)
                key_dict = key_dict[part]
        handle = _alloc_registry_handle()
        g.registry_handles[handle] = key_dict
        phKeyResult[0] = wt.HKEY(handle)
        trace(f"RegOpenKeyExW returning handle {handle}")
        from kernel32 import Kernel32
        Kernel32.SetLastError(wt.DWORD(0))
        return wt.LONG(0)

    @staticmethod
    def RegCreateKeyExW(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phKeyResult, lpdwDisposition):
        trace(f"RegCreateKeyExW called [{hKey=}, {lpSubKey=}]")
        if hKey in g.registry_handles:
            key_dict = g.registry_handles[hKey]
            created_new = False
        else:
            top_name = None
            for name, val in REGKEY_MAP.items():
                if val.value == hKey:
                    top_name = name
                    break
            if top_name:
                key_dict = g.registry.setdefault(top_name, {})
                created_new = False
            else:
                from kernel32 import Kernel32
                error(f"Invalid handle {hKey}")
                Kernel32.SetLastError(wt.DWORD(6))
                return wt.LONG(1)
        if lpSubKey:
            for part in lpSubKey.value.split("\\"):
                if part not in key_dict:
                    key_dict[part] = {}
                    created_new = True
                key_dict = key_dict[part]
        handle = _alloc_registry_handle()
        g.registry_handles[handle] = key_dict
        phKeyResult[0] = wt.HKEY(handle)
        if lpdwDisposition is not None:
            lpdwDisposition[0] = wt.DWORD(1 if created_new else 2)
        _save_registry()
        from kernel32 import Kernel32
        Kernel32.SetLastError(wt.DWORD(0))
        trace(f"RegCreateKeyExW returning handle {handle}, new: {created_new}")
        return wt.LONG(0)

    @staticmethod
    def RegSetValueExW(hKey, lpValueName, Reserved, dwType, lpData, cbData):
        trace(f"RegSetValueExW called [{hKey=}, {lpValueName=}, {dwType=}, {cbData=}]")
        if hKey not in g.registry_handles:
            from kernel32 import Kernel32
            error(f"Invalid handle {hKey}")
            Kernel32.SetLastError(wt.DWORD(6))
            return wt.LONG(1)
        key_dict = g.registry_handles[hKey]
        if dwType in (1, 2):
            raw_data = ct.string_at(lpData, cbData)
            value = raw_data.decode("utf-16le").rstrip('\0')
        elif dwType == 3:
            value = ct.string_at(lpData, cbData)
        elif dwType == 4:
            value = int.from_bytes(ct.string_at(lpData, 4), "little")
        elif dwType == 11:
            value = int.from_bytes(ct.string_at(lpData, 8), "little")
        elif dwType == 7:
            raw_bytes = ct.string_at(lpData, cbData)
            value = [s for s in raw_bytes.decode("utf-16le").split("\x00") if s]
        else:
            from kernel32 import Kernel32
            error(f"Unsupported registry type {dwType}")
            Kernel32.SetLastError(wt.DWORD(13))
            return wt.LONG(13)
        _store_value(key_dict, lpValueName, value, dwType)
        from kernel32 import Kernel32
        Kernel32.SetLastError(wt.DWORD(0))
        trace(f"RegSetValueExW stored [{lpValueName}=...]")
        return wt.LONG(0)

    @staticmethod
    def RegCloseKey(hKey):
        trace(f"RegCloseKey called [{hKey=}]")
        if hKey in g.registry_handles:
            del g.registry_handles[hKey]
            from kernel32 import Kernel32
            Kernel32.SetLastError(wt.DWORD(0))
            trace(f"RegCloseKey closed handle {hKey}")
            return wt.LONG(0)
        from kernel32 import Kernel32
        Kernel32.SetLastError(wt.DWORD(6))
        error(f"RegCloseKey invalid handle {hKey}")
        return wt.LONG(1)

    @staticmethod
    def RegQueryValueExW(hKey, lpValueName, lpReserved, pdwType, pvData, pcbData):
        trace(f"RegQueryValueExW called [{hKey=}, {lpValueName=}]")
        if hKey not in g.registry_handles:
            from kernel32 import Kernel32
            error(f"Invalid handle {hKey}")
            Kernel32.SetLastError(wt.DWORD(6))
            return wt.LONG(1)
        key_dict = g.registry_handles[hKey]
        if lpValueName not in key_dict:
            from kernel32 import Kernel32
            error(f"Value {lpValueName} not found")
            Kernel32.SetLastError(wt.DWORD(2))
            return wt.LONG(2)
        value_entry = key_dict[lpValueName]
        value = _load_value(value_entry)
        reg_type = REG_TYPE_REVERSE[value_entry["type"]]
        if pdwType:
            pdwType[0] = wt.DWORD(reg_type)
        if reg_type in (1, 2):
            data_bytes = value.encode("utf-16le") + b"\x00\x00"
        elif reg_type == 7:
            data_bytes = "\x00".join(value).encode("utf-16le") + b"\x00\x00\x00\x00"
        elif reg_type == 4:
            data_bytes = value.to_bytes(4, "little")
        elif reg_type == 11:
            data_bytes = value.to_bytes(8, "little")
        elif reg_type == 3:
            data_bytes = value
        else:
            from kernel32 import Kernel32
            error(f"Unsupported registry type {reg_type}")
            Kernel32.SetLastError(wt.DWORD(13))
            return wt.LONG(13)
        if pvData and pcbData:
            n = min(pcbData[0], len(data_bytes))
            ct.memmove(pvData, data_bytes, n)
            pcbData[0] = wt.DWORD(len(data_bytes))
            trace(f"Copied {n} bytes to pvData")
        elif pcbData:
            pcbData[0] = wt.DWORD(len(data_bytes))
        from kernel32 import Kernel32
        Kernel32.SetLastError(wt.DWORD(0))
        trace("RegQueryValueExW completed successfully")
        return wt.LONG(0)

    @staticmethod
    def RegGetValueW(hKey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData):
        trace(f"RegGetValueW called [{hKey=}, {lpSubKey=}, {lpValue=}, {dwFlags=}]")
        top_name = None
        for name, val in REGKEY_MAP.items():
            if val.value == hKey:
                top_name = name
                break
        if top_name:
            key_dict = g.registry.setdefault(top_name, {})
        else:
            if hKey in g.registry_handles:
                key_dict = g.registry_handles[hKey]
            else:
                from kernel32 import Kernel32
                error(f"Invalid registry handle {hKey}")
                Kernel32.SetLastError(wt.DWORD(6))
                return wt.LONG(1)
        if lpSubKey:
            for part in lpSubKey.value.split("\\"):
                if not part:
                    continue
                if part not in key_dict:
                    from kernel32 import Kernel32
                    error(f"Subkey not found: {lpSubKey.value}")
                    Kernel32.SetLastError(wt.DWORD(2))
                    return wt.LONG(2)
                key_dict = key_dict[part]
        if lpValue.value not in key_dict:
            from kernel32 import Kernel32
            error(f"Value {lpValue.value} not found")
            Kernel32.SetLastError(wt.DWORD(2))
            return wt.LONG(2)
        value_entry = key_dict[lpValue.value]
        value = _load_value(value_entry)
        reg_type = REG_TYPE_REVERSE[value_entry["type"]]
        if pdwType:
            pdwType[0] = wt.DWORD(reg_type)
        if reg_type in (1, 2):
            data_bytes = value.encode("utf-16le") + b"\x00\x00"
        elif reg_type == 7:
            data_bytes = "\x00".join(value).encode("utf-16le") + b"\x00\x00\x00\x00"
        elif reg_type == 4:
            data_bytes = value.to_bytes(4, "little")
        elif reg_type == 11:
            data_bytes = value.to_bytes(8, "little")
        elif reg_type == 3:
            data_bytes = value
        else:
            from kernel32 import Kernel32
            error(f"Unsupported registry type {reg_type}")
            Kernel32.SetLastError(wt.DWORD(13))
            return wt.LONG(13)
        if pvData and pcbData:
            n = min(pcbData[0], len(data_bytes))
            ct.memmove(pvData, data_bytes, n)
            pcbData[0] = wt.DWORD(len(data_bytes))
            trace(f"Copied {n} bytes to pvData")
        elif pcbData:
            pcbData[0] = wt.DWORD(len(data_bytes))
        from kernel32 import Kernel32
        Kernel32.SetLastError(wt.DWORD(0))
        trace("RegGetValueW completed successfully")
        return wt.LONG(0)

    # ----------------------------
    # Cryptography APIs (stubs)
    # ----------------------------
    @staticmethod
    def CryptAcquireContextW(phProv: PHCRYPTPROV, szContainer: wt.LPCSTR, szProvider: wt.LPCSTR, dwProvType: wt.DWORD, dwFlags: wt.DWORD) -> wt.BOOL:
        fixme(f"CryptAcquireContextW diserror-stub. {locals()}")
        phProv[0] = 0x2137
        from kernel32 import Kernel32
        Kernel32.SetLastError(wt.DWORD(0))
        ret(f"{wt.BOOL(1)}")
        return wt.BOOL(1)

    @staticmethod
    def CryptGenRandom(hProv: HCRYPTPROV, dwLen: wt.DWORD, pbBuffer: wt.PBYTE) -> wt.BOOL:
        fixme(f"CryptGenRandom semi-stub. {locals()}")
        for i in range(dwLen.value):
            pbBuffer[i] = g.system_rnd.randint(0, 255)
        from kernel32 import Kernel32
        Kernel32.SetLastError(wt.DWORD(0))
        ret(f"{wt.BOOL(1)}")
        return wt.BOOL(1)

    @staticmethod
    def CryptReleaseContext(hProv: HCRYPTPROV, dwFlags: wt.DWORD) -> wt.BOOL:
        fixme(f"CryptReleaseContext diserror-stub. {locals()}")
        from kernel32 import Kernel32
        Kernel32.SetLastError(wt.DWORD(0))
        ret(f"{wt.BOOL(1)}")
        return wt.BOOL(1)

    # ----------------------------
    # Eventing APIs (stubs)
    # ----------------------------
    @staticmethod
    def EventRegister(ProviderId: LPCGUID, EnableCallback: PENABLECALLNBACK, CallbackContext: wt.LPVOID, RegHandle: PREGHANDLE) -> wt.ULONG:
        fixme(f"EventRegister diserror-stub. {locals()}")
        RegHandle[0] = 0x1337
        from kernel32 import Kernel32
        Kernel32.SetLastError(wt.DWORD(0))
        ret(f"{wt.ULONG(0)}")
        return wt.ULONG(0)

    @staticmethod
    def EventWriteTransfer(RegHandle: REGHANDLE, EventDescriptor: PEVENT_DESCRIPTOR, ActivityId: LPCGUID, RelatedActivityId: LPCGUID, UserDataCount: wt.ULONG, UserData: PEVENT_DATA_DESCRIPTOR) -> wt.ULONG:
        fixme(f"EventWriteTransfer diserror-stub. {locals()}")
        from kernel32 import Kernel32
        Kernel32.SetLastError(wt.DWORD(0))
        ret(f"{wt.ULONG(0)}")
        return wt.ULONG(0)
