import ctypes as ct
import ctypes.wintypes as wt

type HCRYPTPROV = wt.ULONG



def CryptAcquireContextW(
    phProv: ct._Pointer[HCRYPTPROV],
    szContainer: wt.LPCSTR,
    szProvider: wt.LPCSTR,
    dwProvType: wt.DWORD,
    dwFlags: wt.DWORD
) -> wt.BOOL:
    ...


def CryptGenRandom(
    hProv: HCRYPTPROV,
    dwLen: wt.DWORD,
    pbBuffer: wt.PBYTE
) -> wt.BOOL:
    ...