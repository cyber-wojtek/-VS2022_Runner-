import colorama as clr
from enum import IntEnum

class LogLevel(IntEnum):
    TRACE = 0
    FIXME = 1
    WARN = 2
    ERROR = 3

current_level = LogLevel.TRACE

def fixme(*args, **kwargs):
    if current_level <= LogLevel.FIXME:
        print(clr.Fore.YELLOW  + "[FIXME] " + clr.Style.RESET_ALL, *args, **kwargs)

def warn(*args, **kwargs):
    if current_level <= LogLevel.WARN:
        print(clr.Fore.MAGENTA + "[WARN]  " + clr.Style.RESET_ALL, *args, **kwargs)

def error(*args, **kwargs):
    if current_level <= LogLevel.ERROR:
        print(clr.Fore.RED     + "[ERROR] " + clr.Style.RESET_ALL, *args, **kwargs)

def trace(*args, **kwargs):
    if current_level <= LogLevel.TRACE:
        print(clr.Fore.CYAN    + "[TRACE] " + clr.Style.RESET_ALL, *args, **kwargs)

def ret(*args, **kwargs):
    if current_level <= LogLevel.TRACE:
        print(clr.Fore.GREEN   + "[RETURN]" + clr.Style.RESET_ALL, *args, **kwargs)