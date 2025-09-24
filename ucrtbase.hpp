//
// Created by wojtek on 9/12/25.
//
#pragma ONCE

#include <semaphore.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <pthread.h>
#include <mutex>
#include "global.h"
#include <sys/types.h>
#include "log.h"
#include <cstdarg>
#include <ranges>
#include <unordered_map>
#include <string>
#include <cwchar>
#include <clocale>
#include <cmath>
// complex
#include <complex>
//#include <complex.h>
// for itoa
#include <cassert>
#include <cfenv>
#include <cinttypes>
#include <csignal>
#include <cuchar>
#include <LIEF/PE/OptionalHeader.hpp>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wreserved-identifier"

#ifndef _VS2022_RUNNER__UCRTBASE_HPP
#define _VS2022_RUNNER__UCRTBASE_HPP

class UCRTBase {
public:
    static std::unordered_map<std::wstring, EmulatedExport> get_exports_detailed();

    static void *memset_(void* dest, int ch, size_t count);

    static void *memcpy_(void* dest, const void* src, size_t count);

    static _wchar_t *wmemcpy(_wchar_t* dest, const _wchar_t* src, size_t count);

    static int memcmp_(const void* ptr1, const void* ptr2, size_t count);

    static void *memmove_(void* dest, const void* src, size_t count);

    static _wchar_t *wmemmove(_wchar_t* dest, const _wchar_t* src, size_t count);

    static size_t strlen_(const char* str);

    static char *strcpy_(char* dest, const char* src);

    static char *strncpy_(char* dest, const char* src, size_t count);

    static int strcmp_(const char* str1, const char* str2);

    static int strncmp_(const char* str1, const char* str2, size_t count);

    static char *strcat_(char* dest, const char* src);

    static char *strncat_(char* dest, const char* src, size_t count);

    static int __toascii_(int c);

    static char *strchr_(const char* str, int character);

    static char *strrchr_(const char* str, int character);

    static char *strstr_(const char* haystack, const char* needle);

    static int _atodbl(const char* str, double* value);

    static int _atodbl_l(const char* str, double* value, _locale_t /*locale*/);

    static double _atof_l(const char* str, _locale_t /*locale*/);

    static int _atoflt(const char* str, float* value);

    static int _atoflt_l(const char* str, float* value, _locale_t /*locale*/);

    static INT _atoi_l(const char* str, _locale_t /*locale*/);

    static LONG _atol_l(const char* str, _locale_t /*locale*/);

    static int _atoldbl(const char* str, long double* value);

    static int _atoldbl_l(const char* str, long double* value, _locale_t /*locale*/);

    static LONGLONG _atoll_l(const char* str, _locale_t /*locale*/);

    static LONGLONG _atoll(const char* str);

    static char* _ecvt(double value, int count, int *dec, int *sign);

    static errno_t _ecvt_s(char* buffer, size_t sizeInChars, double value, int count, int* dec, int* sign);

    static char* _fcvt(double value, int count, int* dec, int* sign);

    static errno_t _fcvt_s(char* buffer, size_t sizeInChars, double value, int count, int* dec, int* sign);

    static char* _gcvt(double value, int count, char* buffer);

    static errno_t _gcvt_s(char* buffer, size_t sizeInChars, double value, int count);

    static char* _i64toa(LONGLONG value, char* buffer, int radix);

    static errno_t _i64toa_s(LONGLONG value, char* buffer, size_t sizeInChars, int radix);

    static _wchar_t* _i64tow(LONGLONG value, _wchar_t *buffer, int radix);

    static errno_t _i64tow_s(LONGLONG value, _wchar_t *buffer, size_t sizeInChars, int radix);

    static char* _itoa(int value, char* buffer, int radix);

    static errno_t _itoa_s(int value, char* buffer, size_t sizeInChars, int radix);

    static _wchar_t* _itow(int value, _wchar_t *buffer, int radix);

    static errno_t _itow_s(int value, _wchar_t *buffer, size_t sizeInChars, int radix);

    static char* _ltoa(LONG value, char* buffer, int radix);

    static errno_t _ltoa_s(LONG value, char* buffer, size_t sizeInChars, int radix);

    static _wchar_t* _ltow(LONG value, _wchar_t *buffer, int radix);

    static errno_t _ltow_s(LONG value, _wchar_t *buffer, size_t sizeInChars, int radix);

    static double _strtod_l(const char* str, char** endptr, _locale_t /*locale*/);

    static double _strtod(const char* str, char** endptr);

    static float _strtof_l(const char* str, char** endptr, _locale_t /*locale*/);

    static float _strtof(const char* str, char** endptr);

    static LONGLONG _strtoi64_l(const char* str, char** endptr, int radix, _locale_t /*locale*/);

    static LONGLONG _strtoi64(const char* str, char** endptr, int radix);

    static LONGLONG _strtoimax_l(const char* str, char** endptr, int radix, _locale_t /*locale*/);

    static LONGLONG _strtoimax(const char* str, char** endptr, int radix);

    static LONG _strtol_l(const char* str, char** endptr, int radix, _locale_t /*locale*/);

    static LONG _strtol(const char* str, char** endptr, int radix);

    static long double _strtold_l(const char* str, char** endptr, _locale_t /*locale*/);

    static long double _strtold(const char* str, char** endptr);

    static ULONGLONG _strtoumax_l(const char* str, char** endptr, int radix, _locale_t /*locale*/);

    static ULONGLONG _strtoumax(const char* str, char** endptr, int radix);

    static ULONGLONG _strtoui64_l(const char* str, char** endptr, int radix, _locale_t /*locale*/);

    static ULONGLONG _strtoui64(const char* str, char** endptr, int radix);

    static ULONG _strotoul_l(const char* str, char** endptr, int radix, _locale_t /*locale*/);

    static ULONG _strotoul(const char* str, char** endptr, int radix);

    static char* _ui64toa(ULONGLONG value, char* buffer, int radix);

    static char* _ui64toa_s(ULONGLONG value, char* buffer, size_t sizeInChars, int radix);

    static _wchar_t* _ui64tow(ULONGLONG value, _wchar_t *buffer, int radix);

    static errno_t _ui64tow_s(ULONGLONG value, _wchar_t *buffer, size_t sizeInChars, int radix);

    static char* _ultoa(ULONG value, char* buffer, int radix);

    static errno_t _ultoa_s(ULONG value, char* buffer, size_t sizeInChars, int radix);

    static _wchar_t* _ultow(ULONG value, _wchar_t *buffer, int radix);

    static errno_t _ultow_s(ULONG value, _wchar_t *buffer, size_t sizeInChars, int radix);

    static double _wcstod_l(const _wchar_t* str, _wchar_t** endptr, _locale_t /*locale*/);

    static double _wcstod(const _wchar_t* str, _wchar_t** endptr);

    static float _wcstof_l(const _wchar_t* str, _wchar_t** endptr, _locale_t /*locale*/);

    static float _wcstof(const _wchar_t* str, _wchar_t** endptr);

    static LONGLONG _wcstoi64_l(const _wchar_t* str, _wchar_t** endptr, int radix, _locale_t /*locale*/);

    static LONGLONG _wcstoi64(const _wchar_t* str, _wchar_t** endptr, int radix);

    static LONGLONG _wcstoimax_l(const _wchar_t* str, _wchar_t** endptr, int radix, _locale_t /*locale*/);

    static LONGLONG _wcstoimax(const _wchar_t* str, _wchar_t** endptr, int radix);

    static LONG _wcstol_l(const _wchar_t* str, _wchar_t** endptr, int radix, _locale_t /*locale*/);

    static LONG _wcstol(const _wchar_t* str, _wchar_t** endptr, int radix);

    static long double _wcstold_l(const _wchar_t* str, _wchar_t** endptr, _locale_t /*locale*/);

    static long double _wcstold(const _wchar_t* str, _wchar_t** endptr);

    static LONGLONG _wcstoll_l(const _wchar_t* str, _wchar_t** endptr, int radix, _locale_t /*locale*/);

    static LONGLONG _wcstoll(const _wchar_t* str, _wchar_t** endptr, int radix);

    static ULONGLONG _wcstoull_l(const _wchar_t* str, _wchar_t** endptr, int radix, _locale_t /*locale*/);

    static ULONGLONG _wcstoull(const _wchar_t* str, _wchar_t** endptr, int radix);

    static size_t _wcstombs_l(char* dest, const _wchar_t* src, size_t n, _locale_t /*locale*/);

    static size_t _wcstombs(char* dest, const _wchar_t* src, size_t n);

    static errno_t _wcstombs_s_l(size_t* pReturnValue, char* dest, size_t destSize, const _wchar_t* src, size_t n, _locale_t /*locale*/);

    static errno_t _wcstombs_s(size_t* pReturnValue, char* dest, size_t destSize, const _wchar_t* src, size_t n);

    static size_t _mbstowcs_l(_wchar_t* dest, const char* src, size_t n, _locale_t /*locale*/);

    static size_t _mbstowcs(_wchar_t* dest, const char* src, size_t n);

    static errno_t _mbstowcs_s_l(size_t* pReturnValue, _wchar_t* dest, size_t destSize, const char* src, size_t n, _locale_t /*locale*/);

    static errno_t _mbstowcs_s(size_t* pReturnValue, _wchar_t* dest, size_t destSize, const char* src, size_t n);

    static ULONGLONG _wcstoui64_l(const _wchar_t* str, _wchar_t** endptr, int radix, _locale_t /*locale*/);

    static ULONGLONG _wcstoui64(const _wchar_t* str, _wchar_t** endptr, int radix);

    static ULONG _wcstoul_l(const _wchar_t* str, _wchar_t** endptr, int radix, _locale_t /*locale*/);

    static ULONG _wcstoul(const _wchar_t* str, _wchar_t** endptr, int radix);

    static int _wctomb_l(char* dest, _wchar_t ch, _locale_t /*locale*/);

    static int _wctomb(char* dest, _wchar_t ch);

    static int _wctomb_s_l(size_t* pReturnValue, char* dest, size_t destSize, _wchar_t ch, _locale_t /*locale*/);

    static int _wctomb_s(size_t* pReturnValue, char* dest, size_t destSize, _wchar_t ch);

    static float _wtof_l(const _wchar_t* str, _wchar_t** endptr, _locale_t /*locale*/);

    static float _wtof(const _wchar_t* str, _wchar_t** endptr);

    static int _wtoi_l(const _wchar_t* str, _wchar_t** endptr, _locale_t /*locale*/);

    static int _wtoi(const _wchar_t* str, _wchar_t** endptr);

    static LONGLONG _wtoi64_l(const _wchar_t* str, _wchar_t** endptr, _locale_t /*locale*/);

    static LONGLONG _wtoi64(const _wchar_t* str, _wchar_t** endptr);

    static LONG _wtol_l(const _wchar_t* str, _wchar_t** endptr, _locale_t /*locale*/);

    static LONG _wtol(const _wchar_t* str, _wchar_t** endptr);

    static LONGLONG _wtoll_l(const _wchar_t* str, _wchar_t** endptr, _locale_t /*locale*/);

    static LONGLONG _wtoll(const _wchar_t* str, _wchar_t** endptr);

    static float atof(const char* str);

    static int atoi(const char* str);

    static LONG atol(const char* str);

    static long long atoll(const char* str);

    static _wchar_t btowc(char c);

    static size_t c16rtomb(char* dest, char16_t ch, mbstate_t* state);

    static size_t c32rtomb(char* dest, char32_t ch, mbstate_t* state);

    static size_t mbrtoc16(char16_t* dest, const char* src, size_t n, mbstate_t* state);

    static size_t mbrtoc32(char32_t* dest, const char* src, size_t n, mbstate_t* state);

    static size_t mbrtowc(_wchar_t* dest, const char* src, size_t n, mbstate_t* state);

    static int mbsinit(const mbstate_t* state);

    static size_t mbsrtowcs(_wchar_t* dest, const char** src, size_t len, mbstate_t* state);

    static errno_t mbsrtowcs_s(size_t* pReturnValue, _wchar_t* dest, size_t destSize, const char** src, size_t len, mbstate_t* state);

    static size_t mbtowc(_wchar_t *dest, const char* src, size_t n);

    static double strtod_l(const char* str, char** endptr, _locale_t /*locale*/);

    static double strtod_(const char* str, char** endptr);

    static float strtof_l(const char* str, char** endptr, _locale_t /*locale*/);

    static float strtof_(const char* str, char** endptr);

    static LONGLONG strtoimax_l(const char* str, char** endptr, int radix, _locale_t /*locale*/);

    static intmax_t strtoimax_(const char* str, char** endptr, int radix);

    static LONG strtol_l(const char* str, char** endptr, int radix, _locale_t /*locale*/);

    static LONG strtol_(const char* str, char** endptr, int radix);

    static long double strtold_l(const char* str, char** endptr, _locale_t /*locale*/);

    static long double strtold_(const char* str, char** endptr);

    static LONGLONG strtoll_l(const char* str, char** endptr, int radix, _locale_t /*locale*/);

    static LONGLONG strtoll_(const char* str, char** endptr, int radix);

    static ULONG strtoul_l(const char* str, char** endptr, int radix, _locale_t /*locale*/);

    static ULONG strtoul_(const char* str, char** endptr, int radix);

    static ULONGLONG strtoull_l(const char* str, char** endptr, int radix, _locale_t /*locale*/);

    static ULONGLONG strtoull_(const char* str, char** endptr, int radix);

    static uintmax_t strtoumax_l(const char* str, char** endptr, int radix, _locale_t /*locale*/);

    static uintmax_t strtoumax_(const char* str, char** endptr, int radix);

    static size_t wcrtomb_(char* dest, _wchar_t ch, mbstate_t* state);

    static errno_t wcrtomb_s(size_t* pReturnValue, char* dest, size_t destSize, _wchar_t ch, mbstate_t* state);

    static size_t wcsrtombs_(char* dest, const _wchar_t** src, size_t len, mbstate_t* state);

    static errno_t wcsrtombs_s(size_t* pReturnValue, char* dest, size_t destSize, const _wchar_t** src, size_t len, mbstate_t* state);

    static double wcstod_l(const _wchar_t* str, _wchar_t** endptr, _locale_t /*locale*/);

    static double wcstod_(const _wchar_t* str, _wchar_t** endptr);

    static float wcstof_l(const _wchar_t* str, _wchar_t** endptr, _locale_t /*locale*/);

    static float wcstof_(const _wchar_t* str, _wchar_t** endptr);

    static intmax_t wcstoimax_l(const _wchar_t* str, _wchar_t** endptr, int radix, _locale_t /*locale*/);

    static intmax_t wcstoimax_(const _wchar_t* str, _wchar_t** endptr, int radix);

    static LONG wcstol_l(const _wchar_t* str, _wchar_t** endptr, int radix, _locale_t /*locale*/);

    static LONG wcstol_(const _wchar_t* str, _wchar_t** endptr, int radix);

    static long double wcstold_l(const _wchar_t* str, _wchar_t** endptr, _locale_t /*locale*/);

    static long double wcstold_(const _wchar_t* str, _wchar_t** endptr);

    static LONGLONG wcstoll_l(const _wchar_t* str, _wchar_t** endptr, int radix, _locale_t /*locale*/);

    static LONGLONG wcstoll_(const _wchar_t* str, _wchar_t** endptr, int radix);

    static size_t wcstombs_(char* dest, const _wchar_t* src, size_t n);

    static errno_t wcstombs_s(size_t* pReturnValue, char* dest, size_t destSize, const _wchar_t* src, size_t n);

    static size_t mbstowcs_(_wchar_t *dest, const char* src, size_t n);

    static errno_t mbstowcs_s(size_t* pReturnValue, _wchar_t *dest, size_t destSize, const char* src, size_t n);

    static ULONG wcstoul_l(const _wchar_t* str, _wchar_t** endptr, int radix, _locale_t /*locale*/);

    static ULONG wcstoul_(const _wchar_t* str, _wchar_t** endptr, int radix);

    static ULONGLONG wcstoull_l(const _wchar_t* str, _wchar_t** endptr, int radix, _locale_t /*locale*/);

    static ULONGLONG wcstoull_(const _wchar_t* str, _wchar_t** endptr, int radix);

    static uintmax_t wcstoumax_l(const _wchar_t* str, _wchar_t** endptr, int radix, _locale_t /*locale*/);

    static uintmax_t wcstoumax_(const _wchar_t* str, _wchar_t** endptr, int radix);

    static int wctob_(_wint_t wc);

    static int wctomb_(char* dest, _wchar_t wc);

    static int mbtowc_(_wchar_t* dest, const char* src, size_t n);

    static errno_t wctomb_s(size_t* pReturnValue, char* dest, size_t destSize, _wchar_t wc);

    static wctrans_t wctrans_(const char* charclass);

    static void _Exit_(int exitCode);

    static int __control87_2(unsigned int newControl, unsigned int mask, unsigned int* x86_cw, unsigned int* sse2_cw);

    static errno_t __doserrno();

    static int __fpe_flt_rounds();

    static int __fpecode();

    static int* __p___argc();

    static char*** __p___argv();

    static _wchar_t*** __p___wargv();

    static char** __p___acmdln();

    static _wchar_t** __p___wcmdln();

    static _wchar_t** __p__wpgmptr();

    static EXCEPTION_POINTERS *__pxcptinfoptrs();

    static char* _strerror(char* errMsg);

    static errno_t _strerror_s(char* buffer, size_t numberOfElements, const char* errMsg);

    static _wchar_t *_wcserror(int errNum);

    static errno_t _wcserror_s(wchar_t* errMsg, size_t errMsgSize, int errNum);

    static errno_t __wcserror_s(_wchar_t *buffer, size_t numberOfElements, _wchar_t *errMsg);

    static const char** __sys_errlist();

    static int __sys_nerr();

    static HANDLE __threadhandle();

    static UINT __threadid();

    static void _assert(const char* message, const char* file, unsigned int line);

    static void _wassert(const _wchar_t* message, const _wchar_t* file, unsigned int line);

    struct _beginthread_helper {
        void(*start_address)(void*);
        LPVOID arglist;
    };

    static uintptr_t _beginthread(void(*startAddress)(void*), unsigned stackSize, void* arglist);

    static uintptr_t _beginthreadex(
        void* security,
        unsigned stackSize,
        void(*startAddress)(void*),
        void* arglist,
        unsigned initflag,
        unsigned* thrdaddr);

    static void _c_exit();

    static void _cexit();

    static UINT _clearfp();

    static errno_t _configure_narrow_argv();

    static errno_t _configure_wide_argv();

    static UINT _control87(unsigned int newControl, unsigned int mask);

    static UINT _controlfp(UINT newControl, UINT mask);

    static errno_t _controlfp_s(unsigned int* currentControl, unsigned int newControl, unsigned int mask);

    static int _crt_at_quick_exit(void(*func)());

    static int _crt_atexit(void(*func)());

    static int _crt_debugger_hook(int reportType, char* message, int* returnValue);

    static void _endthread();

    static void _endthreadex(unsigned retval);

    static int* _errno();

    static int _initialize_onexit_table(_onexit_table_t* table);

    static int _register_onexit_function(
        _onexit_table_t* table,
        _onexit_t        function
        );

    static int _execute_onexit_table(
        _onexit_table_t* table
        );

    static void _exit(int exitCode);

    static int _fpieee_flt(ULONG excCode, EXCEPTION_POINTERS *excInfo, int handler(_FPIEEE_RECORD));

    static void _fpreset();

    static errno_t _get_doserrno(unsigned int* perrno);

    static errno_t _get_errno(unsigned int* perrno);

    static char** _get_initial_narrow_environment();

    static _wchar_t **_get_initial_wide_environment();

    static _invalid_parameter_handler _get_invalid_parameter_handler();

    static _invalid_parameter_handler _get_thread_local_invalid_parameter_handler();

    static void _set_invalid_parameter_handler(_invalid_parameter_handler handler);

    static void _set_thread_local_invalid_parameter_handler(_invalid_parameter_handler handler);

    static char* _get_narrow_winmain_command_line();

    static char* _get_pgmptr();

    static _wchar_t* _get_wpgmptr();

    static _wchar_t* _get_wide_winmain_command_line();

    static terminate_function _get_terminate();

    static terminate_function _set_terminate(terminate_function func);

    static FARPROC _getdllprocaddr(HMODULE hModule, char* name, int ordinalOnly);

    static int _getpid();

    static int _initialize_narrow_environment();

    static int _initialize_wide_environment();

    static void _initterm(_PVFV* start, _PVFV* end);

    static int _initterm_e(_PIFV* start, _PIFV* end);

    static void _invalid_parameter_noinfo();

    static void _invalid_parameter_noinfo_noreturn();

    // _invoke_watson
    static void _invoke_watson(
        const _wchar_t* expression,
        const _wchar_t* function,
        const _wchar_t* file,
        unsigned int   line,
        uintptr_t      pReserved
    );

    static int _query_app_type();

    static void _register_thread_local_exe_atexit_callback(_tls_callback_type func);

    static int _resetstkoflw();

    static int _seh_filter_dll(unsigned int exceptionCode);

    static int _seh_filter_exe(unsigned int exceptionCode);

    static UINT _set_abort_behavior(UINT flags, UINT mask);

    static void _set_app_type(int appType);

    static void _set_controlfp(UINT newControl, UINT mask);

    static void _set_doserrno(int err);

    static void _set_errno(int err);

    static int _set_error_mode(int mode);

    static _PNH _set_new_handler(_PNH pNew);

    static int _seterrormode(int mode);

    static void _sleep(ULONG milliseconds);

    static UINT _statusfp();

    static void _statusfp2(UINT* x86_cw, UINT* sse2_cw);

    static int system_(const char* command);

    static int _wsystem(const _wchar_t* command);

    // FINALLY NORMAL FUNCTIONS THAT ARE FUCKING DOCUMENTED !!!!!!! (a little crash out)
    static void abort();

    static void exit(int exitCode);

    static int feclearexcept(int excepts);

    static int fetestexcept(int excepts);

    static int fegetenv(fenv_t* envp);

    static int fesetenv(const fenv_t* envp);

    static int fegetround();

    static int fesetround(int round);

    static int fegetexceptflag(fexcept_t* flagp, int excepts);

    static int feholdexcept(fenv_t* envp);

    static void perror(const char* message);

    static void quick_exit(int exitCode);

    static int raise(int sig);

    static std::terminate_handler set_terminate(std::terminate_handler func);

    static __sighandler_t signal(int sig, __sighandler_t func);

    static const char* strerror(int errnum);

    static errno_t strerror_s(char* buf, size_t buflen, int errnum);

    static void terminate();

    static double _cabs(const _complex z);

    static double _chgsign(const double* x);

    static float _chgsignf(const float* x);

    static long double _chgsignl(const long double* x);

    static double _copysign(const double* x, const double* y);

    static float _copysignf(const float* x, const float* y);

    static long double _copysignl(const long double* x, const long double* y);

    // not even wine has this documented, so this hopefully works ???
    static int _d_int();

    static short _dclass(double x);

    static short _ldclass(long double x);

    static short _fdclass(float x);


    static short _dexp(double *px, double y, LONG exp);

    static short _fdexp(float *px, float y, LONG exp);

    static short _ldexp(long double *px, long double y, LONG exp);

    static short _dlog(double x, int base_flag);

    static short _fdlog(float x, int base_flag);

    static short _ldlog(long double x, int base_flag);

    static short _dnorm(USHORT *ps);


    static short _fdnorm(USHORT *ps);

    static short _ldnorm(USHORT *ps);

    static short _dpcomp(double x, double y);

    static short _dpoly(double x, double const* table, int n);

    static short _fdpoly(float x, float const* table, int n);

    static short _ldpoly(long double x, long double const* table, int n);


    static double _evaluate_polynomial(const std::vector<double>& coefficients, double x);

    static short _dscale(double* x, int exp);

    static short _fdscale(float* x, int exp);

    static short _ldscale(long double* x, int exp);

    static int _dsign(double x);

    static int _fdsign(float x);

    static int _ldsign(long double x);

    static double _dsin(double x, UINT quadrant);

    static float _fdsin(float x, UINT quadrant);

    static long double _ldsin(long double x, UINT quadrant);

    static short _dtest(double* px);

    static short _fdtest(float* px);

    static short _ldtest(long double* px);

    static short _dunscale(int* pexp, double* px);

    static short _fdunscale(int* pexp, float* px);

    static short _ldunscale(int* pexp, long double* px);

    static UINT get_mxcsr();

    static void set_mxcsr(UINT mxcsr);

    // also stolen from wine
    static void _setfp_sse(UINT *cw, UINT cw_mask, UINT* sw, UINT sw_mask);

    // shamelessly stolen from wine cuz no docs
    static double _except1(DWORD fpe, _FP_OPERATION_CODE op, double arg, double res, DWORD cw, void *unk);

    static double _CIacos(double x);

    static double _CIasin(double x);

    static double _CIatan(double x);

    static double _CIatan2(double y, double x);

    static double _CIcos(double x);

    static double _CIsin(double x);

    static double _CItan(double x);


    static double _CIcosh(double x);

    static double _CIexp(double x);

    static double _CIfmod(double x, double y);

    static double _CIlog10(double x);

    static double _CIlog(double x);

    static double _CIsinh(double x);

    static double _CIsqrt(double x);

    static double _CItanh(double x);

    static _Dcomplex _Cbuild(double real, double imag);

    static _Dcomplex _Cmulcc(_Dcomplex a, _Dcomplex b);

    static _Dcomplex _Cmulcr(_Dcomplex a, double b);

    // why tf does wine return ulonglong here?
    // -> because msvc does (says copilot)
    static ULONGLONG _FCbuild(float real, float imag);

    static _Fcomplex _FCmulcc(_Fcomplex a, _Fcomplex b);

    static _Fcomplex _FCmulcr(_Fcomplex a, float b);

    static _Lcomplex _LCbuild(long double real, long double imag);

    static _Lcomplex _LCmulcc(_Lcomplex a, _Lcomplex b);

    static _Lcomplex _LCmulcr(_Lcomplex a, long double b);

    static void __libm_sse2_acos();

    static void __libm_sse2_acos_precise();

    static void __libm_sse2_acosf();

    static void __libm_sse2_asin();

    static void __libm_sse2_asin_precise();

    static void __libm_sse2_asinf();

    static void __libm_sse2_atan();

    static void __libm_sse2_atan_precise();

    static void __libm_sse2_atanf();

    static void __libm_sse2_atan2();

    static void __libm_sse2_atan2_precise();

    static void __libm_sse2_atan2f();

    static void __libm_sse2_cos();

    static void __libm_sse2_cos_precise();

    static void __libm_sse2_cosf();

    static void __libm_sse2_sin();

    static void __libm_sse2_sin_precise();

    static void __libm_sse2_sinf();

    static void __libm_sse2_tan();

    static void __libm_sse2_tan_precise();

    static void __libm_sse2_tanf();

    static void __libm_sse2_exp();

    static void __libm_sse2_exp_precise();

    static void __libm_sse2_expf();

    static void __libm_sse2_log();

    static void __libm_sse2_log_precise();

    static void __libm_sse2_logf();

    static void __libm_sse2_log10();


    static void __libm_sse2_log10_precise();

    static void __libm_sse2_log10f();

    static void __libm_sse2_sqrt();

    static void __libm_sse2_sqrt_precise();

    static void __libm_sse2_sqrtf();

    static void __libm_sse2_pow();

    static void __libm_sse2_pow_precise();

    static void __libm_sse2_powf();

    static void __libm_sse2_cbrt();

    static void __libm_sse2_cbrt_precise();

    static void __libm_sse2_cbrtf();

    static double _logb(double x);

    static float _logbf(float x);

    static long double _logbl(long double x);

    static double _nextafter(double from, double to);

    static float _nextafterf(float from, float to);

    static long double _nextafterl(long double from, long double to);

    static double _scalb(double x, long n);

    static float _scalbf(float x, long n);

    static long double _scalbl(long double x, long n);

    static void __setusermatherr(ucrt_matherr_func func);

    static double _j0(double x);

    static double _j1(double x);

    static double _jn(int n, double x);

    static double _y0(double x);

    static double _y1(double x);

    static double _yn(int n, double x);

    static double acos_(double x);

    static float acosf_(float x);

    static long double acosl_(long double x);

    static double acosh_(double x);

    static double acoshf_(float x);

    static long double acoshl_(long double x);

    static double asin_(double x);

    static float asinf_(float x);

    static long double asinl_(long double x);

    static double asinh_(double x);

    static float asinhf_(float x);

    static long double asinhl_(long double x);

    static double atan_(double x);

    static float atanf_(float x);

    static long double atanl_(long double x);

    static double atanh_(double x);

    static float atanhf_(float x);


    static long double atanhl_(long double x);

    static double atan2_(double y, double x);

    static float atan2f_(float y, float x);

    static long double atan2l_(long double y, long double x);

    static double cabs(double _Complex z);

    static float cabsf(float _Complex z);

    static long double cabsl(long double _Complex z);

    static double _Complex cacos(double _Complex z);

    static float _Complex cacosf(float _Complex z);

    static long double _Complex cacosl(long double _Complex z);

    static double _Complex cacosh(double _Complex z);

    static float _Complex cacoshf(float _Complex z);

    static long double _Complex cacoshl(long double _Complex z);

    static double _Complex casin(double _Complex z);

    static float _Complex casinf(float _Complex z);

    static long double _Complex casinl(long double _Complex z);

    static double _Complex casinh(double _Complex z);

    static float _Complex casinhf(float _Complex z);

    static long double _Complex casinhl(long double _Complex z);

    static double _Complex catan(double _Complex z);

    static float _Complex catanf(float _Complex z);

    static long double _Complex catanl(long double _Complex z);

    static double _Complex catanh(double _Complex z);

    static float _Complex catanhf(float _Complex z);

    static long double _Complex catanhl(long double _Complex z);

    static double carg(double _Complex z);

    static float cargf(float _Complex z);

    static long double cargl(long double _Complex z);

    static double _Complex cexp(double _Complex z);

    static float _Complex cexpf(float _Complex z);

    static long double _Complex cexpl(long double _Complex z);

    static double cimag(double _Complex z);

    static float cimagf(float _Complex z);

    static long double cimagl(long double _Complex z);

    static double creal(double _Complex z);

    static float crealf(float _Complex z);

    static long double creall(long double _Complex z);

    static double _Complex clog(double _Complex z);

    static float _Complex clogf(float _Complex z);

    static long double _Complex clogl(long double _Complex z);

    static double _Complex clog10(double _Complex z);

    static float _Complex clog10f(float _Complex z);

    static long double _Complex clog10l(long double _Complex z);

    static double _Complex conj(double _Complex z);

    static float _Complex conjf(float _Complex z);

    static long double _Complex conjl(long double _Complex z);

    static double _Complex cpow(double _Complex x, double _Complex y);

    static float _Complex cpowf(float _Complex x, float _Complex y);

    static long double _Complex cpowl(long double _Complex x, long double _Complex y);

    static double _Complex cproj(double _Complex z);

    static float _Complex cprojf(float _Complex z);

    static long double _Complex cprojl(long double _Complex z);

    static double _Complex csin(double _Complex z);

    static float _Complex csinf(float _Complex z);

    static long double _Complex csinl(long double _Complex z);

    static double _Complex csinh(double _Complex z);

    static float _Complex csinhf(float _Complex z);

    static long double _Complex csinhl(long double _Complex z);

    static double _Complex ccos(double _Complex z);

    static float _Complex ccosf(float _Complex z);

    static long double _Complex ccosl(long double _Complex z);

    static double _Complex ccosh(double _Complex z);

    static float _Complex ccoshf(float _Complex z);

    static long double _Complex ccoshl(long double _Complex z);

    static double _Complex ctan(double _Complex z);

    static float _Complex ctanf(float _Complex z);

    static long double _Complex ctanl(long double _Complex z);

    static double _Complex ctanh(double _Complex z);

    static float _Complex ctanhf(float _Complex z);

    static long double _Complex ctanhl(long double _Complex z);

    static double _Complex csqrt(double _Complex z);

    static float _Complex csqrtf(float _Complex z);

    static long double _Complex csqrtl(long double _Complex z);

    static double norm_(double _Complex z);

    static float normf_(float _Complex z);

    static long double norml_(long double _Complex z);

    static double erf_(double x);

    static float erff_(float x);

    static long double erfl_(long double x);

    static double erfc_(double x);

    static float erfcf_(float x);

    static long double erfcl_(long double x);

    static double exp_(double x);

    static float expf_(float x);

    static long double expl_(long double x);

    static double exp2_(double x);

    static float exp2f_(float x);

    static long double exp2l_(long double x);

    static double expm1_(double x);

    static float expm1f_(float x);

    static long double expm1l_(long double x);

    static double fabs_(double x);

    static float fabsf_(float x);

    static long double fabsl_(long double x);

    static double fdim_(double x, double y);

    static float fdimf_(float x, float y);

    static long double fdiml_(long double x, long double y);

    static double floor_(double x);

    static float floorf_(float x);

    static long double floorl_(long double x);

    static double fma_(double x, double y, double z);

    static float fmaf_(float x, float y, float z);

    static long double fmal_(long double x, long double y, long double z);

    static double fmax_(double x, double y);

    static float fmaxf_(float x, float y);

    static long double fmaxl_(long double x, long double y);

    static double fmin_(double x, double y);

    static float fminf_(float x, float y);

    static long double fminl_(long double x, long double y);

    static double fmod_(double x, double y);

    static float fmodf_(float x, float y);

    static long double fmodl_(long double x, long double y);

    static double frexp_(double x, int* exp);

    static float frexpf_(float x, int* exp);

    static long double frexpl_(long double x, int* exp);

    static double hypot_(double x, double y);

    static float hypotf_(float x, float y);

    static long double hypotl_(long double x, long double y);

    static int ilogb_(double x);

    static int ilogbf_(float x);

    static int ilogbl_(long double x);

    static double ldexp_(double x, int exp);

    static float ldexpf_(float x, int exp);

    static long double ldexpl_(long double x, int exp);

    static double lgamma_(double x);

    static float lgammaf_(float x);

    static long double lgammal_(long double x);

    static int rint_(double* px);

    static int rintf_(float* px);

    static int rintl_(long double* px);

    static LONG lrint_(double x);

    static LONG lrintf_(float x);

    static LONG lrintl_(long double x);

    static long long llrint_(double x);

    static long long llrintf_(float x);

    static long long llrintl_(long double x);

    static double round_(double x);

    static float roundf_(float x);

    static long double roundl_(long double x);

    static LONG lround_(double x);

    static LONG lroundf_(float x);

    static LONG lroundl_(long double x);

    static long long llround_(double x);

    static long long llroundf_(float x);

    static long long llroundl_(long double x);

    static double log_(double x);

    static float logf_(float x);

    static long double logl_(long double x);

    static double log10_(double x);

    static float log10f_(float x);

    static long double log10l_(long double x);

    static double log1p_(double x);

    static float log1pf_(float x);

    static long double log1pl_(long double x);

    static double log2_(double x);

    static float log2f_(float x);

    static long double log2l_(long double x);

    static double logb_(double x);

    static float logbf_(float x);

    static long double logbl_(long double x);

    static double modf_(double x, double* intpart);

    static float modff_(float x, float* intpart);

    static long double modfl_(long double x, long double* intpart);

    static double nan_(const char* tagp);

    static float nanf_(const char* tagp);

    static long double nanl_(const char* tagp);

    static double nearbyint_(double x);

    static float nearbyintf_(float x);

    static long double nearbyintl_(long double x);

    static double nextafter_(double x, double y);

    static float nextafterf_(float x, float y);

    static long double nextafterl_(long double x, long double y);

    static double nexttoward_(double x, long double y);

    static float nexttowardf_(float x, long double y);

    static long double nexttowardl_(long double x, long double y);

    static double pow_(double x, double y);

    static float powf_(float x, float y);

    static long double powl_(long double x, long double y);

    static double remainder_(double x, double y);

    static float remainderf_(float x, float y);

    static long double remainderl_(long double x, long double y);

    static double remquo_(double x, double y, int* quo);

    static float remquof_(float x, float y, int* quo);

    static long double remquol_(long double x, long double y, int* quo);

    static double scalbln_(double x, long exp);

    static float scalblnf_(float x, long exp);

    static long double scalblnl_(long double x, long exp);

    static double scalbn_(double x, int exp);

    static float scalbnf_(float x, int exp);

    static long double scalbnl_(long double x, int exp);

    static double cbrt_(double x);

    static double ceil_(double x);

    static float ceilf_(float x);

    static long double ceill_(long double x);

    static float cbrtf_(float x);

    static long double cbrtl_(long double x);

    static double copysign_(double x, double y);

    static float copysignf_(float x, float y);

    static long double copysignl_(long double x, long double y);

    static double cos_(double x);

    static float cosf_(float x);

    static long double cosl_(long double x);

    static double cosh_(double x);

    static float coshf_(float x);

    static long double coshl_(long double x);

    static double sin_(double x);

    static float sinf_(float x);

    static long double sinl_(long double x);

    static double sinh_(double x);

    static float sinhf_(float x);

    static long double sinhl_(long double x);

    static double tan_(double x);

    static float tanf_(float x);

    static long double tanl_(long double x);

    static double tanh_(double x);

    static float tanhf_(float x);

    static long double tanhl_(long double x);

    static double sqrt_(double x);

    static float sqrtf_(float x);

    static long double sqrtl_(long double x);

    static double tgamma_(double x);

    static float tgammaf_(float x);

    static long double tgammal_(long double x);

    static double trunc_(double x);

    static float truncf_(float x);

    static long double truncl_(long double x);

    static FILE* __acrt_iob_func(unsigned index);

    static UINT* __p__commode();

    static INT* __p__fmode();

    static int __stdio_common_vfprintf(UINT64 options, FILE* file, const char* format, _locale_t locale, va_list args);

    static int __stdio_common_vfprinf_p(UINT64 options, FILE* file, const char* format, _locale_t locale, va_list args);

    static int __stdio_common_vfprintf_s(UINT64 options, FILE* file, const char* format, _locale_t locale, va_list args);

    static int __stdio_common_vfscanf(UINT64 options, FILE* file, const char* format, _locale_t locale, va_list args);

    static int __stdio_common_vfwprintf(uint64_t options, FILE* file, const _wchar_t* format, _locale_t locale, va_list args);

    static int __stdio_common_vfwprintf_p(UINT64 options, FILE* file, const _wchar_t* format, _locale_t locale, va_list args);

    static int __stdio_common_vfwprintf_s(UINT64 options, FILE* file, const _wchar_t* format, _locale_t locale, va_list args);

    static int __stdio_common_vfwscanf(uint64_t options, FILE* file, const _wchar_t* format, _locale_t locale, va_list args);

    static int __stdio_common_vsnprintf(UINT64 options, char* buffer, size_t sizeOfBuffer, const char* format, _locale_t locale, va_list args);

    static int __stdio_common_vsnprintf_s(UINT64 options, char* buffer, size_t sizeOfBuffer, size_t count, const char* format, _locale_t locale, va_list args);

    static int __stdio_common_vsnwprintf(uint64_t options, _wchar_t *buffer, size_t sizeOfBuffer, size_t count,
                                         const _wchar_t* format, _locale_t locale, va_list args);

    static int __stdio_common_vsprintf(UINT64 options, char* buffer, const char* format, _locale_t locale, va_list args);

    static int __stdio_common_vsprintf_p(UINT64 options, char* buffer, const char* format, _locale_t locale, va_list args);

    static int __stdio_common_vsprintf_s(UINT64 options, char* buffer, size_t sizeOfBuffer, const char* format, _locale_t locale, va_list args);

    static int __stdio_common_vsscanf(UINT64 options, const char* buffer, const char* format, _locale_t locale, va_list args);

    static int __stdio_common_vswprintf(uint64_t options, _wchar_t *buffer, size_t sizeOfBuffer,
                                        const _wchar_t* format, _locale_t locale, va_list args);

    static int __stdio_common_vswscanf(uint64_t options, const _wchar_t *buffer,
                                       const _wchar_t* format, _locale_t locale, va_list args);

    static int __stdio_common_vswprintf_p(UINT64 options, _wchar_t *buffer, size_t sizeOfBuffer, const _wchar_t* format, _locale_t locale, va_list args);

    static int __stdio_common_vswprintf_s(UINT64 options, _wchar_t *buffer, size_t sizeOfBuffer, const _wchar_t* format, _locale_t locale, va_list args);

    static int _chsize(int fd, LONG size);

    static errno_t _chsize_s(int fd, LONGLONG size);

    static int _close(int fd);

    static int _commit(int fd);

    static int _creat(const char* filename, int pmode);

    static int _wcreat(const _wchar_t* filename, int pmode);


    static int _dup(int fd);

    static int _dup2(int fd, int fd2);

    static int _eof(int fd);

    static int _fclose_nolock(FILE* file);

    static int _fcloseall();

    static int _fflush_nolock(FILE* file);

    static int _fgetc_nolock(FILE* file);

    static _wint_t _fgetwc_nolock(FILE* file);

    static int _fgetchar_nolock();

    static _wint_t _fgetwchar_nolock();

    static LONG _filelength(int fd);

    static off_t _filelengthi64(int fd);

    static int _fileno(FILE* file);

    static int _flushall();

    static int _fputc_nolock(int c, FILE* file);

    static _wint_t _fputwc_nolock(_wchar_t c, FILE* file);

    static int _fputchar(int c);

    static _wint_t _fputwchar(_wchar_t c);

    static size_t _fread_nolock(void* buffer, size_t size, size_t count, FILE* file);

    static size_t _fread_nolock_s(void* buffer, size_t sizeOfBuffer, size_t size, size_t count, FILE* file);

    static int _fseek_nolock(FILE* file, LONG offset, int origin);

    static int _fseeki64(FILE* file, LONGLONG offset, int origin);

    static int _fseeki64_nolock(FILE* file, LONGLONG offset, int origin);

    static FILE *_fsopen(const char* filename, const char* mode, int shflag);

    static LONG _ftell_nolock(FILE* file);

    static LONGLONG _ftelli64(FILE* file);

    static LONGLONG _ftelli64_nolock(FILE* file);

    static size_t _fwrite_nolock(const void* buffer, size_t size, size_t count, FILE* file);

    static errno_t _get_fmode(int* pMode);

    static intptr_t _get_osfhandle(int fd);

    static int _get_printf_count_output();

    static void _get_stream_buffer_pointers(FILE* file, char*** base, char*** ptr, int** count);

    static int _getc_nolock(FILE* file);

    static char *_getcwd(char* buffer, int maxlen);

    static _wchar_t *_wgetcwd(_wchar_t *buffer, int maxlen);

    static char *_getdcwd(int drive, char* buffer, int maxlen);

    static int _getmaxstdio();

    static int _getw(FILE* file);

    static _wint_t _getwc_nolock(FILE* file);

    static char* _gets(char* buffer);

    static char* _gets_s(char* buffer, int size);

    static _wchar_t *_getws(_wchar_t *buffer);

    static _wchar_t *_getws_s(_wchar_t *buffer, int size);

    static int _isatty(int fd);

    static int _kbhit();

    static int _locking(int fd, int mode, long nbytes);

    static LONG _lseek(int fd, LONG offset, int origin);

    static off_t _lseeki64(int fd, off_t offset, int origin);

    static char *_mktemp(char* templateStr);

    static _wchar_t *_wmktemp(_wchar_t *templateStr);

    static errno_t _mktemp_s(char* templateStr, size_t size);

    static errno_t _wmktemp_s(_wchar_t *templateStr, size_t size);

    static int _open(const char* filename, int oflag, int pmode);

    static int _wopen(const _wchar_t* filename, int oflag, int pmode);

    static int _open_osfhandle(intptr_t osfhandle, int flags);

    static int _pclose(FILE* stream);

    static int _pipe(int *pfds, unsigned int size, int textmode);

    static int _popen(const char* command, const char* mode);

    static int _wpopen(const _wchar_t* command, const _wchar_t* mode);

    static int _putc_nolock(int ch, FILE* file);

    static int _putwc_nolock(_wint_t ch, FILE* file);

    static int _putw(int w, FILE* file);

    static int _putws(const _wchar_t* str);

    static int _read(const int fd, void *const buffer, const unsigned int count);

    static int _rmtmp();

    static errno_t set_fmode(int mode);

    static int _set_printf_count_output(const int value);

    static int _setmaxstdio(int max);

    static int _sopen(const char* filename, int oflag, int shflag, int pmode);

    static int _wsopen(const _wchar_t* filename, int oflag, int pmode);

    static int _sopen_dispatch(const char* filename, int oflag, int shflag, int pmode);

    static int _wsopen_dispatch(const _wchar_t* filename, int oflag, int pmode);

    static errno_t _sopen_s(int* pfd, const char* filename, int oflag, int shflag, int pmode);

    static errno_t _wsopen_s(int* pfd, const _wchar_t* filename, int oflag, int pmode);

    static LONG _tell(int fd);

    static off_t _telli64(int fd);

    static char *_tempnam(const char* dir, const char* pfx);

    static _wchar_t *_wtempnam(const _wchar_t* dir, const _wchar_t* pfx);

    static int _ungetc_nolock(int ch, FILE* file);

    static _wint_t _ungetwc_nolock(_wint_t ch, FILE* file);

    static FILE *_fdopen(int fd, const char* mode);

    static FILE *_wfdopen(int fd, const _wchar_t* mode);

    static FILE *_wfopen(const _wchar_t* filename, const _wchar_t* mode);

    static errno_t _wfopen_s(FILE** pFile, const _wchar_t* filename, const _wchar_t* mode);

    static FILE *_wfreopen(const _wchar_t* filename, const _wchar_t* mode, FILE* file);

    static errno_t _wfreopen_s(FILE** pFile, const _wchar_t* filename, const _wchar_t* mode, FILE* file);

    static int _write(const int fd, const void *const buffer, const unsigned int count);

    static char* _tmpnam(char* str);

    static _wchar_t* _wtmpnam(_wchar_t *str);

    static void clearerr_(FILE* file);

    static errno_t clearerr_s(FILE* file);

    static int fclose_(FILE* file);

    static int feof_(FILE* file);

    static int ferror_(FILE* file);

    static int fflush_(FILE* file);

    static int fgetc_(FILE* file);

    static int fgetpos_(FILE* file, fpos_t* pos);

    static char *fgets_(char* str, int num, FILE* file);

    static _wint_t fgetwc_(FILE* file);

    static _wchar_t *fgetws_(_wchar_t *str, int num, FILE* file);

    static FILE *fopen_(const char* filename, const char* mode);

    static errno_t fopen_s(FILE** pFile, const char* filename, const char* mode);

    static size_t fread_(void* ptr, size_t size, size_t count, FILE* file);

    static errno_t fread_s(void* ptr, size_t ptrSize, size_t size, size_t count, FILE* file);

    static int fputc_(int ch, FILE* file);

    static int fputs_(const char* str, FILE* file);

    static _wint_t fputwc_(_wint_t ch, FILE* file);

    static int fputws_(const _wchar_t* str, FILE* file);

    static FILE *freopen_(const char* filename, const char* mode, FILE* file);

    static errno_t freopen_s(FILE** pFile, const char* filename, const char* mode, FILE* file);

    static int fseek_(FILE* file, long offset, int origin);

    static int fsetpos_(FILE* file, const fpos_t* pos);

    static LONG ftell_(FILE* file);

    static off_t ftelli64(FILE* file);

    static size_t fwrite_(const void* ptr, size_t size, size_t count, FILE* file);

    static int getc_(FILE* file);

    static int getchar_();

    static char *gets_(char* str);

    static errno_t gets_s(char* str, size_t size);

    static _wint_t getwc_(FILE* file);

    static _wint_t getwchar_();

    static int putc_(int ch, FILE* file);

    static int putchar_(int ch);

    static int puts_(const char* str);

    static _wint_t putwc_(_wint_t ch, FILE* file);

    static _wint_t putwchar_(_wint_t ch);

    static void rewind_(FILE* file);

    static void setbuf_(FILE* file, char* buffer);

    static int setvbuf_(FILE* file, char* buffer, int mode, size_t size);

    static FILE *tmpfile_();

    static errno_t tmpfile_s(FILE** pFile);

    static char *tmpnam_(char* str);

    static errno_t tmpnam_s(char* str, size_t size);

    static int ungetc_(int ch, FILE* file);

    static _wint_t ungetwc_(_wint_t ch, FILE* file);

    static UINT ___lc_codepage_func();

    static UINT ___lc_collate_cp_func();

    static _wchar_t **___lc_locale_name_func();

    static int ___mb_cur_max_func();

    static int ___mb_cur_max_l_func(_locale_t locale);

    // unsure of the signature
    static int __initialize_lconv_for_unsigned_char();

    static const unsigned short *___pctype_func();

    static const unsigned short *__pwctype_func();

    static int _configthreadlocale(int flag);

    static _locale_t _create_locale(int category, const char* locale);

    static _locale_t _wcreate_locale(int category, const _wchar_t* locale);

    static void _free_locale(_locale_t locale);

    static _locale_t _get_current_locale();

    static int _getmbcp();

    static void _lock_locales();

    static void _unlock_locales();

    static int _setmbcp(int codepage);

    static char* setlocale_(int category, const char* locale);

    static _wchar_t *_wsetlocale(int category, const _wchar_t* locale);

    static lconv *localeconv_();

    static void _aligned_free(void* memblock);

    static void *_aligned_malloc(size_t size, size_t alignment);

    static void* _aligned_calloc(size_t count, size_t size, size_t alignment);

    static void* _aligned_realloc(void* memblock, size_t size, size_t alignment);

    static void* _aligned_recalloc(void* memblock, size_t count, size_t size, size_t alignment);

    static size_t _aligned_msize(void* memblock, size_t alignment, size_t offset);

    static void* _aligned_offset_malloc(size_t size, size_t alignment, size_t offset);

    static void* _aligned_offset_realloc(void* memblock, size_t size, size_t alignment, size_t offset);

    static void* _aligned_offset_recalloc(void* memblock, size_t count, size_t size, size_t alignment, size_t offset);

    static int _callnewh(const size_t size);

    static void* _calloc_base(size_t count, size_t size);

    static void* _expand(void* memblock, size_t newsize);

    static void _free_base(void* memblock);

    static intptr_t _get_heap_handle();

    static int _heapchk();

    static int _heapmin();

    static int _heapwalk(_HEAPINFO *entryinfo);

    static void* _malloc_base(size_t size);

    static size_t _msize(void* memblock);

    static _PNH _query_new_handler();

    static int _query_new_mode();

    static int _set_new_mode(int newmode);

    static void* _realloc_base(void* memblock, size_t size);

    static void *_recalloc(void* memblock, size_t num, size_t size);

    static void *calloc(size_t count, size_t size);

    static void free(void* memblock);

    static size_t wcslen_(const _wchar_t* str);

    static _wchar_t *wcscpy_(_wchar_t* dest, const _wchar_t* src);

    static void *malloc(size_t size);

    static void *realloc(void* memblock, size_t size);

    static int __isascii_(int c);

    static int iswascii(_wint_t c);

    static int __iscsym(int c);

    static int __iscsymf(int c);

    static int __iswcsym(_wint_t c);

    static int __iswcsymf(_wint_t c);

    static size_t __strncnt(const char* str, size_t maxsize);

    static size_t __wcsncnt(const _wchar_t* str, size_t maxsize);

    static int _isalnum_l(int c, _locale_t locale);

    static int _isalpha_l(int c, _locale_t locale);

    static int _isblank_l(int c, _locale_t locale);

    static int _iscntrl_l(int c, _locale_t locale);

    static int _isctype_l(int c, int mask, _locale_t locale);

    static int _isctype(int c, int mask);

    static int _isdigit_l(int c, _locale_t locale);

    static int _isgraph_l(int c, _locale_t locale);

    static int _isleadbyte_l(int c);

    static int _islower_l(int c, _locale_t locale);

    static int _isprint_l(int c, _locale_t locale);

    static int _ispunct_l(int c, _locale_t locale);

    static int _isspace_l(int c, _locale_t locale);

    static int _isxdigit_l(int c, _locale_t locale);

    static int _isupper_l(int c, _locale_t locale);

    static int _iswalnum_l(_wint_t c, _locale_t locale);

    static int _iswalpha_l(_wint_t c, _locale_t locale);

    static int _iswblank_l(_wint_t c, _locale_t locale);

    static int _iswcntrl_l(_wint_t c, _locale_t locale);

    static int _iswcsymf_l(_wint_t c, _locale_t locale);

    static int _iswctype_l(_wint_t c, int mask, _locale_t locale);

    static int _iswdigit_l(_wint_t c, _locale_t locale);

    static int _iswgraph_l(_wint_t c, _locale_t locale);

    static int _iswlower_l(_wint_t c, _locale_t locale);


    static int _iswprint_l(_wint_t c, _locale_t locale);

    static int _iswpunct_l(_wint_t c, _locale_t locale);

    static int _iswspace_l(_wint_t c, _locale_t locale);

    static int _iswxdigit_l(_wint_t c, _locale_t locale);

    static void *_memccpy(void* dest, const void* src, int c, size_t n);

    static int _memicmp(const void* buf1, const void* buf2, size_t count);

    static int _memicmp_l(const void* buf1, const void* buf2, size_t count, _locale_t locale);

    static int _strcoll_l(const char* str1, const char* str2, _locale_t locale);

    static int _mbscoll(const unsigned char* str1, const unsigned char* str2);

    static int _mbscoll_l(const unsigned char* str1, const unsigned char* str2, _locale_t locale);

    static std::wstring LPCWSTR_TO_WSTRING(LPCWSTR str);

    static int _wcscoll(const _wchar_t* str1, const _wchar_t* str2);

    static int _wcscoll_l(const _wchar_t* str1, const _wchar_t* str2, _locale_t locale);

    static int _stricoll(const char* str1, const char* str2);

    static int _stricoll_l(const char* str1, const char* str2, _locale_t locale);

    static constexpr _wchar_t null[] = { '(', 'n', 'u', 'l', 'l', ')', 0 };

    static int _wcsicoll(const _wchar_t* str1, const _wchar_t* str2);

    static int _wcsicoll_l(const _wchar_t* str1, const _wchar_t* str2, _locale_t locale);

    static int _mbsicoll(const unsigned char* str1, const unsigned char* str2);

    static int _mbsicoll_l(const unsigned char* str1, const unsigned char* str2, _locale_t locale);

    static char *_strdup(const char* str);

    static _wchar_t *_wcsdup(const _wchar_t* str);

    static unsigned char *_mbsdup(const unsigned char* str);

    static int _stricmp(const char* str1, const char* str2);

    static int _stricmp_l(const char* str1, const char* str2, _locale_t locale);

    static int _wcsicmp(const _wchar_t* str1, const _wchar_t* str2);

    static int _wcsicmp_l(const _wchar_t* str1, const _wchar_t* str2, _locale_t locale);

    static int _mbsicmp(const unsigned char* str1, const unsigned char* str2);

    static int _mbsicmp_l(const unsigned char* str1, const unsigned char* str2, _locale_t locale);

    static char *_strlwr(char* str);

    static char *_strlwr_l(char* str, _locale_t locale);

    static char *_strlwr_s(char* str, size_t size);

    static char *_strlwr_s_l(char* str, size_t size, _locale_t locale);

    static _wchar_t *_wcslwr(_wchar_t* str);

    static _wchar_t *_wcslwr_l(_wchar_t* str, _locale_t locale);

    static _wchar_t *_wcslwr_s(_wchar_t* str, size_t size);

    static _wchar_t *_wcslwr_s_l(_wchar_t* str, size_t size, _locale_t locale);

    static unsigned char *_mbslwr(unsigned char* str);

    static unsigned char *_mbslwr_l(unsigned char* str, _locale_t locale);

    static unsigned char *_mbslwr_s(unsigned char* str, size_t size);

    static unsigned char *_mbslwr_s_l(unsigned char* str, size_t size, _locale_t locale);


    static int wcscmp_(const _wchar_t* str1, const _wchar_t* str2);

    static int _mbscmp(const unsigned char* str1, const unsigned char* str2);

    static int _mbscmp_l(const unsigned char* str1, const unsigned char* str2, _locale_t locale);

    static int _strncoll(const char* str1, const char* str2, size_t count);

    static int _strncoll_l(const char* str1, const char* str2, size_t count, _locale_t locale);

    static int _wcsncoll(const _wchar_t* str1, const _wchar_t* str2, size_t count);

    static int _wcsncoll_l(const _wchar_t* str1, const _wchar_t* str2, size_t count, _locale_t locale);

    static int _mbsncoll(const unsigned char* str1, const unsigned char* str2, size_t count);

    static int _mbsncoll_l(const unsigned char* str1, const unsigned char* str2, size_t count, _locale_t locale);

    static int _strnicoll(const char* str1, const char* str2, size_t count);

    static int _strnicoll_l(const char* str1, const char* str2, size_t count, _locale_t locale);

    static int _wcsnicoll(const _wchar_t* str1, const _wchar_t* str2, size_t count);

    static int _wcsnicoll_l(const _wchar_t* str1, const _wchar_t* str2, size_t count, _locale_t locale);

    static int _mbsnicoll(const unsigned char* str1, const unsigned char* str2, size_t count);

    static int _mbsnicoll_l(const unsigned char* str1, const unsigned char* str2, size_t count, _locale_t locale);

    static char *_strnset(char* str, int c, size_t count);

    static char *_strnset_l(char* str, int c, size_t count, _locale_t locale);

    static errno_t _strnset_s(char* str, size_t size, int c, size_t count);

    static errno_t _strnset_s_l(char* str, size_t size, int c, size_t count, _locale_t locale);

    static _wchar_t *_wcsnset(_wchar_t* str, _wchar_t c, size_t count);

    static _wchar_t *_wcsnset_l(_wchar_t* str, _wchar_t c, size_t count, _locale_t locale);

    static errno_t _wcsnset_s(_wchar_t* str, size_t size, _wchar_t c, size_t count);

    static errno_t _wcsnset_s_l(_wchar_t* str, size_t size, _wchar_t c, size_t count, _locale_t locale);

    static unsigned char *_mbsnset(unsigned char* str, unsigned char c, size_t count);

    static unsigned char *_mbsnset_l(unsigned char* str, unsigned char c, size_t count, _locale_t locale);

    static errno_t _mbsnset_s(unsigned char* str, size_t size, unsigned char c, size_t count);

    static errno_t _mbsnset_s_l(unsigned char* str, size_t size, unsigned char c, size_t count, _locale_t locale);

    static char *_strset(char* str, int c);

    static char *_strset_l(char* str, int c, _locale_t locale);

    static errno_t _strset_s(char* str, size_t size, int c);

    static errno_t _strset_s_l(char* str, size_t size, int c, _locale_t locale);

    static _wchar_t *_wcsset(_wchar_t* str, _wchar_t c);

    static _wchar_t *_wcsset_l(_wchar_t* str, _wchar_t c, _locale_t locale);

    static errno_t _wcsset_s(_wchar_t* str, size_t size, _wchar_t c);

    static errno_t _wcsset_s_l(_wchar_t* str, size_t size, _wchar_t c, _locale_t locale);

    static unsigned char *_mbsset(unsigned char* str, unsigned char c);

    static unsigned char *_mbsset_l(unsigned char* str, unsigned char c, _locale_t locale);

    static errno_t _mbsset_s(unsigned char* str, size_t size, unsigned char c);

    static errno_t _mbsset_s_l(unsigned char* str, size_t size, unsigned char c, _locale_t locale);

    static char *_strrev(char* str);

    static _wchar_t *_wcsrev(_wchar_t* str);

    static unsigned char *_mbsrev(unsigned char* str);

    static unsigned char *_mbsrev_l(unsigned char* str, _locale_t locale);

    static char *_strupr(char* str);

    static char *_strupr_l(char* str, _locale_t locale);

    static errno_t _strupr_s(char* str, size_t size);

    static errno_t _strupr_s_l(char* str, size_t size, _locale_t locale);

    static _wchar_t *_wcsupr(_wchar_t* str);

    static _wchar_t *_wcsupr_l(_wchar_t* str, _locale_t locale);

    static errno_t _wcsupr_s(_wchar_t* str, size_t size);

    static errno_t _wcsupr_s_l(_wchar_t* str, size_t size, _locale_t locale);

    static size_t strxfrm(char* dest, const char* src, size_t count);

    static size_t _strxfrm_l(char* dest, const char* src, size_t count, _locale_t locale);

    static size_t wcsxfrm(_wchar_t* dest, const _wchar_t* src, size_t count);

    static size_t _wcsxfrm_l(_wchar_t* dest, const _wchar_t* src, size_t count, _locale_t locale);

    static int _tolower(int c);

    static int _tolower_l(int c, _locale_t locale);

    static int _toupper(int c);

    static int _toupper_l(int c, _locale_t locale);

    static int towlower_(_wint_t c);

    static int _towlower_l(_wint_t c, _locale_t locale);

    static int towupper_(_wint_t c);

    static int _towupper_l(_wint_t c, _locale_t locale);

    static int is_ctype(int c, int ctype);

    static int is_wctype(_wint_t c, _wctype_t ctype);

    static int isalpha_(int c);

    static int isblank_(int c);

    static int iscntrl_(int c);

    static int isdigit_(int c);

    static int isgraph_(int c);

    static int isleadbyte_(int c);

    static int islower_(int c);

    static int isprint_(int c);

    static int ispunct_(int c);

    static int isspace_(int c);

    static int isupper_(int c);

    static int isxdigit_(int c);

    static int iswalnum_(_wint_t c);

    static int iswalpha_(_wint_t c);

    static int iswblank_(_wint_t c);

    static int iswcntrl_(_wint_t c);

    static int iswctype_(_wint_t c, _wctype_t ctype);

    static int iswdigit_(_wint_t c);

    static int iswgraph_(_wint_t c);

    static int iswlower_(_wint_t c);

    static int iswprint_(_wint_t c);

    static int iswpunct_(_wint_t c);

    static int iswspace_(_wint_t c);

    static int iswupper_(_wint_t c);

    static int iswxdigit_(_wint_t c);

    static int mblen_(const char* str, size_t n);

    static int mbrlen_(const char* str, size_t n, mbstate_t* ps);

    static errno_t memcpy_s(void* dest, size_t destSize, const void* src, size_t count);

    static errno_t memmove_s(void* dest, size_t destSize, const void* src, size_t count);

    static errno_t strcat_s(char* dest, size_t destSize, const char* src);

    static _wchar_t *wcscat_(_wchar_t* dest, const _wchar_t* src);

    static errno_t wcscat_s(_wchar_t* dest, size_t destSize, const _wchar_t* src);

    static errno_t _mbscat_s(unsigned char* dest, size_t destSize, const unsigned char* src);

    static errno_t _mbscat_s_l(unsigned char* dest, size_t destSize, const unsigned char* src, _locale_t locale);

    static int strcoll_(const char* str1, const char* str2);

    static int wcscoll_(const _wchar_t* str1, const _wchar_t* str2);

    static unsigned char *_mbscpy(unsigned char* dest, const unsigned char* src);

    static size_t strcspn_(const char* str1, const char* str2);

    static size_t wcscspn_(const _wchar_t* str1, const _wchar_t* str2);

    static size_t _mbscspn(const unsigned char* str1, const unsigned char* str2);

    static size_t _mbscspn_l(const unsigned char* str1, const unsigned char* str2, _locale_t locale);

    static size_t _mbslen(const unsigned char* str);

    static size_t _mbslen_l(const unsigned char* str, _locale_t locale);

    static size_t _mbstrlen(const char* str);

    static size_t _mbstrlen_l(const unsigned char* str, _locale_t locale);

    static _wchar_t *wcsncat_(_wchar_t* dest, const _wchar_t* src, size_t count);

    static errno_t wcsncat_s(_wchar_t* dest, size_t destSize, const _wchar_t* src, size_t count);

    static unsigned char *_mbsncat(unsigned char* dest, const unsigned char* src, size_t count);

    static unsigned char *_mbsncat_l(unsigned char* dest, const unsigned char* src, size_t count, _locale_t locale);

    static errno_t _mbsncat_s(unsigned char* dest, size_t destSize, const unsigned char* src, size_t count);

    static errno_t _mbsncat_s_l(unsigned char* dest, size_t destSize, const unsigned char* src, size_t count, _locale_t locale);

    static errno_t strcpy_s(char* dest, size_t destSize, const char* src);

    static errno_t wcscpy_s(_wchar_t* dest, size_t destSize, const _wchar_t* src);

    static char *_strncpy_l(char* dest, const char* src, size_t count, _locale_t locale);

    static _wchar_t *wcsncpy_(_wchar_t* dest, const _wchar_t* src, size_t count);

    static _wchar_t *_wcsncpy_l(_wchar_t* dest, const _wchar_t* src, size_t count, _locale_t locale);

    static unsigned char *_mbsncpy(unsigned char* dest, const unsigned char* src, size_t count);

    static unsigned char *_mbsncpy_l(unsigned char* dest, const unsigned char* src, size_t count, _locale_t locale);

    static errno_t wcsncpy_s(_wchar_t* dest, size_t destSize, const _wchar_t* src, size_t count);

    static errno_t _mbscpy_s(unsigned char* dest, size_t destSize, const unsigned char* src);

    static size_t strnlen_(const char* str, size_t maxsize);

    static size_t strnlen_s(const char* str, size_t maxsize);

    static size_t wcsnlen_(const _wchar_t* str, size_t maxsize);

    static size_t wcsnlen_s(const _wchar_t* str, size_t maxsize);

    static size_t _mbsnlen(const unsigned char* str, size_t maxsize);

    static size_t _mbsnlen_l(const unsigned char* str, size_t maxsize, _locale_t locale);

    static size_t _mbstrnlen(const char* str, size_t maxsize);

    static size_t _mbstrnlen_l(const char* str, size_t maxsize, _locale_t locale);

    static errno_t strncat_s(char* dest, size_t destSize, const char* src, size_t count);

    static errno_t strncpy_s(char* dest, size_t destSize, const char* src, size_t count);

    static int wcsncmp_(const _wchar_t* str1, const _wchar_t* str2, size_t count);

    static int _mbsnbcmp(const unsigned char* str1, const unsigned char* str2, size_t count);

    static int _mbsnbcmp_l(const unsigned char* str1, const unsigned char* str2, size_t count, _locale_t locale);

    static char* strpbrk_(const char* str1, const char* str2);

    static _wchar_t *wcspbrk_(const _wchar_t* str1, const _wchar_t* str2);

    static unsigned char *_mbspbrk(const unsigned char* str1, const unsigned char* str2);

    static unsigned char *_mbspbrk_l(const unsigned char* str1, const unsigned char* str2, _locale_t locale);

    static size_t strspn_(const char* str1, const char* str2);

    static size_t wcsspn_(const _wchar_t* str1, const _wchar_t* str2);

    static size_t _mbsspn(const unsigned char* str1, const unsigned char* str2);

    static size_t _mbsspn_l(const unsigned char* str1, const unsigned char* str2, _locale_t locale);

    static char *strtok_(char* str, const char* delimiters, char** context);

    static char *strtok_s(char* str, const char* delimiters, char** context);

    static char *_strtok_s_l(char* str, const char* delimiters, char** context, _locale_t locale);

    static _wchar_t *wcstok_(_wchar_t* str, const _wchar_t* delimiters, _wchar_t** context);

    static _wchar_t *wcstok_s(_wchar_t* str, const _wchar_t* delimiters, _wchar_t** context);

    static _wchar_t *_wcstok_s_l(_wchar_t* str, const _wchar_t* delimiters, _wchar_t** context, _locale_t locale);

    static unsigned char *_mbstok(unsigned char* str, const unsigned char* delimiters, unsigned char** context);

    static unsigned char *_mbstok_l(unsigned char* str, const unsigned char* delimiters, unsigned char** context, _locale_t locale);

    static unsigned char *_mbstok_s(unsigned char* str, const unsigned char* delimiters, unsigned char** context);

    static unsigned char *_mbstok_s_l(unsigned char* str, const unsigned char* delimiters, unsigned char** context, _locale_t locale);

    static int tolower_(int c);

    static int toupper_(int c);

    static _wint_t towctrans_(_wint_t c, wctrans_t desc);

    static _wctype_t wctype_(const char* str);

    static _wchar_t *wcschr_(const _wchar_t* str, _wint_t c);

    static unsigned char *_mbschr(const unsigned char* str, unsigned int c);

    static unsigned char *_mbschr_l(const unsigned char* str, unsigned int c, _locale_t locale);

    static int swprintf_(_wchar_t* buffer, size_t sizeOfBuffer, const _wchar_t* format, ...);
};

#endif