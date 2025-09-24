//
// Created by wojtek on 9/15/25.
//

class Kernel32; // forward declaration if needed

#include "ucrtbase.hpp"
#include "kernel32.hpp"


std::unordered_map<std::wstring, EmulatedExport> UCRTBase::get_exports_detailed() {
    return {
        // Memory functions
        {L"memset", {L"memset", reinterpret_cast<uintptr_t>(memset_), true, 0}},
        {L"memcpy", {L"memcpy", reinterpret_cast<uintptr_t>(memcpy_), true, 0}},
        {L"wmemcpy", {L"wmemcpy", reinterpret_cast<uintptr_t>(wmemcpy), true, 0}},
        {L"memcmp", {L"memcmp", reinterpret_cast<uintptr_t>(memcmp_), true, 0}},
        {L"memmove", {L"memmove", reinterpret_cast<uintptr_t>(memmove_), true, 0}},
        {L"wmemmove", {L"wmemmove", reinterpret_cast<uintptr_t>(wmemmove), true, 0}},

        // String functions
        {L"strlen", {L"strlen", reinterpret_cast<uintptr_t>(strlen_), true, 0}},
        {L"strcpy", {L"strcpy", reinterpret_cast<uintptr_t>(strcpy_), true, 0}},
        {L"strncpy", {L"strncpy", reinterpret_cast<uintptr_t>(strncpy_), true, 0}},
        {L"strcmp", {L"strcmp", reinterpret_cast<uintptr_t>(strcmp_), true, 0}},
        {L"strncmp", {L"strncmp", reinterpret_cast<uintptr_t>(strncmp_), true, 0}},
        {L"strcat", {L"strcat", reinterpret_cast<uintptr_t>(strcat_), true, 0}},
        {L"strncat", {L"strncat", reinterpret_cast<uintptr_t>(strncat_), true, 0}},
        {L"__toascii", {L"__toascii", reinterpret_cast<uintptr_t>(__toascii_), true, 0}},
        {L"strchr", {L"strchr", reinterpret_cast<uintptr_t>(strchr_), true, 0}},
        {L"strrchr", {L"strrchr", reinterpret_cast<uintptr_t>(strrchr_), true, 0}},
        {L"strstr", {L"strstr", reinterpret_cast<uintptr_t>(strstr_), true, 0}},

        // Conversion functions
        {L"_atodbl", {L"_atodbl", reinterpret_cast<uintptr_t>(_atodbl), true, 0}},
        {L"_atodbl_l", {L"_atodbl_l", reinterpret_cast<uintptr_t>(_atodbl_l), true, 0}},
        {L"_atof_l", {L"_atof_l", reinterpret_cast<uintptr_t>(_atof_l), true, 0}},
        {L"_atoflt", {L"_atoflt", reinterpret_cast<uintptr_t>(_atoflt), true, 0}},
        {L"_atoflt_l", {L"_atoflt_l", reinterpret_cast<uintptr_t>(_atoflt_l), true, 0}},
        {L"_atoi_l", {L"_atoi_l", reinterpret_cast<uintptr_t>(_atoi_l), true, 0}},
        {L"_atol_l", {L"_atol_l", reinterpret_cast<uintptr_t>(_atol_l), true, 0}},
        {L"_atoldbl", {L"_atoldbl", reinterpret_cast<uintptr_t>(_atoldbl), true, 0}},
        {L"_atoldbl_l", {L"_atoldbl_l", reinterpret_cast<uintptr_t>(_atoldbl_l), true, 0}},
        {L"_atoll_l", {L"_atoll_l", reinterpret_cast<uintptr_t>(_atoll_l), true, 0}},
        {L"_atoll", {L"_atoll", reinterpret_cast<uintptr_t>(_atoll), true, 0}},

        // Float conversion functions
        {L"_ecvt", {L"_ecvt", reinterpret_cast<uintptr_t>(_ecvt), true, 0}},
        {L"_ecvt_s", {L"_ecvt_s", reinterpret_cast<uintptr_t>(_ecvt_s), true, 0}},
        {L"_fcvt", {L"_fcvt", reinterpret_cast<uintptr_t>(_fcvt), true, 0}},
        {L"_fcvt_s", {L"_fcvt_s", reinterpret_cast<uintptr_t>(_fcvt_s), true, 0}},
        {L"_gcvt", {L"_gcvt", reinterpret_cast<uintptr_t>(_gcvt), true, 0}},
        {L"_gcvt_s", {L"_gcvt_s", reinterpret_cast<uintptr_t>(_gcvt_s), true, 0}},

        // Integer to string conversion
        {L"_i64toa", {L"_i64toa", reinterpret_cast<uintptr_t>(_i64toa), true, 0}},
        {L"_i64toa_s", {L"_i64toa_s", reinterpret_cast<uintptr_t>(_i64toa_s), true, 0}},
        {L"_i64tow", {L"_i64tow", reinterpret_cast<uintptr_t>(_i64tow), true, 0}},
        {L"_i64tow_s", {L"_i64tow_s", reinterpret_cast<uintptr_t>(_i64tow_s), true, 0}},
        {L"_itoa", {L"_itoa", reinterpret_cast<uintptr_t>(_itoa), true, 0}},
        {L"_itoa_s", {L"_itoa_s", reinterpret_cast<uintptr_t>(_itoa_s), true, 0}},
        {L"_itow", {L"_itow", reinterpret_cast<uintptr_t>(_itow), true, 0}},
        {L"_itow_s", {L"_itow_s", reinterpret_cast<uintptr_t>(_itow_s), true, 0}},
        {L"_ltoa", {L"_ltoa", reinterpret_cast<uintptr_t>(_ltoa), true, 0}},
        {L"_ltoa_s", {L"_ltoa_s", reinterpret_cast<uintptr_t>(_ltoa_s), true, 0}},
        {L"_ltow", {L"_ltow", reinterpret_cast<uintptr_t>(_ltow), true, 0}},
        {L"_ltow_s", {L"_ltow_s", reinterpret_cast<uintptr_t>(_ltow_s), true, 0}},

        // String to number conversion
        {L"_strtod_l", {L"_strtod_l", reinterpret_cast<uintptr_t>(_strtod_l), true, 0}},
        {L"_strtod", {L"_strtod", reinterpret_cast<uintptr_t>(_strtod), true, 0}},
        {L"_strtof_l", {L"_strtof_l", reinterpret_cast<uintptr_t>(_strtof_l), true, 0}},
        {L"_strtof", {L"_strtof", reinterpret_cast<uintptr_t>(_strtof), true, 0}},
        {L"_strtoi64_l", {L"_strtoi64_l", reinterpret_cast<uintptr_t>(_strtoi64_l), true, 0}},
        {L"_strtoi64", {L"_strtoi64", reinterpret_cast<uintptr_t>(_strtoi64), true, 0}},
        {L"_strtoimax_l", {L"_strtoimax_l", reinterpret_cast<uintptr_t>(_strtoimax_l), true, 0}},
        {L"_strtoimax", {L"_strtoimax", reinterpret_cast<uintptr_t>(_strtoimax), true, 0}},
        {L"_strtol_l", {L"_strtol_l", reinterpret_cast<uintptr_t>(_strtol_l), true, 0}},
        {L"_strtol", {L"_strtol", reinterpret_cast<uintptr_t>(_strtol), true, 0}},
        {L"_strtold_l", {L"_strtold_l", reinterpret_cast<uintptr_t>(_strtold_l), true, 0}},
        {L"_strtold", {L"_strtold", reinterpret_cast<uintptr_t>(_strtold), true, 0}},
        {L"_strtoumax_l", {L"_strtoumax_l", reinterpret_cast<uintptr_t>(_strtoumax_l), true, 0}},
        {L"_strtoumax", {L"_strtoumax", reinterpret_cast<uintptr_t>(_strtoumax), true, 0}},
        {L"_strtoui64_l", {L"_strtoui64_l", reinterpret_cast<uintptr_t>(_strtoui64_l), true, 0}},
        {L"_strtoui64", {L"_strtoui64", reinterpret_cast<uintptr_t>(_strtoui64), true, 0}},
        {L"_strtoul_l", {L"_strtoul_l", reinterpret_cast<uintptr_t>(_strotoul_l), true, 0}},
        {L"_strtoul", {L"_strtoul", reinterpret_cast<uintptr_t>(_strotoul), true, 0}},

        // Unsigned integer to string conversion
        {L"_ui64toa", {L"_ui64toa", reinterpret_cast<uintptr_t>(_ui64toa), true, 0}},
        {L"_ui64toa_s", {L"_ui64toa_s", reinterpret_cast<uintptr_t>(_ui64toa_s), true, 0}},
        {L"_ui64tow", {L"_ui64tow", reinterpret_cast<uintptr_t>(_ui64tow), true, 0}},
        {L"_ui64tow_s", {L"_ui64tow_s", reinterpret_cast<uintptr_t>(_ui64tow_s), true, 0}},
        {L"_ultoa", {L"_ultoa", reinterpret_cast<uintptr_t>(_ultoa), true, 0}},
        {L"_ultoa_s", {L"_ultoa_s", reinterpret_cast<uintptr_t>(_ultoa_s), true, 0}},
        {L"_ultow", {L"_ultow", reinterpret_cast<uintptr_t>(_ultow), true, 0}},
        {L"_ultow_s", {L"_ultow_s", reinterpret_cast<uintptr_t>(_ultow_s), true, 0}},

        // Wide character string to number conversion
        {L"_wcstod_l", {L"_wcstod_l", reinterpret_cast<uintptr_t>(_wcstod_l), true, 0}},
        {L"_wcstod", {L"_wcstod", reinterpret_cast<uintptr_t>(_wcstod), true, 0}},
        {L"_wcstof_l", {L"_wcstof_l", reinterpret_cast<uintptr_t>(_wcstof_l), true, 0}},
        {L"_wcstof", {L"_wcstof", reinterpret_cast<uintptr_t>(_wcstof), true, 0}},
        {L"_wcstoi64_l", {L"_wcstoi64_l", reinterpret_cast<uintptr_t>(_wcstoi64_l), true, 0}},
        {L"_wcstoi64", {L"_wcstoi64", reinterpret_cast<uintptr_t>(_wcstoi64), true, 0}},
        {L"_wcstoimax_l", {L"_wcstoimax_l", reinterpret_cast<uintptr_t>(_wcstoimax_l), true, 0}},
        {L"_wcstoimax", {L"_wcstoimax", reinterpret_cast<uintptr_t>(_wcstoimax), true, 0}},
        {L"_wcstol_l", {L"_wcstol_l", reinterpret_cast<uintptr_t>(_wcstol_l), true, 0}},
        {L"_wcstol", {L"_wcstol", reinterpret_cast<uintptr_t>(_wcstol), true, 0}},
        {L"_wcstold_l", {L"_wcstold_l", reinterpret_cast<uintptr_t>(_wcstold_l), true, 0}},
        {L"_wcstold", {L"_wcstold", reinterpret_cast<uintptr_t>(_wcstold), true, 0}},
        {L"_wcstoll_l", {L"_wcstoll_l", reinterpret_cast<uintptr_t>(_wcstoll_l), true, 0}},
        {L"_wcstoll", {L"_wcstoll", reinterpret_cast<uintptr_t>(_wcstoll), true, 0}},
        {L"_wcstoull_l", {L"_wcstoull_l", reinterpret_cast<uintptr_t>(_wcstoull_l), true, 0}},
        {L"_wcstoull", {L"_wcstoull", reinterpret_cast<uintptr_t>(_wcstoull), true, 0}},

        // Multibyte/wide character conversion
        {L"_wcstombs_l", {L"_wcstombs_l", reinterpret_cast<uintptr_t>(_wcstombs_l), true, 0}},
        {L"_wcstombs", {L"_wcstombs", reinterpret_cast<uintptr_t>(_wcstombs), true, 0}},
        {L"_wcstombs_s_l", {L"_wcstombs_s_l", reinterpret_cast<uintptr_t>(_wcstombs_s_l), true, 0}},
        {L"_wcstombs_s", {L"_wcstombs_s", reinterpret_cast<uintptr_t>(_wcstombs_s), true, 0}},
        {L"_mbstowcs_l", {L"_mbstowcs_l", reinterpret_cast<uintptr_t>(_mbstowcs_l), true, 0}},
        {L"_mbstowcs", {L"_mbstowcs", reinterpret_cast<uintptr_t>(_mbstowcs), true, 0}},
        {L"_mbstowcs_s_l", {L"_mbstowcs_s_l", reinterpret_cast<uintptr_t>(_mbstowcs_s_l), true, 0}},
        {L"_mbstowcs_s", {L"_mbstowcs_s", reinterpret_cast<uintptr_t>(_mbstowcs_s), true, 0}},
        {L"_wcstoui64_l", {L"_wcstoui64_l", reinterpret_cast<uintptr_t>(_wcstoui64_l), true, 0}},
        {L"_wcstoui64", {L"_wcstoui64", reinterpret_cast<uintptr_t>(_wcstoui64), true, 0}},
        {L"_wcstoul_l", {L"_wcstoul_l", reinterpret_cast<uintptr_t>(_wcstoul_l), true, 0}},
        {L"_wcstoul", {L"_wcstoul", reinterpret_cast<uintptr_t>(_wcstoul), true, 0}},
        {L"_wctomb_l", {L"_wctomb_l", reinterpret_cast<uintptr_t>(_wctomb_l), true, 0}},
        {L"_wctomb", {L"_wctomb", reinterpret_cast<uintptr_t>(_wctomb), true, 0}},
        {L"_wctomb_s_l", {L"_wctomb_s_l", reinterpret_cast<uintptr_t>(_wctomb_s_l), true, 0}},
        {L"_wctomb_s", {L"_wctomb_s", reinterpret_cast<uintptr_t>(_wctomb_s), true, 0}},

        // Wide character utility functions
        {L"_wtof_l", {L"_wtof_l", reinterpret_cast<uintptr_t>(_wtof_l), true, 0}},
        {L"_wtof", {L"_wtof", reinterpret_cast<uintptr_t>(_wtof), true, 0}},
        {L"_wtoi_l", {L"_wtoi_l", reinterpret_cast<uintptr_t>(_wtoi_l), true, 0}},
        {L"_wtoi", {L"_wtoi", reinterpret_cast<uintptr_t>(_wtoi), true, 0}},
        {L"_wtoi64_l", {L"_wtoi64_l", reinterpret_cast<uintptr_t>(_wtoi64_l), true, 0}},
        {L"_wtoi64", {L"_wtoi64", reinterpret_cast<uintptr_t>(_wtoi64), true, 0}},
        {L"_wtol_l", {L"_wtol_l", reinterpret_cast<uintptr_t>(_wtol_l), true, 0}},
        {L"_wtol", {L"_wtol", reinterpret_cast<uintptr_t>(_wtol), true, 0}},
        {L"_wtoll_l", {L"_wtoll_l", reinterpret_cast<uintptr_t>(_wtoll_l), true, 0}},
        {L"_wtoll", {L"_wtoll", reinterpret_cast<uintptr_t>(_wtoll), true, 0}},

        // Standard conversion functions
        {L"atof", {L"atof", reinterpret_cast<uintptr_t>(atof), true, 0}},
        {L"atoi", {L"atoi", reinterpret_cast<uintptr_t>(atoi), true, 0}},
        {L"atol", {L"atol", reinterpret_cast<uintptr_t>(atol), true, 0}},
        {L"atoll", {L"atoll", reinterpret_cast<uintptr_t>(atoll), true, 0}},

        // Character conversion functions
        {L"btowc", {L"btowc", reinterpret_cast<uintptr_t>(btowc), true, 0}},
        {L"c16rtomb", {L"c16rtomb", reinterpret_cast<uintptr_t>(c16rtomb), true, 0}},
        {L"c32rtomb", {L"c32rtomb", reinterpret_cast<uintptr_t>(c32rtomb), true, 0}},
        {L"mbrtoc16", {L"mbrtoc16", reinterpret_cast<uintptr_t>(mbrtoc16), true, 0}},
        {L"mbrtoc32", {L"mbrtoc32", reinterpret_cast<uintptr_t>(mbrtoc32), true, 0}},
        {L"mbrtowc", {L"mbrtowc", reinterpret_cast<uintptr_t>(mbrtowc), true, 0}},
        {L"mbsinit", {L"mbsinit", reinterpret_cast<uintptr_t>(mbsinit), true, 0}},
        {L"mbsrtowcs", {L"mbsrtowcs", reinterpret_cast<uintptr_t>(mbsrtowcs), true, 0}},
        {L"mbsrtowcs_s", {L"mbsrtowcs_s", reinterpret_cast<uintptr_t>(mbsrtowcs_s), true, 0}},
        {L"mbtowc", {L"mbtowc", reinterpret_cast<uintptr_t>(mbtowc), true, 0}},

        // Standard string conversion functions
        {L"strtod_l", {L"strtod_l", reinterpret_cast<uintptr_t>(strtod_l), true, 0}},
        {L"strtod", {L"strtod", reinterpret_cast<uintptr_t>(strtod_), true, 0}},
        {L"strtof_l", {L"strtof_l", reinterpret_cast<uintptr_t>(strtof_l), true, 0}},
        {L"strtof", {L"strtof", reinterpret_cast<uintptr_t>(strtof_), true, 0}},
        {L"strtoimax_l", {L"strtoimax_l", reinterpret_cast<uintptr_t>(strtoimax_l), true, 0}},
        {L"strtoimax", {L"strtoimax", reinterpret_cast<uintptr_t>(strtoimax_), true, 0}},
        {L"strtol_l", {L"strtol_l", reinterpret_cast<uintptr_t>(strtol_l), true, 0}},
        {L"strtol", {L"strtol", reinterpret_cast<uintptr_t>(strtol_), true, 0}},
        {L"strtold_l", {L"strtold_l", reinterpret_cast<uintptr_t>(strtold_l), true, 0}},
        {L"strtold", {L"strtold", reinterpret_cast<uintptr_t>(strtold_), true, 0}},
        {L"strtoll_l", {L"strtoll_l", reinterpret_cast<uintptr_t>(strtoll_l), true, 0}},
        {L"strtoll", {L"strtoll", reinterpret_cast<uintptr_t>(strtoll_), true, 0}},
        {L"strtoul_l", {L"strtoul_l", reinterpret_cast<uintptr_t>(strtoul_l), true, 0}},
        {L"strtoul", {L"strtoul", reinterpret_cast<uintptr_t>(strtoul_), true, 0}},
        {L"strtoull_l", {L"strtoull_l", reinterpret_cast<uintptr_t>(strtoull_l), true, 0}},
        {L"strtoull", {L"strtoull", reinterpret_cast<uintptr_t>(strtoull_), true, 0}},
        {L"strtoumax_l", {L"strtoumax_l", reinterpret_cast<uintptr_t>(strtoumax_l), true, 0}},
        {L"strtoumax", {L"strtoumax", reinterpret_cast<uintptr_t>(strtoumax_), true, 0}},

        // Wide character runtime conversion
        {L"wcrtomb", {L"wcrtomb", reinterpret_cast<uintptr_t>(wcrtomb_), true, 0}},
        {L"wcrtomb_s", {L"wcrtomb_s", reinterpret_cast<uintptr_t>(wcrtomb_s), true, 0}},
        {L"wcsrtombs", {L"wcsrtombs", reinterpret_cast<uintptr_t>(wcsrtombs_), true, 0}},
        {L"wcsrtombs_s", {L"wcsrtombs_s", reinterpret_cast<uintptr_t>(wcsrtombs_s), true, 0}},

        // Wide character string conversion
        {L"wcstod_l", {L"wcstod_l", reinterpret_cast<uintptr_t>(wcstod_l), true, 0}},
        {L"wcstod", {L"wcstod", reinterpret_cast<uintptr_t>(wcstod_), true, 0}},
        {L"wcstof_l", {L"wcstof_l", reinterpret_cast<uintptr_t>(wcstof_l), true, 0}},
        {L"wcstof", {L"wcstof", reinterpret_cast<uintptr_t>(wcstof_), true, 0}},
        {L"wcstoimax_l", {L"wcstoimax_l", reinterpret_cast<uintptr_t>(wcstoimax_l), true, 0}},
        {L"wcstoimax", {L"wcstoimax", reinterpret_cast<uintptr_t>(wcstoimax_), true, 0}},
        {L"wcstol_l", {L"wcstol_l", reinterpret_cast<uintptr_t>(wcstol_l), true, 0}},
        {L"wcstol", {L"wcstol", reinterpret_cast<uintptr_t>(wcstol_), true, 0}},
        {L"wcstold_l", {L"wcstold_l", reinterpret_cast<uintptr_t>(wcstold_l), true, 0}},
        {L"wcstold", {L"wcstold", reinterpret_cast<uintptr_t>(wcstold_), true, 0}},
        {L"wcstoll_l", {L"wcstoll_l", reinterpret_cast<uintptr_t>(wcstoll_l), true, 0}},
        {L"wcstoll", {L"wcstoll", reinterpret_cast<uintptr_t>(wcstoll_), true, 0}},
        {L"wcstombs", {L"wcstombs", reinterpret_cast<uintptr_t>(wcstombs_), true, 0}},
        {L"wcstombs_s", {L"wcstombs_s", reinterpret_cast<uintptr_t>(wcstombs_s), true, 0}},
        {L"mbstowcs", {L"mbstowcs", reinterpret_cast<uintptr_t>(mbstowcs_), true, 0}},
        {L"mbstowcs_s", {L"mbstowcs_s", reinterpret_cast<uintptr_t>(mbstowcs_s), true, 0}},
        {L"wcstoul_l", {L"wcstoul_l", reinterpret_cast<uintptr_t>(wcstoul_l), true, 0}},
        {L"wcstoul", {L"wcstoul", reinterpret_cast<uintptr_t>(wcstoul_), true, 0}},
        {L"wcstoull_l", {L"wcstoull_l", reinterpret_cast<uintptr_t>(wcstoull_l), true, 0}},
        {L"wcstoull", {L"wcstoull", reinterpret_cast<uintptr_t>(wcstoull_), true, 0}},
        {L"wcstoumax_l", {L"wcstoumax_l", reinterpret_cast<uintptr_t>(wcstoumax_l), true, 0}},
        {L"wcstoumax", {L"wcstoumax", reinterpret_cast<uintptr_t>(wcstoumax_), true, 0}},
        {L"wctob", {L"wctob", reinterpret_cast<uintptr_t>(wctob_), true, 0}},
        {L"wctomb", {L"wctomb", reinterpret_cast<uintptr_t>(wctomb_), true, 0}},
        {L"mbtowc", {L"mbtowc", reinterpret_cast<uintptr_t>(mbtowc_), true, 0}},
        {L"wctomb_s", {L"wctomb_s", reinterpret_cast<uintptr_t>(wctomb_s), true, 0}},
        {L"wctrans", {L"wctrans", reinterpret_cast<uintptr_t>(wctrans_), true, 0}},

        // Process control functions
        {L"_Exit", {L"_Exit", reinterpret_cast<uintptr_t>(_Exit_), true, 0}},
        {L"__control87_2", {L"__control87_2", reinterpret_cast<uintptr_t>(__control87_2), true, 0}},
        {L"__doserrno", {L"__doserrno", reinterpret_cast<uintptr_t>(__doserrno), true, 0}},
        {L"__fpe_flt_rounds", {L"__fpe_flt_rounds", reinterpret_cast<uintptr_t>(__fpe_flt_rounds), true, 0}},
        {L"__fpecode", {L"__fpecode", reinterpret_cast<uintptr_t>(__fpecode), true, 0}},
        {L"__p___argc", {L"__p___argc", reinterpret_cast<uintptr_t>(__p___argc), true, 0}},
        {L"__p___argv", {L"__p___argv", reinterpret_cast<uintptr_t>(__p___argv), true, 0}},
        {L"__p___wargv", {L"__p___wargv", reinterpret_cast<uintptr_t>(__p___wargv), true, 0}},
        {L"__p___acmdln", {L"__p___acmdln", reinterpret_cast<uintptr_t>(__p___acmdln), true, 0}},
        {L"__p___wcmdln", {L"__p___wcmdln", reinterpret_cast<uintptr_t>(__p___wcmdln), true, 0}},
        {L"__p__wpgmptr", {L"__p__wpgmptr", reinterpret_cast<uintptr_t>(__p__wpgmptr), true, 0}},
        {L"__pxcptinfoptrs", {L"__pxcptinfoptrs", reinterpret_cast<uintptr_t>(__pxcptinfoptrs), true, 0}},

        // Error handling functions
        {L"_strerror", {L"_strerror", reinterpret_cast<uintptr_t>(_strerror), true, 0}},
        {L"_strerror_s", {L"_strerror_s", reinterpret_cast<uintptr_t>(_strerror_s), true, 0}},
        {L"_wcserror", {L"_wcserror", reinterpret_cast<uintptr_t>(_wcserror), true, 0}},
        {L"_wcserror_s", {L"_wcserror_s", reinterpret_cast<uintptr_t>(_wcserror_s), true, 0}},
        {L"__wcserror_s", {L"__wcserror_s", reinterpret_cast<uintptr_t>(__wcserror_s), true, 0}},
        {L"__sys_errlist", {L"__sys_errlist", reinterpret_cast<uintptr_t>(__sys_errlist), true, 0}},
        {L"__sys_nerr", {L"__sys_nerr", reinterpret_cast<uintptr_t>(__sys_nerr), true, 0}},
        {L"__threadhandle", {L"__threadhandle", reinterpret_cast<uintptr_t>(__threadhandle), true, 0}},
        {L"__threadid", {L"__threadid", reinterpret_cast<uintptr_t>(__threadid), true, 0}},
        {L"_assert", {L"_assert", reinterpret_cast<uintptr_t>(_assert), true, 0}},
        {L"_wassert", {L"_wassert", reinterpret_cast<uintptr_t>(_wassert), true, 0}},

        // Threading functions
        {L"_beginthread", {L"_beginthread", reinterpret_cast<uintptr_t>(_beginthread), true, 0}},
        {L"_beginthreadex", {L"_beginthreadex", reinterpret_cast<uintptr_t>(_beginthreadex), true, 0}},
        {L"_c_exit", {L"_c_exit", reinterpret_cast<uintptr_t>(_c_exit), true, 0}},
        {L"_cexit", {L"_cexit", reinterpret_cast<uintptr_t>(_cexit), true, 0}},
        {L"_clearfp", {L"_clearfp", reinterpret_cast<uintptr_t>(_clearfp), true, 0}},
        {L"_configure_narrow_argv", {L"_configure_narrow_argv", reinterpret_cast<uintptr_t>(_configure_narrow_argv), true, 0}},
        {L"_configure_wide_argv", {L"_configure_wide_argv", reinterpret_cast<uintptr_t>(_configure_wide_argv), true, 0}},
        {L"_control87", {L"_control87", reinterpret_cast<uintptr_t>(_control87), true, 0}},
        {L"_controlfp", {L"_controlfp", reinterpret_cast<uintptr_t>(_controlfp), true, 0}},
        {L"_controlfp_s", {L"_controlfp_s", reinterpret_cast<uintptr_t>(_controlfp_s), true, 0}},
        {L"_crt_at_quick_exit", {L"_crt_at_quick_exit", reinterpret_cast<uintptr_t>(_crt_at_quick_exit), true, 0}},
        {L"_crt_atexit", {L"_crt_atexit", reinterpret_cast<uintptr_t>(_crt_atexit), true, 0}},
        {L"_crt_debugger_hook", {L"_crt_debugger_hook", reinterpret_cast<uintptr_t>(_crt_debugger_hook), true, 0}},
        {L"_endthread", {L"_endthread", reinterpret_cast<uintptr_t>(_endthread), true, 0}},
        {L"_endthreadex", {L"_endthreadex", reinterpret_cast<uintptr_t>(_endthreadex), true, 0}},
        {L"_errno", {L"_errno", reinterpret_cast<uintptr_t>(_errno), true, 0}},

        // Exit table functions
        {L"_initialize_onexit_table", {L"_initialize_onexit_table", reinterpret_cast<uintptr_t>(_initialize_onexit_table), true, 0}},
        {L"_register_onexit_function", {L"_register_onexit_function", reinterpret_cast<uintptr_t>(_register_onexit_function), true, 0}},
        {L"_execute_onexit_table", {L"_execute_onexit_table", reinterpret_cast<uintptr_t>(_execute_onexit_table), true, 0}},
        {L"exit", {L"exit", reinterpret_cast<uintptr_t>(exit), true, 0}},
        {L"_exit", {L"_exit", reinterpret_cast<uintptr_t>(_exit), true, 0}},

        // Floating point exception handling
        {L"_fpieee_flt", {L"_fpieee_flt", reinterpret_cast<uintptr_t>(_fpieee_flt), true, 0}},
        {L"_fpreset", {L"_fpreset", reinterpret_cast<uintptr_t>(_fpreset), true, 0}},
        {L"_get_doserrno", {L"_get_doserrno", reinterpret_cast<uintptr_t>(_get_doserrno), true, 0}},
        {L"_get_errno", {L"_get_errno", reinterpret_cast<uintptr_t>(_get_errno), true, 0}},
        {L"_get_initial_narrow_environment", {L"_get_initial_narrow_environment", reinterpret_cast<uintptr_t>(_get_initial_narrow_environment), true, 0}},
        {L"_get_initial_wide_environment", {L"_get_initial_wide_environment", reinterpret_cast<uintptr_t>(_get_initial_wide_environment), true, 0}},
        {L"_get_invalid_parameter_handler", {L"_get_invalid_parameter_handler", reinterpret_cast<uintptr_t>(_get_invalid_parameter_handler), true, 0}},
        {L"_get_thread_local_invalid_parameter_handler", {L"_get_thread_local_invalid_parameter_handler", reinterpret_cast<uintptr_t>(_get_thread_local_invalid_parameter_handler), true, 0}},
        {L"_set_invalid_parameter_handler", {L"_set_invalid_parameter_handler", reinterpret_cast<uintptr_t>(_set_invalid_parameter_handler), true, 0}},
        {L"_set_thread_local_invalid_parameter_handler", {L"_set_thread_local_invalid_parameter_handler", reinterpret_cast<uintptr_t>(_set_thread_local_invalid_parameter_handler), true, 0}},
        {L"_get_narrow_winmain_command_line", {L"_get_narrow_winmain_command_line", reinterpret_cast<uintptr_t>(_get_narrow_winmain_command_line), true, 0}},
        {L"_get_pgmptr", {L"_get_pgmptr", reinterpret_cast<uintptr_t>(_get_pgmptr), true, 0}},
        {L"_get_wpgmptr", {L"_get_wpgmptr", reinterpret_cast<uintptr_t>(_get_wpgmptr), true, 0}},
        {L"_get_wide_winmain_command_line", {L"_get_wide_winmain_command_line", reinterpret_cast<uintptr_t>(_get_wide_winmain_command_line), true, 0}},
        {L"_get_terminate", {L"_get_terminate", reinterpret_cast<uintptr_t>(_get_terminate), true, 0}},
        {L"_set_terminate", {L"_set_terminate", reinterpret_cast<uintptr_t>(_set_terminate), true, 0}},
        {L"_getdllprocaddr", {L"_getdllprocaddr", reinterpret_cast<uintptr_t>(_getdllprocaddr), true, 0}},
        {L"_getpid", {L"_getpid", reinterpret_cast<uintptr_t>(_getpid), true, 0}},
        {L"_initialize_narrow_environment", {L"_initialize_narrow_environment", reinterpret_cast<uintptr_t>(_initialize_narrow_environment), true, 0}},
        {L"_initialize_wide_environment", {L"_initialize_wide_environment", reinterpret_cast<uintptr_t>(_initialize_wide_environment), true, 0}},
        {L"_initterm", {L"_initterm", reinterpret_cast<uintptr_t>(_initterm), true, 0}},
        {L"_initterm_e", {L"_initterm_e", reinterpret_cast<uintptr_t>(_initterm_e), true, 0}},
        {L"_invalid_parameter_noinfo", {L"_invalid_parameter_noinfo", reinterpret_cast<uintptr_t>(_invalid_parameter_noinfo), true, 0}},
        {L"_invalid_parameter_noinfo_noreturn", {L"_invalid_parameter_noinfo_noreturn", reinterpret_cast<uintptr_t>(_invalid_parameter_noinfo_noreturn), true, 0}},
        {L"_invoke_watson", {L"_invoke_watson", reinterpret_cast<uintptr_t>(_invoke_watson), true, 0}},
        {L"_query_app_type", {L"_query_app_type", reinterpret_cast<uintptr_t>(_query_app_type), true, 0}},
        {L"_register_thread_local_exe_atexit_callback", {L"_register_thread_local_exe_atexit_callback", reinterpret_cast<uintptr_t>(_register_thread_local_exe_atexit_callback), true, 0}},
        {L"_resetstkoflw", {L"_resetstkoflw", reinterpret_cast<uintptr_t>(_resetstkoflw), true, 0}},
        {L"_seh_filter_dll", {L"_seh_filter_dll", reinterpret_cast<uintptr_t>(_seh_filter_dll), true, 0}},
        {L"_seh_filter_exe", {L"_seh_filter_exe", reinterpret_cast<uintptr_t>(_seh_filter_exe), true, 0}},
        {L"_set_abort_behavior", {L"_set_abort_behavior", reinterpret_cast<uintptr_t>(_set_abort_behavior), true, 0}},
        {L"_set_app_type", {L"_set_app_type", reinterpret_cast<uintptr_t>(_set_app_type), true, 0}},
        {L"_set_controlfp", {L"_set_controlfp", reinterpret_cast<uintptr_t>(_set_controlfp), true, 0}},
        {L"_set_doserrno", {L"_set_doserrno", reinterpret_cast<uintptr_t>(_set_doserrno), true, 0}},
        {L"_set_errno", {L"_set_errno", reinterpret_cast<uintptr_t>(_set_errno), true, 0}},
        {L"_set_error_mode", {L"_set_error_mode", reinterpret_cast<uintptr_t>(_set_error_mode), true, 0}},
        {L"_set_new_handler", {L"_set_new_handler", reinterpret_cast<uintptr_t>(_set_new_handler), true, 0}},
        {L"_seterrormode", {L"_seterrormode", reinterpret_cast<uintptr_t>(_seterrormode), true, 0}},
        {L"_sleep", {L"_sleep", reinterpret_cast<uintptr_t>(_sleep), true, 0}},
        {L"_statusfp", {L"_statusfp", reinterpret_cast<uintptr_t>(_statusfp), true, 0}},
        {L"_statusfp2", {L"_statusfp2", reinterpret_cast<uintptr_t>(_statusfp2), true, 0}},
        {L"system", {L"system", reinterpret_cast<uintptr_t>(system_), true, 0}},
        {L"_wsystem", {L"_wsystem", reinterpret_cast<uintptr_t>(_wsystem), true, 0}},

        // Standard functions
        {L"abort", {L"abort", reinterpret_cast<uintptr_t>(abort), true, 0}},
        {L"feclearexcept", {L"feclearexcept", reinterpret_cast<uintptr_t>(feclearexcept), true, 0}},
        {L"fetestexcept", {L"fetestexcept", reinterpret_cast<uintptr_t>(fetestexcept), true, 0}},
        {L"fegetenv", {L"fegetenv", reinterpret_cast<uintptr_t>(fegetenv), true, 0}},
        {L"fesetenv", {L"fesetenv", reinterpret_cast<uintptr_t>(fesetenv), true, 0}},
        {L"fegetround", {L"fegetround", reinterpret_cast<uintptr_t>(fegetround), true, 0}},
        {L"fesetround", {L"fesetround", reinterpret_cast<uintptr_t>(fesetround), true, 0}},
        {L"fegetexceptflag", {L"fegetexceptflag", reinterpret_cast<uintptr_t>(fegetexceptflag), true, 0}},
        {L"feholdexcept", {L"feholdexcept", reinterpret_cast<uintptr_t>(feholdexcept), true, 0}},
        {L"perror", {L"perror", reinterpret_cast<uintptr_t>(perror), true, 0}},
        {L"quick_exit", {L"quick_exit", reinterpret_cast<uintptr_t>(quick_exit), true, 0}},
        {L"raise", {L"raise", reinterpret_cast<uintptr_t>(raise), true, 0}},
        {L"set_terminate", {L"set_terminate", reinterpret_cast<uintptr_t>(set_terminate), true, 0}},
        {L"signal", {L"signal", reinterpret_cast<uintptr_t>(signal), true, 0}},
        {L"strerror", {L"strerror", reinterpret_cast<uintptr_t>(strerror), true, 0}},
        {L"strerror_s", {L"strerror_s", reinterpret_cast<uintptr_t>(strerror_s), true, 0}},
        {L"terminate", {L"terminate", reinterpret_cast<uintptr_t>(terminate), true, 0}},

        // Math functions - complex and advanced
        {L"_cabs", {L"_cabs", reinterpret_cast<uintptr_t>(_cabs), true, 0}},
        {L"_chgsign", {L"_chgsign", reinterpret_cast<uintptr_t>(_chgsign), true, 0}},
        {L"_chgsignf", {L"_chgsignf", reinterpret_cast<uintptr_t>(_chgsignf), true, 0}},
        {L"_chgsignl", {L"_chgsignl", reinterpret_cast<uintptr_t>(_chgsignl), true, 0}},
        {L"_copysign", {L"_copysign", reinterpret_cast<uintptr_t>(_copysign), true, 0}},
        {L"_copysignf", {L"_copysignf", reinterpret_cast<uintptr_t>(_copysignf), true, 0}},
        {L"_copysignl", {L"_copysignl", reinterpret_cast<uintptr_t>(_copysignl), true, 0}},
        {L"_d_int", {L"_d_int", reinterpret_cast<uintptr_t>(_d_int), true, 0}},
        {L"_dclass", {L"_dclass", reinterpret_cast<uintptr_t>(_dclass), true, 0}},
        {L"_ldclass", {L"_ldclass", reinterpret_cast<uintptr_t>(_ldclass), true, 0}},
        {L"_fdclass", {L"_fdclass", reinterpret_cast<uintptr_t>(_fdclass), true, 0}},
        {L"_dexp", {L"_dexp", reinterpret_cast<uintptr_t>(_dexp), true, 0}},
        {L"_fdexp", {L"_fdexp", reinterpret_cast<uintptr_t>(_fdexp), true, 0}},
        {L"_ldexp", {L"_ldexp", reinterpret_cast<uintptr_t>(_ldexp), true, 0}},
        {L"_dlog", {L"_dlog", reinterpret_cast<uintptr_t>(_dlog), true, 0}},
        {L"_fdlog", {L"_fdlog", reinterpret_cast<uintptr_t>(_fdlog), true, 0}},
        {L"_ldlog", {L"_ldlog", reinterpret_cast<uintptr_t>(_ldlog), true, 0}},
        {L"_dnorm", {L"_dnorm", reinterpret_cast<uintptr_t>(_dnorm), true, 0}},
        {L"_fdnorm", {L"_fdnorm", reinterpret_cast<uintptr_t>(_fdnorm), true, 0}},
        {L"_ldnorm", {L"_ldnorm", reinterpret_cast<uintptr_t>(_ldnorm), true, 0}},
        {L"_dpcomp", {L"_dpcomp", reinterpret_cast<uintptr_t>(_dpcomp), true, 0}},
        {L"_dpoly", {L"_dpoly", reinterpret_cast<uintptr_t>(_dpoly), true, 0}},
        {L"_fdpoly", {L"_fdpoly", reinterpret_cast<uintptr_t>(_fdpoly), true, 0}},
        {L"_ldpoly", {L"_ldpoly", reinterpret_cast<uintptr_t>(_ldpoly), true, 0}},
        {L"_evaluate_polynomial", {L"_evaluate_polynomial", reinterpret_cast<uintptr_t>(_evaluate_polynomial), true, 0}},
        {L"_dscale", {L"_dscale", reinterpret_cast<uintptr_t>(_dscale), true, 0}},
        {L"_fdscale", {L"_fdscale", reinterpret_cast<uintptr_t>(_fdscale), true, 0}},
        {L"_ldscale", {L"_ldscale", reinterpret_cast<uintptr_t>(_ldscale), true, 0}},
        {L"_dsign", {L"_dsign", reinterpret_cast<uintptr_t>(_dsign), true, 0}},
        {L"_fdsign", {L"_fdsign", reinterpret_cast<uintptr_t>(_fdsign), true, 0}},
        {L"_ldsign", {L"_ldsign", reinterpret_cast<uintptr_t>(_ldsign), true, 0}},
        {L"_dsin", {L"_dsin", reinterpret_cast<uintptr_t>(_dsin), true, 0}},
        {L"_fdsin", {L"_fdsin", reinterpret_cast<uintptr_t>(_fdsin), true, 0}},
        {L"_ldsin", {L"_ldsin", reinterpret_cast<uintptr_t>(_ldsin), true, 0}},
        {L"_dtest", {L"_dtest", reinterpret_cast<uintptr_t>(_dtest), true, 0}},
        {L"_fdtest", {L"_fdtest", reinterpret_cast<uintptr_t>(_fdtest), true, 0}},
        {L"_ldtest", {L"_ldtest", reinterpret_cast<uintptr_t>(_ldtest), true, 0}},
        {L"_dunscale", {L"_dunscale", reinterpret_cast<uintptr_t>(_dunscale), true, 0}},
        {L"_fdunscale", {L"_fdunscale", reinterpret_cast<uintptr_t>(_fdunscale), true, 0}},
        {L"_ldunscale", {L"_ldunscale", reinterpret_cast<uintptr_t>(_ldunscale), true, 0}},
        {L"get_mxcsr", {L"get_mxcsr", reinterpret_cast<uintptr_t>(get_mxcsr), true, 0}},
        {L"set_mxcsr", {L"set_mxcsr", reinterpret_cast<uintptr_t>(set_mxcsr), true, 0}},
        {L"_setfp_sse", {L"_setfp_sse", reinterpret_cast<uintptr_t>(_setfp_sse), true, 0}},
        {L"_except1", {L"_except1", reinterpret_cast<uintptr_t>(_except1), true, 0}},

        // CRT intrinsic math functions
        {L"_CIacos", {L"_CIacos", reinterpret_cast<uintptr_t>(_CIacos), true, 0}},
        {L"_CIasin", {L"_CIasin", reinterpret_cast<uintptr_t>(_CIasin), true, 0}},
        {L"_CIatan", {L"_CIatan", reinterpret_cast<uintptr_t>(_CIatan), true, 0}},
        {L"_CIatan2", {L"_CIatan2", reinterpret_cast<uintptr_t>(_CIatan2), true, 0}},
        {L"_CIcos", {L"_CIcos", reinterpret_cast<uintptr_t>(_CIcos), true, 0}},
        {L"_CIsin", {L"_CIsin", reinterpret_cast<uintptr_t>(_CIsin), true, 0}},
        {L"_CItan", {L"_CItan", reinterpret_cast<uintptr_t>(_CItan), true, 0}},
        {L"_CIcosh", {L"_CIcosh", reinterpret_cast<uintptr_t>(_CIcosh), true, 0}},
        {L"_CIexp", {L"_CIexp", reinterpret_cast<uintptr_t>(_CIexp), true, 0}},
        {L"_CIfmod", {L"_CIfmod", reinterpret_cast<uintptr_t>(_CIfmod), true, 0}},
        {L"_CIlog10", {L"_CIlog10", reinterpret_cast<uintptr_t>(_CIlog10), true, 0}},
        {L"_CIlog", {L"_CIlog", reinterpret_cast<uintptr_t>(_CIlog), true, 0}},
        {L"_CIsinh", {L"_CIsinh", reinterpret_cast<uintptr_t>(_CIsinh), true, 0}},
        {L"_CIsqrt", {L"_CIsqrt", reinterpret_cast<uintptr_t>(_CIsqrt), true, 0}},
        {L"_CItanh", {L"_CItanh", reinterpret_cast<uintptr_t>(_CItanh), true, 0}},

        // Complex number functions
        {L"_Cbuild", {L"_Cbuild", reinterpret_cast<uintptr_t>(_Cbuild), true, 0}},
        {L"_Cmulcc", {L"_Cmulcc", reinterpret_cast<uintptr_t>(_Cmulcc), true, 0}},
        {L"_Cmulcr", {L"_Cmulcr", reinterpret_cast<uintptr_t>(_Cmulcr), true, 0}},
        {L"_FCbuild", {L"_FCbuild", reinterpret_cast<uintptr_t>(_FCbuild), true, 0}},
        {L"_FCmulcc", {L"_FCmulcc", reinterpret_cast<uintptr_t>(_FCmulcc), true, 0}},
        {L"_FCmulcr", {L"_FCmulcr", reinterpret_cast<uintptr_t>(_FCmulcr), true, 0}},
        {L"_LCbuild", {L"_LCbuild", reinterpret_cast<uintptr_t>(_LCbuild), true, 0}},
        {L"_LCmulcc", {L"_LCmulcc", reinterpret_cast<uintptr_t>(_LCmulcc), true, 0}},
        {L"_LCmulcr", {L"_LCmulcr", reinterpret_cast<uintptr_t>(_LCmulcr), true, 0}},

        // SSE2 optimized math functions
        {L"__libm_sse2_acos", {L"__libm_sse2_acos", reinterpret_cast<uintptr_t>(__libm_sse2_acos), true, 0}},
        {L"__libm_sse2_acos_precise", {L"__libm_sse2_acos_precise", reinterpret_cast<uintptr_t>(__libm_sse2_acos_precise), true, 0}},
        {L"__libm_sse2_acosf", {L"__libm_sse2_acosf", reinterpret_cast<uintptr_t>(__libm_sse2_acosf), true, 0}},
        {L"__libm_sse2_asin", {L"__libm_sse2_asin", reinterpret_cast<uintptr_t>(__libm_sse2_asin), true, 0}},
        {L"__libm_sse2_asin_precise", {L"__libm_sse2_asin_precise", reinterpret_cast<uintptr_t>(__libm_sse2_asin_precise), true, 0}},
        {L"__libm_sse2_asinf", {L"__libm_sse2_asinf", reinterpret_cast<uintptr_t>(__libm_sse2_asinf), true, 0}},
        {L"__libm_sse2_atan", {L"__libm_sse2_atan", reinterpret_cast<uintptr_t>(__libm_sse2_atan), true, 0}},
        {L"__libm_sse2_atan_precise", {L"__libm_sse2_atan_precise", reinterpret_cast<uintptr_t>(__libm_sse2_atan_precise), true, 0}},
        {L"__libm_sse2_atanf", {L"__libm_sse2_atanf", reinterpret_cast<uintptr_t>(__libm_sse2_atanf), true, 0}},
        {L"__libm_sse2_atan2", {L"__libm_sse2_atan2", reinterpret_cast<uintptr_t>(__libm_sse2_atan2), true, 0}},
        {L"__libm_sse2_atan2_precise", {L"__libm_sse2_atan2_precise", reinterpret_cast<uintptr_t>(__libm_sse2_atan2_precise), true, 0}},
        {L"__libm_sse2_atan2f", {L"__libm_sse2_atan2f", reinterpret_cast<uintptr_t>(__libm_sse2_atan2f), true, 0}},
        {L"__libm_sse2_cos", {L"__libm_sse2_cos", reinterpret_cast<uintptr_t>(__libm_sse2_cos), true, 0}},
        {L"__libm_sse2_cos_precise", {L"__libm_sse2_cos_precise", reinterpret_cast<uintptr_t>(__libm_sse2_cos_precise), true, 0}},
        {L"__libm_sse2_cosf", {L"__libm_sse2_cosf", reinterpret_cast<uintptr_t>(__libm_sse2_cosf), true, 0}},
        {L"__libm_sse2_sin", {L"__libm_sse2_sin", reinterpret_cast<uintptr_t>(__libm_sse2_sin), true, 0}},
        {L"__libm_sse2_sin_precise", {L"__libm_sse2_sin_precise", reinterpret_cast<uintptr_t>(__libm_sse2_sin_precise), true, 0}},
        {L"__libm_sse2_sinf", {L"__libm_sse2_sinf", reinterpret_cast<uintptr_t>(__libm_sse2_sinf), true, 0}},
        {L"__libm_sse2_tan", {L"__libm_sse2_tan", reinterpret_cast<uintptr_t>(__libm_sse2_tan), true, 0}},
        {L"__libm_sse2_tan_precise", {L"__libm_sse2_tan_precise", reinterpret_cast<uintptr_t>(__libm_sse2_tan_precise), true, 0}},
        {L"__libm_sse2_tanf", {L"__libm_sse2_tanf", reinterpret_cast<uintptr_t>(__libm_sse2_tanf), true, 0}},
        {L"__libm_sse2_exp", {L"__libm_sse2_exp", reinterpret_cast<uintptr_t>(__libm_sse2_exp), true, 0}},
        {L"__libm_sse2_exp_precise", {L"__libm_sse2_exp_precise", reinterpret_cast<uintptr_t>(__libm_sse2_exp_precise), true, 0}},
        {L"__libm_sse2_expf", {L"__libm_sse2_expf", reinterpret_cast<uintptr_t>(__libm_sse2_expf), true, 0}},
        {L"__libm_sse2_log", {L"__libm_sse2_log", reinterpret_cast<uintptr_t>(__libm_sse2_log), true, 0}},
        {L"__libm_sse2_log_precise", {L"__libm_sse2_log_precise", reinterpret_cast<uintptr_t>(__libm_sse2_log_precise), true, 0}},
        {L"__libm_sse2_logf", {L"__libm_sse2_logf", reinterpret_cast<uintptr_t>(__libm_sse2_logf), true, 0}},
        {L"__libm_sse2_log10", {L"__libm_sse2_log10", reinterpret_cast<uintptr_t>(__libm_sse2_log10), true, 0}},
        {L"__libm_sse2_log10_precise", {L"__libm_sse2_log10_precise", reinterpret_cast<uintptr_t>(__libm_sse2_log10_precise), true, 0}},
        {L"__libm_sse2_log10f", {L"__libm_sse2_log10f", reinterpret_cast<uintptr_t>(__libm_sse2_log10f), true, 0}},
        {L"__libm_sse2_sqrt", {L"__libm_sse2_sqrt", reinterpret_cast<uintptr_t>(__libm_sse2_sqrt), true, 0}},
        {L"__libm_sse2_sqrt_precise", {L"__libm_sse2_sqrt_precise", reinterpret_cast<uintptr_t>(__libm_sse2_sqrt_precise), true, 0}},
        {L"__libm_sse2_sqrtf", {L"__libm_sse2_sqrtf", reinterpret_cast<uintptr_t>(__libm_sse2_sqrtf), true, 0}},
        {L"__libm_sse2_pow", {L"__libm_sse2_pow", reinterpret_cast<uintptr_t>(__libm_sse2_pow), true, 0}},
        {L"__libm_sse2_pow_precise", {L"__libm_sse2_pow_precise", reinterpret_cast<uintptr_t>(__libm_sse2_pow_precise), true, 0}},
        {L"__libm_sse2_powf", {L"__libm_sse2_powf", reinterpret_cast<uintptr_t>(__libm_sse2_powf), true, 0}},
        {L"__libm_sse2_cbrt", {L"__libm_sse2_cbrt", reinterpret_cast<uintptr_t>(__libm_sse2_cbrt), true, 0}},
        {L"__libm_sse2_cbrt_precise", {L"__libm_sse2_cbrt_precise", reinterpret_cast<uintptr_t>(__libm_sse2_cbrt_precise), true, 0}},
        {L"__libm_sse2_cbrtf", {L"__libm_sse2_cbrtf", reinterpret_cast<uintptr_t>(__libm_sse2_cbrtf), true, 0}},

        // Additional math functions
        {L"_logb", {L"_logb", reinterpret_cast<uintptr_t>(_logb), true, 0}},
        {L"_logbf", {L"_logbf", reinterpret_cast<uintptr_t>(_logbf), true, 0}},
        {L"_logbl", {L"_logbl", reinterpret_cast<uintptr_t>(_logbl), true, 0}},
        {L"_nextafter", {L"_nextafter", reinterpret_cast<uintptr_t>(_nextafter), true, 0}},
        {L"_nextafterf", {L"_nextafterf", reinterpret_cast<uintptr_t>(_nextafterf), true, 0}},
        {L"_nextafterl", {L"_nextafterl", reinterpret_cast<uintptr_t>(_nextafterl), true, 0}},
        {L"_scalb", {L"_scalb", reinterpret_cast<uintptr_t>(_scalb), true, 0}},
        {L"_scalbf", {L"_scalbf", reinterpret_cast<uintptr_t>(_scalbf), true, 0}},
        {L"_scalbl", {L"_scalbl", reinterpret_cast<uintptr_t>(_scalbl), true, 0}},
        {L"__setusermatherr", {L"__setusermatherr", reinterpret_cast<uintptr_t>(__setusermatherr), true, 0}},

        // Bessel functions
        {L"_j0", {L"_j0", reinterpret_cast<uintptr_t>(_j0), true, 0}},
        {L"_j1", {L"_j1", reinterpret_cast<uintptr_t>(_j1), true, 0}},
        {L"_jn", {L"_jn", reinterpret_cast<uintptr_t>(_jn), true, 0}},
        {L"_y0", {L"_y0", reinterpret_cast<uintptr_t>(_y0), true, 0}},
        {L"_y1", {L"_y1", reinterpret_cast<uintptr_t>(_y1), true, 0}},
        {L"_yn", {L"_yn", reinterpret_cast<uintptr_t>(_yn), true, 0}},

        // Standard math functions
        {L"acos", {L"acos", reinterpret_cast<uintptr_t>(acos_), true, 0}},
        {L"acosf", {L"acosf", reinterpret_cast<uintptr_t>(acosf_), true, 0}},
        {L"acosl", {L"acosl", reinterpret_cast<uintptr_t>(acosl_), true, 0}},
        {L"acosh", {L"acosh", reinterpret_cast<uintptr_t>(acosh_), true, 0}},
        {L"acoshf", {L"acoshf", reinterpret_cast<uintptr_t>(acoshf_), true, 0}},
        {L"acoshl", {L"acoshl", reinterpret_cast<uintptr_t>(acoshl_), true, 0}},
        {L"asin", {L"asin", reinterpret_cast<uintptr_t>(asin_), true, 0}},
        {L"asinf", {L"asinf", reinterpret_cast<uintptr_t>(asinf_), true, 0}},
        {L"asinl", {L"asinl", reinterpret_cast<uintptr_t>(asinl_), true, 0}},
        {L"asinh", {L"asinh", reinterpret_cast<uintptr_t>(asinh_), true, 0}},
        {L"asinhf", {L"asinhf", reinterpret_cast<uintptr_t>(asinhf_), true, 0}},
        {L"asinhl", {L"asinhl", reinterpret_cast<uintptr_t>(asinhl_), true, 0}},
        {L"atan", {L"atan", reinterpret_cast<uintptr_t>(atan_), true, 0}},
        {L"atanf", {L"atanf", reinterpret_cast<uintptr_t>(atanf_), true, 0}},
        {L"atanl", {L"atanl", reinterpret_cast<uintptr_t>(atanl_), true, 0}},
        {L"atanh", {L"atanh", reinterpret_cast<uintptr_t>(atanh_), true, 0}},
        {L"atanhf", {L"atanhf", reinterpret_cast<uintptr_t>(atanhf_), true, 0}},
        {L"atanhl", {L"atanhl", reinterpret_cast<uintptr_t>(atanhl_), true, 0}},
        {L"atan2", {L"atan2", reinterpret_cast<uintptr_t>(atan2_), true, 0}},
        {L"atan2f", {L"atan2f", reinterpret_cast<uintptr_t>(atan2f_), true, 0}},
        {L"atan2l", {L"atan2l", reinterpret_cast<uintptr_t>(atan2l_), true, 0}},

        // Complex math functions
        {L"cabs", {L"cabs", reinterpret_cast<uintptr_t>(cabs), true, 0}},
        {L"cabsf", {L"cabsf", reinterpret_cast<uintptr_t>(cabsf), true, 0}},
        {L"cabsl", {L"cabsl", reinterpret_cast<uintptr_t>(cabsl), true, 0}},
        {L"cacos", {L"cacos", reinterpret_cast<uintptr_t>(cacos), true, 0}},
        {L"cacosf", {L"cacosf", reinterpret_cast<uintptr_t>(cacosf), true, 0}},
        {L"cacosl", {L"cacosl", reinterpret_cast<uintptr_t>(cacosl), true, 0}},
        {L"cacosh", {L"cacosh", reinterpret_cast<uintptr_t>(cacosh), true, 0}},
        {L"cacoshf", {L"cacoshf", reinterpret_cast<uintptr_t>(cacoshf), true, 0}},
        {L"cacoshl", {L"cacoshl", reinterpret_cast<uintptr_t>(cacoshl), true, 0}},
        {L"casin", {L"casin", reinterpret_cast<uintptr_t>(casin), true, 0}},
        {L"casinf", {L"casinf", reinterpret_cast<uintptr_t>(casinf), true, 0}},
        {L"casinl", {L"casinl", reinterpret_cast<uintptr_t>(casinl), true, 0}},
        {L"casinh", {L"casinh", reinterpret_cast<uintptr_t>(casinh), true, 0}},
        {L"casinhf", {L"casinhf", reinterpret_cast<uintptr_t>(casinhf), true, 0}},
        {L"casinhl", {L"casinhl", reinterpret_cast<uintptr_t>(casinhl), true, 0}},
        {L"catan", {L"catan", reinterpret_cast<uintptr_t>(catan), true, 0}},
        {L"catanf", {L"catanf", reinterpret_cast<uintptr_t>(catanf), true, 0}},
        {L"catanl", {L"catanl", reinterpret_cast<uintptr_t>(catanl), true, 0}},
        {L"catanh", {L"catanh", reinterpret_cast<uintptr_t>(catanh), true, 0}},
        {L"catanhf", {L"catanhf", reinterpret_cast<uintptr_t>(catanhf), true, 0}},
        {L"catanhl", {L"catanhl", reinterpret_cast<uintptr_t>(catanhl), true, 0}},
        {L"carg", {L"carg", reinterpret_cast<uintptr_t>(carg), true, 0}},
        {L"cargf", {L"cargf", reinterpret_cast<uintptr_t>(cargf), true, 0}},
        {L"cargl", {L"cargl", reinterpret_cast<uintptr_t>(cargl), true, 0}},
        {L"cexp", {L"cexp", reinterpret_cast<uintptr_t>(cexp), true, 0}},
        {L"cexpf", {L"cexpf", reinterpret_cast<uintptr_t>(cexpf), true, 0}},
        {L"cexpl", {L"cexpl", reinterpret_cast<uintptr_t>(cexpl), true, 0}},
        {L"cimag", {L"cimag", reinterpret_cast<uintptr_t>(cimag), true, 0}},
        {L"cimagf", {L"cimagf", reinterpret_cast<uintptr_t>(cimagf), true, 0}},
        {L"cimagl", {L"cimagl", reinterpret_cast<uintptr_t>(cimagl), true, 0}},
        {L"creal", {L"creal", reinterpret_cast<uintptr_t>(creal), true, 0}},
        {L"crealf", {L"crealf", reinterpret_cast<uintptr_t>(crealf), true, 0}},
        {L"creall", {L"creall", reinterpret_cast<uintptr_t>(creall), true, 0}},
        {L"clog", {L"clog", reinterpret_cast<uintptr_t>(clog), true, 0}},
        {L"clogf", {L"clogf", reinterpret_cast<uintptr_t>(clogf), true, 0}},
        {L"clogl", {L"clogl", reinterpret_cast<uintptr_t>(clogl), true, 0}},
        {L"clog10", {L"clog10", reinterpret_cast<uintptr_t>(clog10), true, 0}},
        {L"clog10f", {L"clog10f", reinterpret_cast<uintptr_t>(clog10f), true, 0}},
        {L"clog10l", {L"clog10l", reinterpret_cast<uintptr_t>(clog10l), true, 0}},
        {L"conj", {L"conj", reinterpret_cast<uintptr_t>(conj), true, 0}},
        {L"conjf", {L"conjf", reinterpret_cast<uintptr_t>(conjf), true, 0}},
        {L"conjl", {L"conjl", reinterpret_cast<uintptr_t>(conjl), true, 0}},
        {L"cpow", {L"cpow", reinterpret_cast<uintptr_t>(cpow), true, 0}},
        {L"cpowf", {L"cpowf", reinterpret_cast<uintptr_t>(cpowf), true, 0}},
        {L"cpowl", {L"cpowl", reinterpret_cast<uintptr_t>(cpowl), true, 0}},
        {L"cproj", {L"cproj", reinterpret_cast<uintptr_t>(cproj), true, 0}},
        {L"cprojf", {L"cprojf", reinterpret_cast<uintptr_t>(cprojf), true, 0}},
        {L"cprojl", {L"cprojl", reinterpret_cast<uintptr_t>(cprojl), true, 0}},
        {L"csin", {L"csin", reinterpret_cast<uintptr_t>(csin), true, 0}},
        {L"csinf", {L"csinf", reinterpret_cast<uintptr_t>(csinf), true, 0}},
        {L"csinl", {L"csinl", reinterpret_cast<uintptr_t>(csinl), true, 0}},
        {L"csinh", {L"csinh", reinterpret_cast<uintptr_t>(csinh), true, 0}},
        {L"csinhf", {L"csinhf", reinterpret_cast<uintptr_t>(csinhf), true, 0}},
        {L"csinhl", {L"csinhl", reinterpret_cast<uintptr_t>(csinhl), true, 0}},
        {L"ccos", {L"ccos", reinterpret_cast<uintptr_t>(ccos), true, 0}},
        {L"ccosf", {L"ccosf", reinterpret_cast<uintptr_t>(ccosf), true, 0}},
        {L"ccosl", {L"ccosl", reinterpret_cast<uintptr_t>(ccosl), true, 0}},
        {L"ccosh", {L"ccosh", reinterpret_cast<uintptr_t>(ccosh), true, 0}},
        {L"ccoshf", {L"ccoshf", reinterpret_cast<uintptr_t>(ccoshf), true, 0}},
        {L"ccoshl", {L"ccoshl", reinterpret_cast<uintptr_t>(ccoshl), true, 0}},
        {L"ctan", {L"ctan", reinterpret_cast<uintptr_t>(ctan), true, 0}},
        {L"ctanf", {L"ctanf", reinterpret_cast<uintptr_t>(ctanf), true, 0}},
        {L"ctanl", {L"ctanl", reinterpret_cast<uintptr_t>(ctanl), true, 0}},
        {L"ctanh", {L"ctanh", reinterpret_cast<uintptr_t>(ctanh), true, 0}},
        {L"ctanhf", {L"ctanhf", reinterpret_cast<uintptr_t>(ctanhf), true, 0}},
        {L"ctanhl", {L"ctanhl", reinterpret_cast<uintptr_t>(ctanhl), true, 0}},
        {L"csqrt", {L"csqrt", reinterpret_cast<uintptr_t>(csqrt), true, 0}},
        {L"csqrtf", {L"csqrtf", reinterpret_cast<uintptr_t>(csqrtf), true, 0}},
        {L"csqrtl", {L"csqrtl", reinterpret_cast<uintptr_t>(csqrtl), true, 0}},
        {L"norm", {L"norm", reinterpret_cast<uintptr_t>(norm_), true, 0}},
        {L"normf", {L"normf", reinterpret_cast<uintptr_t>(normf_), true, 0}},
        {L"norml", {L"norml", reinterpret_cast<uintptr_t>(norml_), true, 0}},

        // More standard math functions
        {L"erf", {L"erf", reinterpret_cast<uintptr_t>(erf_), true, 0}},
        {L"erff", {L"erff", reinterpret_cast<uintptr_t>(erff_), true, 0}},
        {L"erfl", {L"erfl", reinterpret_cast<uintptr_t>(erfl_), true, 0}},
        {L"erfc", {L"erfc", reinterpret_cast<uintptr_t>(erfc_), true, 0}},
        {L"erfcf", {L"erfcf", reinterpret_cast<uintptr_t>(erfcf_), true, 0}},
        {L"erfcl", {L"erfcl", reinterpret_cast<uintptr_t>(erfcl_), true, 0}},
        {L"exp", {L"exp", reinterpret_cast<uintptr_t>(exp_), true, 0}},
        {L"expf", {L"expf", reinterpret_cast<uintptr_t>(expf_), true, 0}},
        {L"expl", {L"expl", reinterpret_cast<uintptr_t>(expl_), true, 0}},
        {L"exp2", {L"exp2", reinterpret_cast<uintptr_t>(exp2_), true, 0}},
        {L"exp2f", {L"exp2f", reinterpret_cast<uintptr_t>(exp2f_), true, 0}},
        {L"exp2l", {L"exp2l", reinterpret_cast<uintptr_t>(exp2l_), true, 0}},
        {L"expm1", {L"expm1", reinterpret_cast<uintptr_t>(expm1_), true, 0}},
        {L"expm1f", {L"expm1f", reinterpret_cast<uintptr_t>(expm1f_), true, 0}},
        {L"expm1l", {L"expm1l", reinterpret_cast<uintptr_t>(expm1l_), true, 0}},
        {L"fabs", {L"fabs", reinterpret_cast<uintptr_t>(fabs_), true, 0}},
        {L"fabsf", {L"fabsf", reinterpret_cast<uintptr_t>(fabsf_), true, 0}},
        {L"fabsl", {L"fabsl", reinterpret_cast<uintptr_t>(fabsl_), true, 0}},
        {L"fdim", {L"fdim", reinterpret_cast<uintptr_t>(fdim_), true, 0}},
        {L"fdimf", {L"fdimf", reinterpret_cast<uintptr_t>(fdimf_), true, 0}},
        {L"fdiml", {L"fdiml", reinterpret_cast<uintptr_t>(fdiml_), true, 0}},
        {L"floor", {L"floor", reinterpret_cast<uintptr_t>(floor_), true, 0}},
        {L"floorf", {L"floorf", reinterpret_cast<uintptr_t>(floorf_), true, 0}},
        {L"floorl", {L"floorl", reinterpret_cast<uintptr_t>(floorl_), true, 0}},
        {L"fma", {L"fma", reinterpret_cast<uintptr_t>(fma_), true, 0}},
        {L"fmaf", {L"fmaf", reinterpret_cast<uintptr_t>(fmaf_), true, 0}},
        {L"fmal", {L"fmal", reinterpret_cast<uintptr_t>(fmal_), true, 0}},
        {L"fmax", {L"fmax", reinterpret_cast<uintptr_t>(fmax_), true, 0}},
        {L"fmaxf", {L"fmaxf", reinterpret_cast<uintptr_t>(fmaxf_), true, 0}},
        {L"fmaxl", {L"fmaxl", reinterpret_cast<uintptr_t>(fmaxl_), true, 0}},
        {L"fmin", {L"fmin", reinterpret_cast<uintptr_t>(fmin_), true, 0}},
        {L"fminf", {L"fminf", reinterpret_cast<uintptr_t>(fminf_), true, 0}},
        {L"fminl", {L"fminl", reinterpret_cast<uintptr_t>(fminl_), true, 0}},
        {L"fmod", {L"fmod", reinterpret_cast<uintptr_t>(fmod_), true, 0}},
        {L"fmodf", {L"fmodf", reinterpret_cast<uintptr_t>(fmodf_), true, 0}},
        {L"fmodl", {L"fmodl", reinterpret_cast<uintptr_t>(fmodl_), true, 0}},
        {L"frexp", {L"frexp", reinterpret_cast<uintptr_t>(frexp_), true, 0}},
        {L"frexpf", {L"frexpf", reinterpret_cast<uintptr_t>(frexpf_), true, 0}},
        {L"frexpl", {L"frexpl", reinterpret_cast<uintptr_t>(frexpl_), true, 0}},
        {L"hypot", {L"hypot", reinterpret_cast<uintptr_t>(hypot_), true, 0}},
        {L"hypotf", {L"hypotf", reinterpret_cast<uintptr_t>(hypotf_), true, 0}},
        {L"hypotl", {L"hypotl", reinterpret_cast<uintptr_t>(hypotl_), true, 0}},
        {L"ilogb", {L"ilogb", reinterpret_cast<uintptr_t>(ilogb_), true, 0}},
        {L"ilogbf", {L"ilogbf", reinterpret_cast<uintptr_t>(ilogbf_), true, 0}},
        {L"ilogbl", {L"ilogbl", reinterpret_cast<uintptr_t>(ilogbl_), true, 0}},
        {L"ldexp", {L"ldexp", reinterpret_cast<uintptr_t>(ldexp_), true, 0}},
        {L"ldexpf", {L"ldexpf", reinterpret_cast<uintptr_t>(ldexpf_), true, 0}},
        {L"ldexpl", {L"ldexpl", reinterpret_cast<uintptr_t>(ldexpl_), true, 0}},
        {L"lgamma", {L"lgamma", reinterpret_cast<uintptr_t>(lgamma_), true, 0}},
        {L"lgammaf", {L"lgammaf", reinterpret_cast<uintptr_t>(lgammaf_), true, 0}},
        {L"lgammal", {L"lgammal", reinterpret_cast<uintptr_t>(lgammal_), true, 0}},
        {L"rint", {L"rint", reinterpret_cast<uintptr_t>(rint_), true, 0}},
        {L"rintf", {L"rintf", reinterpret_cast<uintptr_t>(rintf_), true, 0}},
        {L"rintl", {L"rintl", reinterpret_cast<uintptr_t>(rintl_), true, 0}},
        {L"lrint", {L"lrint", reinterpret_cast<uintptr_t>(lrint_), true, 0}},
        {L"lrintf", {L"lrintf", reinterpret_cast<uintptr_t>(lrintf_), true, 0}},
        {L"lrintl", {L"lrintl", reinterpret_cast<uintptr_t>(lrintl_), true, 0}},
        {L"llrint", {L"llrint", reinterpret_cast<uintptr_t>(llrint_), true, 0}},
        {L"llrintf", {L"llrintf", reinterpret_cast<uintptr_t>(llrintf_), true, 0}},
        {L"llrintl", {L"llrintl", reinterpret_cast<uintptr_t>(llrintl_), true, 0}},
        {L"round", {L"round", reinterpret_cast<uintptr_t>(round_), true, 0}},
        {L"roundf", {L"roundf", reinterpret_cast<uintptr_t>(roundf_), true, 0}},
        {L"roundl", {L"roundl", reinterpret_cast<uintptr_t>(roundl_), true, 0}},
        {L"lround", {L"lround", reinterpret_cast<uintptr_t>(lround_), true, 0}},
        {L"lroundf", {L"lroundf", reinterpret_cast<uintptr_t>(lroundf_), true, 0}},
        {L"lroundl", {L"lroundl", reinterpret_cast<uintptr_t>(lroundl_), true, 0}},
        {L"llround", {L"llround", reinterpret_cast<uintptr_t>(llround_), true, 0}},
        {L"llroundf", {L"llroundf", reinterpret_cast<uintptr_t>(llroundf_), true, 0}},
        {L"llroundl", {L"llroundl", reinterpret_cast<uintptr_t>(llroundl_), true, 0}},
        {L"log", {L"log", reinterpret_cast<uintptr_t>(log_), true, 0}},
        {L"logf", {L"logf", reinterpret_cast<uintptr_t>(logf_), true, 0}},
        {L"logl", {L"logl", reinterpret_cast<uintptr_t>(logl_), true, 0}},
        {L"log10", {L"log10", reinterpret_cast<uintptr_t>(log10_), true, 0}},
        {L"log10f", {L"log10f", reinterpret_cast<uintptr_t>(log10f_), true, 0}},
        {L"log10l", {L"log10l", reinterpret_cast<uintptr_t>(log10l_), true, 0}},
        {L"log1p", {L"log1p", reinterpret_cast<uintptr_t>(log1p_), true, 0}},
        {L"log1pf", {L"log1pf", reinterpret_cast<uintptr_t>(log1pf_), true, 0}},
        {L"log1pl", {L"log1pl", reinterpret_cast<uintptr_t>(log1pl_), true, 0}},
        {L"log2", {L"log2", reinterpret_cast<uintptr_t>(log2_), true, 0}},
        {L"log2f", {L"log2f", reinterpret_cast<uintptr_t>(log2f_), true, 0}},
        {L"log2l", {L"log2l", reinterpret_cast<uintptr_t>(log2l_), true, 0}},
        {L"logb", {L"logb", reinterpret_cast<uintptr_t>(logb_), true, 0}},
        {L"logbf", {L"logbf", reinterpret_cast<uintptr_t>(logbf_), true, 0}},
        {L"logbl", {L"logbl", reinterpret_cast<uintptr_t>(logbl_), true, 0}},
        {L"modf", {L"modf", reinterpret_cast<uintptr_t>(modf_), true, 0}},
        {L"modff", {L"modff", reinterpret_cast<uintptr_t>(modff_), true, 0}},
        {L"modfl", {L"modfl", reinterpret_cast<uintptr_t>(modfl_), true, 0}},
        {L"nan", {L"nan", reinterpret_cast<uintptr_t>(nan_), true, 0}},
        {L"nanf", {L"nanf", reinterpret_cast<uintptr_t>(nanf_), true, 0}},
        {L"nanl", {L"nanl", reinterpret_cast<uintptr_t>(nanl_), true, 0}},
        {L"nearbyint", {L"nearbyint", reinterpret_cast<uintptr_t>(nearbyint_), true, 0}},
        {L"nearbyintf", {L"nearbyintf", reinterpret_cast<uintptr_t>(nearbyintf_), true, 0}},
        {L"nearbyintl", {L"nearbyintl", reinterpret_cast<uintptr_t>(nearbyintl_), true, 0}},
        {L"nextafter", {L"nextafter", reinterpret_cast<uintptr_t>(nextafter_), true, 0}},
        {L"nextafterf", {L"nextafterf", reinterpret_cast<uintptr_t>(nextafterf_), true, 0}},
        {L"nextafterl", {L"nextafterl", reinterpret_cast<uintptr_t>(nextafterl_), true, 0}},
        {L"nexttoward", {L"nexttoward", reinterpret_cast<uintptr_t>(nexttoward_), true, 0}},
        {L"nexttowardf", {L"nexttowardf", reinterpret_cast<uintptr_t>(nexttowardf_), true, 0}},
        {L"nexttowardl", {L"nexttowardl", reinterpret_cast<uintptr_t>(nexttowardl_), true, 0}},
        {L"pow", {L"pow", reinterpret_cast<uintptr_t>(pow_), true, 0}},
        {L"powf", {L"powf", reinterpret_cast<uintptr_t>(powf_), true, 0}},
        {L"powl", {L"powl", reinterpret_cast<uintptr_t>(powl_), true, 0}},
        {L"remainder", {L"remainder", reinterpret_cast<uintptr_t>(remainder_), true, 0}},
        {L"remainderf", {L"remainderf", reinterpret_cast<uintptr_t>(remainderf_), true, 0}},
        {L"remainderl", {L"remainderl", reinterpret_cast<uintptr_t>(remainderl_), true, 0}},
        {L"remquo", {L"remquo", reinterpret_cast<uintptr_t>(remquo_), true, 0}},
        {L"remquof", {L"remquof", reinterpret_cast<uintptr_t>(remquof_), true, 0}},
        {L"remquol", {L"remquol", reinterpret_cast<uintptr_t>(remquol_), true, 0}},
        {L"scalbln", {L"scalbln", reinterpret_cast<uintptr_t>(scalbln_), true, 0}},
        {L"scalblnf", {L"scalblnf", reinterpret_cast<uintptr_t>(scalblnf_), true, 0}},
        {L"scalblnl", {L"scalblnl", reinterpret_cast<uintptr_t>(scalblnl_), true, 0}},
        {L"scalbn", {L"scalbn", reinterpret_cast<uintptr_t>(scalbn_), true, 0}},
        {L"scalbnf", {L"scalbnf", reinterpret_cast<uintptr_t>(scalbnf_), true, 0}},
        {L"scalbnl", {L"scalbnl", reinterpret_cast<uintptr_t>(scalbnl_), true, 0}},
        {L"cbrt", {L"cbrt", reinterpret_cast<uintptr_t>(cbrt_), true, 0}},
        {L"ceil", {L"ceil", reinterpret_cast<uintptr_t>(ceil_), true, 0}},
        {L"ceilf", {L"ceilf", reinterpret_cast<uintptr_t>(ceilf_), true, 0}},
        {L"ceill", {L"ceill", reinterpret_cast<uintptr_t>(ceill_), true, 0}},
        {L"cbrtf", {L"cbrtf", reinterpret_cast<uintptr_t>(cbrtf_), true, 0}},
        {L"cbrtl", {L"cbrtl", reinterpret_cast<uintptr_t>(cbrtl_), true, 0}},
        {L"copysign", {L"copysign", reinterpret_cast<uintptr_t>(copysign_), true, 0}},
        {L"copysignf", {L"copysignf", reinterpret_cast<uintptr_t>(copysignf_), true, 0}},
        {L"copysignl", {L"copysignl", reinterpret_cast<uintptr_t>(copysignl_), true, 0}},
        {L"cos", {L"cos", reinterpret_cast<uintptr_t>(cos_), true, 0}},
        {L"cosf", {L"cosf", reinterpret_cast<uintptr_t>(cosf_), true, 0}},
        {L"cosl", {L"cosl", reinterpret_cast<uintptr_t>(cosl_), true, 0}},
        {L"cosh", {L"cosh", reinterpret_cast<uintptr_t>(cosh_), true, 0}},
        {L"coshf", {L"coshf", reinterpret_cast<uintptr_t>(coshf_), true, 0}},
        {L"coshl", {L"coshl", reinterpret_cast<uintptr_t>(coshl_), true, 0}},
        {L"sin", {L"sin", reinterpret_cast<uintptr_t>(sin_), true, 0}},
        {L"sinf", {L"sinf", reinterpret_cast<uintptr_t>(sinf_), true, 0}},
        {L"sinl", {L"sinl", reinterpret_cast<uintptr_t>(sinl_), true, 0}},
        {L"sinh", {L"sinh", reinterpret_cast<uintptr_t>(sinh_), true, 0}},
        {L"sinhf", {L"sinhf", reinterpret_cast<uintptr_t>(sinhf_), true, 0}},
        {L"sinhl", {L"sinhl", reinterpret_cast<uintptr_t>(sinhl_), true, 0}},
        {L"tan", {L"tan", reinterpret_cast<uintptr_t>(tan_), true, 0}},
        {L"tanf", {L"tanf", reinterpret_cast<uintptr_t>(tanf_), true, 0}},
        {L"tanl", {L"tanl", reinterpret_cast<uintptr_t>(tanl_), true, 0}},
        {L"tanh", {L"tanh", reinterpret_cast<uintptr_t>(tanh_), true, 0}},
        {L"tanhf", {L"tanhf", reinterpret_cast<uintptr_t>(tanhf_), true, 0}},
        {L"tanhl", {L"tanhl", reinterpret_cast<uintptr_t>(tanhl_), true, 0}},
        {L"sqrt", {L"sqrt", reinterpret_cast<uintptr_t>(sqrt_), true, 0}},
        {L"sqrtf", {L"sqrtf", reinterpret_cast<uintptr_t>(sqrtf_), true, 0}},
        {L"sqrtl", {L"sqrtl", reinterpret_cast<uintptr_t>(sqrtl_), true, 0}},
        {L"tgamma", {L"tgamma", reinterpret_cast<uintptr_t>(tgamma_), true, 0}},
        {L"tgammaf", {L"tgammaf", reinterpret_cast<uintptr_t>(tgammaf_), true, 0}},
        {L"tgammal", {L"tgammal", reinterpret_cast<uintptr_t>(tgammal_), true, 0}},
        {L"trunc", {L"trunc", reinterpret_cast<uintptr_t>(trunc_), true, 0}},
        {L"truncf", {L"truncf", reinterpret_cast<uintptr_t>(truncf_), true, 0}},
        {L"truncl", {L"truncl", reinterpret_cast<uintptr_t>(truncl_), true, 0}},

        // Standard I/O functions
        {L"__acrt_iob_func", {L"__acrt_iob_func", reinterpret_cast<uintptr_t>(__acrt_iob_func), true, 0}},
        {L"__p__commode", {L"__p__commode", reinterpret_cast<uintptr_t>(__p__commode), true, 0}},
        {L"__p__fmode", {L"__p__fmode", reinterpret_cast<uintptr_t>(__p__fmode), true, 0}},
        {L"__stdio_common_vfprintf", {L"__stdio_common_vfprintf", reinterpret_cast<uintptr_t>(__stdio_common_vfprintf), true, 0}},
        {L"__stdio_common_vfprinf_p", {L"__stdio_common_vfprinf_p", reinterpret_cast<uintptr_t>(__stdio_common_vfprinf_p), true, 0}},
        {L"__stdio_common_vfprintf_s", {L"__stdio_common_vfprintf_s", reinterpret_cast<uintptr_t>(__stdio_common_vfprintf_s), true, 0}},
        {L"__stdio_common_vfscanf", {L"__stdio_common_vfscanf", reinterpret_cast<uintptr_t>(__stdio_common_vfscanf), true, 0}},
        {L"__stdio_common_vfwprintf", {L"__stdio_common_vfwprintf", reinterpret_cast<uintptr_t>(__stdio_common_vfwprintf), true, 0}},
        {L"__stdio_common_vfwprintf_p", {L"__stdio_common_vfwprintf_p", reinterpret_cast<uintptr_t>(__stdio_common_vfwprintf_p), true, 0}},
        {L"__stdio_common_vfwprintf_s", {L"__stdio_common_vfwprintf_s", reinterpret_cast<uintptr_t>(__stdio_common_vfwprintf_s), true, 0}},
        {L"__stdio_common_vfwscanf", {L"__stdio_common_vfwscanf", reinterpret_cast<uintptr_t>(__stdio_common_vfwscanf), true, 0}},
        {L"__stdio_common_vsnprintf", {L"__stdio_common_vsnprintf", reinterpret_cast<uintptr_t>(__stdio_common_vsnprintf), true, 0}},
        {L"__stdio_common_vsnprintf_s", {L"__stdio_common_vsnprintf_s", reinterpret_cast<uintptr_t>(__stdio_common_vsnprintf_s), true, 0}},
        {L"__stdio_common_vsnwprintf", {L"__stdio_common_vsnwprintf", reinterpret_cast<uintptr_t>(__stdio_common_vsnwprintf), true, 0}},
        {L"__stdio_common_vsprintf", {L"__stdio_common_vsprintf", reinterpret_cast<uintptr_t>(__stdio_common_vsprintf), true, 0}},
        {L"__stdio_common_vsprintf_p", {L"__stdio_common_vsprintf_p", reinterpret_cast<uintptr_t>(__stdio_common_vsprintf_p), true, 0}},
        {L"__stdio_common_vsprintf_s", {L"__stdio_common_vsprintf_s", reinterpret_cast<uintptr_t>(__stdio_common_vsprintf_s), true, 0}},
        {L"__stdio_common_vsscanf", {L"__stdio_common_vsscanf", reinterpret_cast<uintptr_t>(__stdio_common_vsscanf), true, 0}},
        {L"__stdio_common_vswprintf", {L"__stdio_common_vswprintf", reinterpret_cast<uintptr_t>(__stdio_common_vswprintf), true, 0}},
        {L"__stdio_common_vswscanf", {L"__stdio_common_vswscanf", reinterpret_cast<uintptr_t>(__stdio_common_vswscanf), true, 0}},
        {L"__stdio_common_vswprintf_p", {L"__stdio_common_vswprintf_p", reinterpret_cast<uintptr_t>(__stdio_common_vswprintf_p), true, 0}},
        {L"__stdio_common_vswprintf_s", {L"__stdio_common_vswprintf_s", reinterpret_cast<uintptr_t>(__stdio_common_vswprintf_s), true, 0}},

        // File I/O functions
        {L"_chsize", {L"_chsize", reinterpret_cast<uintptr_t>(_chsize), true, 0}},
        {L"_chsize_s", {L"_chsize_s", reinterpret_cast<uintptr_t>(_chsize_s), true, 0}},
        {L"_close", {L"_close", reinterpret_cast<uintptr_t>(_close), true, 0}},
        {L"_commit", {L"_commit", reinterpret_cast<uintptr_t>(_commit), true, 0}},
        {L"_creat", {L"_creat", reinterpret_cast<uintptr_t>(_creat), true, 0}},
        {L"_wcreat", {L"_wcreat", reinterpret_cast<uintptr_t>(_wcreat), true, 0}},
        {L"_dup", {L"_dup", reinterpret_cast<uintptr_t>(_dup), true, 0}},
        {L"_dup2", {L"_dup2", reinterpret_cast<uintptr_t>(_dup2), true, 0}},
        {L"_eof", {L"_eof", reinterpret_cast<uintptr_t>(_eof), true, 0}},
        {L"_fclose_nolock", {L"_fclose_nolock", reinterpret_cast<uintptr_t>(_fclose_nolock), true, 0}},
        {L"_fcloseall", {L"_fcloseall", reinterpret_cast<uintptr_t>(_fcloseall), true, 0}},
        {L"_fflush_nolock", {L"_fflush_nolock", reinterpret_cast<uintptr_t>(_fflush_nolock), true, 0}},
        {L"_fgetc_nolock", {L"_fgetc_nolock", reinterpret_cast<uintptr_t>(_fgetc_nolock), true, 0}},
        {L"_fgetwc_nolock", {L"_fgetwc_nolock", reinterpret_cast<uintptr_t>(_fgetwc_nolock), true, 0}},
        {L"_fgetchar_nolock", {L"_fgetchar_nolock", reinterpret_cast<uintptr_t>(_fgetchar_nolock), true, 0}},
        {L"_fgetwchar_nolock", {L"_fgetwchar_nolock", reinterpret_cast<uintptr_t>(_fgetwchar_nolock), true, 0}},
        {L"_filelength", {L"_filelength", reinterpret_cast<uintptr_t>(_filelength), true, 0}},
        {L"_filelengthi64", {L"_filelengthi64", reinterpret_cast<uintptr_t>(_filelengthi64), true, 0}},
        {L"_fileno", {L"_fileno", reinterpret_cast<uintptr_t>(_fileno), true, 0}},
        {L"_flushall", {L"_flushall", reinterpret_cast<uintptr_t>(_flushall), true, 0}},
        {L"_fputc_nolock", {L"_fputc_nolock", reinterpret_cast<uintptr_t>(_fputc_nolock), true, 0}},
        {L"_fputwc_nolock", {L"_fputwc_nolock", reinterpret_cast<uintptr_t>(_fputwc_nolock), true, 0}},
        {L"_fputchar", {L"_fputchar", reinterpret_cast<uintptr_t>(_fputchar), true, 0}},
        {L"_fputwchar", {L"_fputwchar", reinterpret_cast<uintptr_t>(_fputwchar), true, 0}},
        {L"_fread_nolock", {L"_fread_nolock", reinterpret_cast<uintptr_t>(_fread_nolock), true, 0}},
        {L"_fread_nolock_s", {L"_fread_nolock_s", reinterpret_cast<uintptr_t>(_fread_nolock_s), true, 0}},
        {L"_fseek_nolock", {L"_fseek_nolock", reinterpret_cast<uintptr_t>(_fseek_nolock), true, 0}},
        {L"_fseeki64", {L"_fseeki64", reinterpret_cast<uintptr_t>(_fseeki64), true, 0}},
        {L"_fseeki64_nolock", {L"_fseeki64_nolock", reinterpret_cast<uintptr_t>(_fseeki64_nolock), true, 0}},
        {L"_fsopen", {L"_fsopen", reinterpret_cast<uintptr_t>(_fsopen), true, 0}},
        {L"_ftell_nolock", {L"_ftell_nolock", reinterpret_cast<uintptr_t>(_ftell_nolock), true, 0}},
        {L"_ftelli64", {L"_ftelli64", reinterpret_cast<uintptr_t>(_ftelli64), true, 0}},
        {L"_ftelli64_nolock", {L"_ftelli64_nolock", reinterpret_cast<uintptr_t>(_ftelli64_nolock), true, 0}},
        {L"_fwrite_nolock", {L"_fwrite_nolock", reinterpret_cast<uintptr_t>(_fwrite_nolock), true, 0}},
        {L"_get_fmode", {L"_get_fmode", reinterpret_cast<uintptr_t>(_get_fmode), true, 0}},
        {L"_get_osfhandle", {L"_get_osfhandle", reinterpret_cast<uintptr_t>(_get_osfhandle), true, 0}},
        {L"_get_printf_count_output", {L"_get_printf_count_output", reinterpret_cast<uintptr_t>(_get_printf_count_output), true, 0}},
        {L"_get_stream_buffer_pointers", {L"_get_stream_buffer_pointers", reinterpret_cast<uintptr_t>(_get_stream_buffer_pointers), true, 0}},
        {L"_getc_nolock", {L"_getc_nolock", reinterpret_cast<uintptr_t>(_getc_nolock), true, 0}},
        {L"_getcwd", {L"_getcwd", reinterpret_cast<uintptr_t>(_getcwd), true, 0}},
        {L"_wgetcwd", {L"_wgetcwd", reinterpret_cast<uintptr_t>(_wgetcwd), true, 0}},
        {L"_getdcwd", {L"_getdcwd", reinterpret_cast<uintptr_t>(_getdcwd), true, 0}},
        {L"_getmaxstdio", {L"_getmaxstdio", reinterpret_cast<uintptr_t>(_getmaxstdio), true, 0}},
        {L"_getw", {L"_getw", reinterpret_cast<uintptr_t>(_getw), true, 0}},
        {L"_getwc_nolock", {L"_getwc_nolock", reinterpret_cast<uintptr_t>(_getwc_nolock), true, 0}},
        {L"_gets", {L"_gets", reinterpret_cast<uintptr_t>(_gets), true, 0}},
        {L"_gets_s", {L"_gets_s", reinterpret_cast<uintptr_t>(_gets_s), true, 0}},
        {L"_getws", {L"_getws", reinterpret_cast<uintptr_t>(_getws), true, 0}},
        {L"_getws_s", {L"_getws_s", reinterpret_cast<uintptr_t>(_getws_s), true, 0}},
        {L"_isatty", {L"_isatty", reinterpret_cast<uintptr_t>(_isatty), true, 0}},
        {L"_kbhit", {L"_kbhit", reinterpret_cast<uintptr_t>(_kbhit), true, 0}},
        {L"_locking", {L"_locking", reinterpret_cast<uintptr_t>(_locking), true, 0}},
        {L"_lseek", {L"_lseek", reinterpret_cast<uintptr_t>(_lseek), true, 0}},
        {L"_lseeki64", {L"_lseeki64", reinterpret_cast<uintptr_t>(_lseeki64), true, 0}},
        {L"_mktemp", {L"_mktemp", reinterpret_cast<uintptr_t>(_mktemp), true, 0}},
        {L"_wmktemp", {L"_wmktemp", reinterpret_cast<uintptr_t>(_wmktemp), true, 0}},
        {L"_mktemp_s", {L"_mktemp_s", reinterpret_cast<uintptr_t>(_mktemp_s), true, 0}},
        {L"_wmktemp_s", {L"_wmktemp_s", reinterpret_cast<uintptr_t>(_wmktemp_s), true, 0}},
        {L"_open", {L"_open", reinterpret_cast<uintptr_t>(_open), true, 0}},
        {L"_wopen", {L"_wopen", reinterpret_cast<uintptr_t>(_wopen), true, 0}},
        {L"_open_osfhandle", {L"_open_osfhandle", reinterpret_cast<uintptr_t>(_open_osfhandle), true, 0}},
        {L"_pclose", {L"_pclose", reinterpret_cast<uintptr_t>(_pclose), true, 0}},
        {L"_pipe", {L"_pipe", reinterpret_cast<uintptr_t>(_pipe), true, 0}},
        {L"_popen", {L"_popen", reinterpret_cast<uintptr_t>(_popen), true, 0}},
        {L"_wpopen", {L"_wpopen", reinterpret_cast<uintptr_t>(_wpopen), true, 0}},
        {L"_putc_nolock", {L"_putc_nolock", reinterpret_cast<uintptr_t>(_putc_nolock), true, 0}},
        {L"_putwc_nolock", {L"_putwc_nolock", reinterpret_cast<uintptr_t>(_putwc_nolock), true, 0}},
        {L"_putw", {L"_putw", reinterpret_cast<uintptr_t>(_putw), true, 0}},
        {L"_putws", {L"_putws", reinterpret_cast<uintptr_t>(_putws), true, 0}},
        {L"_read", {L"_read", reinterpret_cast<uintptr_t>(_read), true, 0}},
        {L"_rmtmp", {L"_rmtmp", reinterpret_cast<uintptr_t>(_rmtmp), true, 0}},
        {L"_set_fmode", {L"_set_fmode", reinterpret_cast<uintptr_t>(set_fmode), true, 0}},
        {L"_set_printf_count_output", {L"_set_printf_count_output", reinterpret_cast<uintptr_t>(_set_printf_count_output), true, 0}},
        {L"_setmaxstdio", {L"_setmaxstdio", reinterpret_cast<uintptr_t>(_setmaxstdio), true, 0}},
        {L"_sopen", {L"_sopen", reinterpret_cast<uintptr_t>(_sopen), true, 0}},
        {L"_wsopen", {L"_wsopen", reinterpret_cast<uintptr_t>(_wsopen), true, 0}},
        {L"_sopen_dispatch", {L"_sopen_dispatch", reinterpret_cast<uintptr_t>(_sopen_dispatch), true, 0}},
        {L"_wsopen_dispatch", {L"_wsopen_dispatch", reinterpret_cast<uintptr_t>(_wsopen_dispatch), true, 0}},
        {L"_sopen_s", {L"_sopen_s", reinterpret_cast<uintptr_t>(_sopen_s), true, 0}},
        {L"_wsopen_s", {L"_wsopen_s", reinterpret_cast<uintptr_t>(_wsopen_s), true, 0}},
        {L"_tell", {L"_tell", reinterpret_cast<uintptr_t>(_tell), true, 0}},
        {L"_telli64", {L"_telli64", reinterpret_cast<uintptr_t>(_telli64), true, 0}},
        {L"_tempnam", {L"_tempnam", reinterpret_cast<uintptr_t>(_tempnam), true, 0}},
        {L"_wtempnam", {L"_wtempnam", reinterpret_cast<uintptr_t>(_wtempnam), true, 0}},
        {L"_ungetc_nolock", {L"_ungetc_nolock", reinterpret_cast<uintptr_t>(_ungetc_nolock), true, 0}},
        {L"_ungetwc_nolock", {L"_ungetwc_nolock", reinterpret_cast<uintptr_t>(_ungetwc_nolock), true, 0}},
        {L"_fdopen", {L"_fdopen", reinterpret_cast<uintptr_t>(_fdopen), true, 0}},
        {L"_wfdopen", {L"_wfdopen", reinterpret_cast<uintptr_t>(_wfdopen), true, 0}},
        {L"_wfopen", {L"_wfopen", reinterpret_cast<uintptr_t>(_wfopen), true, 0}},
        {L"_wfopen_s", {L"_wfopen_s", reinterpret_cast<uintptr_t>(_wfopen_s), true, 0}},
        {L"_wfreopen", {L"_wfreopen", reinterpret_cast<uintptr_t>(_wfreopen), true, 0}},
        {L"_wfreopen_s", {L"_wfreopen_s", reinterpret_cast<uintptr_t>(_wfreopen_s), true, 0}},
        {L"_write", {L"_write", reinterpret_cast<uintptr_t>(_write), true, 0}},
        {L"_tmpnam", {L"_tmpnam", reinterpret_cast<uintptr_t>(_tmpnam), true, 0}},
        {L"_wtmpnam", {L"_wtmpnam", reinterpret_cast<uintptr_t>(_wtmpnam), true, 0}},

        // Standard I/O functions
        {L"clearerr", {L"clearerr", reinterpret_cast<uintptr_t>(clearerr_), true, 0}},
        {L"clearerr_s", {L"clearerr_s", reinterpret_cast<uintptr_t>(clearerr_s), true, 0}},
        {L"fclose", {L"fclose", reinterpret_cast<uintptr_t>(fclose_), true, 0}},
        {L"feof", {L"feof", reinterpret_cast<uintptr_t>(feof_), true, 0}},
        {L"ferror", {L"ferror", reinterpret_cast<uintptr_t>(ferror_), true, 0}},
        {L"fflush", {L"fflush", reinterpret_cast<uintptr_t>(fflush_), true, 0}},
        {L"fgetc", {L"fgetc", reinterpret_cast<uintptr_t>(fgetc_), true, 0}},
        {L"fgetpos", {L"fgetpos", reinterpret_cast<uintptr_t>(fgetpos_), true, 0}},
        {L"fgets", {L"fgets", reinterpret_cast<uintptr_t>(fgets_), true, 0}},
        {L"fgetwc", {L"fgetwc", reinterpret_cast<uintptr_t>(fgetwc_), true, 0}},
        {L"fgetws", {L"fgetws", reinterpret_cast<uintptr_t>(fgetws_), true, 0}},
        {L"fopen", {L"fopen", reinterpret_cast<uintptr_t>(fopen_), true, 0}},
        {L"fopen_s", {L"fopen_s", reinterpret_cast<uintptr_t>(fopen_s), true, 0}},
        {L"fread", {L"fread", reinterpret_cast<uintptr_t>(fread_), true, 0}},
        {L"fread_s", {L"fread_s", reinterpret_cast<uintptr_t>(fread_s), true, 0}},
        {L"fputc", {L"fputc", reinterpret_cast<uintptr_t>(fputc_), true, 0}},
        {L"fputs", {L"fputs", reinterpret_cast<uintptr_t>(fputs_), true, 0}},
        {L"fputwc", {L"fputwc", reinterpret_cast<uintptr_t>(fputwc_), true, 0}},
        {L"fputws", {L"fputws", reinterpret_cast<uintptr_t>(fputws_), true, 0}},
        {L"freopen", {L"freopen", reinterpret_cast<uintptr_t>(freopen_), true, 0}},
        {L"freopen_s", {L"freopen_s", reinterpret_cast<uintptr_t>(freopen_s), true, 0}},
        {L"fseek", {L"fseek", reinterpret_cast<uintptr_t>(fseek_), true, 0}},
        {L"fsetpos", {L"fsetpos", reinterpret_cast<uintptr_t>(fsetpos_), true, 0}},
        {L"ftell", {L"ftell", reinterpret_cast<uintptr_t>(ftell_), true, 0}},
        {L"ftelli64", {L"ftelli64", reinterpret_cast<uintptr_t>(ftelli64), true, 0}},
        {L"fwrite", {L"fwrite", reinterpret_cast<uintptr_t>(fwrite_), true, 0}},
        {L"getc", {L"getc", reinterpret_cast<uintptr_t>(getc_), true, 0}},
        {L"getchar", {L"getchar", reinterpret_cast<uintptr_t>(getchar_), true, 0}},
        {L"gets", {L"gets", reinterpret_cast<uintptr_t>(gets_), true, 0}},
        {L"gets_s", {L"gets_s", reinterpret_cast<uintptr_t>(gets_s), true, 0}},
        {L"getwc", {L"getwc", reinterpret_cast<uintptr_t>(getwc_), true, 0}},
        {L"getwchar", {L"getwchar", reinterpret_cast<uintptr_t>(getwchar_), true, 0}},
        {L"putc", {L"putc", reinterpret_cast<uintptr_t>(putc_), true, 0}},
        {L"putchar", {L"putchar", reinterpret_cast<uintptr_t>(putchar_), true, 0}},
        {L"puts", {L"puts", reinterpret_cast<uintptr_t>(puts_), true, 0}},
        {L"putwc", {L"putwc", reinterpret_cast<uintptr_t>(putwc_), true, 0}},
        {L"putwchar", {L"putwchar", reinterpret_cast<uintptr_t>(putwchar_), true, 0}},
        {L"rewind", {L"rewind", reinterpret_cast<uintptr_t>(rewind_), true, 0}},
        {L"setbuf", {L"setbuf", reinterpret_cast<uintptr_t>(setbuf_), true, 0}},
        {L"setvbuf", {L"setvbuf", reinterpret_cast<uintptr_t>(setvbuf_), true, 0}},
        {L"tmpfile", {L"tmpfile", reinterpret_cast<uintptr_t>(tmpfile_), true, 0}},
        {L"tmpfile_s", {L"tmpfile_s", reinterpret_cast<uintptr_t>(tmpfile_s), true, 0}},
        {L"tmpnam", {L"tmpnam", reinterpret_cast<uintptr_t>(tmpnam_), true, 0}},
        {L"tmpnam_s", {L"tmpnam_s", reinterpret_cast<uintptr_t>(tmpnam_s), true, 0}},
        {L"ungetc", {L"ungetc", reinterpret_cast<uintptr_t>(ungetc_), true, 0}},
        {L"ungetwc", {L"ungetwc", reinterpret_cast<uintptr_t>(ungetwc_), true, 0}},
        {L"___lc_codepage_func", {L"___lc_codepage_func", reinterpret_cast<uintptr_t>(___lc_codepage_func), true, 0}},
        // Locale functions (continuing from where the code left off)
        {L"___lc_collate_cp_func", {L"___lc_collate_cp_func", reinterpret_cast<uintptr_t>(___lc_collate_cp_func), true, 0}},
        {L"___lc_locale_name_func", {L"___lc_locale_name_func", reinterpret_cast<uintptr_t>(___lc_locale_name_func), true, 0}},
        {L"___mb_cur_max_func", {L"___mb_cur_max_func", reinterpret_cast<uintptr_t>(___mb_cur_max_func), true, 0}},
        {L"___mb_cur_max_l_func", {L"___mb_cur_max_l_func", reinterpret_cast<uintptr_t>(___mb_cur_max_l_func), true, 0}},
        {L"__initialize_lconv_for_unsigned_char", {L"__initialize_lconv_for_unsigned_char", reinterpret_cast<uintptr_t>(__initialize_lconv_for_unsigned_char), true, 0}},
        {L"___pctype_func", {L"___pctype_func", reinterpret_cast<uintptr_t>(___pctype_func), true, 0}},
        {L"__pwctype_func", {L"__pwctype_func", reinterpret_cast<uintptr_t>(__pwctype_func), true, 0}},
        {L"_configthreadlocale", {L"_configthreadlocale", reinterpret_cast<uintptr_t>(_configthreadlocale), true, 0}},
        {L"_create_locale", {L"_create_locale", reinterpret_cast<uintptr_t>(_create_locale), true, 0}},
        {L"_wcreate_locale", {L"_wcreate_locale", reinterpret_cast<uintptr_t>(_wcreate_locale), true, 0}},
        {L"_free_locale", {L"_free_locale", reinterpret_cast<uintptr_t>(_free_locale), true, 0}},
        {L"_get_current_locale", {L"_get_current_locale", reinterpret_cast<uintptr_t>(_get_current_locale), true, 0}},
        {L"_getmbcp", {L"_getmbcp", reinterpret_cast<uintptr_t>(_getmbcp), true, 0}},
        {L"_lock_locales", {L"_lock_locales", reinterpret_cast<uintptr_t>(_lock_locales), true, 0}},
        {L"_unlock_locales", {L"_unlock_locales", reinterpret_cast<uintptr_t>(_unlock_locales), true, 0}},
        {L"_setmbcp", {L"_setmbcp", reinterpret_cast<uintptr_t>(_setmbcp), true, 0}},
        {L"setlocale", {L"setlocale", reinterpret_cast<uintptr_t>(setlocale_), true, 0}},
        {L"_wsetlocale", {L"_wsetlocale", reinterpret_cast<uintptr_t>(_wsetlocale), true, 0}},
        {L"localeconv", {L"localeconv", reinterpret_cast<uintptr_t>(localeconv_), true, 0}},

        // Memory management functions
        {L"_aligned_free", {L"_aligned_free", reinterpret_cast<uintptr_t>(_aligned_free), true, 0}},
        {L"_aligned_malloc", {L"_aligned_malloc", reinterpret_cast<uintptr_t>(_aligned_malloc), true, 0}},
        {L"_aligned_calloc", {L"_aligned_calloc", reinterpret_cast<uintptr_t>(_aligned_calloc), true, 0}},
        {L"_aligned_realloc", {L"_aligned_realloc", reinterpret_cast<uintptr_t>(_aligned_realloc), true, 0}},
        {L"_aligned_recalloc", {L"_aligned_recalloc", reinterpret_cast<uintptr_t>(_aligned_recalloc), true, 0}},
        {L"_aligned_msize", {L"_aligned_msize", reinterpret_cast<uintptr_t>(_aligned_msize), true, 0}},
        {L"_aligned_offset_malloc", {L"_aligned_offset_malloc", reinterpret_cast<uintptr_t>(_aligned_offset_malloc), true, 0}},
        {L"_aligned_offset_realloc", {L"_aligned_offset_realloc", reinterpret_cast<uintptr_t>(_aligned_offset_realloc), true, 0}},
        {L"_aligned_offset_recalloc", {L"_aligned_offset_recalloc", reinterpret_cast<uintptr_t>(_aligned_offset_recalloc), true, 0}},
        {L"_callnewh", {L"_callnewh", reinterpret_cast<uintptr_t>(_callnewh), true, 0}},
        {L"_calloc_base", {L"_calloc_base", reinterpret_cast<uintptr_t>(_calloc_base), true, 0}},
        {L"_expand", {L"_expand", reinterpret_cast<uintptr_t>(_expand), true, 0}},
        {L"_free_base", {L"_free_base", reinterpret_cast<uintptr_t>(_free_base), true, 0}},
        {L"_get_heap_handle", {L"_get_heap_handle", reinterpret_cast<uintptr_t>(_get_heap_handle), true, 0}},
        {L"_heapchk", {L"_heapchk", reinterpret_cast<uintptr_t>(_heapchk), true, 0}},
        {L"_heapmin", {L"_heapmin", reinterpret_cast<uintptr_t>(_heapmin), true, 0}},
        {L"_heapwalk", {L"_heapwalk", reinterpret_cast<uintptr_t>(_heapwalk), true, 0}},
        {L"_malloc_base", {L"_malloc_base", reinterpret_cast<uintptr_t>(_malloc_base), true, 0}},
        {L"_msize", {L"_msize", reinterpret_cast<uintptr_t>(_msize), true, 0}},
        {L"_query_new_handler", {L"_query_new_handler", reinterpret_cast<uintptr_t>(_query_new_handler), true, 0}},
        {L"_query_new_mode", {L"_query_new_mode", reinterpret_cast<uintptr_t>(_query_new_mode), true, 0}},
        {L"_set_new_mode", {L"_set_new_mode", reinterpret_cast<uintptr_t>(_set_new_mode), true, 0}},
        {L"_realloc_base", {L"_realloc_base", reinterpret_cast<uintptr_t>(_realloc_base), true, 0}},
        {L"_recalloc", {L"_recalloc", reinterpret_cast<uintptr_t>(_recalloc), true, 0}},
        {L"calloc", {L"calloc", reinterpret_cast<uintptr_t>(calloc), true, 0}},
        {L"free", {L"free", reinterpret_cast<uintptr_t>(free), true, 0}},
        {L"malloc", {L"malloc", reinterpret_cast<uintptr_t>(malloc), true, 0}},
        {L"realloc", {L"realloc", reinterpret_cast<uintptr_t>(realloc), true, 0}},

        // Wide character string functions
        {L"wcslen", {L"wcslen", reinterpret_cast<uintptr_t>(wcslen_), true, 0}},
        {L"wcscpy", {L"wcscpy", reinterpret_cast<uintptr_t>(wcscpy_), true, 0}},

        // Character classification and conversion
        {L"__isascii", {L"__isascii", reinterpret_cast<uintptr_t>(__isascii_), true, 0}},
        {L"iswascii", {L"iswascii", reinterpret_cast<uintptr_t>(iswascii), true, 0}},
        {L"__iscsym", {L"__iscsym", reinterpret_cast<uintptr_t>(__iscsym), true, 0}},
        {L"__iscsymf", {L"__iscsymf", reinterpret_cast<uintptr_t>(__iscsymf), true, 0}},
        {L"__iswcsym", {L"__iswcsym", reinterpret_cast<uintptr_t>(__iswcsym), true, 0}},
        {L"__iswcsymf", {L"__iswcsymf", reinterpret_cast<uintptr_t>(__iswcsymf), true, 0}},
        {L"__strncnt", {L"__strncnt", reinterpret_cast<uintptr_t>(__strncnt), true, 0}},
        {L"__wcsncnt", {L"__wcsncnt", reinterpret_cast<uintptr_t>(__wcsncnt), true, 0}},
        {L"_isalnum_l", {L"_isalnum_l", reinterpret_cast<uintptr_t>(_isalnum_l), true, 0}},
        {L"_isalpha_l", {L"_isalpha_l", reinterpret_cast<uintptr_t>(_isalpha_l), true, 0}},
        {L"_isblank_l", {L"_isblank_l", reinterpret_cast<uintptr_t>(_isblank_l), true, 0}},
        {L"_iscntrl_l", {L"_iscntrl_l", reinterpret_cast<uintptr_t>(_iscntrl_l), true, 0}},
        {L"_isctype_l", {L"_isctype_l", reinterpret_cast<uintptr_t>(_isctype_l), true, 0}},
        {L"_isctype", {L"_isctype", reinterpret_cast<uintptr_t>(_isctype), true, 0}},
        {L"_isdigit_l", {L"_isdigit_l", reinterpret_cast<uintptr_t>(_isdigit_l), true, 0}},
        {L"_isgraph_l", {L"_isgraph_l", reinterpret_cast<uintptr_t>(_isgraph_l), true, 0}},
        {L"_isleadbyte_l", {L"_isleadbyte_l", reinterpret_cast<uintptr_t>(_isleadbyte_l), true, 0}},
        {L"_islower_l", {L"_islower_l", reinterpret_cast<uintptr_t>(_islower_l), true, 0}},
        {L"_isprint_l", {L"_isprint_l", reinterpret_cast<uintptr_t>(_isprint_l), true, 0}},
        {L"_ispunct_l", {L"_ispunct_l", reinterpret_cast<uintptr_t>(_ispunct_l), true, 0}},
        {L"_isspace_l", {L"_isspace_l", reinterpret_cast<uintptr_t>(_isspace_l), true, 0}},
        {L"_isxdigit_l", {L"_isxdigit_l", reinterpret_cast<uintptr_t>(_isxdigit_l), true, 0}},
        {L"_isupper_l", {L"_isupper_l", reinterpret_cast<uintptr_t>(_isupper_l), true, 0}},
        {L"_iswalnum_l", {L"_iswalnum_l", reinterpret_cast<uintptr_t>(_iswalnum_l), true, 0}},
        {L"_iswalpha_l", {L"_iswalpha_l", reinterpret_cast<uintptr_t>(_iswalpha_l), true, 0}},
        {L"_iswblank_l", {L"_iswblank_l", reinterpret_cast<uintptr_t>(_iswblank_l), true, 0}},
        {L"_iswcntrl_l", {L"_iswcntrl_l", reinterpret_cast<uintptr_t>(_iswcntrl_l), true, 0}},
        {L"_iswcsymf_l", {L"_iswcsymf_l", reinterpret_cast<uintptr_t>(_iswcsymf_l), true, 0}},
        {L"_iswctype_l", {L"_iswctype_l", reinterpret_cast<uintptr_t>(_iswctype_l), true, 0}},
        {L"_iswdigit_l", {L"_iswdigit_l", reinterpret_cast<uintptr_t>(_iswdigit_l), true, 0}},
        {L"_iswgraph_l", {L"_iswgraph_l", reinterpret_cast<uintptr_t>(_iswgraph_l), true, 0}},
        {L"_iswlower_l", {L"_iswlower_l", reinterpret_cast<uintptr_t>(_iswlower_l), true, 0}},
        {L"_iswprint_l", {L"_iswprint_l", reinterpret_cast<uintptr_t>(_iswprint_l), true, 0}},
        {L"_iswpunct_l", {L"_iswpunct_l", reinterpret_cast<uintptr_t>(_iswpunct_l), true, 0}},
        {L"_iswspace_l", {L"_iswspace_l", reinterpret_cast<uintptr_t>(_iswspace_l), true, 0}},
        {L"_iswxdigit_l", {L"_iswxdigit_l", reinterpret_cast<uintptr_t>(_iswxdigit_l), true, 0}},

        // Extended string functions
        {L"_memccpy", {L"_memccpy", reinterpret_cast<uintptr_t>(_memccpy), true, 0}},
        {L"_memicmp", {L"_memicmp", reinterpret_cast<uintptr_t>(_memicmp), true, 0}},
        {L"_memicmp_l", {L"_memicmp_l", reinterpret_cast<uintptr_t>(_memicmp_l), true, 0}},
        {L"_strcoll_l", {L"_strcoll_l", reinterpret_cast<uintptr_t>(_strcoll_l), true, 0}},
        {L"_mbscoll", {L"_mbscoll", reinterpret_cast<uintptr_t>(_mbscoll), true, 0}},
        {L"_mbscoll_l", {L"_mbscoll_l", reinterpret_cast<uintptr_t>(_mbscoll_l), true, 0}},
        {L"_wcscoll", {L"_wcscoll", reinterpret_cast<uintptr_t>(_wcscoll), true, 0}},
        {L"_wcscoll_l", {L"_wcscoll_l", reinterpret_cast<uintptr_t>(_wcscoll_l), true, 0}},
        {L"_stricoll", {L"_stricoll", reinterpret_cast<uintptr_t>(_stricoll), true, 0}},
        {L"_stricoll_l", {L"_stricoll_l", reinterpret_cast<uintptr_t>(_stricoll_l), true, 0}},
        {L"_wcsicoll", {L"_wcsicoll", reinterpret_cast<uintptr_t>(_wcsicoll), true, 0}},
        {L"_wcsicoll_l", {L"_wcsicoll_l", reinterpret_cast<uintptr_t>(_wcsicoll_l), true, 0}},
        {L"_mbsicoll", {L"_mbsicoll", reinterpret_cast<uintptr_t>(_mbsicoll), true, 0}},
        {L"_mbsicoll_l", {L"_mbsicoll_l", reinterpret_cast<uintptr_t>(_mbsicoll_l), true, 0}},
        {L"_strdup", {L"_strdup", reinterpret_cast<uintptr_t>(_strdup), true, 0}},
        {L"_wcsdup", {L"_wcsdup", reinterpret_cast<uintptr_t>(_wcsdup), true, 0}},
        {L"_mbsdup", {L"_mbsdup", reinterpret_cast<uintptr_t>(_mbsdup), true, 0}},
        {L"_stricmp", {L"_stricmp", reinterpret_cast<uintptr_t>(_stricmp), true, 0}},
        {L"_stricmp_l", {L"_stricmp_l", reinterpret_cast<uintptr_t>(_stricmp_l), true, 0}},
        {L"_wcsicmp", {L"_wcsicmp", reinterpret_cast<uintptr_t>(_wcsicmp), true, 0}},
        {L"_wcsicmp_l", {L"_wcsicmp_l", reinterpret_cast<uintptr_t>(_wcsicmp_l), true, 0}},
        {L"_mbsicmp", {L"_mbsicmp", reinterpret_cast<uintptr_t>(_mbsicmp), true, 0}},
        {L"_mbsicmp_l", {L"_mbsicmp_l", reinterpret_cast<uintptr_t>(_mbsicmp_l), true, 0}},
        {L"_strlwr", {L"_strlwr", reinterpret_cast<uintptr_t>(_strlwr), true, 0}},
        {L"_strlwr_l", {L"_strlwr_l", reinterpret_cast<uintptr_t>(_strlwr_l), true, 0}},
        {L"_strlwr_s", {L"_strlwr_s", reinterpret_cast<uintptr_t>(_strlwr_s), true, 0}},
        {L"_strlwr_s_l", {L"_strlwr_s_l", reinterpret_cast<uintptr_t>(_strlwr_s_l), true, 0}},
        {L"_wcslwr", {L"_wcslwr", reinterpret_cast<uintptr_t>(_wcslwr), true, 0}},
        {L"_wcslwr_l", {L"_wcslwr_l", reinterpret_cast<uintptr_t>(_wcslwr_l), true, 0}},
        {L"_wcslwr_s", {L"_wcslwr_s", reinterpret_cast<uintptr_t>(_wcslwr_s), true, 0}},
        {L"_wcslwr_s_l", {L"_wcslwr_s_l", reinterpret_cast<uintptr_t>(_wcslwr_s_l), true, 0}},
        {L"_mbslwr", {L"_mbslwr", reinterpret_cast<uintptr_t>(_mbslwr), true, 0}},
        {L"_mbslwr_l", {L"_mbslwr_l", reinterpret_cast<uintptr_t>(_mbslwr_l), true, 0}},
        {L"_mbslwr_s", {L"_mbslwr_s", reinterpret_cast<uintptr_t>(_mbslwr_s), true, 0}},
        {L"_mbslwr_s_l", {L"_mbslwr_s_l", reinterpret_cast<uintptr_t>(_mbslwr_s_l), true, 0}},
        {L"wcscmp", {L"wcscmp", reinterpret_cast<uintptr_t>(wcscmp_), true, 0}},
        {L"_mbscmp", {L"_mbscmp", reinterpret_cast<uintptr_t>(_mbscmp), true, 0}},
        {L"_mbscmp_l", {L"_mbscmp_l", reinterpret_cast<uintptr_t>(_mbscmp_l), true, 0}},
        {L"_strncoll", {L"_strncoll", reinterpret_cast<uintptr_t>(_strncoll), true, 0}},
        {L"_strncoll_l", {L"_strncoll_l", reinterpret_cast<uintptr_t>(_strncoll_l), true, 0}},
        {L"_wcsncoll", {L"_wcsncoll", reinterpret_cast<uintptr_t>(_wcsncoll), true, 0}},
        {L"_wcsncoll_l", {L"_wcsncoll_l", reinterpret_cast<uintptr_t>(_wcsncoll_l), true, 0}},
        {L"_mbsncoll", {L"_mbsncoll", reinterpret_cast<uintptr_t>(_mbsncoll), true, 0}},
        {L"_mbsncoll_l", {L"_mbsncoll_l", reinterpret_cast<uintptr_t>(_mbsncoll_l), true, 0}},
        {L"_strnicoll", {L"_strnicoll", reinterpret_cast<uintptr_t>(_strnicoll), true, 0}},
        {L"_strnicoll_l", {L"_strnicoll_l", reinterpret_cast<uintptr_t>(_strnicoll_l), true, 0}},
        {L"_wcsnicoll", {L"_wcsnicoll", reinterpret_cast<uintptr_t>(_wcsnicoll), true, 0}},
        {L"_wcsnicoll_l", {L"_wcsnicoll_l", reinterpret_cast<uintptr_t>(_wcsnicoll_l), true, 0}},
        {L"_mbsnicoll", {L"_mbsnicoll", reinterpret_cast<uintptr_t>(_mbsnicoll), true, 0}},
        {L"_mbsnicoll_l", {L"_mbsnicoll_l", reinterpret_cast<uintptr_t>(_mbsnicoll_l), true, 0}},
        {L"_strnset", {L"_strnset", reinterpret_cast<uintptr_t>(_strnset), true, 0}},
        {L"_strnset_l", {L"_strnset_l", reinterpret_cast<uintptr_t>(_strnset_l), true, 0}},
        {L"_strnset_s", {L"_strnset_s", reinterpret_cast<uintptr_t>(_strnset_s), true, 0}},
        {L"_strnset_s_l", {L"_strnset_s_l", reinterpret_cast<uintptr_t>(_strnset_s_l), true, 0}},
        {L"_wcsnset", {L"_wcsnset", reinterpret_cast<uintptr_t>(_wcsnset), true, 0}},
        {L"_wcsnset_l", {L"_wcsnset_l", reinterpret_cast<uintptr_t>(_wcsnset_l), true, 0}},
        {L"_wcsnset_s", {L"_wcsnset_s", reinterpret_cast<uintptr_t>(_wcsnset_s), true, 0}},
        {L"_wcsnset_s_l", {L"_wcsnset_s_l", reinterpret_cast<uintptr_t>(_wcsnset_s_l), true, 0}},
        {L"_mbsnset", {L"_mbsnset", reinterpret_cast<uintptr_t>(_mbsnset), true, 0}},
        {L"_mbsnset_l", {L"_mbsnset_l", reinterpret_cast<uintptr_t>(_mbsnset_l), true, 0}},
        {L"_mbsnset_s", {L"_mbsnset_s", reinterpret_cast<uintptr_t>(_mbsnset_s), true, 0}},
        {L"_mbsnset_s_l", {L"_mbsnset_s_l", reinterpret_cast<uintptr_t>(_mbsnset_s_l), true, 0}},
        {L"_strset", {L"_strset", reinterpret_cast<uintptr_t>(_strset), true, 0}},
        {L"_strset_l", {L"_strset_l", reinterpret_cast<uintptr_t>(_strset_l), true, 0}},
        {L"_strset_s", {L"_strset_s", reinterpret_cast<uintptr_t>(_strset_s), true, 0}},
        {L"_strset_s_l", {L"_strset_s_l", reinterpret_cast<uintptr_t>(_strset_s_l), true, 0}},
        {L"_wcsset", {L"_wcsset", reinterpret_cast<uintptr_t>(_wcsset), true, 0}},
        {L"_wcsset_l", {L"_wcsset_l", reinterpret_cast<uintptr_t>(_wcsset_l), true, 0}},
        {L"_wcsset_s", {L"_wcsset_s", reinterpret_cast<uintptr_t>(_wcsset_s), true, 0}},
        {L"_wcsset_s_l", {L"_wcsset_s_l", reinterpret_cast<uintptr_t>(_wcsset_s_l), true, 0}},
        {L"_mbsset", {L"_mbsset", reinterpret_cast<uintptr_t>(_mbsset), true, 0}},
        {L"_mbsset_l", {L"_mbsset_l", reinterpret_cast<uintptr_t>(_mbsset_l), true, 0}},
        {L"_mbsset_s", {L"_mbsset_s", reinterpret_cast<uintptr_t>(_mbsset_s), true, 0}},
        {L"_mbsset_s_l", {L"_mbsset_s_l", reinterpret_cast<uintptr_t>(_mbsset_s_l), true, 0}},
        {L"_strrev", {L"_strrev", reinterpret_cast<uintptr_t>(_strrev), true, 0}},
        {L"_wcsrev", {L"_wcsrev", reinterpret_cast<uintptr_t>(_wcsrev), true, 0}},
        {L"_mbsrev", {L"_mbsrev", reinterpret_cast<uintptr_t>(_mbsrev), true, 0}},
        {L"_mbsrev_l", {L"_mbsrev_l", reinterpret_cast<uintptr_t>(_mbsrev_l), true, 0}},
        {L"_strupr", {L"_strupr", reinterpret_cast<uintptr_t>(_strupr), true, 0}},
        {L"_strupr_l", {L"_strupr_l", reinterpret_cast<uintptr_t>(_strupr_l), true, 0}},
        {L"_strupr_s", {L"_strupr_s", reinterpret_cast<uintptr_t>(_strupr_s), true, 0}},
        {L"_strupr_s_l", {L"_strupr_s_l", reinterpret_cast<uintptr_t>(_strupr_s_l), true, 0}},
        {L"_wcsupr", {L"_wcsupr", reinterpret_cast<uintptr_t>(_wcsupr), true, 0}},
        {L"_wcsupr_l", {L"_wcsupr_l", reinterpret_cast<uintptr_t>(_wcsupr_l), true, 0}},
        {L"_wcsupr_s", {L"_wcsupr_s", reinterpret_cast<uintptr_t>(_wcsupr_s), true, 0}},
        {L"_wcsupr_s_l", {L"_wcsupr_s_l", reinterpret_cast<uintptr_t>(_wcsupr_s_l), true, 0}},
        {L"strxfrm", {L"strxfrm", reinterpret_cast<uintptr_t>(strxfrm), true, 0}},
        {L"_strxfrm_l", {L"_strxfrm_l", reinterpret_cast<uintptr_t>(_strxfrm_l), true, 0}},
        {L"wcsxfrm", {L"wcsxfrm", reinterpret_cast<uintptr_t>(wcsxfrm), true, 0}},
        {L"_wcsxfrm_l", {L"_wcsxfrm_l", reinterpret_cast<uintptr_t>(_wcsxfrm_l), true, 0}},
        {L"_tolower", {L"_tolower", reinterpret_cast<uintptr_t>(_tolower), true, 0}},
        {L"_tolower_l", {L"_tolower_l", reinterpret_cast<uintptr_t>(_tolower_l), true, 0}},
        {L"_toupper", {L"_toupper", reinterpret_cast<uintptr_t>(_toupper), true, 0}},
        {L"_toupper_l", {L"_toupper_l", reinterpret_cast<uintptr_t>(_toupper_l), true, 0}},
        {L"towlower", {L"towlower", reinterpret_cast<uintptr_t>(towlower_), true, 0}},
        {L"_towlower_l", {L"_towlower_l", reinterpret_cast<uintptr_t>(_towlower_l), true, 0}},
        {L"towupper", {L"towupper", reinterpret_cast<uintptr_t>(towupper_), true, 0}},
        {L"_towupper_l", {L"_towupper_l", reinterpret_cast<uintptr_t>(_towupper_l), true, 0}},

        // Character type functions
        {L"is_ctype", {L"is_ctype", reinterpret_cast<uintptr_t>(is_ctype), true, 0}},
        {L"is_wctype", {L"is_wctype", reinterpret_cast<uintptr_t>(is_wctype), true, 0}},
        {L"isalpha", {L"isalpha", reinterpret_cast<uintptr_t>(isalpha_), true, 0}},
        {L"isblank", {L"isblank", reinterpret_cast<uintptr_t>(isblank_), true, 0}},
        {L"iscntrl", {L"iscntrl", reinterpret_cast<uintptr_t>(iscntrl_), true, 0}},
        {L"isdigit", {L"isdigit", reinterpret_cast<uintptr_t>(isdigit_), true, 0}},
        {L"isgraph", {L"isgraph", reinterpret_cast<uintptr_t>(isgraph_), true, 0}},
        {L"isleadbyte", {L"isleadbyte", reinterpret_cast<uintptr_t>(isleadbyte_), true, 0}},
        {L"islower", {L"islower", reinterpret_cast<uintptr_t>(islower_), true, 0}},
        {L"isprint", {L"isprint", reinterpret_cast<uintptr_t>(isprint_), true, 0}},
        {L"ispunct", {L"ispunct", reinterpret_cast<uintptr_t>(ispunct_), true, 0}},
        {L"isspace", {L"isspace", reinterpret_cast<uintptr_t>(isspace_), true, 0}},
        {L"isupper", {L"isupper", reinterpret_cast<uintptr_t>(isupper_), true, 0}},
        {L"isxdigit", {L"isxdigit", reinterpret_cast<uintptr_t>(isxdigit_), true, 0}},
        {L"iswalnum", {L"iswalnum", reinterpret_cast<uintptr_t>(iswalnum_), true, 0}},
        {L"iswalpha", {L"iswalpha", reinterpret_cast<uintptr_t>(iswalpha_), true, 0}},
        {L"iswblank", {L"iswblank", reinterpret_cast<uintptr_t>(iswblank_), true, 0}},
        {L"iswcntrl", {L"iswcntrl", reinterpret_cast<uintptr_t>(iswcntrl_), true, 0}},
        {L"iswctype", {L"iswctype", reinterpret_cast<uintptr_t>(iswctype_), true, 0}},
        {L"iswdigit", {L"iswdigit", reinterpret_cast<uintptr_t>(iswdigit_), true, 0}},
        {L"iswgraph", {L"iswgraph", reinterpret_cast<uintptr_t>(iswgraph_), true, 0}},
        {L"iswlower", {L"iswlower", reinterpret_cast<uintptr_t>(iswlower_), true, 0}},
        {L"iswprint", {L"iswprint", reinterpret_cast<uintptr_t>(iswprint_), true, 0}},
        {L"iswpunct", {L"iswpunct", reinterpret_cast<uintptr_t>(iswpunct_), true, 0}},
        {L"iswspace", {L"iswspace", reinterpret_cast<uintptr_t>(iswspace_), true, 0}},
        {L"iswupper", {L"iswupper", reinterpret_cast<uintptr_t>(iswupper_), true, 0}},
        {L"iswxdigit", {L"iswxdigit", reinterpret_cast<uintptr_t>(iswxdigit_), true, 0}},

        // Multibyte character functions
        {L"mblen", {L"mblen", reinterpret_cast<uintptr_t>(mblen_), true, 0}},
        {L"mbrlen", {L"mbrlen", reinterpret_cast<uintptr_t>(mbrlen_), true, 0}},

        // Secure string functions
        {L"memcpy_s", {L"memcpy_s", reinterpret_cast<uintptr_t>(memcpy_s), true, 0}},
        {L"memmove_s", {L"memmove_s", reinterpret_cast<uintptr_t>(memmove_s), true, 0}},
        {L"strcat_s", {L"strcat_s", reinterpret_cast<uintptr_t>(strcat_s), true, 0}},
        {L"wcscat", {L"wcscat", reinterpret_cast<uintptr_t>(wcscat_), true, 0}},
        {L"wcscat_s", {L"wcscat_s", reinterpret_cast<uintptr_t>(wcscat_s), true, 0}},
        {L"_mbscat_s", {L"_mbscat_s", reinterpret_cast<uintptr_t>(_mbscat_s), true, 0}},
        {L"_mbscat_s_l", {L"_mbscat_s_l", reinterpret_cast<uintptr_t>(_mbscat_s_l), true, 0}},
        {L"strcoll", {L"strcoll", reinterpret_cast<uintptr_t>(strcoll_), true, 0}},
        {L"wcscoll", {L"wcscoll", reinterpret_cast<uintptr_t>(wcscoll_), true, 0}},
        {L"_mbscpy", {L"_mbscpy", reinterpret_cast<uintptr_t>(_mbscpy), true, 0}},
        {L"strcspn", {L"strcspn", reinterpret_cast<uintptr_t>(strcspn_), true, 0}},
        {L"wcscspn", {L"wcscspn", reinterpret_cast<uintptr_t>(wcscspn_), true, 0}},
        {L"_mbscspn", {L"_mbscspn", reinterpret_cast<uintptr_t>(_mbscspn), true, 0}},
        {L"_mbscspn_l", {L"_mbscspn_l", reinterpret_cast<uintptr_t>(_mbscspn_l), true, 0}},
        {L"_mbslen", {L"_mbslen", reinterpret_cast<uintptr_t>(_mbslen), true, 0}},
        {L"_mbslen_l", {L"_mbslen_l", reinterpret_cast<uintptr_t>(_mbslen_l), true, 0}},
        {L"_mbstrlen", {L"_mbstrlen", reinterpret_cast<uintptr_t>(_mbstrlen), true, 0}},
        {L"_mbstrlen_l", {L"_mbstrlen_l", reinterpret_cast<uintptr_t>(_mbstrlen_l), true, 0}},
        {L"wcsncat", {L"wcsncat", reinterpret_cast<uintptr_t>(wcsncat_), true, 0}},
        {L"wcsncat_s", {L"wcsncat_s", reinterpret_cast<uintptr_t>(wcsncat_s), true, 0}},
        {L"_mbsncat", {L"_mbsncat", reinterpret_cast<uintptr_t>(_mbsncat), true, 0}},
        {L"_mbsncat_l", {L"_mbsncat_l", reinterpret_cast<uintptr_t>(_mbsncat_l), true, 0}},
        {L"_mbsncat_s", {L"_mbsncat_s", reinterpret_cast<uintptr_t>(_mbsncat_s), true, 0}},
        {L"_mbsncat_s_l", {L"_mbsncat_s_l", reinterpret_cast<uintptr_t>(_mbsncat_s_l), true, 0}},
        {L"strcpy_s", {L"strcpy_s", reinterpret_cast<uintptr_t>(strcpy_s), true, 0}},
        {L"wcscpy_s", {L"wcscpy_s", reinterpret_cast<uintptr_t>(wcscpy_s), true, 0}},
        {L"_strncpy_l", {L"_strncpy_l", reinterpret_cast<uintptr_t>(_strncpy_l), true, 0}},
        {L"wcsncpy", {L"wcsncpy", reinterpret_cast<uintptr_t>(wcsncpy_), true, 0}},
        {L"_wcsncpy_l", {L"_wcsncpy_l", reinterpret_cast<uintptr_t>(_wcsncpy_l), true, 0}},
        {L"_mbsncpy", {L"_mbsncpy", reinterpret_cast<uintptr_t>(_mbsncpy), true, 0}},
        {L"_mbsncpy_l", {L"_mbsncpy_l", reinterpret_cast<uintptr_t>(_mbsncpy_l), true, 0}},
        {L"wcsncpy_s", {L"wcsncpy_s", reinterpret_cast<uintptr_t>(wcsncpy_s), true, 0}},
        {L"_mbscpy_s", {L"_mbscpy_s", reinterpret_cast<uintptr_t>(_mbscpy_s), true, 0}},
        {L"strnlen", {L"strnlen", reinterpret_cast<uintptr_t>(strnlen_), true, 0}},
        {L"strnlen_s", {L"strnlen_s", reinterpret_cast<uintptr_t>(strnlen_s), true, 0}},
        {L"wcsnlen", {L"wcsnlen", reinterpret_cast<uintptr_t>(wcsnlen_), true, 0}},
        {L"wcsnlen_s", {L"wcsnlen_s", reinterpret_cast<uintptr_t>(wcsnlen_s), true, 0}},
        {L"_mbsnlen", {L"_mbsnlen", reinterpret_cast<uintptr_t>(_mbsnlen), true, 0}},
        {L"_mbsnlen_l", {L"_mbsnlen_l", reinterpret_cast<uintptr_t>(_mbsnlen_l), true, 0}},
        {L"_mbstrnlen", {L"_mbstrnlen", reinterpret_cast<uintptr_t>(_mbstrnlen), true, 0}},
        {L"_mbstrnlen_l", {L"_mbstrnlen_l", reinterpret_cast<uintptr_t>(_mbstrnlen_l), true, 0}},
        {L"strncat_s", {L"strncat_s", reinterpret_cast<uintptr_t>(strncat_s), true, 0}},
        {L"strncpy_s", {L"strncpy_s", reinterpret_cast<uintptr_t>(strncpy_s), true, 0}},
        {L"wcsncmp", {L"wcsncmp", reinterpret_cast<uintptr_t>(wcsncmp_), true, 0}},
        {L"_mbsnbcmp", {L"_mbsnbcmp", reinterpret_cast<uintptr_t>(_mbsnbcmp), true, 0}},
        {L"_mbsnbcmp_l", {L"_mbsnbcmp_l", reinterpret_cast<uintptr_t>(_mbsnbcmp_l), true, 0}},
        {L"strpbrk", {L"strpbrk", reinterpret_cast<uintptr_t>(strpbrk_), true, 0}},
        {L"wcspbrk", {L"wcspbrk", reinterpret_cast<uintptr_t>(wcspbrk_), true, 0}},
        {L"_mbspbrk", {L"_mbspbrk", reinterpret_cast<uintptr_t>(_mbspbrk), true, 0}},
        {L"_mbspbrk_l", {L"_mbspbrk_l", reinterpret_cast<uintptr_t>(_mbspbrk_l), true, 0}},
        {L"strspn", {L"strspn", reinterpret_cast<uintptr_t>(strspn_), true, 0}},
        {L"wcsspn", {L"wcsspn", reinterpret_cast<uintptr_t>(wcsspn_), true, 0}},
        {L"_mbsspn", {L"_mbsspn", reinterpret_cast<uintptr_t>(_mbsspn), true, 0}},
        {L"_mbsspn_l", {L"_mbsspn_l", reinterpret_cast<uintptr_t>(_mbsspn_l), true, 0}},
        {L"strtok", {L"strtok", reinterpret_cast<uintptr_t>(strtok_), true, 0}},
        {L"strtok_s", {L"strtok_s", reinterpret_cast<uintptr_t>(strtok_s), true, 0}},
        {L"_strtok_s_l", {L"_strtok_s_l", reinterpret_cast<uintptr_t>(_strtok_s_l), true, 0}},
        {L"wcstok", {L"wcstok", reinterpret_cast<uintptr_t>(wcstok_), true, 0}},
        {L"wcstok_s", {L"wcstok_s", reinterpret_cast<uintptr_t>(wcstok_s), true, 0}},
        {L"_wcstok_s_l", {L"_wcstok_s_l", reinterpret_cast<uintptr_t>(_wcstok_s_l), true, 0}},
        {L"_mbstok", {L"_mbstok", reinterpret_cast<uintptr_t>(_mbstok), true, 0}},
        {L"_mbstok_l", {L"_mbstok_l", reinterpret_cast<uintptr_t>(_mbstok_l), true, 0}},
        {L"_mbstok_s", {L"_mbstok_s", reinterpret_cast<uintptr_t>(_mbstok_s), true, 0}},
        {L"_mbstok_s_l", {L"_mbstok_s_l", reinterpret_cast<uintptr_t>(_mbstok_s_l), true, 0}},
        {L"tolower", {L"tolower", reinterpret_cast<uintptr_t>(tolower_), true, 0}},
        {L"toupper", {L"toupper", reinterpret_cast<uintptr_t>(toupper_), true, 0}},
        {L"towctrans", {L"towctrans", reinterpret_cast<uintptr_t>(towctrans_), true, 0}},
        {L"wctype", {L"wctype", reinterpret_cast<uintptr_t>(wctype_), true, 0}},
        {L"wcschr", {L"wcschr", reinterpret_cast<uintptr_t>(wcschr_), true, 0}},
        {L"_mbschr", {L"_mbschr", reinterpret_cast<uintptr_t>(_mbschr), true, 0}},
        {L"_mbschr_l", {L"_mbschr_l", reinterpret_cast<uintptr_t>(_mbschr_l), true, 0}},

        // Wide character swprintf function (special case due to signature)
        {L"swprintf", {L"swprintf", reinterpret_cast<uintptr_t>(swprintf_), true, 0}},

        {L"_c_exit", {L"_c_exit", reinterpret_cast<uintptr_t>(_c_exit), true, 0}},
        {L"_cexit", {L"_cexit", reinterpret_cast<uintptr_t>(_cexit), true, 0}},
        {L"__p___argc", {L"__p___argc", reinterpret_cast<uintptr_t>(&__p___argc), false, 0}},
        {L"__p___argv", {L"__p___argv", reinterpret_cast<uintptr_t>(&__p___argv), false, 0}},
        {L"_exit", {L"_exit", reinterpret_cast<uintptr_t>(_exit), true, 0}},
        {L"_configure_narrow_argv", {L"_configure_narrow_argv", reinterpret_cast<uintptr_t>(_configure_narrow_argv), true, 0}},
        {L"_get_initial_narrow_environment", {L"_get_initial_narrow_environment", reinterpret_cast<uintptr_t>(_get_initial_narrow_environment), true, 0}},
        {L"__setusermatherr", {L"__setusermatherr", reinterpret_cast<uintptr_t>(&__setusermatherr), false, 0}},
        {L"__p__commode", {L"__p__commode", reinterpret_cast<uintptr_t>(&__p__commode), false, 0}},
        {L"terminate", {L"terminate", reinterpret_cast<uintptr_t>(terminate), true, 0}},
        {L"_register_onexit_function", {L"_register_onexit_function", reinterpret_cast<uintptr_t>(_register_onexit_function), true, 0}},
        {L"_crt_atexit", {L"_crt_atexit", reinterpret_cast<uintptr_t>(_crt_atexit), true, 0}},
        {L"_set_app_type", {L"_set_app_type", reinterpret_cast<uintptr_t>(_set_app_type), true, 0}},
        {L"_initialize_onexit_table", {L"_initialize_onexit_table", reinterpret_cast<uintptr_t>(_initialize_onexit_table), true, 0}},
        {L"_register_thread_local_exe_atexit_callback", {L"_register_thread_local_exe_atexit_callback", reinterpret_cast<uintptr_t>(_register_thread_local_exe_atexit_callback), true, 0}},
        {L"_seh_filter_exe", {L"_seh_filter_exe", reinterpret_cast<uintptr_t>(_seh_filter_exe), true, 0}},
        {L"exit", {L"exit", reinterpret_cast<uintptr_t>(exit), true, 0}},
        {L"_initterm_e", {L"_initterm_e", reinterpret_cast<uintptr_t>(_initterm_e), true, 0}},
        {L"_initterm", {L"_initterm", reinterpret_cast<uintptr_t>(_initterm), true, 0}},
        {L"_initialize_narrow_environment", {L"_initialize_narrow_environment", reinterpret_cast<uintptr_t>(_initialize_narrow_environment), true, 0}},
        {L"_configthreadlocale", {L"_configthreadlocale", reinterpret_cast<uintptr_t>(_configthreadlocale), true, 0}},
        {L"_get_fmode", {L"_get_fmode", reinterpret_cast<uintptr_t>(_get_fmode), true, 0}},
        {L"_set_new_mode", {L"_set_new_mode", reinterpret_cast<uintptr_t>(_set_new_mode), true, 0}}
    };
}

void * UCRTBase::memset_(void *dest, int ch, size_t count) {
    trace("memset called. Arguments: dest=<void*>[", dest, "], ch=", std::to_wstring(ch), ", count=", std::to_wstring(count));
    if (dest == nullptr) {
        error("Error set to: EINVAL, Return value: <void*>[]");
        errno = EINVAL;
        return nullptr;
    }
    void* result = memset(dest, ch, count);
    ret("Error set to: -, Return value: <void*>[", result, "]");
    return result;
}

void * UCRTBase::memcpy_(void *dest, const void *src, size_t count) {
    trace("memcpy called. Arguments: dest=<void*>[", dest, "], nt_apiset_cpp_hooks=<const void*>[", src, "], count=", std::to_wstring(count));
    if (dest == nullptr || src == nullptr) {
        error("Error set to: EINVAL, Return value: <void*>[]");
        errno = EINVAL;
        return nullptr;
    }
    void* result = memcpy(dest, src, count);
    ret("Error set to: -, Return value: <void*>[", result, "]");
    return result;
}

int UCRTBase::memcmp_(const void *ptr1, const void *ptr2, size_t count) {
    trace("memcmp called. Arguments: ptr1=<const void*>[", ptr1, "], ptr2=<const void*>[", ptr2, "], count=", std::to_wstring(count));
    if (ptr1 == nullptr || ptr2 == nullptr) {
        error("Error set to: EINVAL, Return value: 0");
        errno = EINVAL;
        return 0;
    }
    const int result = memcmp(ptr1, ptr2, count);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

void * UCRTBase::memmove_(void *dest, const void *src, size_t count) {
    trace("memmove called. Arguments: dest=<void*>[", dest, "], nt_apiset_cpp_hooks=<const void*>[", src, "], count=", std::to_wstring(count));
    if (dest == nullptr || src == nullptr) {
        error("Error set to: EINVAL, Return value: <void*>[]");
        errno = EINVAL;
        return nullptr;
    }
    void* result = memmove(dest, src, count);
    ret("Error set to: -, Return value: <void*>[", result, "]");
    return result;
}

size_t UCRTBase::strlen_(const char *str) {
    trace("strlen called. Arguments: str=<const char*>[", static_cast<const void*>(str), "]");
    if (str == nullptr) {
        error("Error set to: EINVAL, Return value: 0");
        errno = EINVAL;
        return 0;
    }
    const size_t result = strlen(str);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

char * UCRTBase::strcpy_(char *dest, const char *src) {
    trace("strcpy called. Arguments: dest=<char*>[", static_cast<void*>(dest), "], nt_apiset_cpp_hooks=<const char*>[", static_cast<const void*>(src), "]");
    if (dest == nullptr || src == nullptr) {
        error("Error set to: EINVAL, Return value: <char*>[]");
        errno = EINVAL;
        return nullptr;
    }
    char* result = strcpy(dest, src);
    ret("Error set to: -, Return value: <char*>[", static_cast<const void*>(result), "]");
    return result;
}

char * UCRTBase::strncpy_(char *dest, const char *src, size_t count) {
    trace("strncpy called. Arguments: dest=<char*>[", static_cast<void*>(dest), "], nt_apiset_cpp_hooks=<const char*>[", static_cast<const void*>(src), "], count=", std::to_wstring(count));
    if (dest == nullptr || src == nullptr) {
        error("Error set to: EINVAL, Return value: <char*>[]");
        errno = EINVAL;
        return nullptr;
    }
    char* result = strncpy(dest, src, count);
    ret("Error set to: -, Return value: <char*>[", static_cast<const void*>(result), "]");
    return result;
}

int UCRTBase::strcmp_(const char *str1, const char *str2) {
    trace("strcmp called. Arguments: str1=<const char*>[", static_cast<const void*>(str1), "], str2=<const char*>[", static_cast<const void*>(str2), "]");
    if (str1 == nullptr || str2 == nullptr) {
        error("Error set to: EINVAL, Return value: 0");
        errno = EINVAL;
        return 0;
    }
    const int result = strcmp(str1, str2);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

int UCRTBase::strncmp_(const char *str1, const char *str2, size_t count) {
    trace("strncmp called. Arguments: str1=<const char*>[", static_cast<const void*>(str1), "], str2=<const char*>[", static_cast<const void*>(str2), "], count=", std::to_wstring(count));
    if (str1 == nullptr || str2 == nullptr) {
        error("Error set to: EINVAL, Return value: 0");
        errno = EINVAL;
        return 0;
    }
    const int result = strncmp(str1, str2, count);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

char * UCRTBase::strcat_(char *dest, const char *src) {
    trace("strcat called. Arguments: dest=<char*>[", static_cast<void*>(dest), "], nt_apiset_cpp_hooks=<const char*>[", static_cast<const void*>(src), "]");
    if (dest == nullptr || src == nullptr) {
        error("Error set to: EINVAL, Return value: <char*>[]");
        errno = EINVAL;
        return nullptr;
    }
    char* result = strcat(dest, src);
    ret("Error set to: -, Return value: <char*>[", static_cast<const void*>(result), "]");
    return result;
}

char * UCRTBase::strncat_(char *dest, const char *src, size_t count) {
    trace("strncat called. Arguments: dest=<char*>[", static_cast<void*>(dest), "], nt_apiset_cpp_hooks=<const char*>[", static_cast<const void*>(src), "], count=", std::to_wstring(count));
    if (dest == nullptr || src == nullptr) {
        error("Error set to: EINVAL, Return value: <char*>[]");
        errno = EINVAL;
        return nullptr;
    }
    char* result = strncat(dest, src, count);
    ret("Error set to: -, Return value: <char*>[", static_cast<const void*>(result), "]");
    return result;
}

int UCRTBase::__toascii_(int c) {
    trace("__toascii called. Arguments: c=", std::to_wstring(c));
    const int result = c & 0x7F;
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

char * UCRTBase::strchr_(const char *str, int character) {
    trace("strchr called. Arguments: str=<const char*>[", static_cast<const void*>(str), "], character=", std::to_wstring(character));
    if (str == nullptr) {
        error("Error set to: -, Return value: <char*>[]");
        return nullptr;
    }
    const char* result = strchr(str, character);
    ret("Error set to: -, Return value: <char*>[", static_cast<const void*>(result), "]");
    return const_cast<char*>(result);
}

char * UCRTBase::strrchr_(const char *str, int character) {
    trace("strrchr called. Arguments: str=<const char*>[", static_cast<const void*>(str), "], character=", std::to_wstring(character));
    if (str == nullptr) {
        error("Error set to: -, Return value: <char*>[]");
        return nullptr;
    }
    const char* result = strrchr(str, character);
    ret("Error set to: -, Return value: <char*>[", static_cast<const void*>(result), "]");
    return const_cast<char*>(result);
}

char * UCRTBase::strstr_(const char *haystack, const char *needle) {
    trace("strstr called. Arguments: haystack=<const char*>[", static_cast<const void*>(haystack),
          "], needle=<const char*>[", static_cast<const void*>(needle), "]");
    if (haystack == nullptr || needle == nullptr) {
        error("Error set to: -, Return value: <char*>[]");
        return nullptr;
    }
    const char* result = strstr(haystack, needle);
    ret("Error set to: -, Return value: <char*>[", static_cast<const void*>(result), "]");
    return const_cast<char*>(result);
}

int UCRTBase::_atodbl(const char *str, double *value) {
    trace("_atodbl called. Arguments: str=<const char*>[", static_cast<const void*>(str), "], value=<double*>[", value, "]");
    if (str == nullptr || value == nullptr) {
        ret("Error set to: -, Return value: -1");
        return -1;
    }
    char* endptr = nullptr;
    errno = 0;
    const double result = strtod(str, &endptr);
    if (endptr == str) {
        ret("Error set to: -, Return value: -1");
        return -1; // No conversion performed
    }
    if (errno == ERANGE) {
        ret("Error set to: ERANGE, Return value: -1");
        return -1; // Out of range
    }
    *value = result;
    ret("Error set to: -, Return value: 0");
    return 0;
}

int UCRTBase::_atodbl_l(const char *str, double *value, _locale_t) {
    // <idontcare> Locale is ignored </idontcare>
    int res = _atodbl(str, value);
    ret("Error set to: -, Return value: ", std::to_wstring(res));
    return res;
}

double UCRTBase::_atof_l(const char *str, _locale_t) {
    trace("_atof_l called. Arguments: str=<const char*>[", static_cast<const void*>(str), "], locale=<_locale_t>[]");
    if (str == nullptr) {
        error("Error set to: -, Return value: 0.0");
        return 0.0;
    }
    char* endptr = nullptr;
    errno = 0;
    const double result = strtod(str, &endptr);
    if (endptr == str) {
        error("Error set to: -, Return value: 0.0");
        return 0.0; // No conversion performed
    }
    if (errno == ERANGE) {
        error("Error set to: ERANGE, Return value: HUGE_VAL");
        return HUGE_VAL; // Out of range
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

int UCRTBase::_atoflt(const char *str, float *value) {
    trace("_atoflt called. Arguments: str=<const char*>[", static_cast<const void*>(str), "], value=<float*>[", value, "]");
    if (str == nullptr || value == nullptr) {
        ret("Error set to: -, Return value: -1");
        return -1;
    }
    char* endptr = nullptr;
    errno = 0;
    const float result = strtof(str, &endptr);
    if (endptr == str) {
        ret("Error set to: -, Return value: -1");
        return -1; // No conversion performed
    }
    if (errno == ERANGE) {
        ret("Error set to: ERANGE, Return value: -1");
        return -1; // Out of range
    }
    *value = result;
    ret("Error set to: -, Return value: 0");
    return 0;
}

int UCRTBase::_atoflt_l(const char *str, float *value, _locale_t) {
    // <idontcare> Locale is ignored </idontcare>
    int res = _atoflt(str, value);
    ret("Error set to: -, Return value: ", std::to_wstring(res));
    return res;
}

INT UCRTBase::_atoi_l(const char *str, _locale_t) {
    // <idontcare> Locale is ignored </idontcare>
    trace("_atoi_l called. Arguments: str=<const char*>[", static_cast<const void*>(str), "], locale=<_locale_t>[]");
    const int res = atoi(str);
    ret("Error set to: -, Return value: ", std::to_wstring(res));
    return res;
}

LONG UCRTBase::_atol_l(const char *str, _locale_t) {
    // <idontcare> Locale is ignored </idontcare>
    trace("_atol_l called. Arguments: str=<const char*>[", static_cast<const void*>(str), "], locale=<_locale_t>[]");
    return atol(str);
}

int UCRTBase::_atoldbl(const char *str, long double *value) {
    trace("_atoldbl called. Arguments: str=<const char*>[", static_cast<const void*>(str), "], value=<long double*>[", value, "]");
    if (str == nullptr || value == nullptr) {
        ret("Error set to: -, Return value: -1");
        return -1;
    }
    char* endptr = nullptr;
    errno = 0;
    const long double result = strtold(str, &endptr);
    if (endptr == str) {
        ret("Error set to: -, Return value: -1");
        return -1; // No conversion performed
    }
    if (errno == ERANGE) {
        ret("Error set to: ERANGE, Return value: -1");
        return -1; // Out of range
    }
    *value = result;
    ret("Error set to: -, Return value: 0");
    return 0;
}

int UCRTBase::_atoldbl_l(const char *str, long double *value, _locale_t) {
    // <idontcare> Locale is ignored </idontcare>
    const int res = _atoldbl(str, value);
    ret("Error set to: -, Return value: ", std::to_wstring(res));
    return res;
}

LONGLONG UCRTBase::_atoll_l(const char *str, _locale_t) {
    // <idontcare> Locale is ignored </idontcare>
    trace("_atoll_l called. Arguments: str=<const char*>[", static_cast<const void*>(str), "], locale=<_locale_t>[]");
    return _atoll(str);
}

LONGLONG UCRTBase::_atoll(const char *str) {
    trace("_atoll called. Arguments: str=<const char*>[", static_cast<const void*>(str), "]");
    const long long res = atoll(str);
    ret("Error set to: -, Return value: ", std::to_wstring(res));
    return res;
}

char * UCRTBase::_ecvt(double value, int count, int *dec, int *sign) {
    trace("_ecvt called. Arguments: value=", std::to_wstring(value), ", count=", std::to_wstring(count),
          ", dec=<int*>[", dec, "], sign=<int*>[", sign, "]");
    char *res = ecvt(value, count, dec, sign);
    ret("Error set to: -, Return value: <char*>[", static_cast<const void*>(res), "]");
    return res;
}

errno_t UCRTBase::_ecvt_s(char *buffer, size_t sizeInChars, double value, int count, int *dec, int *sign) {
    trace("_ecvt_s called. Arguments: buffer=<char*>[", static_cast<void*>(buffer), "], sizeInChars=", std::to_wstring(sizeInChars),
          ", value=", std::to_wstring(value), ", count=", std::to_wstring(count),
          ", dec=<int*>[", dec, "], sign=<int*>[", sign, "]");
    // just use ecvt() and copy the result to buffer
    if (buffer == nullptr || sizeInChars == 0) {
        ret("Error set to: -, Return value: EINVAL");
        return EINVAL;
    }
    if (count < 0 || count > 309) {
        // 309 is the max precision for a double
        ret("Error set to: -, Return value: EINVAL");
        return EINVAL;
    }
    if (dec == nullptr || sign == nullptr) {
        ret("Error set to: -, Return value: EINVAL");
        return EINVAL;
    }
    const char* temp = ecvt(value, count, dec, sign);
    if (strlen(temp) + 1 > sizeInChars) {
        ret("Error set to: -, Return value: ERANGE");
        return ERANGE;
    }
    strcpy(buffer, temp);
    ret("Error set to: -, Return value: 0");
    return 0;
}

char * UCRTBase::_fcvt(double value, int count, int *dec, int *sign) {
    trace("_fcvt called. Arguments: value=", std::to_wstring(value), ", count=", std::to_wstring(count),
          ", dec=<int*>[", dec, "], sign=<int*>[", sign, "]");
    char *res = fcvt(value, count, dec, sign);
    ret("Error set to: -, Return value: <char*>[", static_cast<const void*>(res), "]");
    return res;
}

errno_t UCRTBase::_fcvt_s(char *buffer, size_t sizeInChars, double value, int count, int *dec, int *sign) {
    trace("_fcvt_s called. Arguments: buffer=<char*>[", static_cast<void*>(buffer), "], sizeInChars=", std::to_wstring(sizeInChars),
          ", value=", std::to_wstring(value), ", count=", std::to_wstring(count),
          ", dec=<int*>[", dec, "], sign=<int*>[", sign, "]");
    if (buffer == nullptr || sizeInChars == 0) {
        ret("Error set to: -, Return value: EINVAL");
        return EINVAL;
    }
    if (count < 0 || count > 309) { // 309 is the max precision for a double
        ret("Error set to: -, Return value: EINVAL");
        return EINVAL;
    }
    if (dec == nullptr || sign == nullptr) {
        ret("Error set to: -, Return value: EINVAL");
        return EINVAL;
    }
    const char* temp = fcvt(value, count, dec, sign);
    if (strlen(temp) + 1 > sizeInChars) {
        ret("Error set to: -, Return value: ERANGE");
        return ERANGE;
    }
    strcpy(buffer, temp);
    ret("Error set to: -, Return value: 0");
    return 0;
}

char * UCRTBase::_gcvt(double value, int count, char *buffer) {
    trace("_gcvt called. Arguments: value=", std::to_wstring(value), ", count=", std::to_wstring(count),
          ", buffer=<char*>[", static_cast<void*>(buffer), "]");
    char *res = gcvt(value, count, buffer);
    ret("Error set to: -, Return value: <char*>[", static_cast<const void*>(res), "]");
    return res;
}

errno_t UCRTBase::_gcvt_s(char *buffer, size_t sizeInChars, double value, int count) {
    trace("_gcvt_s called. Arguments: buffer=<char*>[", static_cast<void*>(buffer), "], sizeInChars=", std::to_wstring(sizeInChars),
          ", value=", std::to_wstring(value), ", count=", std::to_wstring(count));
    if (buffer == nullptr || sizeInChars == 0) {
        ret("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    if (count < 1 || count > 317) { // 317 is the max precision for a double in general format
        ret("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    // Use snprintf to convert the double to string with the specified precision
    if (const int written = snprintf(buffer, sizeInChars, "%.*g", count, value); written < 0 || static_cast<size_t>(written) >= sizeInChars) {
        ret("Error set to: ERANGE, Return value: ERANGE");
        return ERANGE;
    }
    ret("Error set to: -, Return value: 0");
    return 0;
}

char * UCRTBase::_i64toa(LONGLONG value, char *buffer, int radix) {
    trace("_i64toa called. Arguments: value=", std::to_wstring(value), ", buffer=<char*>[", static_cast<void*>(buffer), "], radix=", std::to_wstring(radix));
    if (buffer == nullptr) {
        ret("Error set to: -, Return value: EINVAL");
        return nullptr;
    }
    if (radix < 2 || radix > 36) {
        ret("Error set to: -, Return value: EINVAL");
        return nullptr;
    }
    snprintf(buffer, 65, (radix == 10) ? "%lld" : (radix == 16) ? "%llx" : (radix == 8) ? "%llo" : (radix == 2) ? "%llb" : "%lld", value);
    ret("Error set to: -, Return value: <char*>[", static_cast<const void*>(buffer), "]");
    return buffer;
}

errno_t UCRTBase::_i64toa_s(LONGLONG value, char *buffer, size_t sizeInChars, int radix) {
    trace("_i64toa_s called. Arguments: value=", std::to_wstring(value), ", buffer=<char*>[", static_cast<void*>(buffer), "], sizeInChars=", std::to_wstring(sizeInChars), ", radix=", std::to_wstring(radix));
    if (buffer == nullptr || sizeInChars == 0) {
        ret("Error set to: -, Return value: EINVAL");
        return EINVAL;
    }
    if (radix < 2 || radix > 36) {
        ret("Error set to: -, Return value: EINVAL");
        return EINVAL;
    }
    snprintf(buffer, sizeInChars, (radix == 10) ? "%lld" : (radix == 16) ? "%llx" : (radix == 8) ? "%llo" : (radix == 2) ? "%llb" : "%lld", value);
    ret("Error set to: -, Return value: 0");
    return 0;
}

_wchar_t * UCRTBase::_i64tow(LONGLONG value, _wchar_t *buffer, int radix) {
    if (!buffer || radix < 2 || radix > 36) return nullptr;

    const bool negative = (radix == 10 && value < 0);
    uint64_t uvalue = negative ? -value : value;

    _wchar_t temp[65]; // max 64 digits + null
    int pos = 0;

    // convert number to string in reverse
    do {
        const auto digits = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        temp[pos++] = digits[uvalue % radix];
        uvalue /= radix;
    } while (uvalue && pos < 64);

    if (negative) temp[pos++] = L'-';

    // reverse into buffer
    for (int i = 0; i < pos; i++) {
        buffer[i] = temp[pos - 1 - i];
    }
    errno = 0;
    buffer[pos] = 0;
    return buffer;
}

errno_t UCRTBase::_i64tow_s(LONGLONG value, _wchar_t *buffer, size_t sizeInChars, int radix) {
    if (!buffer || sizeInChars == 0) return EINVAL;
    if (radix < 2 || radix > 36) return EINVAL;

    const bool negative = (radix == 10 && value < 0);
    uint64_t uvalue = negative ? -value : value;

    _wchar_t temp[65]; // max 64 digits + null
    int pos = 0;

    // Convert number to string in reverse
    do {
        const auto digits = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        temp[pos++] = digits[uvalue % radix];
        uvalue /= radix;
    } while (uvalue && pos < 64);

    if (negative) temp[pos++] = L'-';

    // Check buffer size
    if (sizeInChars <= static_cast<size_t>(pos)) { // not enough space for digits + null
        buffer[0] = 0; // null-terminate on error as Windows does
        errno = ERANGE;
        return ERANGE;
    }

    // Reverse into buffer
    for (int i = 0; i < pos; i++) {
        buffer[i] = temp[pos - 1 - i];
    }
    errno = 0;
    buffer[pos] = 0;
    return 0; // success
}

char * UCRTBase::_itoa(int value, char *buffer, int radix) {
    trace("_itoa called. Arguments: value=", std::to_wstring(value), ", buffer=<char*>[", static_cast<void*>(buffer), "], radix=", std::to_wstring(radix));
    if (buffer == nullptr) {
        error("Error set to: -, Return value: <char*>[]");
        return nullptr;
    }
    if (radix < 2 || radix > 36) {
        error("Error set to: -, Return value: <char*>[]");
        return nullptr;
    }
    snprintf(buffer, 33, (radix == 10) ? "%d" : (radix == 16) ? "%x" : (radix == 8) ? "%o" : (radix == 2) ? "%b" : "%d", value);
    ret("Error set to: -, Return value: <char*>[", static_cast<const void*>(buffer), "]");
    return buffer;
}

errno_t UCRTBase::_itoa_s(int value, char *buffer, size_t sizeInChars, int radix) {
    trace("_itoa_s called. Arguments: value=", std::to_wstring(value), ", buffer=<char*>[", static_cast<void*>(buffer), "], sizeInChars=", std::to_wstring(sizeInChars), ", radix=", std::to_wstring(radix));
    if (buffer == nullptr || sizeInChars == 0) {
        ret("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    if (radix < 2 || radix > 36) {
        ret("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    snprintf(buffer, sizeInChars, (radix == 10) ? "%d" : (radix == 16) ? "%x" : (radix == 8) ? "%o" : (radix == 2) ? "%b" : "%d", value);
    ret("Error set to: -, Return value: 0");
    return 0;
}

_wchar_t * UCRTBase::_itow(int value, _wchar_t *buffer, int radix) {
    trace("_itow called. Arguments: value=", std::to_wstring(value), ", buffer=<wchar_t*>[", static_cast<void*>(buffer), "], radix=", std::to_wstring(radix));
    if (buffer == nullptr) {
        error("Error set to: -, Return value: <wchar_t*>[]");
        return nullptr;
    }
    if (radix < 2 || radix > 36) {
        error("Error set to: -, Return value: <wchar_t*>[]");
        return nullptr;
    }
    // similar to _i64tow but for int
    const bool negative = (radix == 10 && value < 0);
    uint32_t uvalue = negative ? -value : value;
    _wchar_t temp[33]; // max 32 digits + null
    int pos = 0;
    // convert number to string in reverse
    do {
        const auto digits = L"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        temp[pos++] = digits[uvalue % radix];
        uvalue /= radix;
    } while (uvalue && pos < 32);
    if (negative) temp[pos++] = L'-';
    // reverse into buffer
    for (int i = 0; i < pos; i++) {
        buffer[i] = temp[pos - 1 - i];
    }
    errno = 0;
    buffer[pos] = 0;
    ret("Error set to: -, Return value: <wchar_t*>[", static_cast<void*>(buffer), "]");
    return buffer;
}

errno_t UCRTBase::_itow_s(int value, _wchar_t *buffer, size_t sizeInChars, int radix) {
    trace("_itow_s called. Arguments: value=", std::to_wstring(value), ", buffer=<wchar_t*>[", static_cast<void*>(buffer), "], sizeInChars=", std::to_wstring(sizeInChars), ", radix=", std::to_wstring(radix));
    if (buffer == nullptr || sizeInChars == 0) {
        ret("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    if (radix < 2 || radix > 36) {
        ret("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    // similar to _i64tow_s but for int
    const bool negative = (radix == 10 && value < 0);
    uint32_t uvalue = negative ? -value : value;
    _wchar_t temp[33]; // max 32 digits + null
    int pos = 0;
    // convert number to string in reverse
    do {
        const auto digits = L"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        temp[pos++] = digits[uvalue % radix];
        uvalue /= radix;
    } while (uvalue && pos < 32);
    if (negative) temp[pos++] = L'-';
    // check buffer size
    if (sizeInChars <= static_cast<size_t>(pos)) {
        // not enough space for digits + null
        buffer[0] = 0; // null-terminate on error as Windows does
        errno = ERANGE;
        ret("Error set to: ERANGE, Return value: ERANGE");
        return ERANGE;
    }
    // reverse into buffer
    for (int i = 0; i < pos; i++) {
        buffer[i] = temp[pos - 1 - i];
    }
    errno = 0;
    buffer[pos] = 0;
    ret("Error set to: -, Return value: 0");
    return 0; // success
}

char * UCRTBase::_ltoa(LONG value, char *buffer, int radix) {
    trace("ltoa called. Arguments: value=", std::to_wstring(value), ", buffer=<char*>[", static_cast<void*>(buffer), "], radix=", std::to_wstring(radix));
    if (buffer == nullptr) {
        error("Error set to: -, Return value: <char*>[]");
        return nullptr;
    }
    if (radix < 2 || radix > 36) {
        error("Error set to: -, Return value: <char*>[]");
        return nullptr;
    }
    snprintf(buffer, 33, (radix == 10) ? "%d" : (radix == 16) ? "%x" : (radix == 8) ? "%o" : (radix == 2) ? "%b" : "%d", value);
    ret("Error set to: -, Return value: <char*>[", static_cast<const void*>(buffer), "]");
    return buffer;
}

errno_t UCRTBase::_ltoa_s(LONG value, char *buffer, size_t sizeInChars, int radix) {
    trace("ltoa_s called. Arguments: value=", std::to_wstring(value), ", buffer=<char*>[", static_cast<void*>(buffer), "], sizeInChars=", std::to_wstring(sizeInChars), ", radix=", std::to_wstring(radix));
    if (buffer == nullptr || sizeInChars == 0) {
        ret("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    if (radix < 2 || radix > 36) {
        ret("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    snprintf(buffer, sizeInChars, (radix == 10) ? "%d" : (radix == 16) ? "%x" : (radix == 8) ? "%o" : (radix == 2) ? "%b" : "%d", value);
    ret("Error set to: -, Return value: 0");
    return 0;
}

_wchar_t * UCRTBase::_ltow(LONG value, _wchar_t *buffer, int radix) {
    trace("ltow called. Arguments: value=", std::to_wstring(value), ", buffer=<wchar_t*>[", static_cast<void*>(buffer), "], radix=", std::to_wstring(radix));
    if (buffer == nullptr) {
        error("Error set to: -, Return value: <wchar_t*>[]");
        return nullptr;
    }
    if (radix < 2 || radix > 36) {
        error("Error set to: -, Return value: <wchar_t*>[]");
        return nullptr;
    }
    // similar to _i64tow but for LONG
    const bool negative = (radix == 10 && value < 0);
    uint32_t uvalue = negative ? -value : value;
    _wchar_t temp[33]; // max 32 digits + null
    int pos = 0;
    // convert number to string in reverse
    do {
        const auto digits = L"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        temp[pos++] = digits[uvalue % radix];
        uvalue /= radix;
    } while (uvalue && pos < 32);
    if (negative) temp[pos++] = L'-';
    // reverse into buffer
    for (int i = 0; i < pos; i++) {
        buffer[i] = temp[pos - 1 - i];
    }
    errno = 0;
    buffer[pos] = 0;
    ret("Error set to: -, Return value: <wchar_t*>[", static_cast<void*>(buffer), "]");
    return buffer;
}

errno_t UCRTBase::_ltow_s(LONG value, _wchar_t *buffer, size_t sizeInChars, int radix) {
    trace("ltow_s called. Arguments: value=", std::to_wstring(value), ", buffer=<wchar_t*>[", static_cast<void*>(buffer), "], sizeInChars=", std::to_wstring(sizeInChars), ", radix=", std::to_wstring(radix));
    if (buffer == nullptr || sizeInChars == 0) {
        ret("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    if (radix < 2 || radix > 36) {
        ret("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    // similar to _i64tow_s but for LONG
    const bool negative = (radix == 10 && value < 0);
    uint32_t uvalue = negative ? -value : value;
    _wchar_t temp[33]; // max 32 digits + null
    int pos = 0;
    // convert number to string in reverse
    do {
        const auto digits = L"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        temp[pos++] = digits[uvalue % radix];
        uvalue /= radix;
    } while (uvalue && pos < 32);
    if (negative) temp[pos++] = L'-';
    // check buffer size
    if (sizeInChars <= static_cast<size_t>(pos)) {
        // not enough space for digits + null
        buffer[0] = 0; // null-terminate on error as Windows does
        errno = ERANGE;
        ret("Error set to: ERANGE, Return value: ERANGE");
        return ERANGE;
    }
    // reverse into buffer
    for (int i = 0; i < pos; i++) {
        buffer[i] = temp[pos - 1 - i];
    }
    errno = 0;
    buffer[pos] = 0;
    ret("Error set to: -, Return value: 0");
    return 0; // success
}

double UCRTBase::_strtod_l(const char *str, char **endptr, _locale_t) {
    // <idontcare> Locale is ignored </idontcare>
    return _strtod(str, endptr);
}

double UCRTBase::_strtod(const char *str, char **endptr) {
    trace("_strtod called. Arguments: str=<const char*>[", static_cast<const void*>(str), "], endptr=<char**>[", endptr, "]");
    if (str == nullptr) {
        error("Error set to: -, Return value: 0.0");
        return 0.0;
    }
    errno = 0;
    const double result = strtod(str, endptr);
    if (endptr != nullptr && *endptr == str) {
        error("Error set to: -, Return value: 0.0");
        return 0.0; // No conversion performed
    }
    if (errno == ERANGE) {
        error("Error set to: ERANGE, Return value: HUGE_VAL, -HUGE_VAL, or 0.0");
        return (result > 0) ? HUGE_VAL : (result < 0) ? -HUGE_VAL : 0.0; // Out of range
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

float UCRTBase::_strtof_l(const char *str, char **endptr, _locale_t) {
    // <idontcare> Locale is ignored </idontcare>
    return _strtof(str, endptr);
}

float UCRTBase::_strtof(const char *str, char **endptr) {
    trace("_strtof called. Arguments: str=<const char*>[", static_cast<const void*>(str), "], endptr=<char**>[", endptr, "]");
    if (str == nullptr) {
        error("Error set to: -, Return value: 0.0f");
        return 0.0f;
    }
    errno = 0;
    const float result = strtof(str, endptr);
    if (endptr != nullptr && *endptr == str) {
        error("Error set to: -, Return value: 0.0f");
        return 0.0f; // No conversion performed
    }
    if (errno == ERANGE) {
        error("Error set to: ERANGE, Return value: HUGE_VALF, -HUGE_VALF, or 0.0f");
        return (result > 0) ? HUGE_VALF : (result < 0) ? -HUGE_VALF : 0.0f; // Out of range
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

LONGLONG UCRTBase::_strtoi64_l(const char *str, char **endptr, int radix, _locale_t) {
    // <idontcare> Locale is ignored </idontcare>
    return _strtoi64(str, endptr, radix);
}

LONGLONG UCRTBase::_strtoi64(const char *str, char **endptr, int radix) {
    trace("_strtoi64 called. Arguments: str=<const char*>[", static_cast<const void*>(str), "], endptr=<char**>[", endptr, "], radix=", std::to_wstring(radix));
    if (str == nullptr) {
        error("Error set to: -, Return value: 0");
        return 0;
    }
    if (radix != 0 && (radix < 2 || radix > 36)) {
        error("Error set to: -, Return value: 0");
        return 0; // Invalid radix
    }
    errno = 0;
    const LONGLONG result = strtoll(str, endptr, radix);
    if (endptr != nullptr && *endptr == str) {
        error("Error set to: -, Return value: 0");
        return 0; // No conversion performed
    }
    if (errno == ERANGE) {
        error("Error set to: ERANGE, Return value: LLONG_MAX or LLONG_MIN");
        return (result > 0) ? LLONG_MAX : LLONG_MIN; // Out of range
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

LONGLONG UCRTBase::_strtoimax_l(const char *str, char **endptr, int radix, _locale_t) {
    // <idontcare> Locale is ignored </idontcare>
    return _strtoimax(str, endptr, radix);
}

LONGLONG UCRTBase::_strtoimax(const char *str, char **endptr, int radix) {
    trace("_strtoimax called. Arguments: str=<const char*>[", static_cast<const void*>(str), "], endptr=<char**>[", endptr, "], radix=", std::to_wstring(radix));
    if (str == nullptr) {
        error("Error set to: -, Return value: 0");
        return 0;
    }
    if (radix != 0 && (radix < 2 || radix > 36)) {
        error("Error set to: -, Return value: 0");
        return 0; // Invalid radix
    }
    errno = 0;
    const LONGLONG result = strtoll(str, endptr, radix);
    if (endptr != nullptr && *endptr == str) {
        error("Error set to: -, Return value: 0");
        return 0; // No conversion performed
    }
    if (errno == ERANGE) {
        error("Error set to: ERANGE, Return value: LLONG_MAX or LLONG_MIN");
        return (result > 0) ? LLONG_MAX : LLONG_MIN; // Out of range
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

LONG UCRTBase::_strtol_l(const char *str, char **endptr, int radix, _locale_t) {
    // <idontcare> Locale is ignored </idontcare>
    return _strtol(str, endptr, radix);
}

LONG UCRTBase::_strtol(const char *str, char **endptr, int radix) {
    trace("_strtol called. Arguments: str=<const char*>[", static_cast<const void*>(str), "], endptr=<char**>[", endptr, "], radix=", std::to_wstring(radix));
    if (str == nullptr) {
        error("Error set to: -, Return value: 0");
        return 0;
    }
    if (radix != 0 && (radix < 2 || radix > 36)) {
        error("Error set to: -, Return value: 0");
        return 0; // Invalid radix
    }
    errno = 0;
    const LONG result = static_cast<LONG>(strtol(str, endptr, radix));
    if (endptr != nullptr && *endptr == str) {
        error("Error set to: -, Return value: 0");
        return 0; // No conversion performed
    }
    if (errno == ERANGE) {
        error("Error set to: ERANGE, Return value: LONG_MAX or LONG_MIN");
        return (result > 0) ? INT_MAX : INT_MIN; // Out of range
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

long double UCRTBase::_strtold_l(const char *str, char **endptr, _locale_t) {
    // <idontcare> Locale is ignored </idontcare>
    return _strtold(str, endptr);
}

long double UCRTBase::_strtold(const char *str, char **endptr) {
    trace("_strtold called. Arguments: str=<const char*>[", static_cast<const void*>(str), "], endptr=<char**>[", endptr, "]");
    if (str == nullptr) {
        error("Error set to: -, Return value: 0.0");
        return 0.0;
    }
    errno = 0;
    const long double result = strtold(str, endptr);
    if (endptr != nullptr && *endptr == str) {
        error("Error set to: -, Return value: 0.0");
        return 0.0; // No conversion performed
    }
    if (errno == ERANGE) {
        error("Error set to: ERANGE, Return value: HUGE_VALL, -HUGE_VALL, or 0.0");
        return (result > 0) ? HUGE_VALL : (result < 0) ? -HUGE_VALL : 0.0; // Out of range
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

ULONGLONG UCRTBase::_strtoumax_l(const char *str, char **endptr, int radix, _locale_t) {
    // <idontcare> Locale is ignored </idontcare>
    return _strtoumax(str, endptr, radix);
}

ULONGLONG UCRTBase::_strtoumax(const char *str, char **endptr, int radix) {
    trace("_strtoumax called. Arguments: str=<const char*>[", static_cast<const void*>(str), "], endptr=<char**>[", endptr, "], radix=", std::to_wstring(radix));
    if (str == nullptr) {
        error("Error set to: -, Return value: 0");
        return 0;
    }
    if (radix != 0 && (radix < 2 || radix > 36)) {
        error("Error set to: -, Return value: 0");
        return 0; // Invalid radix
    }
    errno = 0;
    const ULONGLONG result = strtoull(str, endptr, radix);
    if (endptr != nullptr && *endptr == str) {
        error("Error set to: -, Return value: 0");
        return 0; // No conversion performed
    }
    if (errno == ERANGE) {
        error("Error set to: ERANGE, Return value: ULLONG_MAX");
        return ULLONG_MAX; // Out of range
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

ULONGLONG UCRTBase::_strtoui64_l(const char *str, char **endptr, int radix, _locale_t) {
    // <idontcare> Locale is ignored </idontcare>
    return _strtoui64(str, endptr, radix);
}

ULONGLONG UCRTBase::_strtoui64(const char *str, char **endptr, int radix) {
    trace("_strtoui64 called. Arguments: str=<const char*>[", static_cast<const void*>(str), "], endptr=<char**>[", endptr, "], radix=", std::to_wstring(radix));
    if (str == nullptr) {
        error("Error set to: -, Return value: 0");
        return 0;
    }
    if (radix != 0 && (radix < 2 || radix > 36)) {
        error("Error set to: -, Return value: 0");
        return 0; // Invalid radix
    }
    errno = 0;
    const ULONGLONG result = strtoull(str, endptr, radix);
    if (endptr != nullptr && *endptr == str) {
        error("Error set to: -, Return value: 0");
        return 0; // No conversion performed
    }
    if (errno == ERANGE) {
        error("Error set to: ERANGE, Return value: ULLONG_MAX");
        return ULLONG_MAX; // Out of range
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

ULONG UCRTBase::_strotoul_l(const char *str, char **endptr, int radix, _locale_t) {
    // <idontcare> Locale is ignored </idontcare>
    return _strotoul(str, endptr, radix);
}

ULONG UCRTBase::_strotoul(const char *str, char **endptr, int radix) {
    trace("_strotoul called. Arguments: str=<const char*>[", static_cast<const void*>(str), "], endptr=<char**>[", endptr, "], radix=", std::to_wstring(radix));
    if (str == nullptr) {
        error("Error set to: -, Return value: 0");
        return 0;
    }
    if (radix != 0 && (radix < 2 || radix > 36)) {
        error("Error set to: -, Return value: 0");
        return 0; // Invalid radix
    }
    errno = 0;
    const ULONG result = strtoul(str, endptr, radix);
    if (endptr != nullptr && *endptr == str) {
        error("Error set to: -, Return value: 0");
        return 0; // No conversion performed
    }
    if (errno == ERANGE) {
        error("Error set to: ERANGE, Return value: ULONG_MAX");
        return UINT_MAX; // Out of range
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

char * UCRTBase::_ui64toa(ULONGLONG value, char *buffer, int radix) {
    trace("_ui64toa called. Arguments: value=", std::to_wstring(value), ", buffer=<char*>[", static_cast<void*>(buffer), "], radix=", std::to_wstring(radix));
    if (buffer == nullptr) {
        error("Error set to: -, Return value: <char*>[]");
        return nullptr;
    }
    if (radix < 2 || radix > 36) {
        error("Error set to: -, Return value: <char*>[]");
        return nullptr;
    }
    snprintf(buffer, 65, (radix == 10) ? "%llu" : (radix == 16) ? "%llx" : (radix == 8) ? "%llo" : (radix == 2) ? "%llb" : "%llu", value);
    ret("Error set to: -, Return value: <char*>[", static_cast<void*>(buffer), "]");
    return buffer;
}

char * UCRTBase::_ui64toa_s(ULONGLONG value, char *buffer, size_t sizeInChars, int radix) {
    trace("_ui64toa_s called. Arguments: value=", std::to_wstring(value), ", buffer=<char*>[", static_cast<void*>(buffer), "], sizeInChars=", std::to_wstring(sizeInChars), ", radix=", std::to_wstring(radix));
    if (buffer == nullptr || sizeInChars == 0) {
        ret("Error set to: EINVAL, Return value: EINVAL");
        return nullptr;
    }
    if (radix < 2 || radix > 36) {
        ret("Error set to: EINVAL, Return value: EINVAL");
        return nullptr;
    }
    snprintf(buffer, sizeInChars, (radix == 10) ? "%llu" : (radix == 16) ? "%llx" : (radix == 8) ? "%llo" : (radix == 2) ? "%llb" : "%llu", value);
    ret("Error set to: -, Return value: 0");
    return buffer;
}

_wchar_t * UCRTBase::_ui64tow(ULONGLONG value, _wchar_t *buffer, int radix) {
    trace("_ui64tow called. Arguments: value=", std::to_wstring(value), ", buffer=<wchar_t*>[", static_cast<void*>(buffer), "], radix=", std::to_wstring(radix));
    if (buffer == nullptr) {
        error("Error set to: -, Return value: <wchar_t*>[]");
        return nullptr;
    }
    if (radix < 2 || radix > 36) {
        error("Error set to: -, Return value: <wchar_t*>[]");
        return nullptr;
    }
    // similar to _i64tow but without negative handling
    _wchar_t temp[65]; // max 64 digits + null
    int pos = 0;
    // convert number to string in reverse
    do {
        const auto digits = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        temp[pos++] = digits[value % radix];
        value /= radix;
    } while (value && pos < 64);
    // reverse into buffer
    for (int i = 0; i < pos; i++) {
        buffer[i] = temp[pos - 1 - i];
    }
    buffer[pos] = 0;
    ret("Error set to: -, Return value: <wchar_t*>[", static_cast<void*>(buffer), "]");
    return buffer;
}

errno_t UCRTBase::_ui64tow_s(ULONGLONG value, _wchar_t *buffer, size_t sizeInChars, int radix) {
    trace("_ui64tow_s called. Arguments: value=", std::to_wstring(value), ", buffer=<wchar_t*>[", static_cast<void*>(buffer), "], sizeInChars=", std::to_wstring(sizeInChars), ", radix=", std::to_wstring(radix));
    if (buffer == nullptr || sizeInChars == 0) {
        ret("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    if (radix < 2 || radix > 36) {
        ret("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    // similar to _i64tow_s but without negative handling
    _wchar_t temp[65]; // max 64 digits + null
    int pos = 0;
    // convert number to string in reverse
    do {
        const auto digits = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        temp[pos++] = digits[value % radix];
        value /= radix;
    } while (value && pos < 64);
    // Check buffer size
    if (sizeInChars <= static_cast<size_t>(pos)) { // not enough space for digits + null
        buffer[0] = 0; // null-terminate on error as Windows does
        return ERANGE;
    }
    // reverse into buffer
    for (int i = 0; i < pos; i++) {
        buffer[i] = temp[pos - 1 - i];
    }
    buffer[pos] = 0;
    ret("Error set to: -, Return value: 0");
    return 0; // success
}

char * UCRTBase::_ultoa(ULONG value, char *buffer, int radix) {
    trace("_ultoa called. Arguments: value=", std::to_wstring(value), ", buffer=<char*>[", static_cast<void*>(buffer), "], radix=", std::to_wstring(radix));
    if (buffer == nullptr) {
        error("Error set to: -, Return value: <char*>[]");
        return nullptr;
    }
    if (radix < 2 || radix > 36) {
        error("Error set to: -, Return value: <char*>[]");
        return nullptr;
    }
    snprintf(buffer, 33, (radix == 10) ? "%u" : (radix == 16) ? "%x" : (radix == 8) ? "%o" : (radix == 2) ? "%b" : "%u", value);
    ret("Error set to: -, Return value: <char*>[", static_cast<void*>(buffer), "]");
    return buffer;
}

errno_t UCRTBase::_ultoa_s(ULONG value, char *buffer, size_t sizeInChars, int radix) {
    trace("_ultoa_s called. Arguments: value=", std::to_wstring(value), ", buffer=<char*>[", static_cast<void*>(buffer), "], sizeInChars=", std::to_wstring(sizeInChars), ", radix=", std::to_wstring(radix));
    if (buffer == nullptr || sizeInChars == 0) {
        ret("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    if (radix < 2 || radix > 36) {
        ret("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    snprintf(buffer, sizeInChars, (radix == 10) ? "%u" : (radix == 16) ? "%x" : (radix == 8) ? "%o" : (radix == 2) ? "%b" : "%u", value);
    ret("Error set to: -, Return value: 0");
    return 0;
}

_wchar_t * UCRTBase::_ultow(ULONG value, _wchar_t *buffer, int radix) {
    trace("_ultow called. Arguments: value=", std::to_wstring(value), ", buffer=<wchar_t*>[", static_cast<void*>(buffer), "], radix=", std::to_wstring(radix));
    if (buffer == nullptr) {
        error("Error set to: -, Return value: <wchar_t*>[]");
        return nullptr;
    }
    if (radix < 2 || radix > 36) {
        error("Error set to: -, Return value: <wchar_t*>[]");
        return nullptr;
    }
    // similar to _ui64tow but for ULONG
    _wchar_t temp[33]; // max 32 digits + null
    int pos = 0;
    // convert number to string in reverse
    do {
        const auto digits = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        temp[pos++] = digits[value % radix];
        value /= radix;
    } while (value && pos < 32);
    // reverse into buffer
    for (int i = 0; i < pos; i++) {
        buffer[i] = temp[pos - 1 - i];
    }
    buffer[pos] = 0;
    ret("Error set to: -, Return value: <wchar_t*>[", static_cast<void*>(buffer), "]");
    return buffer;
}

errno_t UCRTBase::_ultow_s(ULONG value, _wchar_t *buffer, size_t sizeInChars, int radix) {
    trace("_ultow_s called. Arguments: value=", std::to_wstring(value), ", buffer=<wchar_t*>[", static_cast<void*>(buffer), "], sizeInChars=", std::to_wstring(sizeInChars), ", radix=", std::to_wstring(radix));
    if (buffer == nullptr || sizeInChars == 0) {
        ret("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    if (radix < 2 || radix > 36) {
        ret("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    // similar to _ui64tow_s but for ULONG
    _wchar_t temp[33]; // max 32 digits + null
    int pos = 0;
    // convert number to string in reverse
    do {
        const auto digits = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        temp[pos++] = digits[value % radix];
        value /= radix;
    } while (value && pos < 32);
    // Check buffer size
    if (sizeInChars <= static_cast<size_t>(pos)) { // not enough space for digits + null
        buffer[0] = 0; // null-terminate on error as Windows does
        return ERANGE;
    }
    // reverse into buffer
    for (int i = 0; i < pos; i++) {
        buffer[i] = temp[pos - 1 - i];
    }
    buffer[pos] = 0;
    ret("Error set to: -, Return value: 0");
    return 0; // success
}

double UCRTBase::_wcstod_l(const _wchar_t *str, _wchar_t **endptr, _locale_t) {
    // <idontcare> Locale is ignored </idontcare>
    return _wcstod(str, endptr);
}

double UCRTBase::_wcstod(const _wchar_t *str, _wchar_t **endptr) {
    if (!str) return 0.0;

    // Step 1: convert _wchar_t (16-bit) -> wchar_t (32-bit on Unix)
    size_t len = 0;
    while (str[len]) len++;

    const auto buf = new wchar_t[len + 1];
    for (size_t i = 0; i <= len; i++) buf[i] = str[i];

    errno = 0;
    wchar_t* e = nullptr;
    const double result = std::wcstod(buf, &e);

    // Step 2: adjust endptr to point into _wchar_t* string
    if (endptr) {
        if (e == buf) {
            *endptr = const_cast<_wchar_t*>(str); // no conversion
        } else {
            *endptr = const_cast<_wchar_t*>(str + (e - buf));
        }
    }

    delete[] buf;

    // Step 3: handle range errors
    if (errno == ERANGE) {
        if (result > 0) return HUGE_VAL;
        if (result < 0) return -HUGE_VAL;
        return 0.0;
    }

    return result;
}

float UCRTBase::_wcstof_l(const _wchar_t *str, _wchar_t **endptr, _locale_t) {
    // <idontcare> Locale is ignored </idontcare>
    return _wcstof(str, endptr);
}

float UCRTBase::_wcstof(const _wchar_t *str, _wchar_t **endptr) {
    if (!str) return 0.0;

    // Step 1: convert _wchar_t (16-bit) -> wchar_t (32-bit on Unix)
    size_t len = 0;
    while (str[len]) len++;

    const auto buf = new wchar_t[len + 1];
    for (size_t i = 0; i <= len; i++) buf[i] = str[i];

    errno = 0;
    wchar_t* e = nullptr;
    const float result = std::wcstof(buf, &e);

    // Step 2: adjust endptr to point into _wchar_t* string
    if (endptr) {
        if (e == buf) {
            *endptr = const_cast<_wchar_t*>(str); // no conversion
        } else {
            *endptr = const_cast<_wchar_t*>(str + (e - buf));
        }
    }

    delete[] buf;

    // Step 3: handle range errors
    if (errno == ERANGE) {
        if (result > 0) return static_cast<float>(HUGE_VAL);
        if (result < 0) return static_cast<float>(-HUGE_VAL);
        return 0.0;
    }

    return result;
}

LONGLONG UCRTBase::_wcstoi64_l(const _wchar_t *str, _wchar_t **endptr, int radix, _locale_t) {
    // <idontcare> Locale is ignored </idontcare>
    return _wcstoi64(str, endptr, radix);
}

LONGLONG UCRTBase::_wcstoi64(const _wchar_t *str, _wchar_t **endptr, int radix) {
    if (!str) {
        if (endptr) *endptr = nullptr;
        return 0;
    }
    if (radix != 0 && (radix < 2 || radix > 36)) {
        if (endptr) *endptr = const_cast<_wchar_t*>(str);
        return 0;
    }

    // Convert _wchar_t (16-bit) -> wchar_t (32-bit) for Unix wcstoll
    size_t len = 0;
    while (str[len]) len++;

    auto buf = new wchar_t[len + 1];
    for (size_t i = 0; i <= len; i++) buf[i] = str[i];

    errno = 0;
    wchar_t* e = nullptr;
    LONGLONG result = std::wcstoll(buf, &e, radix);

    // Adjust endptr to point into the original _wchar_t * buffer
    if (endptr) {
        if (e == buf) {
            *endptr = const_cast<_wchar_t*>(str); // no conversion
        } else {
            *endptr = const_cast<_wchar_t*>(str + (e - buf));
        }
    }

    delete[] buf;

    // Handle overflow/underflow
    if (errno == ERANGE) {
        if (result > 0) return LLONG_MAX;
        if (result < 0) return LLONG_MIN;
        return 0;
    }

    return result;
}

LONGLONG UCRTBase::_wcstoimax_l(const _wchar_t *str, _wchar_t **endptr, int radix, _locale_t) {
    // <idontcare> Locale is ignored </idontcare>
    return _wcstoimax(str, endptr, radix);
}

LONGLONG UCRTBase::_wcstoimax(const _wchar_t *str, _wchar_t **endptr, int radix) {
    trace("_wcstoimax called. Arguments: str=<const _wchar_t*>[", static_cast<const void*>(str), "], endptr=<wchar_t**>[", endptr, "], radix=", std::to_wstring(radix));
    return _wcstoi64(str, endptr, radix);
}

LONG UCRTBase::_wcstol_l(const _wchar_t *str, _wchar_t **endptr, int radix, _locale_t) {
    // <idontcare> Locale is ignored </idontcare>
    return _wcstol(str, endptr, radix);
}

LONG UCRTBase::_wcstol(const _wchar_t *str, _wchar_t **endptr, int radix) {
    trace("_wcstol called. Arguments: str=<const _wchar_t*>[", static_cast<const void*>(str), "], endptr=<wchar_t**>[", endptr, "], radix=", std::to_wstring(radix));
    if (!str) {
        if (endptr) *endptr = nullptr;
        return 0;
    }
    if (radix != 0 && (radix < 2 || radix > 36)) {
        if (endptr) *endptr = const_cast<_wchar_t*>(str);
        return 0;
    }

    // Convert _wchar_t (16-bit) -> wchar_t (32-bit) for Unix wcstoll
    size_t len = 0;
    while (str[len]) len++;

    const auto buf = new wchar_t[len + 1];
    for (size_t i = 0; i <= len; i++) buf[i] = str[i];

    errno = 0;
    wchar_t* e = nullptr;
    const LONG result = static_cast<LONG>(std::wcstol(buf, &e, radix));

    // Adjust endptr to point into the original _wchar_t * buffer
    if (endptr) {
        if (e == buf) {
            *endptr = const_cast<_wchar_t*>(str); // no conversion
        } else {
            *endptr = const_cast<_wchar_t*>(str + (e - buf));
        }
    }

    delete[] buf;

    // Handle overflow/underflow
    if (errno == ERANGE) {
        if (result > 0) return INT_MAX;
        if (result < 0) return INT_MIN;
        return 0;
    }

    return result;
}

long double UCRTBase::_wcstold_l(const _wchar_t *str, _wchar_t **endptr, _locale_t) {
    // <idontcare> Locale is ignored </idontcare>
    return _wcstold(str, endptr);
}

long double UCRTBase::_wcstold(const _wchar_t *str, _wchar_t **endptr) {
    trace("_wcstold called. Arguments: str=<const _wchar_t*>[", static_cast<const void*>(str), "], endptr=<wchar_t**>[", endptr, "]");
    if (!str) return 0.0;

    // Step 1: convert _wchar_t (16-bit) -> wchar_t (32-bit on Unix)
    size_t len = 0;
    while (str[len]) len++;

    const auto buf = new wchar_t[len + 1];
    for (size_t i = 0; i <= len; i++) buf[i] = str[i];

    errno = 0;
    wchar_t* e = nullptr;
    const long double result = std::wcstold(buf, &e);

    // Step 2: adjust endptr to point into _wchar_t* string
    if (endptr) {
        if (e == buf) {
            *endptr = const_cast<_wchar_t*>(str); // no conversion
        } else {
            *endptr = const_cast<_wchar_t*>(str + (e - buf));
        }
    }

    delete[] buf;

    // Step 3: handle range errors
    if (errno == ERANGE) {
        if (result > 0) return HUGE_VAL;
        if (result < 0) return -HUGE_VAL;
        return 0.0;
    }

    return result;
}

LONGLONG UCRTBase::_wcstoll_l(const _wchar_t *str, _wchar_t **endptr, int radix, _locale_t) {
    // <idontcare> Locale is ignored </idontcare>
    return _wcstoll(str, endptr, radix);
}

LONGLONG UCRTBase::_wcstoll(const _wchar_t *str, _wchar_t **endptr, int radix) {
    trace("_wcstoll called. Arguments: str=<const _wchar_t*>[", static_cast<const void*>(str), "], endptr=<wchar_t**>[", endptr, "], radix=", std::to_wstring(radix));
    return _wcstoi64(str, endptr, radix);
}

ULONGLONG UCRTBase::_wcstoull_l(const _wchar_t *str, _wchar_t **endptr, int radix, _locale_t) {
    // <idontcare> Locale is ignored </idontcare>
    return _wcstoull(str, endptr, radix);
}

ULONGLONG UCRTBase::_wcstoull(const _wchar_t *str, _wchar_t **endptr, int radix) {
    trace("_wcstoull called. Arguments: str=<const _wchar_t*>[", static_cast<const void*>(str), "], endptr=<wchar_t**>[", endptr, "], radix=", std::to_wstring(radix));
    return _wcstoui64(str, endptr, radix);
}

size_t UCRTBase::_wcstombs_l(char *dest, const _wchar_t *src, size_t n, _locale_t) {
    // <idontcare> Locale is ignored </idontcare>
    return _wcstombs(dest, src, n);
}

size_t UCRTBase::_wcstombs(char *dest, const _wchar_t *src, size_t n) {
    if (!src || (dest == nullptr && n != 0)) {
        return -1; // EINVAL
    }

    // Step 1: Convert _wchar_t (16-bit) -> wchar_t (32-bit)
    size_t len = 0;
    while (src[len]) len++;

    const auto buf = new wchar_t[len + 1];
    for (size_t i = 0; i <= len; i++) buf[i] = src[i];

    // Step 2: Perform conversion
    size_t converted = 0;
    if (dest) {
        converted = std::wcstombs(dest, buf, n);
        if (converted == static_cast<size_t>(-1)) {
            delete[] buf;
            return -1; // Invalid wide char sequence
        }
    } else {
        converted = std::wcstombs(nullptr, buf, 0); // get required length
    }

    delete[] buf;
    return converted;
}

errno_t UCRTBase::_wcstombs_s_l(size_t *pReturnValue, char *dest, size_t destSize, const _wchar_t *src, size_t n,
    _locale_t) {
    // <idontcare> Locale is ignored </idontcare>
    return _wcstombs_s(pReturnValue, dest, destSize, src, n);
}

errno_t UCRTBase::_wcstombs_s(size_t *pReturnValue, char *dest, size_t destSize, const _wchar_t *src, size_t n) {
    if (pReturnValue) *pReturnValue = 0;

    if (!src || (!dest && destSize != 0)) return EINVAL;

    // Step 1: convert _wchar_t (16-bit) -> wchar_t (32-bit)
    size_t len = 0;
    while (src[len]) len++;

    const auto buf = new wchar_t[len + 1];
    for (size_t i = 0; i <= len; i++) buf[i] = src[i];

    // Step 2: compute the number of bytes needed
    const size_t required = std::wcstombs(nullptr, buf, 0);
    if (required == static_cast<size_t>(-1)) {
        delete[] buf;
        return EILSEQ;
    }

    // Step 3: determine the actual number of bytes to copy
    size_t toCopy = (n == static_cast<size_t>(-1) || n > required) ? required : n;

    if (destSize < toCopy + 1) { // +1 for null terminator
        delete[] buf;
        return ERANGE;
    }

    // Step 4: perform actual conversion
    const size_t converted = std::wcstombs(dest, buf, toCopy);
    delete[] buf;

    if (converted == static_cast<size_t>(-1)) return EILSEQ;

    if (dest && destSize > converted) dest[converted] = '\0';
    if (pReturnValue) *pReturnValue = converted;

    return 0; // success
}

size_t UCRTBase::_mbstowcs_l(_wchar_t *dest, const char *src, size_t n, _locale_t) {
    // <idontcare> Locale is ignored </idontcare>
    return _mbstowcs(dest, src, n);
}

size_t UCRTBase::_mbstowcs(_wchar_t *dest, const char *src, size_t n) {
    if (!src || (dest == nullptr && n != 0)) {
        return -1; // EINVAL
    }

    // Step 1: Convert char* -> wchar_t* (32-bit)
    size_t len = 0;
    while (src[len]) len++;

    const auto buf = new wchar_t[len + 1];
    size_t converted = std::mbstowcs(buf, src, len + 1);
    if (converted == static_cast<size_t>(-1)) {
        delete[] buf;
        return -1; // Invalid multibyte sequence
    }

    // Step 2: Convert wchar_t* (32-bit) -> _wchar_t* (16-bit)
    if (dest) {
        size_t toCopy = (n > converted) ? converted : n;
        for (size_t i = 0; i < toCopy; i++) {
            dest[i] = static_cast<_wchar_t>(buf[i]);
        }
        if (n > toCopy) dest[toCopy] = 0; // null-terminate if space
    }

    delete[] buf;
    return converted;
}

errno_t UCRTBase::_mbstowcs_s_l(size_t *pReturnValue, _wchar_t *dest, size_t destSize, const char *src, size_t n,
    _locale_t) {
    // <idontcare> Locale is ignored </idontcare>
    return _mbstowcs_s(pReturnValue, dest, destSize, src, n);
}

errno_t UCRTBase::_mbstowcs_s(size_t *pReturnValue, _wchar_t *dest, size_t destSize, const char *src, size_t n) {
    if (pReturnValue) *pReturnValue = 0;

    if (!src || (!dest && destSize != 0)) return EINVAL;

    // Step 1: Convert char* -> wchar_t* (32-bit)
    size_t len = 0;
    while (src[len]) len++;

    const auto buf = new wchar_t[len + 1];
    size_t converted = std::mbstowcs(buf, src, len + 1);
    if (converted == static_cast<size_t>(-1)) {
        delete[] buf;
        return EILSEQ;
    }

    // Step 2: Determine how many characters to copy
    size_t toCopy = (n == static_cast<size_t>(-1) || n > converted) ? converted : n;

    if (destSize < toCopy + 1) { // +1 for null terminator
        delete[] buf;
        return ERANGE;
    }

    // Step 3: Convert wchar_t* (32-bit) -> _wchar_t* (16-bit)
    for (size_t i = 0; i < toCopy; i++) {
        dest[i] = static_cast<_wchar_t>(buf[i]);
    }
    if (dest && destSize > toCopy) dest[toCopy] = 0; // null-terminate if space
    if (pReturnValue) *pReturnValue = toCopy;

    delete[] buf;
    return 0; // success
}

ULONGLONG UCRTBase::_wcstoui64_l(const _wchar_t *str, _wchar_t **endptr, int radix, _locale_t) {
    // <idontcare> Locale is ignored </idontcare>
    return _wcstoui64(str, endptr, radix);
}

ULONGLONG UCRTBase::_wcstoui64(const _wchar_t *str, _wchar_t **endptr, int radix) {
    if (!str) {
        if (endptr) *endptr = nullptr;
        return 0;
    }
    if (radix != 0 && (radix < 2 || radix > 36)) {
        if (endptr) *endptr = const_cast<_wchar_t*>(str);
        return 0;
    }

    // Convert _wchar_t (16-bit) -> wchar_t (32-bit)
    size_t len = 0;
    while (str[len]) len++;

    const auto buf = new wchar_t[len + 1];
    for (size_t i = 0; i <= len; i++) buf[i] = str[i];

    errno = 0;
    wchar_t* e = nullptr;
    const ULONGLONG result = std::wcstoull(buf, &e, radix);

    // Adjust endptr to the original _ wchar_t * buffer
    if (endptr) {
        if (e == buf) {
            *endptr = const_cast<_wchar_t*>(str);
        } else {
            *endptr = const_cast<_wchar_t*>(str + (e - buf));
        }
    }

    delete[] buf;

    // Handle overflow
    if (errno == ERANGE) return ULLONG_MAX;

    return result;
}

ULONG UCRTBase::_wcstoul_l(const _wchar_t *str, _wchar_t **endptr, int radix, _locale_t) {
    // <idontcare> Locale is ignored </idontcare>
    return _wcstoul(str, endptr, radix);
}

ULONG UCRTBase::_wcstoul(const _wchar_t *str, _wchar_t **endptr, int radix) {
    if (!str) {
        if (endptr) *endptr = nullptr;
        return 0;
    }
    if (radix != 0 && (radix < 2 || radix > 36)) {
        if (endptr) *endptr = const_cast<_wchar_t*>(str);
        return 0;
    }

    // Step 1: Convert _wchar_t (16-bit) -> wchar_t (32-bit)
    size_t len = 0;
    while (str[len]) len++;

    const auto buf = new wchar_t[len + 1];
    for (size_t i = 0; i <= len; i++) buf[i] = str[i];

    // Step 2: Call standard wcstoul
    errno = 0;
    wchar_t* e = nullptr;
    const ULONG result = std::wcstoul(buf, &e, radix);

    // Step 3: Adjust endptr to the original _ wchar_t * buffer
    if (endptr) {
        if (e == buf) {
            *endptr = const_cast<_wchar_t*>(str); // no conversion
        } else {
            *endptr = const_cast<_wchar_t*>(str + (e - buf));
        }
    }

    delete[] buf;

    // Step 4: Handle overflow
    if (errno == ERANGE) return INT_MAX;

    return result;
}

int UCRTBase::_wctomb_l(char *dest, _wchar_t ch, _locale_t) {
    // <idontcare> Locale is ignored </idontcare>
    return _wctomb(dest, ch);
}

int UCRTBase::_wctomb(char *dest, _wchar_t ch) {
    trace("_wctomb called. Arguments: dest=<char*>[", static_cast<void*>(dest), "], ch=", std::to_wstring(static_cast<int>(ch)));
    if (dest == nullptr) {
        error("Error set to: EINVAL, Return value: -1");
        return -1;
    }
    // use wctomb
    const int result = wctomb(dest, ch);
    if (result == -1) {
        error("Error set to: EILSEQ, Return value: -1");
        return -1; // Conversion error
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

int UCRTBase::_wctomb_s_l(size_t *pReturnValue, char *dest, size_t destSize, _wchar_t ch, _locale_t) {
    // <idontcare> Locale is ignored </idontcare>
    return _wctomb_s(pReturnValue, dest, destSize, ch);
}

int UCRTBase::_wctomb_s(size_t *pReturnValue, char *dest, size_t destSize, _wchar_t ch) {
    trace("_wctomb_s called. Arguments: pReturnValue=<size_t*>[", pReturnValue, "], dest=<char*>[", static_cast<void*>(dest), "], destSize=", std::to_wstring(destSize), ", ch=", std::to_wstring(static_cast<int>(ch)));
    if (pReturnValue != nullptr) {
        *pReturnValue = 0;
    }
    if (dest == nullptr && destSize != 0) {
        if (pReturnValue != nullptr) {
            *pReturnValue = 0;
        }
        error("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    if (destSize == 0) {
        if (pReturnValue != nullptr) {
            *pReturnValue = 0;
        }
        error("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    // use wctomb
    const int result = wctomb(dest, ch);
    if (result == -1) {
        if (pReturnValue != nullptr) {
            *pReturnValue = 0;
        }
        error("Error set to: EILSEQ, Return value: EILSEQ");
        return EILSEQ; // Conversion error
    }
    if (static_cast<size_t>(result) >= destSize) {
        if (pReturnValue != nullptr) {
            *pReturnValue = 0;
        }
        error("Error set to: ERANGE, Return value: ERANGE");
        return ERANGE; // Not enough space
    }
    if (pReturnValue != nullptr) {
        *pReturnValue = static_cast<size_t>(result);
    }
    ret("Error set to: -, Return value: 0");
    return 0; // Success
}

float UCRTBase::_wtof_l(const _wchar_t *str, _wchar_t **endptr, _locale_t) {
    // <idontcare> Locale is ignored </idontcare>
    return _wtof(str, endptr);
}

float UCRTBase::_wtof(const _wchar_t *str, _wchar_t **endptr) {
    if (!str) {
        if (endptr) *endptr = nullptr;
        return 0.0f;
    }

    // Convert _wchar_t (16-bit) -> wchar_t (32-bit)
    size_t len = 0;
    while (str[len]) len++;

    const auto buf = new wchar_t[len + 1];
    for (size_t i = 0; i <= len; i++) buf[i] = str[i];

    errno = 0;
    wchar_t* e = nullptr;
    const float result = std::wcstof(buf, &e);

    // Adjust endptr to the original _ wchar_t * buffer
    if (endptr) {
        if (e == buf) {
            *endptr = const_cast<_wchar_t*>(str); // no conversion
        } else {
            *endptr = const_cast<_wchar_t*>(str + (e - buf));
        }
    }

    delete[] buf;

    // Handle overflow / underflow
    if (errno == ERANGE) {
        if (result > 0) return HUGE_VALF;
        if (result < 0) return -HUGE_VALF;
        return 0.0f;
    }

    return result;
}

int UCRTBase::_wtoi_l(const _wchar_t *str, _wchar_t **endptr, _locale_t) {
    // <idontcare> Locale is ignored </idontcare>
    return _wtoi(str, endptr);
}

int UCRTBase::_wtoi(const _wchar_t *str, _wchar_t **endptr) {
    trace("_wtoi called. Arguments: str=<const _wchar_t*>[", static_cast<const void*>(str), "], endptr=<wchar_t**>[", endptr, "]");
    return _wcstol(str, endptr, 10); // long == int on Windows
}

LONGLONG UCRTBase::_wtoi64_l(const _wchar_t *str, _wchar_t **endptr, _locale_t) {
    // <idontcare> Locale is ignored </idontcare>
    return _wtoi64(str, endptr);
}

LONGLONG UCRTBase::_wtoi64(const _wchar_t *str, _wchar_t **endptr) {
    trace("_wtoi64 called. Arguments: str=<const _wchar_t*>[", static_cast<const void*>(str), "], endptr=<wchar_t**>[", endptr, "]");
    return _wcstoi64(str, endptr, 10);
}

LONG UCRTBase::_wtol_l(const _wchar_t *str, _wchar_t **endptr, _locale_t) {
    // <idontcare> Locale is ignored </idontcare>
    return _wtol(str, endptr);
}

LONG UCRTBase::_wtol(const _wchar_t *str, _wchar_t **endptr) {
    trace("_wtol called. Arguments: str=<const _wchar_t*>[", static_cast<const void*>(str), "], endptr=<wchar_t**>[", endptr, "]");
    return _wcstol(str, endptr, 10);
}

LONGLONG UCRTBase::_wtoll_l(const _wchar_t *str, _wchar_t **endptr, _locale_t) {
    // <idontcare> Locale is ignored </idontcare>
    return _wtoll(str, endptr);
}

LONGLONG UCRTBase::_wtoll(const _wchar_t *str, _wchar_t **endptr) {
    trace("_wtoll called. Arguments: str=<const _wchar_t*>[", static_cast<const void*>(str), "], endptr=<wchar_t**>[", endptr, "]");
    return _wcstoll(str, endptr, 10);
}

float UCRTBase::atof(const char *str) {
    trace("atof called. Arguments: str=<const char*>[", static_cast<const void*>(str), "]");
    if (str == nullptr) {
        error("Error set to: -, Return value: 0.0f");
        return 0.0f;
    }
    errno = 0;
    const float result = strtof(str, nullptr);
    if (errno == ERANGE) {
        error("Error set to: ERANGE, Return value: HUGE_VALF, -HUGE_VALF, or 0.0f");
        return (result > 0) ? HUGE_VALF : (result < 0) ? -HUGE_VALF : 0.0f; // Out of range
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

int UCRTBase::atoi(const char *str) {
    trace("atoi called. Arguments: str=<const char*>[", static_cast<const void*>(str), "]");
    if (str == nullptr) {
        error("Error set to: -, Return value: 0");
        return 0;
    }
    errno = 0;
    const int result = static_cast<int>(strtol(str, nullptr, 10));
    if (errno == ERANGE) {
        error("Error set to: ERANGE, Return value: INT_MAX or INT_MIN");
        return (result > 0) ? INT_MAX : INT_MIN; // Out of range
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

LONG UCRTBase::atol(const char *str) {
    trace("atol called. Arguments: str=<const char*>[", static_cast<const void*>(str), "]");
    if (str == nullptr) {
        error("Error set to: -, Return value: 0");
        return 0;
    }
    errno = 0;
    const LONG result = static_cast<LONG>(strtol(str, nullptr, 10));
    if (errno == ERANGE) {
        error("Error set to: ERANGE, Return value: LONG_MAX or LONG_MIN");
        return (result > 0) ? INT_MAX : INT_MIN; // Out of range (also LONG == int not long bcz Windows has 32bit long)
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

long long UCRTBase::atoll(const char *str) {
    trace("atoll called. Arguments: str=<const char*>[", static_cast<const void*>(str), "]");
    if (str == nullptr) {
        error("Error set to: -, Return value: 0");
        return 0;
    }
    errno = 0;
    const long long result = strtoll(str, nullptr, 10);
    if (errno == ERANGE) {
        error("Error set to: ERANGE, Return value: LLONG_MAX or LLONG_MIN");
        return (result > 0) ? LLONG_MAX : LLONG_MIN; // Out of range
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

_wchar_t UCRTBase::btowc(char c) {
    trace("btowc called. Arguments: c=", std::to_wstring(static_cast<int>(c)));
    const _wchar_t result = c;
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

size_t UCRTBase::c16rtomb(char *dest, char16_t ch, mbstate_t *state) {
    trace("c16rtomb called. Arguments: dest=<char*>[", static_cast<void*>(dest), "], ch=", std::to_wstring(static_cast<int>(ch)), ", state=<mbstate_t*>[", state, "]");
    if (dest == nullptr) {
        error("Error set to: EINVAL, Return value: -1");
        return static_cast<size_t>(-1);
    }
    return std::c16rtomb(dest, ch, state);
}

size_t UCRTBase::c32rtomb(char *dest, char32_t ch, mbstate_t *state) {
    trace("c32rtomb called. Arguments: dest=<char*>[", static_cast<void*>(dest), "], ch=", std::to_wstring(static_cast<int>(ch)), ", state=<mbstate_t*>[", state, "]");
    if (dest == nullptr) {
        error("Error set to: EINVAL, Return value: -1");
        return static_cast<size_t>(-1);
    }
    return std::c32rtomb(dest, ch, state);
}

size_t UCRTBase::mbrtoc16(char16_t *dest, const char *src, size_t n, mbstate_t *state) {
    trace("mbrtoc16 called. Arguments: dest=<char16_t*>[", static_cast<void*>(dest), "], nt_apiset_cpp_hooks=<const char*>[", static_cast<const void*>(src), "], n=", std::to_wstring(n), ", state=<mbstate_t*>[", state, "]");
    if (src == nullptr) {
        error("Error set to: EINVAL, Return value: -1");
        return static_cast<size_t>(-1);
    }
    return std::mbrtoc16(dest, src, n, state);
}

size_t UCRTBase::mbrtoc32(char32_t *dest, const char *src, size_t n, mbstate_t *state) {
    trace("mbrtoc32 called. Arguments: dest=<char32_t*>[", static_cast<void*>(dest), "], nt_apiset_cpp_hooks=<const char*>[", static_cast<const void*>(src), "], n=", std::to_wstring(n), ", state=<mbstate_t*>[", state, "]");
    if (src == nullptr) {
        error("Error set to: EINVAL, Return value: -1");
        return static_cast<size_t>(-1);
    }
    return std::mbrtoc32(dest, src, n, state);
}

size_t UCRTBase::mbrtowc(_wchar_t *dest, const char *src, size_t n, mbstate_t *state) {
    if (!src) {
        errno = EINVAL;
        return static_cast<size_t>(-1);
    }

    wchar_t wc;
    const size_t ret = std::mbrtowc(&wc, src, n, state);

    if (ret != static_cast<size_t>(-1) && ret != static_cast<size_t>(-2)) {
        // conversion succeeded: store in 16-bit _wchar_t
        if (dest) *dest = static_cast<_wchar_t>(wc & 0xFFFF);
    }

    return ret;
}

int UCRTBase::mbsinit(const mbstate_t *state) {
    trace("mbsinit called. Arguments: state=<const mbstate_t*>[", state, "]");
    if (state == nullptr) {
        error("Error set to: EINVAL, Return value: 1");
        return 1; // Consider null state as initial state
    }
    return std::mbsinit(state);
}

size_t UCRTBase::mbsrtowcs(_wchar_t *dest, const char **src, size_t len, mbstate_t *state) {
    if (!src || !*src) {
        errno = EINVAL;
        return static_cast<size_t>(-1);
    }

    // Temporary buffer for 32-bit wchar_t conversion
    wchar_t* tmp = dest ? new wchar_t[len] : nullptr;

    size_t ret = std::mbsrtowcs(tmp, src, len, state);

    if (ret != static_cast<size_t>(-1) && ret != static_cast<size_t>(-2) && dest) {
        for (size_t i = 0; i < ret; ++i) {
            dest[i] = static_cast<_wchar_t>(tmp[i] & 0xFFFF);
        }
    }

    delete[] tmp;
    return ret;
}

errno_t UCRTBase::mbsrtowcs_s(size_t *pReturnValue, _wchar_t *dest, size_t destSize, const char **src, size_t len,
    mbstate_t *state) {
    if (pReturnValue) *pReturnValue = 0;

    if (!src || !*src || (dest == nullptr && destSize != 0) || destSize == 0) {
        return EINVAL;
    }

    // Step 1: convert _wchar_t → wchar_t temporary buffer
    const auto tmp = new wchar_t[destSize];

    // Step 2: compute the required size
    const size_t required = std::mbsrtowcs(nullptr, src, 0, state);
    if (required == static_cast<size_t>(-1)) {
        delete[] tmp;
        return EILSEQ;
    }

    // Step 3: determine how many chars to convert
    const size_t toConvert = (len == static_cast<size_t>(-1) || len > required) ? required : len;

    if (destSize < toConvert + 1) { // +1 for null terminator
        delete[] tmp;
        return ERANGE;
    }

    // Step 4: perform conversion
    const size_t actual = std::mbsrtowcs(tmp, src, toConvert, state);
    if (actual == static_cast<size_t>(-1)) {
        delete[] tmp;
        return EILSEQ;
    }

    // Step 5: copy to 16-bit _wchar_t and null-terminate
    if (dest) {
        for (size_t i = 0; i < actual; ++i) {
            dest[i] = static_cast<_wchar_t>(tmp[i] & 0xFFFF);
        }
        dest[actual] = 0;
    }

    delete[] tmp;

    if (pReturnValue) *pReturnValue = actual;

    return 0; // success
}

size_t UCRTBase::mbtowc(_wchar_t *dest, const char *src, size_t n) {
    trace("mbtowc called. Arguments: dest=<wchar_t*>[", static_cast<void*>(dest), "], nt_apiset_cpp_hooks=<const char*>[", static_cast<const void*>(src), "], n=", std::to_wstring(n));
    if (src == nullptr) {
        error("Error set to: EINVAL, Return value: -1");
        return -1;
    }
    if (dest == nullptr) {
        error("Error set to: EINVAL, Return value: -1");
        return -1;
    }
    wchar_t wc;
    const size_t result = std::mbrtowc(&wc, src, n, nullptr);
    if (result == -1) {
        error("Error set to: EILSEQ, Return value: -1");
        return -1; // Conversion error
    }
    if (result == -2) {
        error("Error set to: -, Return value: -2");
        return -2; // Incomplete multibyte sequence
    }
    *dest = static_cast<_wchar_t>(wc & 0xFFFF); // Store as 16-bit _wchar_t
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

double UCRTBase::strtod_l(const char *str, char **endptr, _locale_t) {
    // <idontcare> Locale is ignored </idontcare>
    return strtod_(str, endptr);
}

double UCRTBase::strtod_(const char *str, char **endptr) {
    trace("strtod called. Arguments: str=<const char*>[", static_cast<const void*>(str), "], endptr=<char**>[", endptr, "]");
    if (str == nullptr) {
        error("Error set to: -, Return value: 0.0");
        return 0.0;
    }
    errno = 0;
    const double result = std::strtod(str, endptr);
    if (endptr != nullptr && *endptr == str) {
        error("Error set to: -, Return value: 0.0");
        return 0.0; // No conversion performed
    }
    if (errno == ERANGE) {
        error("Error set to: ERANGE, Return value: HUGE_VAL, -HUGE_VAL, or 0.0");
        return (result > 0) ? HUGE_VAL : (result < 0) ? -HUGE_VAL : 0.0; // Out of range
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

float UCRTBase::strtof_l(const char *str, char **endptr, _locale_t) {
    // <idontcare> Locale is ignored </idontcare>
    return strtof_(str, endptr);
}

float UCRTBase::strtof_(const char *str, char **endptr) {
    trace("strtof called. Arguments: str=<const char*>[", static_cast<const void*>(str), "], endptr=<char**>[", endptr, "]");
    if (str == nullptr) {
        error("Error set to: -, Return value: 0.0f");
        return 0.0f;
    }
    errno = 0;
    const float result = std::strtof(str, endptr);
    if (endptr != nullptr && *endptr == str) {
        error("Error set to: -, Return value: 0.0f");
        return 0.0f; // No conversion performed
    }
    if (errno == ERANGE) {
        error("Error set to: ERANGE, Return value: HUGE_VALF, -HUGE_VALF, or 0.0f");
        return (result > 0) ? HUGE_VALF : (result < 0) ? -HUGE_VALF : 0.0f; // Out of range
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

LONGLONG UCRTBase::strtoimax_l(const char *str, char **endptr, int radix, _locale_t) {
    // <idontcare> Locale is ignored </idontcare>
    return strtoimax_(str, endptr, radix);
}

intmax_t UCRTBase::strtoimax_(const char *str, char **endptr, int radix) {
    trace("strtoimax called. Arguments: str=<const char*>[", static_cast<const void*>(str), "], endptr=<char**>[", endptr, "], radix=", std::to_wstring(radix));
    if (str == nullptr) {
        error("Error set to: -, Return value: 0");
        return 0;
    }
    if (radix != 0 && (radix < 2 || radix > 36)) {
        error("Error set to: -, Return value: 0");
        return 0; // Invalid radix
    }
    errno = 0;
    const LONGLONG result = std::strtoimax(str, endptr, radix);
    if (endptr != nullptr && *endptr == str) {
        error("Error set to: -, Return value: 0");
        return 0; // No conversion performed
    }
    if (errno == ERANGE) {
        error("Error set to: ERANGE, Return value: LLONG_MAX or LLONG_MIN");
        return (result > 0) ? LLONG_MAX : LLONG_MIN; // Out of range
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

LONG UCRTBase::strtol_l(const char *str, char **endptr, int radix, _locale_t) {
    // <idontcare> Locale is ignored </idontcare>
    return strtol_(str, endptr, radix);
}

LONG UCRTBase::strtol_(const char *str, char **endptr, int radix) {
    trace("strtol called. Arguments: str=<const char*>[", static_cast<const void*>(str), "], endptr=<char**>[", endptr, "], radix=", std::to_wstring(radix));
    if (str == nullptr) {
        error("Error set to: -, Return value: 0");
        return 0;
    }
    if (radix != 0 && (radix < 2 || radix > 36)) {
        error("Error set to: -, Return value: 0");
        return 0; // Invalid radix
    }
    errno = 0;
    const LONG result = static_cast<LONG>(std::strtol(str, endptr, radix));
    if (endptr != nullptr && *endptr == str) {
        error("Error set to: -, Return value: 0");
        return 0; // No conversion performed
    }
    if (errno == ERANGE) {
        error("Error set to: ERANGE, Return value: LONG_MAX or LONG_MIN");
        return (result > 0) ? INT_MAX : INT_MIN; // Out of range
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

long double UCRTBase::strtold_l(const char *str, char **endptr, _locale_t) {
    // <idontcare> Locale is ignored </idontcare>
    return strtold_(str, endptr);
}

long double UCRTBase::strtold_(const char *str, char **endptr) {
    trace("strtold called. Arguments: str=<const char*>[", static_cast<const void*>(str), "], endptr=<char**>[", endptr, "]");
    if (str == nullptr) {
        error("Error set to: -, Return value: 0.0");
        return 0.0;
    }
    errno = 0;
    const long double result = std::strtold(str, endptr);
    if (endptr != nullptr && *endptr == str) {
        error("Error set to: -, Return value: 0.0");
        return 0.0; // No conversion performed
    }
    if (errno == ERANGE) {
        error("Error set to: ERANGE, Return value: HUGE_VALL, -HUGE_VALL, or 0.0");
        return (result > 0) ? HUGE_VALL : (result < 0) ? -HUGE_VALL : 0.0; // Out of range
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

LONGLONG UCRTBase::strtoll_l(const char *str, char **endptr, int radix, _locale_t) {
    // <idontcare> Locale is ignored </idontcare>
    return strtoll_(str, endptr, radix);
}

LONGLONG UCRTBase::strtoll_(const char *str, char **endptr, int radix) {
    trace("strtoll called. Arguments: str=<const char*>[", static_cast<const void*>(str), "], endptr=<char**>[", endptr, "], radix=", std::to_wstring(radix));
    if (str == nullptr) {
        error("Error set to: -, Return value: 0");
        return 0;
    }
    if (radix != 0 && (radix < 2 || radix > 36)) {
        error("Error set to: -, Return value: 0");
        return 0; // Invalid radix
    }
    errno = 0;
    const LONGLONG result = std::strtoll(str, endptr, radix);
    if (endptr != nullptr && *endptr == str) {
        error("Error set to: -, Return value: 0");
        return 0; // No conversion performed
    }
    if (errno == ERANGE) {
        error("Error set to: ERANGE, Return value: LLONG_MAX or LLONG_MIN");
        return (result > 0) ? LLONG_MAX : LLONG_MIN; // Out of range
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

ULONG UCRTBase::strtoul_l(const char *str, char **endptr, int radix, _locale_t) {
    // <idontcare> Locale is ignored </idontcare>
    return strtoul_(str, endptr, radix);
}

ULONG UCRTBase::strtoul_(const char *str, char **endptr, int radix) {
    trace("strtoul called. Arguments: str=<const char*>[", static_cast<const void*>(str), "], endptr=<char**>[", endptr, "], radix=", std::to_wstring(radix));
    if (str == nullptr) {
        error("Error set to: -, Return value: 0");
        return 0;
    }
    if (radix != 0 && (radix < 2 || radix > 36)) {
        error("Error set to: -, Return value: 0");
        return 0; // Invalid radix
    }
    errno = 0;
    const auto result = static_cast<ULONG>(std::strtoul(str, endptr, radix));
    if (endptr != nullptr && *endptr == str) {
        error("Error set to: -, Return value: 0");
        return 0; // No conversion performed
    }
    if (errno == ERANGE) {
        error("Error set to: ERANGE, Return value: ULONG_MAX");
        return UINT_MAX; // Out of range
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

ULONGLONG UCRTBase::strtoull_l(const char *str, char **endptr, int radix, _locale_t) {
    // <idontcare> Locale is ignored </idontcare>
    return strtoull_(str, endptr, radix);
}

ULONGLONG UCRTBase::strtoull_(const char *str, char **endptr, int radix) {
    trace("strtoull called. Arguments: str=<const char*>[", static_cast<const void*>(str), "], endptr=<char**>[", endptr, "], radix=", std::to_wstring(radix));
    return _strtoui64(str, endptr, radix);
}

uintmax_t UCRTBase::strtoumax_l(const char *str, char **endptr, int radix, _locale_t) {
    // <idontcare> Locale is ignored </idontcare>
    return strtoumax_(str, endptr, radix);
}

uintmax_t UCRTBase::strtoumax_(const char *str, char **endptr, int radix) {
    trace("strtoumax called. Arguments: str=<const char*>[", static_cast<const void*>(str), "], endptr=<char**>[", endptr, "], radix=", std::to_wstring(radix));
    return _strtoumax(str, endptr, radix);
}

size_t UCRTBase::wcrtomb_(char *dest, _wchar_t ch, mbstate_t *state) {
    trace("wcrtomb called. Arguments: dest=<char*>[", static_cast<void*>(dest), "], ch=", std::to_wstring(static_cast<int>(ch)));
    if (dest == nullptr) {
        error("Error set to: EINVAL, Return value: -1");
        return -1;
    }
    const size_t result = (std::wcrtomb(dest, ch, state));
    if (result == -1) {
        error("Error set to: EILSEQ, Return value: -1");
        return -1; // Conversion error
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

errno_t UCRTBase::wcrtomb_s(size_t *pReturnValue, char *dest, size_t destSize, _wchar_t ch, mbstate_t *state) {
    trace("wcrtomb_s called. Arguments: pReturnValue=<size_t*>[", pReturnValue, "], dest=<char*>[", static_cast<void*>(dest), "], destSize=", std::to_wstring(destSize), ", ch=", std::to_wstring(static_cast<int>(ch)), ", state=<mbstate_t*>[", state, "]");
    if (pReturnValue != nullptr) {
        *pReturnValue = 0;
    }
    if (dest == nullptr && destSize != 0) {
        if (pReturnValue != nullptr) {
            *pReturnValue = 0;
        }
        error("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    if (destSize == 0) {
        if (pReturnValue != nullptr) {
            *pReturnValue = 0;
        }
        error("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    const size_t result = std::wcrtomb(dest, ch, state);
    if (result == -1) {
        if (pReturnValue != nullptr) {
            *pReturnValue = 0;
        }
        error("Error set to: EILSEQ, Return value: EILSEQ");
        return EILSEQ; // Conversion error
    }
    if (result >= destSize) {
        if (pReturnValue != nullptr) {
            *pReturnValue = 0;
        }
        error("Error set to: ERANGE, Return value: ERANGE");
        return ERANGE; // Not enough space
    }
    if (pReturnValue != nullptr) {
        *pReturnValue = result;
    }
    ret("Error set to: -, Return value: 0");
    return 0; // Success
}

size_t UCRTBase::wcsrtombs_(char *dest, const _wchar_t **src, size_t len, mbstate_t *state) {
    trace("wcsrtombs called. Arguments: dest=<char*>[", static_cast<void*>(dest), "], nt_apiset_cpp_hooks=<const _wchar_t**>[", src, "], len=", std::to_wstring(len), ", state=<mbstate_t*>[", state, "]");
    if (!src || !*src) {
        errno = EINVAL;
        return static_cast<size_t>(-1);
    }
    // Step 1: convert _wchar_t* → wchar_t* temporary buffer
    size_t srcLen = 0;
    while ((*src)[srcLen]) ++srcLen;
    const auto tmp = new wchar_t[srcLen + 1];
    for (size_t i = 0; i <= srcLen; ++i) tmp[i] = (*src)[i];
    // Step 2: perform conversion
    const wchar_t* tmpPtr = tmp;
    const size_t ret = std::wcsrtombs(dest, &tmpPtr, len, state);
    delete[] tmp;
    return ret;
}

errno_t UCRTBase::wcsrtombs_s(size_t *pReturnValue, char *dest, size_t destSize, const _wchar_t **src, size_t len,
    mbstate_t *state) {
    if (pReturnValue) *pReturnValue = 0;
    if (!src || !*src || (dest == nullptr && destSize != 0) || destSize == 0) return EINVAL;

    // Step 1: convert _wchar_t* → wchar_t* temporary buffer
    size_t srcLen = 0;
    while ((*src)[srcLen]) ++srcLen;

    const auto tmp = new wchar_t[srcLen + 1];
    for (size_t i = 0; i <= srcLen; ++i) tmp[i] = (*src)[i];

    // Step 2: compute the required size
    const wchar_t* tmpPtr = tmp;
    const size_t required = std::wcsrtombs(nullptr, &tmpPtr, 0, state);
    if (required == static_cast<size_t>(-1)) {
        delete[] tmp;
        return EILSEQ;
    }

    // Step 3: determine how many bytes to convert
    const size_t toConvert = (len == static_cast<size_t>(-1) || len > required) ? required : len;
    if (destSize < toConvert + 1) { // +1 for null terminator
        delete[] tmp;
        return ERANGE;
    }

    // Step 4: perform conversion
    tmpPtr = tmp;
    const size_t actual = std::wcsrtombs(dest, &tmpPtr, toConvert, state);
    if (actual == static_cast<size_t>(-1)) {
        delete[] tmp;
        return EILSEQ;
    }

    if (dest && destSize > actual) dest[actual] = '\0'; // null-terminate
    if (pReturnValue) *pReturnValue = actual;

    delete[] tmp;
    return 0; // success
}

double UCRTBase::wcstod_l(const _wchar_t *str, _wchar_t **endptr, _locale_t) {
    // <idontcare> Locale is ignored </idontcare>
    return wcstod_(str, endptr);
}

double UCRTBase::wcstod_(const _wchar_t *str, _wchar_t **endptr) {
    trace("wcstod called. Arguments: str=<const _wchar_t*>[", static_cast<const void*>(str), "], endptr=<wchar_t**>[", endptr, "]");
    return _wcstod(str, endptr);
}

float UCRTBase::wcstof_l(const _wchar_t *str, _wchar_t **endptr, _locale_t) {
    // <idontcare> Locale is ignored </idontcare>
    return wcstof_(str, endptr);
}

float UCRTBase::wcstof_(const _wchar_t *str, _wchar_t **endptr) {
    trace("wcstof called. Arguments: str=<const _wchar_t*>[", static_cast<const void*>(str), "], endptr=<wchar_t**>[", endptr, "]");
    return _wcstof(str, endptr);
}

intmax_t UCRTBase::wcstoimax_l(const _wchar_t *str, _wchar_t **endptr, int radix, _locale_t) {
    // <idontcare> Locale is ignored </idontcare>
    return wcstoimax_(str, endptr, radix);
}

intmax_t UCRTBase::wcstoimax_(const _wchar_t *str, _wchar_t **endptr, int radix) {
    trace("wcstoimax called. Arguments: str=<const _wchar_t*>[", static_cast<const void*>(str), "], endptr=<wchar_t**>[", endptr, "], radix=", std::to_wstring(radix));
    return _wcstoimax(str, endptr, radix);
}

LONG UCRTBase::wcstol_l(const _wchar_t *str, _wchar_t **endptr, int radix, _locale_t) {
    // <idontcare> Locale is ignored </idontcare>
    return wcstol_(str, endptr, radix);
}

LONG UCRTBase::wcstol_(const _wchar_t *str, _wchar_t **endptr, int radix) {
    trace("wcstol called. Arguments: str=<const _wchar_t*>[", static_cast<const void*>(str), "], endptr=<wchar_t**>[", endptr, "], radix=", std::to_wstring(radix));
    return _wcstol(str, endptr, radix);
}

long double UCRTBase::wcstold_l(const _wchar_t *str, _wchar_t **endptr, _locale_t) {
    // <idontcare> Locale is ignored </idontcare>
    return wcstold_(str, endptr);
}

long double UCRTBase::wcstold_(const _wchar_t *str, _wchar_t **endptr) {
    trace("wcstold called. Arguments: str=<const _wchar_t*>[", static_cast<const void*>(str), "], endptr=<wchar_t**>[", endptr, "]");
    return _wcstold(str, endptr);
}

LONGLONG UCRTBase::wcstoll_l(const _wchar_t *str, _wchar_t **endptr, int radix, _locale_t) {
    // <idontcare> Locale is ignored </idontcare>
    return wcstoll_(str, endptr, radix);
}

LONGLONG UCRTBase::wcstoll_(const _wchar_t *str, _wchar_t **endptr, int radix) {
    trace("wcstoll called. Arguments: str=<const _wchar_t*>[", static_cast<const void*>(str), "], endptr=<wchar_t**>[", endptr, "], radix=", std::to_wstring(radix));
    return _wcstoll(str, endptr, radix);
}

size_t UCRTBase::wcstombs_(char *dest, const _wchar_t *src, size_t n) {
    trace("wcstombs called. Arguments: dest=<char*>[", static_cast<void*>(dest), "], nt_apiset_cpp_hooks=<const _wchar_t*>[", static_cast<const void*>(src), "], n=", std::to_wstring(n));
    return _wcstombs(dest, src, n);
}

errno_t UCRTBase::wcstombs_s(size_t *pReturnValue, char *dest, size_t destSize, const _wchar_t *src, size_t n) {
    trace("wcstombs_s called. Arguments: pReturnValue=<size_t*>[", pReturnValue, "], dest=<char*>[", static_cast<void*>(dest), "], destSize=", std::to_wstring(destSize), ", nt_apiset_cpp_hooks=<const _wchar_t*>[", static_cast<const void*>(src), "], n=", std::to_wstring(n));
    return _wcstombs_s(pReturnValue, dest, destSize, src, n);
}

size_t UCRTBase::mbstowcs_(_wchar_t *dest, const char *src, size_t n) {
    trace("mbstowcs called. Arguments: dest=<_wchar_t*>[", static_cast<void*>(dest), "], nt_apiset_cpp_hooks=<const char*>[", static_cast<const void*>(src), "], n=", std::to_wstring(n));
    return _mbstowcs(dest, src, n);
}

errno_t UCRTBase::mbstowcs_s(size_t *pReturnValue, _wchar_t *dest, size_t destSize, const char *src, size_t n) {
    trace("mbstowcs_s called. Arguments: pReturnValue=<size_t*>[", pReturnValue, "], dest=<_wchar_t*>[", static_cast<void*>(dest), "], destSize=", std::to_wstring(destSize), ", nt_apiset_cpp_hooks=<const char*>[", static_cast<const void*>(src), "], n=", std::to_wstring(n));
    return _mbstowcs_s(pReturnValue, dest, destSize, src, n);
}

ULONG UCRTBase::wcstoul_l(const _wchar_t *str, _wchar_t **endptr, int radix, _locale_t) {
    // <idontcare> Locale is ignored </idontcare>
    return wcstoul_(str, endptr, radix);
}

ULONG UCRTBase::wcstoul_(const _wchar_t *str, _wchar_t **endptr, int radix) {
    trace("wcstoul called. Arguments: str=<const _wchar_t*>[", static_cast<const void*>(str), "], endptr=<wchar_t**>[", endptr, "], radix=", std::to_wstring(radix));
    return _wcstoul(str, endptr, radix);
}

ULONGLONG UCRTBase::wcstoull_l(const _wchar_t *str, _wchar_t **endptr, int radix, _locale_t) {
    // <idontcare> Locale is ignored </idontcare>
    return wcstoull_(str, endptr, radix);
}

ULONGLONG UCRTBase::wcstoull_(const _wchar_t *str, _wchar_t **endptr, int radix) {
    trace("wcstoull called. Arguments: str=<const _wchar_t*>[", static_cast<const void*>(str), "], endptr=<wchar_t**>[", endptr, "], radix=", std::to_wstring(radix));
    return _wcstoull(str, endptr, radix);
}

uintmax_t UCRTBase::wcstoumax_l(const _wchar_t *str, _wchar_t **endptr, int radix, _locale_t) {
    // <idontcare> Locale is ignored </idontcare>
    return wcstoumax_(str, endptr, radix);
}

uintmax_t UCRTBase::wcstoumax_(const _wchar_t *str, _wchar_t **endptr, int radix) {
    trace("wcstoumax called. Arguments: str=<const _wchar_t*>[", static_cast<const void*>(str), "], endptr=<wchar_t**>[", endptr, "], radix=", std::to_wstring(radix));
    return _wcstoui64(str, endptr, radix);
}

int UCRTBase::wctob_(_wint_t wc) {
    trace("wctob called. Arguments: wc=", std::to_wstring(static_cast<int>(wc)));
    ret("Error set to: -, Return value: ", std::to_wstring(static_cast<int>(wc)));
    return std::wctob(wc);
}

int UCRTBase::wctomb_(char *dest, _wchar_t wc) {
    trace("wctomb called. Arguments: dest=<char*>[", static_cast<void*>(dest), "], wc=", std::to_wstring(static_cast<int>(wc)));
    if (dest == nullptr) {
        error("Error set to: EINVAL, Return value: -1");
        return -1;
    }
    const int result = std::wctomb(dest, wc);
    if (result == -1) {
        error("Error set to: EILSEQ, Return value: -1");
        return -1; // Conversion error
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

int UCRTBase::mbtowc_(_wchar_t *dest, const char *src, size_t n) {
    trace("mbtowc called. Arguments: dest=<_wchar_t*>[", static_cast<void*>(dest), "], nt_apiset_cpp_hooks=<const char*>[", static_cast<const void*>(src), "], n=", std::to_wstring(n));
    if (src == nullptr) {
        error("Error set to: EINVAL, Return value: -1");
        return -1;
    }
    if (dest == nullptr) {
        error("Error set to: EINVAL, Return value: -1");
        return -1;
    }
    wchar_t wc;
    const int result = std::mbtowc(&wc, src, n);
    if (result == -1) {
        error("Error set to: EILSEQ, Return value: -1");
        return -1; // Conversion error
    }
    if (result == -2) {
        error("Error set to: -, Return value: -2");
        return -2; // Incomplete multibyte sequence
    }
    *dest = static_cast<_wchar_t>(wc & 0xFFFF); // Store as 16-bit _wchar_t
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

errno_t UCRTBase::wctomb_s(size_t *pReturnValue, char *dest, size_t destSize, _wchar_t wc) {
    trace("wctomb_s called. Arguments: pReturnValue=<size_t*>[", pReturnValue, "], dest=<char*>[", static_cast<void*>(dest), "], destSize=", std::to_wstring(destSize), ", wc=", std::to_wstring(static_cast<int>(wc)));
    if (pReturnValue != nullptr) {
        *pReturnValue = 0;
    }
    if (dest == nullptr && destSize != 0) {
        if (pReturnValue != nullptr) {
            *pReturnValue = 0;
        }
        error("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    if (destSize == 0) {
        if (pReturnValue != nullptr) {
            *pReturnValue = 0;
        }
        error("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    const int result = std::wctomb(dest, wc);
    if (result == -1) {
        if (pReturnValue != nullptr) {
            *pReturnValue = 0;
        }
        error("Error set to: EILSEQ, Return value: EILSEQ");
        return EILSEQ; // Conversion error
    }
    if (static_cast<size_t>(result) >= destSize) {
        if (pReturnValue != nullptr) {
            *pReturnValue = 0;
        }
        error("Error set to: ERANGE, Return value: ERANGE");
        return ERANGE; // Not enough space
    }
    if (pReturnValue != nullptr) {
        *pReturnValue = static_cast<size_t>(result);
    }
    ret("Error set to: -, Return value: 0");
    return 0; // Success
}

wctrans_t UCRTBase::wctrans_(const char *charclass) {
    trace("wctrans called. Arguments: charclass=<PCSTR>[", static_cast<const void*>(charclass), "]");
    if (charclass == nullptr) {
        error("Error set to: EINVAL, Return value: nullptr");
        return nullptr;
    }

    return wctrans(charclass);
}

void UCRTBase::_Exit_(int exitCode) {
    trace("_Exit called. Arguments: exitCode=", std::to_wstring(exitCode));
    _Exit(exitCode);
}

int UCRTBase::__control87_2(unsigned int newControl, unsigned int mask, unsigned int *x86_cw, unsigned int *sse2_cw) {
    trace("_control87 called. Arguments: newControl=", std::to_wstring(newControl), ", mask=", std::to_wstring(mask), ", x86_cw=<unsigned int*>[", x86_cw, "], sse2_cw=<unsigned int*>[", sse2_cw, "]");
    // This is a stub implementation. In a real implementation, you would modify the floating-point control word.
    ret("Return value: 0");
    return 0; // Dummy return value
}

errno_t UCRTBase::__doserrno() {
    trace("_doserrno called. No arguments.");
    ret("Return value: ", std::to_wstring(errno));
    return errno;
}

int UCRTBase::__fpe_flt_rounds() {
    trace("_fpe_flt_rounds called. No arguments.");
    // This is a stub implementation. In a real implementation, you would return the current floating-point rounding mode.
    constexpr int roundingMode = 1; // Example: round to nearest (safe default)
    ret("Return value: ", std::to_wstring(roundingMode));
    return roundingMode;
}

int UCRTBase::__fpecode() {
    trace("_fpecode called. No arguments.");
    // This is a stub implementation. In a real implementation, you would return the last floating-point exception code.
    constexpr int fpeCode = 0; // Example: no exception
    ret("Return value: ", std::to_wstring(fpeCode));
    return fpeCode;
}

int * UCRTBase::__p___argc() {
    trace("_p___argc called. No arguments.");
    ret("Return value: <int*>[", &process_info[tls.process].argc, "]");
    return &process_info[tls.process].argc;
}

char *** UCRTBase::__p___argv() {
    trace("_p___argv called. No arguments.");
    ret("Return value: <char***>[", &process_info[tls.process].argv, "]");
    return &process_info[tls.process].argv;
}

_wchar_t *** UCRTBase::__p___wargv() {
    trace("_p___wargv called. No arguments.");
    ret("Return value: <wchar_t***>[", &process_info[tls.process].wargv, "]");
    return &process_info[tls.process].wargv;
}

char ** UCRTBase::__p___acmdln() {
    trace("_p___acmdln called. No arguments.");
    ret("Return value: <char***>[", &process_info[tls.process].cmdline, "]");
    return &process_info[tls.process].cmdline;
}

_wchar_t ** UCRTBase::__p___wcmdln() {
    trace("_p___wcmdln called. No arguments.");
    ret("Return value: <wchar_t***>[", &process_info[tls.process].cmdline_w, "]");
    return &process_info[tls.process].cmdline_w;
}

_wchar_t ** UCRTBase::__p__wpgmptr() {
    trace("_p__pgmptr called. No arguments.");
    ret("Return value: <char**>[", &process_info[tls.process].argv[0], "]");
    return &process_info[tls.process].wpgmptr;
}

EXCEPTION_POINTERS * UCRTBase::__pxcptinfoptrs() {
    trace("_pxcptinfoptrs called. No arguments.");
    ret("Return value: <EXCEPTION_POINTERS>[", &tls.xcptinfoptrs, "]");
    return &tls.xcptinfoptrs;
}

char * UCRTBase::_strerror(char *errMsg) {
    trace("_strerror called. Arguments: errMsg=<const char*>[", static_cast<const void*>(errMsg), "]");
    if (errMsg == nullptr) {
        error("Error set to: EINVAL, Return value: errMsg");
        return errMsg;
    }
    return errMsg;
}

errno_t UCRTBase::_strerror_s(char *buffer, size_t numberOfElements, const char *errMsg) {
    trace("_strerror_s called. Arguments: buffer=<char*>[", static_cast<void*>(buffer), "], numberOfElements=", std::to_wstring(numberOfElements), ", errMsg=<const char*>[", static_cast<const void*>(errMsg), "]");
    if (buffer == nullptr || numberOfElements == 0) {
        error("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    if (errMsg == nullptr) {
        if (numberOfElements > 0) {
            buffer[0] = '\0'; // Empty string for a null error message
        }
        error("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    const size_t errMsgLen = std::strlen(errMsg);
    if (errMsgLen + 1 > numberOfElements) { // +1 for null terminator
        if (numberOfElements > 0) {
            buffer[0] = '\0'; // Empty string if not enough space
        }
        error("Error set to: ERANGE, Return value: ERANGE");
        return ERANGE;
    }
    std::strncpy(buffer, errMsg, numberOfElements);
    buffer[errMsgLen] = '\0'; // Ensure null-termination
    ret("Error set to: -, Return value: 0");
    return 0; // Success
}

_wchar_t * UCRTBase::_wcserror(int errNum) {
    trace("_wcserror called. Arguments: errNum=", std::to_wstring(errNum));
    if (errNum < 0 || static_cast<size_t>(errNum) >= static_cast<size_t>(__sys_nerr())) {
        error("Error set to: EINVAL, Return value: nullptr");
        return nullptr;
    }
    const char* msg = __sys_errlist()[errNum];
    static thread_local _wchar_t wmsg[256]; // Thread-local buffer for an error message
    mbstowcs_(wmsg, msg, std::size(wmsg));
    ret("Error set to: -, Return value: <wchar_t*>[", static_cast<void*>(wmsg), "]");
    return wmsg;
}

errno_t UCRTBase::_wcserror_s(wchar_t *errMsg, size_t errMsgSize, int errNum) {
    trace("_wcserror_s called. Arguments: errMsg=<wchar_t*>[", static_cast<void*>(errMsg), "], errMsgSize=", std::to_wstring(errMsgSize), ", errNum=", std::to_wstring(errNum));
    if (errMsg == nullptr || errMsgSize == 0) {
        error("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    if (errNum < 0 || static_cast<size_t>(errNum) >= static_cast<size_t>(__sys_nerr())) {
        if (errMsgSize > 0) {
            errMsg[0] = L'\0'; // Empty string for an invalid error number
        }
        error("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    const char* msg = __sys_errlist()[errNum];
    const size_t msgLen = std::strlen(msg);
    if (msgLen + 1 > errMsgSize) { // +1 for null terminator
        if (errMsgSize > 0) {
            errMsg[0] = L'\0'; // Empty string if not enough space
        }
        error("Error set to: ERANGE, Return value: ERANGE");
        return ERANGE;
    }
    mbstowcs(errMsg, msg, errMsgSize);
    errMsg[msgLen] = L'\0'; // Ensure null-termination
    ret("Error set to: -, Return value: 0");
    return 0; // Success
}

errno_t UCRTBase::__wcserror_s(_wchar_t *buffer, size_t numberOfElements, _wchar_t *errMsg) {
    trace("_wcserror_s called. Arguments: buffer=<wchar_t*>[", static_cast<void*>(buffer), "], numberOfElements=", std::to_wstring(numberOfElements), ", errMsg=<const _wchar_t*>[", static_cast<const void*>(errMsg), "]");
    if (buffer == nullptr || numberOfElements == 0) {
        error("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    if (errMsg == nullptr) {
        if (numberOfElements > 0) {
            buffer[0] = L'\0'; // Empty string for a null error message
        }
        error("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    const size_t errMsgLen = wcslen_(errMsg);
    if (errMsgLen + 1 > numberOfElements) { // +1 for null terminator
        if (numberOfElements > 0) {
            buffer[0] = L'\0'; // Empty string if not enough space
        }
        error("Error set to: ERANGE, Return value: ERANGE");
        return ERANGE;
    }
    wcsncpy_(buffer, errMsg, numberOfElements);
    buffer[errMsgLen] = L'\0'; // Ensure null-termination
    ret("Error set to: -, Return value: 0");
    return 0; // Success
}

const char ** UCRTBase::__sys_errlist() { // TODO.
    trace("_sys_errlist called. No arguments.");
    static const char *sys_errlist[42] = {
        "No error",               // 0
        "Operation not permitted", // 1
        "No such file or directory", // 2
        "No such process",        // 3
        "Interrupted system call", // 4
        "Input/output error",     // 5
        "No such device or address", // 6
        "Argument list too long", // 7
        "Exec format error",      // 8
        "Bad file descriptor",    // 9
        "No child processes",     // 10
        "Resource temporarily unavailable", // 11
        "Cannot allocate memory", // 12
        "Permission denied",      // 13
        "Bad address",           // 14
        "Block device required",  // 15
        "Device or resource busy", // 16
        "File exists",           // 17
        "Invalid cross-device link", // 18
        "No such device",        // 19
        "Not a directory",       // 20
        "Is a directory",        // 21
        "Invalid argument",      // 22
        "Too many open files in system", // 23
        "Too many open files",   // 24
        "Inappropriate ioctl for device", // 25
        "Text file busy",        // 26
        "File too large",        // 27
        "No space left on device", // 28
        "Illegal seek",          // 29
        "Read-only file system", // 30
        "Too many links",        // 31
        "Broken pipe",           // 32
        "Numerical argument out of domain", // 33
        "Numerical result out of range", // 34
        "Resource deadlock avoided", // 35
        "File name too long",    // 36
        "No locks available",    // 37
        "Function not implemented", // 38
        "Directory not empty",   // 39
        "Too many levels of symbolic links", // 40
        "Unknown error"          // Fallback for unknown errors
    };
    ret("Return value: <const char**>[", static_cast<const void*>(sys_errlist), "]");
    return sys_errlist;
}

int UCRTBase::__sys_nerr() {
    trace("_sys_nerr called. No arguments.");
    constexpr int sys_nerr = 41; // Number of error messages in sys_errlist
    ret("Return value: ", std::to_wstring(sys_nerr));
    return sys_nerr;
}

HANDLE UCRTBase::__threadhandle() {
    trace("_threadhandle called. No arguments.");
    ret("Return value: <HANDLE>[", tls.thread, "]");
    return tls.thread;
}

UINT UCRTBase::__threadid() {
    trace("_threadid called. No arguments.");
    ret("Return value: ", std::to_wstring(static_cast<UINT>(reinterpret_cast<uintptr_t>(tls.thread))));
    return reinterpret_cast<uintptr_t>(tls.thread);
}

void UCRTBase::_assert(const char *message, const char *file, unsigned int line) {
    trace("_assert called. Arguments: message=<const char*>[", static_cast<const void*>(message), "], file=<const char*>[", static_cast<const void*>(file), "], line=", std::to_wstring(line));
    std::cerr << "Assertion failed: " << (message ? message : "No message") << ", file " << (file ? file : "Unknown") << ", line " << line << std::endl;
    std::abort();
}

void UCRTBase::_wassert(const _wchar_t *message, const _wchar_t *file, unsigned int line) {
    constexpr _wchar_t empty[] = { 'N', 'o', ' ', 'm', 'e', 's', 's', 'a', 'g', 'e', 0 };
    constexpr _wchar_t unknown[] = { 'U', 'n', 'k', 'n', 'o', 'w', 'n', 0 };
    trace("_wassert called. Arguments: message=<const _wchar_t*>[", static_cast<const void*>(message), "], file=<const _wchar_t*>[", static_cast<const void*>(file), "], line=", std::to_wstring(line));
    std::wcerr << L"Assertion failed: " << (message ? message : empty) << L", file " << (file ? file : unknown) << L", line " << line << std::endl;
    std::abort();
}

uintptr_t UCRTBase::_beginthread(void(*startAddress)(void *), unsigned stackSize, void *arglist) {
    trace("beginthread called. Arguments: startAddress=<void(*)(void*)>[", reinterpret_cast<void*>(startAddress), "], stackSize=", std::to_wstring(stackSize), ", arglist=<void*>[", arglist, "]");
    if (startAddress == nullptr) {
        error("Error set to: EINVAL, Return value: -1");
        return static_cast<uintptr_t>(-1);
    }
    HANDLE thread = Kernel32::CreateThread(
        nullptr, // default security attributes
        stackSize, // stack size
        [](LPVOID param) -> DWORD {
            const _beginthread_helper* helper = static_cast<_beginthread_helper*>(param);
            helper->start_address(helper->arglist);
            delete helper;
            return 0;
        },
        new _beginthread_helper{ startAddress, arglist }, // argument to thread function
        0, // default creation flags
        nullptr); // receive thread identifier
    if (thread == nullptr) {
        error("Error set to: EAGAIN, Return value: -1");
    }
    else {
        ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(thread)));
        return reinterpret_cast<uintptr_t>(thread);
    }
    return static_cast<uintptr_t>(-1);
}

uintptr_t UCRTBase::_beginthreadex(void *security, unsigned stackSize, void(*startAddress)(void *), void *arglist,
    unsigned initflag, unsigned *thrdaddr) {
    trace("beginthreadex called. Arguments: security=<void*>[", security, "], stackSize=", std::to_wstring(stackSize), ", startAddress=<void(*)(void*)>[", reinterpret_cast<void*>(startAddress), "], arglist=<void*>[", arglist, "], initflag=", std::to_wstring(initflag), ", thrdaddr=<unsigned*>[", thrdaddr, "]");
    HANDLE thread = Kernel32::CreateThread(
        static_cast<LPSECURITY_ATTRIBUTES>(security), // security attributes
        stackSize, // stack size
        [](LPVOID param) -> DWORD {
            const _beginthread_helper* helper = static_cast<_beginthread_helper*>(param);
            helper->start_address(helper->arglist);
            delete helper;
            return 0;
        },
        new _beginthread_helper{ startAddress, arglist }, // argument to thread function
        initflag, // creation flags
        thrdaddr); // receive thread identifier
    if (thread == nullptr) {
        error("Error set to: EAGAIN, Return value: -1");
    }
    else {
        ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(thread)));
        return reinterpret_cast<uintptr_t>(thread);
    }
    return static_cast<uintptr_t>(-1);
}

void UCRTBase::_c_exit() {
    for (const auto func : process_info[tls.process].atexit_functions) {
        func();
    }
    for (const auto func : process_info[tls.process].onexit_functions) {
        func();
    }
    if (tls.tls_atexit_callback) {
        tls.tls_atexit_callback(nullptr, DLL_PROCESS_DETACH /* ? */, nullptr);
    }
}

void UCRTBase::_cexit() {
    _c_exit();
}

UINT UCRTBase::_clearfp() {
    trace("_clearfp called. No arguments.");
    // This is a stub implementation. In a real implementation, you would clear the floating-point exception flags.
    constexpr UINT fpStatus = 0; // Example: no exceptions
    ret("Return value: ", std::to_wstring(fpStatus));
    return fpStatus;
}

errno_t UCRTBase::_configure_narrow_argv() {
    trace("_configure_narrow_argv called. No arguments.");
    // I already configure all the argvs in main.cpp
    ret("Return value: 0");
    return 0; // Success
}

errno_t UCRTBase::_configure_wide_argv() {
    trace("_configure_wide_argv called. No arguments.");
    // I already configure all the argvs in main.cpp
    ret("Return value: 0");
    return 0; // Success
}

UINT UCRTBase::_control87(unsigned int newControl, unsigned int mask) {
    trace("_control87 called. Arguments: newControl=", std::to_wstring(newControl), ", mask=", std::to_wstring(mask));
    return __control87_2(newControl, mask, nullptr, nullptr);
}

UINT UCRTBase::_controlfp(UINT newControl, UINT mask) {
    trace("_controlfp called. Arguments: newControl=", std::to_wstring(newControl), ", mask=", std::to_wstring(mask));
    return __control87_2(newControl, mask, nullptr, nullptr);
}

errno_t UCRTBase::_controlfp_s(unsigned int *currentControl, unsigned int newControl, unsigned int mask) {
    trace("_controlfp_s called. Arguments: currentControl=<unsigned int*>[", currentControl, "], newControl=", std::to_wstring(newControl), ", mask=", std::to_wstring(mask));
    return __control87_2(newControl, mask, nullptr, nullptr);
}

int UCRTBase::_crt_at_quick_exit(void(*func)()) {
    trace("_crt_at_quick_exit called. Arguments: func=<void(*)(void)>[", reinterpret_cast<void*>(func), "]");
    if (func == nullptr) {
        error("Error set to: EINVAL, Return value: -1");
        return -1;
    }
    process_info[tls.process].at_quick_exit_functions.push_back(func);
    ret("Error set to: -, Return value: 0");
    return 0; // Success
}

int UCRTBase::_crt_atexit(void(*func)()) {
    trace("_crt_atexit called. Arguments: func=<void(*)(void)>[", reinterpret_cast<void*>(func), "]");
    if (func == nullptr) {
        error("Error set to: EINVAL, Return value: -1");
        return -1;
    }
    process_info[tls.process].atexit_functions.push_back(func);
    ret("Error set to: -, Return value: 0");
    return 0; // Success
}

int UCRTBase::_crt_debugger_hook(int reportType, char *message, int *returnValue) {
    trace("_crt_debugger_hook called. Arguments: reportType=", std::to_wstring(reportType), ", message=<char*>[", static_cast<void*>(message), "], returnValue=<int*>[", returnValue, "]");
    if (message != nullptr) {
        std::cerr << "Debug Report Type " << reportType << ": " << message << std::endl;
    } else {
        std::cerr << "Debug Report Type " << reportType << ": <No message>" << std::endl;
    }
    if (returnValue != nullptr) {
        *returnValue = 1; // Indicate that the debugger handled the report
    }
    ret("Return value: 1");
    return 1; // Indicate that the debugger handled the report
}

void UCRTBase::_endthread() {
    trace("_endthread called. No arguments.");
    Kernel32::ExitThread(0);
    std::exit(0);
}

void UCRTBase::_endthreadex(unsigned retval) {
    trace("_endthreadex called. Arguments: retval=", std::to_wstring(retval));
    Kernel32::ExitThread(0);
    std::exit(static_cast<int>(retval));
}

int * UCRTBase::_errno() {
    trace("_errno called. No arguments.");
    ret("Return value: <int*>[", __errno_location(), "]");
    return __errno_location(); // prolly glibc-specific
}

int UCRTBase::_initialize_onexit_table(_onexit_table_t *table) {
    trace("_initialize_onexit_table called. Arguments: table=<_onexit_table_t*>[", table, "]");
    return 0; // Success (we do not need to do anything special here)
}

int UCRTBase::_register_onexit_function(_onexit_table_t *table, _onexit_t function) {
    trace("_register_onexit_function called. Arguments: table=<_onexit_table_t*>[", table, "], function=<_onexit_t>[", reinterpret_cast<void*>(function), "]");
    if (table == nullptr || function == nullptr) {
        error("Error set to: EINVAL, Return value: -1");
        return -1;
    }
    table->push_back(function);
    return 0; // Success
}

int UCRTBase::_execute_onexit_table(_onexit_table_t *table) {
    trace("_execute_onexit_table called. Arguments: table=<_onexit_table_t*>[", table, "]");
    if (table == nullptr) {
        error("Error set to: EINVAL, Return value: -1");
        return -1;
    }
    for (const auto &it : std::ranges::reverse_view(*table)) {
        it();
    }
    return 0;
}

void UCRTBase::_exit(int exitCode) {
    trace("_exit called. Arguments: exitCode=", std::to_wstring(exitCode));
    _c_exit();
    ret("No return value, function does not return.");
    std::exit(exitCode);
}

int UCRTBase::_fpieee_flt(ULONG excCode, EXCEPTION_POINTERS *excInfo, int handler(_FPIEEE_RECORD)) {
    trace("_fpieee_flt called. Arguments: excCode=", std::to_wstring(excCode), ", excInfo=<EXCEPTION_POINTERS*>[", excInfo, "], handler=<int(*)(_FPIEEE_RECORD)>[", reinterpret_cast<void*>(handler), "]");
    if (excInfo == nullptr || handler == nullptr) {
        error("Error set to: EINVAL, Return value: -1");
        return -1;
    }
    _FPIEEE_RECORD record = {};
    record.Cause = _FPIEEE_EXCEPTION_FLAGS{ .Inexact = 0, .Underflow = 0, .Overflow = 0, .ZeroDivide = 0, .InvalidOperation = 1 };
    record.Enable = _FPIEEE_EXCEPTION_FLAGS{ .Inexact = 1, .Underflow = 1, .Overflow = 1, .ZeroDivide = 1, .InvalidOperation = 1 };
    record.Status = _FPIEEE_EXCEPTION_FLAGS{ .Inexact = 0, .Underflow = 0, .Overflow = 0, .ZeroDivide = 0, .InvalidOperation = 0 };
    record.Operation = 0;
    record.Operand1 = _FPIEEE_VALUE{};
    record.Operand1.Value.Fp64Value = _FP64{};
    record.Operand2 = _FPIEEE_VALUE{};
    record.Operand2.Value.Fp64Value = _FP64{};
    record.Result = _FPIEEE_VALUE{};
    record.Result.Value.Fp64Value = _FP64{};
    record.RoundingMode = 0;
    record.Precision = 0;
    const int result = handler(record);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

void UCRTBase::_fpreset() {
    trace("_fpreset called. No arguments.");
    // This is a stub implementation. In a real implementation, you would reset the floating-point environment.
    ret("No return value, function is void.");
}

errno_t UCRTBase::_get_doserrno(unsigned int *perrno) {
    trace("_get_doserrno called. Arguments: perrno=<unsigned int*>[", perrno, "]");
    if (perrno == nullptr) {
        error("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    *perrno = static_cast<unsigned int>(errno);
    ret("Error set to: -, Return value: 0");
    return 0; // Success
}

errno_t UCRTBase::_get_errno(unsigned int *perrno) {
    trace("_get_errno called. Arguments: perrno=<unsigned int*>[", perrno, "]");
    if (perrno == nullptr) {
        error("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    *perrno = static_cast<unsigned int>(errno);
    ret("Error set to: -, Return value: 0");
    return 0; // Success
}

char ** UCRTBase::_get_initial_narrow_environment() {
    trace("_get_initial_narrow_environment called. No arguments.");
    return environment_narrow;
}

_wchar_t ** UCRTBase::_get_initial_wide_environment() {
    trace("_get_initial_wide_environment called. No arguments.");
    return environment_wide; // fucking architectural change just for this to work
}

_invalid_parameter_handler UCRTBase::_get_invalid_parameter_handler() {
    trace("_get_invalid_parameter_handler called. No arguments.");
    ret("Return value: <_invalid_parameter_handler>[", nullptr, "]");
    return nullptr;
}

_invalid_parameter_handler UCRTBase::_get_thread_local_invalid_parameter_handler() {
    trace("_get_thread_local_invalid_parameter_handler called. No arguments.");
    ret("Return value: <_invalid_parameter_handler>[", nullptr, "]");
    return nullptr;
}

void UCRTBase::_set_invalid_parameter_handler(_invalid_parameter_handler handler) {
    trace("set_invalid_parameter_handler called. Arguments: handler=<_invalid_parameter_handler>[", reinterpret_cast<void*>(handler), "]");
    process_info[tls.process].invalid_parameter_handler = handler;
}

void UCRTBase::_set_thread_local_invalid_parameter_handler(_invalid_parameter_handler handler) {
    trace("set_thread_local_invalid_parameter_handler called. Arguments: handler=<_invalid_parameter_handler>[", reinterpret_cast<void*>(handler), "]");
    tls.invalid_parameter_handler = handler;
}

char * UCRTBase::_get_narrow_winmain_command_line() {
    trace("_get_narrow_winmain_command_line called. No arguments.");
    ret("Return value: <char*>[", process_info[tls.process].cmdline, "]");
    return process_info[tls.process].cmdline;
}

char * UCRTBase::_get_pgmptr() {
    trace("_get_pgmptr called. No arguments.");
    ret("Return value: <char*>[", process_info[tls.process].pgmptr, "]");
    return process_info[tls.process].pgmptr;
}

_wchar_t * UCRTBase::_get_wpgmptr() {
    trace("_get_wpgmptr called. No arguments.");
    ret("Return value: <wchar_t*>[", process_info[tls.process].wpgmptr, "]");
    return process_info[tls.process].wpgmptr;
}

_wchar_t * UCRTBase::_get_wide_winmain_command_line() {
    trace("_get_wide_winmain_command_line called. No arguments.");
    ret("Return value: <wchar_t*>[", process_info[tls.process].cmdline_w, "]");
    return process_info[tls.process].cmdline_w;
}

terminate_function UCRTBase::_get_terminate() {
    trace("_get_terminate called. No arguments.");
    ret("Return value: <terminate_function>[", process_info[tls.process].terminate_handler, "]");
    return process_info[tls.process].terminate_handler;
}

terminate_function UCRTBase::_set_terminate(terminate_function func) {
    trace("_set_terminate called. Arguments: func=<terminate_function>[", func, "]");
    terminate_function old = process_info[tls.process].terminate_handler;
    process_info[tls.process].terminate_handler = func;
    ret("Return value: <terminate_function>[", old, "]");
    return old;
}

FARPROC UCRTBase::_getdllprocaddr(HMODULE hModule, char *name, int ordinalOnly) {
    if (!hModule) return nullptr;
    if (ordinalOnly) {
        const auto ord = reinterpret_cast<UINT_PTR>(name);
        return Kernel32::GetProcAddress(hModule, reinterpret_cast<LPCSTR>(ord));
    }
    return Kernel32::GetProcAddress(hModule, name);
}

int UCRTBase::_getpid() {
    trace("_getpid called. No arguments.");
    const int pid = static_cast<int>(Kernel32::GetCurrentProcessId());
    ret("Return value: ", std::to_wstring(pid));
    return pid;
}

int UCRTBase::_initialize_narrow_environment() {
    trace("_initialize_narrow_environment called. No arguments.");
    // I already configure all the envs in main.cpp
    ret("Return value: 0");
    return 0; // Success
}

int UCRTBase::_initialize_wide_environment() {
    trace("_initialize_wide_environment called. No arguments.");
    // I already configure all the envs in main.cpp
    ret("Return value: 0");
    return 0; // Success
}

void UCRTBase::_initterm(_PVFV*start, _PVFV*end) {
    trace("_initterm called. Arguments: start=<_PVFV*>[", start, "], end=<_PVFV*>[", end, "]");
    for (const _PVFV* func = start; func < end; ++func) {
        if (*func != nullptr) {
            (*func)();
        }
    }
}

int UCRTBase::_initterm_e(_PIFV*start, _PIFV*end) {
    trace("_initterm_e called. Arguments: start=<_PIFV*>[", start, "], end=<_PIFV*>[", end, "]");
    for (const _PIFV* func = start; func < end; ++func) {
        if (*func != nullptr) {
            if (const int result = (*func)(); result != 0) {
                error("Error set to: -, Return value: ", std::to_wstring(result));
                return result; // Propagate error
            }
        }
    }
    ret("Error set to: -, Return value: 0");
    return 0; // Success
}

void UCRTBase::_invalid_parameter_noinfo() {
    trace("_invalid_parameter_noinfo called. No arguments.");
    if (tls.invalid_parameter_handler) {
        tls.invalid_parameter_handler(nullptr, nullptr, nullptr, 0, 0);
    } else if (process_info[tls.process].invalid_parameter_handler) {
        process_info[tls.process].invalid_parameter_handler(nullptr, nullptr, nullptr, 0, 0);
    } else {
        std::cerr << "Invalid parameter detected." << std::endl;
        std::abort();
    }
}

void UCRTBase::_invalid_parameter_noinfo_noreturn() {
    trace("_invalid_parameter_noinfo_noreturn called. No arguments.");
    _invalid_parameter_noinfo();
    std::abort(); // Ensure the function does not return
}

void UCRTBase::_invoke_watson(const _wchar_t *expression, const _wchar_t *function, const _wchar_t *file,
    unsigned int line, uintptr_t pReserved) {
    constexpr _wchar_t empty[] = { '<', 'n', 'o', ' ', 'e', 'x', 'p', 'r', 'e', 's', 's', 'i', 'o', 'n', '>', 0 };
    constexpr _wchar_t unknown[] = { '<', 'u', 'n', 'k', 'n', 'o', 'w', 'n', '>', 0 };
    trace("_invoke_watson called. Arguments: expression=<const _wchar_t*>[", static_cast<const void*>(expression), "], function=<const _wchar_t*>[", static_cast<const void*>(function), "], file=<const _wchar_t*>[", static_cast<const void*>(file), "], line=", std::to_wstring(line), ", reserved=", std::to_wstring(pReserved));
    std::wcerr << L"Fatal error: " << (expression ? expression : empty) << L", function " << (function ? function : unknown) << L", file " << (file ? file : unknown) << L", line " << line << std::endl;
    std::abort();
}

int UCRTBase::_query_app_type() {
    trace("_query_app_type called. No arguments.");
    switch (process_info[tls.process].subsystem) {
        case LIEF::PE::OptionalHeader::SUBSYSTEM::WINDOWS_CUI:
            ret("Return value: _CONSOLE_APP");
            return _CONSOLE_APP; // Console application
        case LIEF::PE::OptionalHeader::SUBSYSTEM::WINDOWS_GUI:
            ret("Return value: _GUI_APP");
            return _GUI_APP; // GUI application
        default:
            ret("Return value: _UNKNOWN_APP");
            return _UNKNOWN_APP;
    }
}

void UCRTBase::_register_thread_local_exe_atexit_callback(_tls_callback_type func) {
    trace("_register_thread_local_exe_atexit_callback called. Arguments: func=<void(*)(void)>[", reinterpret_cast<void*>(func), "]");
    if (func != nullptr) {
        tls.tls_atexit_callback = func;
    }
}

int UCRTBase::_resetstkoflw() {
    trace("_resetstkoflw called. No arguments.");
    // This is a stub implementation. In a real implementation, you would reset the stack overflow condition.
    ret("Return value: 0");
    return 0; // Success
}

int UCRTBase::_seh_filter_dll(unsigned int exceptionCode) {
    trace("_seh_filter_dll called. Arguments: exceptionCode=", std::to_wstring(exceptionCode));
    // This is a stub implementation. In a real implementation, you would handle the exception code appropriately.
    ret("Return value: 0");
    return 0; // Continue search
}

int UCRTBase::_seh_filter_exe(unsigned int exceptionCode) {
    trace("_seh_filter_exe called. Arguments: exceptionCode=", std::to_wstring(exceptionCode));
    // This is a stub implementation. In a real implementation, you would handle the exception code appropriately.
    ret("Return value: 0");
    return 0; // Continue search
}

UINT UCRTBase::_set_abort_behavior(UINT flags, UINT mask) {
    trace("_set_abort_behavior called. Arguments: flags=", std::to_wstring(flags), ", mask=", std::to_wstring(mask));
    // This is a stub implementation. In a real implementation, you would set the abort behavior accordingly.
    ret("Return value: 0");
    return 0; // Previous flags (stub)
}

void UCRTBase::_set_app_type(int appType) {
    trace("_set_app_type called. Arguments: appType=", std::to_wstring(appType));
    process_info[tls.process].subsystem = (appType == _CONSOLE_APP) ? LIEF::PE::OptionalHeader::SUBSYSTEM::WINDOWS_CUI : (appType == _GUI_APP) ? LIEF::PE::OptionalHeader::SUBSYSTEM::WINDOWS_GUI : LIEF::PE::OptionalHeader::SUBSYSTEM::UNKNOWN;
}

void UCRTBase::_set_controlfp(UINT newControl, UINT mask) {
    trace("_set_controlfp called. Arguments: newControl=", std::to_wstring(newControl), ", mask=", std::to_wstring(mask));
    __control87_2(newControl, mask, nullptr, nullptr);
}

void UCRTBase::_set_doserrno(int err) {
    trace("_set_doserrno called. Arguments: err=", std::to_wstring(err));
    errno = err;
}

void UCRTBase::_set_errno(int err) {
    trace("_set_errno called. Arguments: err=", std::to_wstring(err));
    errno = err;
}

int UCRTBase::_set_error_mode(int mode) {
    trace("_set_error_mode called. Arguments: mode=", std::to_wstring(mode));
    const int oldMode = process_info[tls.process].error_mode;
    process_info[tls.process].error_mode = mode;
    ret("Return value: ", std::to_wstring(oldMode));
    return oldMode;
}

_PNH UCRTBase::_set_new_handler(_PNH pNew) {
    trace("_set_new_handler called. Arguments: pNew=<_PNH>[", reinterpret_cast<void*>(pNew), "]");
    const _PNH oldHandler = process_info[tls.process].new_handler;
    process_info[tls.process].new_handler = pNew;
    ret("Return value: <_PNH>[", reinterpret_cast<void*>(oldHandler), "]");
    return oldHandler;
}

int UCRTBase::_seterrormode(int mode) {
    trace("_seterrormode called. Arguments: mode=", std::to_wstring(mode));
    const int oldMode = process_info[tls.process].error_mode;
    process_info[tls.process].error_mode = mode;
    ret("Return value: ", std::to_wstring(oldMode));
    return oldMode;
}

void UCRTBase::_sleep(ULONG milliseconds) {
    trace("_sleep called. Arguments: milliseconds=", std::to_wstring(milliseconds));
    Kernel32::Sleep(milliseconds);
}

UINT UCRTBase::_statusfp() {
    trace("_statusfp called. No arguments.");
    // This is a stub implementation. In a real implementation, you would return the current floating-point status word.
    constexpr UINT fpStatus = 0; // Example: no exceptions
    ret("Return value: ", std::to_wstring(fpStatus));
    return fpStatus;
}

void UCRTBase::_statusfp2(UINT *x86_cw, UINT *sse2_cw) {
    trace("_statusfp2 called. Arguments: x86_cw=<UINT*>[", x86_cw, "], sse2_cw=<UINT*>[", sse2_cw, "]");
    if (x86_cw) {
        *x86_cw = 0; // Example: no exceptions
    }
    if (sse2_cw) {
        *sse2_cw = 0; // Example: no exceptions
    }
}

int UCRTBase::system_(const char *command) {
    trace("system called. Arguments: command=<const char*>[", static_cast<const void*>(command), "]");
    if (command == nullptr) {
        ret("Return value: 1");
        return 0; // Indicate that a command processor is not available
    }
    // always return error wtf the lag u mfr!!!!
    return 1;
}

int UCRTBase::_wsystem(const _wchar_t *command) {
    trace("_wsystem called. Arguments: command=<const _wchar_t*>[", static_cast<const void*>(command), "]");
    if (command == nullptr) {
        ret("Return value: 1");
        return 0; // Indicate that a command processor is not available
    }
    // always return error wtf the lag u mfr!!!!
    return 1;
}

void UCRTBase::abort() {
    trace("abort called. No arguments.");
    std::abort();
}

void UCRTBase::exit(int exitCode) {
    trace("exit called. Arguments: exitCode=", std::to_wstring(exitCode));
    _c_exit();
    ret("No return value, function does not return.");
    std::exit(exitCode);
}

int UCRTBase::feclearexcept(int excepts) {
    trace("feclearexcept called. Arguments: excepts=", std::to_wstring(excepts));
    return std::feclearexcept(excepts);
}

int UCRTBase::fetestexcept(int excepts) {
    trace("fetestexcept called. Arguments: excepts=", std::to_wstring(excepts));
    return std::fetestexcept(excepts);
}

int UCRTBase::fegetenv(fenv_t *envp) {
    trace("fegetenv called. Arguments: envp=<fenv_t*>[", envp, "]");
    return std::fegetenv(envp);
}

int UCRTBase::fesetenv(const fenv_t *envp) {
    trace("fesetenv called. Arguments: envp=<const fenv_t*>[", envp, "]");
    return std::fesetenv(envp);
}

int UCRTBase::fegetround() {
    trace("fegetround called. No arguments.");
    return std::fegetround();
}

int UCRTBase::fesetround(int round) {
    trace("fesetround called. Arguments: round=", std::to_wstring(round));
    return std::fesetround(round);
}

int UCRTBase::fegetexceptflag(fexcept_t *flagp, int excepts) {
    trace("fegetexceptflag called. Arguments: flagp=<fexcept_t*>[", flagp, "], excepts=", std::to_wstring(excepts));
    return std::fegetexceptflag(flagp, excepts);
}

int UCRTBase::feholdexcept(fenv_t *envp) {
    trace("feholdexcept called. Arguments: envp=<fenv_t*>[", envp, "]");
    return std::feholdexcept(envp);
}

void UCRTBase::perror(const char *message) {
    trace("perror called. Arguments: message=<const char*>[", static_cast<const void*>(message), "]");
    if (message) {
        std::cerr << message << ": ";
    }
    std::cerr << std::strerror(errno) << std::endl;
}

void UCRTBase::quick_exit(int exitCode) {
    trace("quick_exit called. Arguments: exitCode=", std::to_wstring(exitCode));
    for (const auto func : process_info[tls.process].at_quick_exit_functions) {
        func();
    }
    if (tls.tls_atexit_callback) {
        tls.tls_atexit_callback(nullptr, DLL_PROCESS_DETACH /* ? */, nullptr);
    }
    ret("No return value, function does not return.");
    std::quick_exit(exitCode);
}

int UCRTBase::raise(int sig) {
    trace("raise called. Arguments: sig=", std::to_wstring(sig));
    return std::raise(sig);
}

std::terminate_handler UCRTBase::set_terminate(std::terminate_handler func) {
    trace("set_terminate called. Arguments: func=<terminate_function>[", func, "]");
    const std::terminate_handler old = std::get_terminate();
    std::set_terminate(func);
    ret("Return value: <terminate_function>[", old, "]");
    return old;
}

__sighandler_t UCRTBase::signal(int sig, __sighandler_t func) {
    trace("signal called. Arguments: sig=", std::to_wstring(sig), ", func=<void(*)(int)>[", reinterpret_cast<void*>(func), "]");
    const auto old = std::signal(sig, func);
    ret("Return value: <void(*)(int)>[", reinterpret_cast<void*>(old), "]");
    return old;
}

const char * UCRTBase::strerror(int errnum) {
    trace("strerror called. Arguments: errnum=", std::to_wstring(errnum));
    const char* errMsg = nullptr;
    if (errnum >= 0 && errnum < __sys_nerr()) {
        errMsg = __sys_errlist()[errnum];
    } else {
        errMsg = "Unknown error";
    }
    ret("Return value: <const char*>[", static_cast<const void*>(errMsg), "]");
    return errMsg;
}

errno_t UCRTBase::strerror_s(char *buf, size_t buflen, int errnum) {
    trace("strerror_s called. Arguments: buf=<char*>[", static_cast<void*>(buf), "], buflen=", std::to_wstring(buflen), ", errnum=", std::to_wstring(errnum));
    if (buf == nullptr || buflen == 0) {
        error("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    const char* errMsg = nullptr;
    if (errnum >= 0 && errnum < __sys_nerr()) {
        errMsg = __sys_errlist()[errnum];
    } else {
        errMsg = "Unknown error";
    }
    std::strncpy(buf, errMsg, buflen - 1);
    buf[buflen - 1] = '\0'; // Ensure null-termination
    ret("Error set to: -, Return value: 0");
    return 0; // Success
}

void UCRTBase::terminate() {
    trace("terminate called. No arguments.");
    std::terminate();
}

double UCRTBase::_cabs(const _complex z) {
    trace("_cabs called. Arguments: z=<_complex>{ real=", std::to_wstring(z.x), ", imag=", std::to_wstring(z.y), " }");
    const double result = std::hypot(z.x, z.y);
    ret("Return value: ", std::to_wstring(result));
    return result;
}

double UCRTBase::_chgsign(const double *x) {
    trace("_chgsign called. Arguments: x=<const double*>[", x, "]");
    if (x == nullptr) {
        error("Error set to: EINVAL, Return value: NaN");
        return std::numeric_limits<double>::quiet_NaN();
    }
    const double result = -*x;
    ret("Return value: ", std::to_wstring(result));
    return result;
}

float UCRTBase::_chgsignf(const float *x) {
    trace("_chgsignf called. Arguments: x=<const float*>[", x, "]");
    if (x == nullptr) {
        error("Error set to: EINVAL, Return value: NaN");
        return std::numeric_limits<float>::quiet_NaN();
    }
    const float result = -*x;
    ret("Return value: ", std::to_wstring(result));
    return result;
}

long double UCRTBase::_chgsignl(const long double *x) {
    trace("_chgsignl called. Arguments: x=<const long double*>[", x, "]");
    if (x == nullptr) {
        error("Error set to: EINVAL, Return value: NaN");
        return std::numeric_limits<long double>::quiet_NaN();
    }
    const long double result = -*x;
    ret("Return value: ", std::to_wstring(static_cast<double>(result)));
    return result;
}

double UCRTBase::_copysign(const double *x, const double *y) {
    trace("_copysign called. Arguments: x=<const double*>[", x, "], y=<const double*>[", y, "]");
    if (x == nullptr || y == nullptr) {
        error("Error set to: EINVAL, Return value: NaN");
        return std::numeric_limits<double>::quiet_NaN();
    }
    const double result = std::copysign(*x, *y);
    ret("Return value: ", std::to_wstring(result));
    return result;
}

float UCRTBase::_copysignf(const float *x, const float *y) {
    trace("_copysignf called. Arguments: x=<const float*>[", x, "], y=<const float*>[", y, "]");
    if (x == nullptr || y == nullptr) {
        error("Error set to: EINVAL, Return value: NaN");
        return std::numeric_limits<float>::quiet_NaN();
    }
    const float result = std::copysign(*x, *y);
    ret("Return value: ", std::to_wstring(result));
    return result;
}

long double UCRTBase::_copysignl(const long double *x, const long double *y) {
    trace("_copysignl called. Arguments: x=<const long double*>[", x, "], y=<const long double*>[", y, "]");
    if (x == nullptr || y == nullptr) {
        error("Error set to: EINVAL, Return value: NaN");
        return std::numeric_limits<long double>::quiet_NaN();
    }
    const long double result = std::copysign(*x, *y);
    ret("Return value: ", std::to_wstring(static_cast<double>(result)));
    return result;
}

int UCRTBase::_d_int() {
    trace("_d_int called. No arguments.");
    ret("Return value: 0");
    return 0; // Stub implementation
}

short UCRTBase::_dclass(double x) {
    trace("_dclass called. Arguments: x=", std::to_wstring(x));
    if (std::isnan(x)) return _FPCLASS_SNAN | _FPCLASS_QNAN;
    if (std::isinf(x)) return (x > 0) ? _FPCLASS_PINF : _FPCLASS_NINF;
    if (x == 0.0) return (std::signbit(x)) ? _FPCLASS_NZ : _FPCLASS_PZ;
    if (std::fpclassify(x) == FP_SUBNORMAL) return (x > 0) ? _FPCLASS_PSUB : _FPCLASS_NSUB;
    return (x > 0) ? _FPCLASS_PN : _FPCLASS_NN;
}

short UCRTBase::_ldclass(long double x) {
    trace("_ldclass called. Arguments: x=", std::to_wstring(static_cast<double>(x)));
    if (std::isnan(x)) return _FPCLASS_SNAN | _FPCLASS_QNAN;
    if (std::isinf(x)) return (x > 0) ? _FPCLASS_PINF : _FPCLASS_NINF;
    if (x == 0.0) return (std::signbit(x)) ? _FPCLASS_NZ : _FPCLASS_PZ;
    if (std::fpclassify(x) == FP_SUBNORMAL) return (x > 0) ? _FPCLASS_PSUB : _FPCLASS_NSUB;
    return (x > 0) ? _FPCLASS_PN : _FPCLASS_NN;
}

short UCRTBase::_fdclass(float x) {
    trace("_fdclass called. Arguments: x=", std::to_wstring(x));
    if (std::isnan(x)) return _FPCLASS_SNAN | _FPCLASS_QNAN;
    if (std::isinf(x)) return (x > 0) ? _FPCLASS_PINF : _FPCLASS_NINF;
    if (x == 0.0f) return (std::signbit(x)) ? _FPCLASS_NZ : _FPCLASS_PZ;
    if (std::fpclassify(x) == FP_SUBNORMAL) return (x > 0) ? _FPCLASS_PSUB : _FPCLASS_NSUB;
    return (x > 0) ? _FPCLASS_PN : _FPCLASS_NN;
}

short UCRTBase::_dexp(double *px, double y, LONG exp) {
    trace("_dexp called. Arguments: px=<double*>[", px, "], y=", std::to_wstring(y), ", exp=", std::to_wstring(exp));
    if (px == nullptr) {
        error("Error set to: EINVAL, Return value: _FPCLASS_QNAN");
        return _FPCLASS_QNAN;
    }
    *px = y * std::pow(2.0, exp);
    return _dclass(*px);
}

short UCRTBase::_fdexp(float *px, float y, LONG exp) {
    trace("_fdexp called. Arguments: px=<float*>[", px, "], y=", std::to_wstring(y), ", exp=", std::to_wstring(exp));
    if (px == nullptr) {
        error("Error set to: EINVAL, Return value: _FPCLASS_QNAN");
        return _FPCLASS_QNAN;
    }
    *px = y * std::pow(2.0f, exp);
    return _fdclass(*px);
}

short UCRTBase::_ldexp(long double *px, long double y, LONG exp) {
    trace("_ldexp called. Arguments: px=<long double*>[", px, "], y=", std::to_wstring(static_cast<double>(y)), ", exp=", std::to_wstring(exp));
    if (px == nullptr) {
        error("Error set to: EINVAL, Return value: _FPCLASS_QNAN");
        return _FPCLASS_QNAN;
    }
    *px = y * std::pow(2.0L, exp);
    return _ldclass(*px);
}

short UCRTBase::_dlog(double x, int base_flag) {
    trace("_dlog called. Arguments: x=", std::to_wstring(x), ", base_flag=", std::to_wstring(base_flag));
    if (x < 0.0) {
        error("Error set to: EDOM, Return value: _FPCLASS_QNAN");
        return _FPCLASS_QNAN;
    }
    double result = 0.0;
    if (base_flag == 0) { //base 10
        result = std::log10(x);
    } else {
        result = std::log(x); // natural log
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return _dclass(result);
}

short UCRTBase::_fdlog(float x, int base_flag) {
    trace("_fdlog called. Arguments: x=", std::to_wstring(x), ", base_flag=", std::to_wstring(base_flag));
    if (x < 0.0f) {
        error("Error set to: EDOM, Return value: _FPCLASS_QNAN");
        return _FPCLASS_QNAN;
    }
    float result = 0.0f;
    if (base_flag == 0) { //base 10
        result = std::log10(x);
    } else {
        result = std::log(x); // natural log
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return _fdclass(result);
}

short UCRTBase::_ldlog(long double x, int base_flag) {
    trace("_ldlog called. Arguments: x=", std::to_wstring(static_cast<double>(x)), ", base_flag=", std::to_wstring(base_flag));
    if (x < 0.0L) {
        error("Error set to: EDOM, Return value: _FPCLASS_QNAN");
        return _FPCLASS_QNAN;
    }
    long double result = 0.0L;
    if (base_flag == 0) { //base 10
        result = std::log10(x);
    } else {
        result = std::log(x); // natural log
    }
    ret("Error set to: -, Return value: ", std::to_wstring(static_cast<double>(result)));
    return _ldclass(result);
}

short UCRTBase::_dnorm(USHORT *ps) {
    trace("_dnorm called. Arguments: ps=<USHORT*>[", ps, "]");
    if (ps == nullptr) {
        error("Error set to: EINVAL, Return value: _FPCLASS_QNAN");
        return _FPCLASS_QNAN;
    }
    // This is a stub implementation. In a real implementation, you would normalize the floating-point number.
    ret("Error set to: -, Return value: _FPCLASS_PN");
    return _FPCLASS_PN; // Assume normalized positive number
}

short UCRTBase::_fdnorm(USHORT *ps) {
    trace("_fdnorm called. Arguments: ps=<USHORT*>[", ps, "]");
    if (ps == nullptr) {
        error("Error set to: EINVAL, Return value: _FPCLASS_QNAN");
        return _FPCLASS_QNAN;
    }
    // This is a stub implementation. In a real implementation, you would normalize the floating-point number.
    ret("Error set to: -, Return value: _FPCLASS_PN");
    return _FPCLASS_PN; // Assume normalized positive number
}

short UCRTBase::_ldnorm(USHORT *ps) {
    trace("_ldnorm called. Arguments: ps=<USHORT*>[", ps, "]");
    if (ps == nullptr) {
        error("Error set to: EINVAL, Return value: _FPCLASS_QNAN");
        return _FPCLASS_QNAN;
    }
    // This is a stub implementation. In a real implementation, you would normalize the floating-point number.
    ret("Error set to: -, Return value: _FPCLASS_PN");
    return _FPCLASS_PN; // Assume normalized positive number
}

short UCRTBase::_dpcomp(double x, double y) {
    trace("_dpcomp called. Arguments: x=", std::to_wstring(x), ", y=", std::to_wstring(y));
    if (std::isnan(x) || std::isnan(y)) {
        error("Error set to: EDOM, Return value: 0");
        return 0; // NaN comparison
    }
    if (x < y) {
        ret("Error set to: -, Return value: -1");
        return _FP_LT; // value = -1
    } else if (x > y) {
        ret("Error set to: -, Return value: 1");
        return _FP_GT; // value = 1
    } else {
        ret("Error set to: -, Return value: 0");
        return _FP_EQ; // value = 0
    }
}

short UCRTBase::_dpoly(double x, double const *table, int n) {
    trace("_dpoly called. Arguments: x=", std::to_wstring(x), ", table=<const double*>[", table, "], n=", std::to_wstring(n));
    if (table == nullptr || n <= 0) {
        error("Error set to: EINVAL, Return value: _FPCLASS_QNAN");
        return _FPCLASS_QNAN;
    }
    const std::vector coefficients(table, table + n);
    const double result = _evaluate_polynomial(coefficients, x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return _dclass(result);
}

short UCRTBase::_fdpoly(float x, float const *table, int n) {
    trace("_fdpoly called. Arguments: x=", std::to_wstring(x), ", table=<const float*>[", table, "], n=", std::to_wstring(n));
    if (table == nullptr || n <= 0) {
        error("Error set to: EINVAL, Return value: _FPCLASS_QNAN");
        return _FPCLASS_QNAN;
    }
    const std::vector<double> coefficients(table, table + n);
    const auto result = static_cast<float>(_evaluate_polynomial(coefficients, x));
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return _fdclass(result);
}

short UCRTBase::_ldpoly(long double x, long double const *table, int n) {
    trace("_ldpoly called. Arguments: x=", std::to_wstring(static_cast<double>(x)), ", table=<const long double*>[", table, "], n=", std::to_wstring(n));
    if (table == nullptr || n <= 0) {
        error("Error set to: EINVAL, Return value: _FPCLASS_QNAN");
        return _FPCLASS_QNAN;
    }
    const std::vector<double> coefficients(table, table + n);
    const auto result = static_cast<long double>(_evaluate_polynomial(coefficients, static_cast<double>(x)));
    ret("Error set to: -, Return value: ", std::to_wstring(static_cast<double>(result)));
    return _ldclass(result);
}

double UCRTBase::_evaluate_polynomial(const std::vector<double> &coefficients, double x) {
    double result = 0.0;
    for (size_t i = 0; i < coefficients.size(); ++i) {
        result += coefficients[i] * std::pow(x, i);
    }
    return result;
}

short UCRTBase::_dscale(double *x, int exp) {
    trace("_dscale called. Arguments: x=<double*>[", x, "], exp=", std::to_wstring(exp));
    if (x == nullptr) {
        error("Error set to: EINVAL, Return value: _FPCLASS_QNAN");
        return _FPCLASS_QNAN;
    }
    *x *= std::pow(2.0, exp);
    return _dclass(*x);
}

short UCRTBase::_fdscale(float *x, int exp) {
    trace("_fdscale called. Arguments: x=<float*>[", x, "], exp=", std::to_wstring(exp));
    if (x == nullptr) {
        error("Error set to: EINVAL, Return value: _FPCLASS_QNAN");
        return _FPCLASS_QNAN;
    }
    *x *= std::pow(2.0f, exp);
    return _fdclass(*x);
}

short UCRTBase::_ldscale(long double *x, int exp) {
    trace("_ldscale called. Arguments: x=<long double*>[", x, "], exp=", std::to_wstring(exp));
    if (x == nullptr) {
        error("Error set to: EINVAL, Return value: _FPCLASS_QNAN");
        return _FPCLASS_QNAN;
    }
    *x *= std::pow(2.0L, exp);
    return _ldclass(*x);
}

int UCRTBase::_dsign(double x) {
    trace("_dsign called. Arguments: x=", std::to_wstring(x));
    if (std::isnan(x)) {
        error("Error set to: EDOM, Return value: 0");
        return 0; // NaN has no sign
    }
    const int sign = (x > 0) ? 1 : (x < 0) ? -1 : 0;
    ret("Error set to: -, Return value: ", std::to_wstring(sign));
    return sign;
}

int UCRTBase::_fdsign(float x) {
    trace("_fdsign called. Arguments: x=", std::to_wstring(x));
    if (std::isnan(x)) {
        error("Error set to: EDOM, Return value: 0");
        return 0; // NaN has no sign
    }
    const int sign = (x > 0) ? 1 : (x < 0) ? -1 : 0;
    ret("Error set to: -, Return value: ", std::to_wstring(sign));
    return sign;
}

int UCRTBase::_ldsign(long double x) {
    trace("_ldsign called. Arguments: x=", std::to_wstring(static_cast<double>(x)));
    if (std::isnan(x)) {
        error("Error set to: EDOM, Return value: 0");
        return 0; // NaN has no sign
    }
    const int sign = (x > 0) ? 1 : (x < 0) ? -1 : 0;
    ret("Error set to: -, Return value: ", std::to_wstring(sign));
    return sign;
}

double UCRTBase::_dsin(double x, UINT quadrant) {
    trace("_dsin called. Arguments: x=", std::to_wstring(x), ", quadrant=", std::to_wstring(quadrant));
    double angle = x;
    switch (quadrant % 4) {
        case 0: break; // sin(x)
        case 1: angle = M_PI_2 - x; break; // cos(x)
        case 2: angle = -x; break; // -sin(x)
        case 3: angle = x - M_PI_2; break; // -cos(x)
        default: break;
    }
    const double result = std::sin(angle);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

float UCRTBase::_fdsin(float x, UINT quadrant) {
    trace("_fdsin called. Arguments: x=", std::to_wstring(x), ", quadrant=", std::to_wstring(quadrant));
    float angle = x;
    switch (quadrant % 4) {
        case 0: break; // sin(x)
        case 1: angle = static_cast<float>(M_PI_2) - x; break; // cos(x)
        case 2: angle = -x; break; // -sin(x)
        case 3: angle = x - static_cast<float>(M_PI_2); break; // -cos(x)
        default: break;
    }
    const float result = std::sin(angle);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

long double UCRTBase::_ldsin(long double x, UINT quadrant) {
    trace("_ldsin called. Arguments: x=", std::to_wstring(static_cast<double>(x)), ", quadrant=", std::to_wstring(quadrant));
    long double angle = x;
    switch (quadrant % 4) {
        case 0: break; // sin(x)
        case 1: angle = static_cast<long double>(M_PI_2) - x; break; // cos(x)
        case 2: angle = -x; break; // -sin(x)
        case 3: angle = x - static_cast<long double>(M_PI_2); break; // -cos(x)
        default: break;
    }
    const long double result = std::sin(static_cast<double>(angle));
    ret("Error set to: -, Return value: ", std::to_wstring(static_cast<double>(result)));
    return result;
}

short UCRTBase::_dtest(double *px) {
    trace("_dtest called. Arguments: px=<double*>[", px, "]");
    if (px == nullptr) {
        error("Error set to: EINVAL, Return value: _FPCLASS_QNAN");
        return _FPCLASS_QNAN;
    }
    return _dclass(*px);
}

short UCRTBase::_fdtest(float *px) {
    trace("_fdtest called. Arguments: px=<float*>[", px, "]");
    if (px == nullptr) {
        error("Error set to: EINVAL, Return value: _FPCLASS_QNAN");
        return _FPCLASS_QNAN;
    }
    return _fdclass(*px);
}

short UCRTBase::_ldtest(long double *px) {
    trace("_ldtest called. Arguments: px=<long double*>[", px, "]");
    if (px == nullptr) {
        error("Error set to: EINVAL, Return value: _FPCLASS_QNAN");
        return _FPCLASS_QNAN;
    }
    return _ldclass(*px);
}

short UCRTBase::_dunscale(int *pexp, double *px) {
    trace("_dunscale called. Arguments: pexp=<int*>[", pexp, "], px=<double*>[", px, "]");
    if (px == nullptr || pexp == nullptr) {
        error("Error set to: EINVAL, Return value: _FPCLASS_QNAN");
        return _FPCLASS_QNAN;
    }
    int exponent;
    const double mantissa = std::frexp(*px, &exponent);
    *px = mantissa;
    *pexp = exponent;
    return _dclass(*px);
}

short UCRTBase::_fdunscale(int *pexp, float *px) {
    trace("_fdunscale called. Arguments: pexp=<int*>[", pexp, "], px=<float*>[", px, "]");
    if (px == nullptr || pexp == nullptr) {
        error("Error set to: EINVAL, Return value: _FPCLASS_QNAN");
        return _FPCLASS_QNAN;
    }
    int exponent;
    const float mantissa = std::frexp(*px, &exponent);
    *px = mantissa;
    *pexp = exponent;
    return _fdclass(*px);
}

short UCRTBase::_ldunscale(int *pexp, long double *px) {
    trace("_ldunscale called. Arguments: pexp=<int*>[", pexp, "], px=<long double*>[", px, "]");
    if (px == nullptr || pexp == nullptr) {
        error("Error set to: EINVAL, Return value: _FPCLASS_QNAN");
        return _FPCLASS_QNAN;
    }
    int exponent;
    const long double mantissa = std::frexp(static_cast<double>(*px), &exponent);
    *px = static_cast<long double>(mantissa);
    *pexp = exponent;
    return _ldclass(*px);
}

UINT UCRTBase::get_mxcsr() {
    unsigned int mxcsr;
    __asm__ __volatile__ (
        "stmxcsr %0"
        : "=m" (mxcsr)
    );
    return mxcsr;
}

void UCRTBase::set_mxcsr(UINT mxcsr) {
    __asm__ __volatile__ (
        "ldmxcsr %0"
        :
        : "m" (mxcsr)
    );
}

void UCRTBase::_setfp_sse(UINT *cw, UINT cw_mask, UINT *sw, UINT sw_mask) {
    trace("_setfp_sse called. Arguments: cw=<UINT*>[", cw, "], cw_mask=", std::to_wstring(cw_mask), ", sw=<UINT*>[", sw, "], sw_mask=", std::to_wstring(sw_mask));
    UINT fpword = get_mxcsr();
    UINT flags;
    UINT old_fpword = fpword;

    cw_mask &= _MCW_EM | _MCW_RC | _MCW_DN;
    sw_mask &= _MCW_EM;

    if (sw) {
        flags = 0;
        if (fpword & 0x1) flags |= _SW_INVALID;
        if (fpword & 0x2) flags |= _SW_DENORMAL;
        if (fpword & 0x4) flags |= _SW_ZERODIVIDE;
        if (fpword & 0x8) flags |= _SW_OVERFLOW;
        if (fpword & 0x10) flags |= _SW_UNDERFLOW;
        if (fpword & 0x20) flags |= _SW_INEXACT;

        *sw = (flags & ~sw_mask) | (*sw & sw_mask);

        trace("  sw updated to ", std::to_wstring(*sw));
        fpword &= ~0x3F;
        if (*sw & _SW_INVALID) fpword |= 0x1;
        if (*sw & _SW_DENORMAL) fpword |= 0x2;
        if (*sw & _SW_ZERODIVIDE) fpword |= 0x4;
        if (*sw & _SW_OVERFLOW) fpword |= 0x8;
        if (*sw & _SW_UNDERFLOW) fpword |= 0x10;
        if (*sw & _SW_INEXACT) fpword |= 0x20;
        *sw = flags;
    }

    if (cw) {
        flags = 0;
        if (fpword & 0x80) flags |= _EM_INVALID;
        if (fpword & 0x100) flags |= _EM_DENORMAL;
        if (fpword & 0x200) flags |= _EM_ZERODIVIDE;
        if (fpword & 0x400) flags |= _EM_OVERFLOW;
        if (fpword & 0x800) flags |= _EM_UNDERFLOW;
        if (fpword & 0x1000) flags |= _EM_INEXACT;
        switch (fpword & 0x6000) {
            case 0x6000: flags |= _RC_UP | _RC_DOWN; break;
            case 0x4000: flags |= _RC_UP; break;
            case 0x2000: flags |= _RC_DOWN; break;
            default: break;
        }
        switch (fpword & 0x8040) {
            case 0x0040: flags |= _DN_FLUSH_OPERANDS_SAVE_RESULTS; break;
            case 0x8000: flags |= _DN_SAVE_OPERANDS_FLUSH_RESULTS; break;
            case 0x8040: flags |= _DN_FLUSH; break;
            default: break;
        }
        *cw = (flags & ~cw_mask) | (*cw & cw_mask);
        trace("  cw updated to ", std::to_wstring(*cw));
        fpword &= ~0xFFC0;
        if (*cw & _EM_INVALID) fpword |= 0x80;
        if (*cw & _EM_DENORMAL) fpword |= 0x100;
        if (*cw & _EM_ZERODIVIDE) fpword |= 0x200;
        if (*cw & _EM_OVERFLOW) fpword |= 0x400;
        if (*cw & _EM_UNDERFLOW) fpword |= 0x800;
        if (*cw & _EM_INEXACT) fpword |= 0x1000;
        switch (*cw & _MCW_RC) {
            case _RC_UP | _RC_DOWN: fpword |= 0x6000; break;
            case _RC_UP: fpword |= 0x4000; break;
            case _RC_DOWN: fpword |= 0x2000; break;
            default: break;
        }
        switch (*cw & _MCW_DN) {
            case _DN_FLUSH_OPERANDS_SAVE_RESULTS: fpword |= 0x0040; break;
            case _DN_SAVE_OPERANDS_FLUSH_RESULTS: fpword |= 0x8000; break;
            case _DN_FLUSH: fpword |= 0x8040; break;
            default: break;
        }

        if (fpword != old_fpword && !sw) {
            // clear exceptions if control word changed and sw not requested
            trace("  clearing exceptions because cw changed and sw not requested");
            fpword &= ~0x3F;
        }
    }

    if (fpword != old_fpword) {
        set_mxcsr(fpword);
        trace("  mxcsr updated to ", std::to_wstring(fpword));
    }
}

double UCRTBase::_except1(DWORD fpe, _FP_OPERATION_CODE op, double arg, double res, DWORD cw, void *unk) {
    trace("_except1 called. Arguments: fpe=", std::to_wstring(fpe), ", op=", std::to_wstring(static_cast<DWORD>(op)), ", arg=", std::to_wstring(arg), ", res=", std::to_wstring(res), ", cw=", std::to_wstring(cw), ", unk=<void*>[", unk, "]");
    DWORD exception = 0;
    UINT fpword = 0;
    int raise = 0;

    cw = cw >> 7 & 0x3F | cw >> 3 & 0xC00;
    WORD operation = op << 5;
    auto exception_arg = reinterpret_cast<ULONG_PTR>(&operation);

    if (fpe & 0x1) {
        // overflow
        if ((fpe == 0x1 && cw & 0x8) || (fpe == 0x11 && cw & 0x28)) {
            raise |= FE_OVERFLOW;
            if (fpe & 0x10) {
                raise |= FE_INEXACT;
            }
            res = std::signbit(res) ? -INFINITY : INFINITY;
        }
        else {
            exception = EXCEPTION_FLT_OVERFLOW;
        }

    }
    else if (fpe & 0x2) {
        // underflow
        if ((fpe == 0x2 && cw & 0x4) || (fpe == 0x12 && cw & 0x30)) {
            raise |= FE_UNDERFLOW;
            if (fpe & 0x10) {
                raise |= FE_INEXACT;
            }
            res = std::signbit(res) ? -0.0 : 0.0;
        }
        else {
            exception = EXCEPTION_FLT_UNDERFLOW;
        }
    }
    else if (fpe & 0x4) {
        // zero divide
        if ((fpe == 0x4 && (cw & 0x10)) || (fpe == 0x14 && (cw & 0x24))) {
            raise |= FE_DIVBYZERO;
            res = std::signbit(arg) ? -INFINITY : INFINITY;
        }
        else {
            exception = EXCEPTION_FLT_DIVIDE_BY_ZERO;
        }
    }
    else if (fpe & 0x8) {
        // invalid
        if (fpe == 0x8 && (cw & 0x1)) {
            raise |= FE_INVALID;
            res = NAN;
        }
        else {
            exception = EXCEPTION_FLT_INVALID_OPERATION;
        }
    }
    else if (fpe & 0x10) {
        // inexact
        if (cw & 0x20) {
            raise |= FE_INEXACT;
        }
        else {
            exception = EXCEPTION_FLT_INEXACT_RESULT;
        }
    }
    else {
        ret("Error set to: -, Return value: ", std::to_wstring(res));
        return res;
    }

    if (exception) {
        raise = 0;
    }

    std::feraiseexcept(raise);

    if (exception) {
        Kernel32::RaiseException(exception, 0, 1, &exception_arg);
    }

    if (cw & 0x1) {
        fpword |= _EM_INVALID;
    }
    if (cw & 0x2) {
        fpword |= _EM_DENORMAL;
    }
    if (cw & 0x4) {
        fpword |= _EM_ZERODIVIDE;
    }
    if (cw & 0x8) {
        fpword |= _EM_OVERFLOW;
    }
    if (cw & 0x10) {
        fpword |= _EM_UNDERFLOW;
    }
    if (cw & 0x20) {
        fpword |= _EM_INEXACT;
    }
    switch (cw & 0xC00) {
        case 0xC00: fpword |= _RC_UP | _RC_DOWN; break;
        case 0x800: fpword |= _RC_UP; break;
        case 0x400: fpword |= _RC_DOWN; break;
        default: break;
    }
    switch (cw & 0x300) {
        case 0x0: fpword |= _PC_24; break;
        case 0x100: fpword |= _PC_53; break;
        case 0x200: fpword |= _PC_64; break;
        default: break;
    }
    if (cw & 0x1000) {
        fpword |= _IC_AFFINE;
    }
    _setfp_sse(&fpword, _MCW_EM | _MCW_RC | _MCW_PC | _MCW_IC, nullptr, 0);
    return res;
}

double UCRTBase::_CIacos(double x) {
    trace("_CIacos called. Arguments: x=", std::to_wstring(x));
    if (x < -1.0 || x > 1.0) {
        error("Error set to: EDOM, Return value: NaN");
        return std::numeric_limits<double>::quiet_NaN();
    }
    const double result = std::acos(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

double UCRTBase::_CIasin(double x) {
    trace("_CIasin called. Arguments: x=", std::to_wstring(x));
    if (x < -1.0 || x > 1.0) {
        error("Error set to: EDOM, Return value: NaN");
        return std::numeric_limits<double>::quiet_NaN();
    }
    const double result = std::asin(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

double UCRTBase::_CIatan(double x) {
    trace("_CIatan called. Arguments: x=", std::to_wstring(x));
    const double result = std::atan(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

double UCRTBase::_CIatan2(double y, double x) {
    trace("_CIatan2 called. Arguments: y=", std::to_wstring(y), ", x=", std::to_wstring(x));
    const double result = std::atan2(y, x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

double UCRTBase::_CIcos(double x) {
    trace("_CIcos called. Arguments: x=", std::to_wstring(x));
    const double result = std::cos(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

double UCRTBase::_CIsin(double x) {
    trace("_CIsin called. Arguments: x=", std::to_wstring(x));
    const double result = std::sin(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

double UCRTBase::_CItan(double x) {
    trace("_CItan called. Arguments: x=", std::to_wstring(x));
    const double result = std::tan(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

double UCRTBase::_CIcosh(double x) {
    trace("_CIcosh called. Arguments: x=", std::to_wstring(x));
    const double result = std::cosh(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

double UCRTBase::_CIexp(double x) {
    trace("_CIexp called. Arguments: x=", std::to_wstring(x));
    const double result = std::exp(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

double UCRTBase::_CIfmod(double x, double y) {
    trace("_CIfmod called. Arguments: x=", std::to_wstring(x), ", y=", std::to_wstring(y));
    if (y == 0.0) {
        error("Error set to: EDOM, Return value: NaN");
        return std::numeric_limits<double>::quiet_NaN();
    }
    const double result = std::fmod(x, y);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

double UCRTBase::_CIlog10(double x) {
    trace("_CIlog10 called. Arguments: x=", std::to_wstring(x));
    if (x <= 0.0) {
        error("Error set to: EDOM, Return value: NaN");
        return std::numeric_limits<double>::quiet_NaN();
    }
    const double result = std::log10(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

double UCRTBase::_CIlog(double x) {
    trace("_CIlog called. Arguments: x=", std::to_wstring(x));
    if (x <= 0.0) {
        error("Error set to: EDOM, Return value: NaN");
        return std::numeric_limits<double>::quiet_NaN();
    }
    const double result = std::log(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

double UCRTBase::_CIsinh(double x) {
    trace("_CIsinh called. Arguments: x=", std::to_wstring(x));
    const double result = std::sinh(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

double UCRTBase::_CIsqrt(double x) {
    trace("_CIsqrt called. Arguments: x=", std::to_wstring(x));
    if (x < 0.0) {
        error("Error set to: EDOM, Return value: NaN");
        return std::numeric_limits<double>::quiet_NaN();
    }
    const double result = std::sqrt(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

double UCRTBase::_CItanh(double x) {
    trace("_CItanh called. Arguments: x=", std::to_wstring(x));
    const double result = std::tanh(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

_Dcomplex UCRTBase::_Cbuild(double real, double imag) {
    trace("_Cbuild called. Arguments: real=", std::to_wstring(real), ", imag=", std::to_wstring(imag));
    _Dcomplex result{};
    result._Val[0] = real;
    result._Val[1] = imag;
    ret("Error set to: -, Return value: _complex{ real=", std::to_wstring(result._Val[0]), ", imag=", std::to_wstring(result._Val[1]), " }");
    return result;
}

_Dcomplex UCRTBase::_Cmulcc(_Dcomplex a, _Dcomplex b) {
    _Dcomplex res{};
    res._Val[0] = a._Val[0] * b._Val[0] - a._Val[1] * b._Val[1];
    res._Val[1] = a._Val[0] * b._Val[1] + a._Val[1] * b._Val[0];
    return res;
}

_Dcomplex UCRTBase::_Cmulcr(_Dcomplex a, double b) {
    _Dcomplex res{};
    res._Val[0] = a._Val[0] * b;
    res._Val[1] = a._Val[1] * b;
    return res;
}

ULONGLONG UCRTBase::_FCbuild(float real, float imag) {
    trace("_FCbuild called. Arguments: real=", std::to_wstring(real), ", imag=", std::to_wstring(imag));
    union {
        _Fcomplex c;
        ULONGLONG ull;
    } res{};

    assert(sizeof(res.c) == sizeof(res.ull));

    res.c._Val[0] = real;
    res.c._Val[1] = imag;
    ret("Error set to: -, Return value: ", std::to_wstring(res.ull));
    return res.ull;
}

_Fcomplex UCRTBase::_FCmulcc(_Fcomplex a, _Fcomplex b) {
    _Fcomplex res{};
    res._Val[0] = a._Val[0] * b._Val[0] - a._Val[1] * b._Val[1];
    res._Val[1] = a._Val[0] * b._Val[1] + a._Val[1] * b._Val[0];;
    return res;
}

_Fcomplex UCRTBase::_FCmulcr(_Fcomplex a, float b) {
    _Fcomplex res{};
    res._Val[0] = a._Val[0] * b;
    res._Val[1] = a._Val[1] * b;
    return res;
}

_Lcomplex UCRTBase::_LCbuild(long double real, long double imag) {
    trace("_LCbuild called. Arguments: real=", std::to_wstring(static_cast<double>(real)), ", imag=", std::to_wstring(static_cast<double>(imag)));
    _Lcomplex result{};
    result._Val[0] = real;
    result._Val[1] = imag;
    ret("Error set to: -, Return value: _complex{ real=", std::to_wstring(static_cast<double>(result._Val[0])), ", imag=", std::to_wstring(static_cast<double>(result._Val[1])), " }");
    return result;
}

_Lcomplex UCRTBase::_LCmulcc(_Lcomplex a, _Lcomplex b) {
    _Lcomplex res{};
    res._Val[0] = a._Val[0] * b._Val[0] - a._Val[1] * b._Val[1];
    res._Val[1] = a._Val[0] * b._Val[1] + a._Val[1] * b._Val[0];;
    return res;
}

_Lcomplex UCRTBase::_LCmulcr(_Lcomplex a, long double b) {
    _Lcomplex res{};
    res._Val[0] = a._Val[0] * b;
    res._Val[1] = a._Val[1] * b;
    return res;
}

void UCRTBase::__libm_sse2_acos() {
    double d;
    __asm__ __volatile__ (
        "movq %%xmm0, %0\n"
        : "=m" (d)
    );
    d = acos(d);
    __asm__ __volatile__ (
        "movq %0, %%xmm0\n"
        :
        : "m" (d)
    );
}

void UCRTBase::__libm_sse2_acos_precise() {
    double d;
    __asm__ __volatile__ (
        "movq %%xmm0, %0\n"
        : "=m" (d)
    );
    d = acos(d);
    __asm__ __volatile__ (
        "movq %0, %%xmm0\n"
        :
        : "m" (d)
    );
}

void UCRTBase::__libm_sse2_acosf() {
    float f;
    __asm__ __volatile__ (
        "movd %%xmm0, %0\n"
        : "=m" (f)
    );
    f = acosf(f);
    __asm__ __volatile__ (
        "movd %0, %%xmm0\n"
        :
        : "m" (f)
    );
}

void UCRTBase::__libm_sse2_asin() {
    double d;
    __asm__ __volatile__ (
        "movq %%xmm0, %0\n"
        : "=m" (d)
    );
    d = asin(d);
    __asm__ __volatile__ (
        "movq %0, %%xmm0\n"
        :
        : "m" (d)
    );
}

void UCRTBase::__libm_sse2_asin_precise() {
    double d;
    __asm__ __volatile__ (
        "movq %%xmm0, %0\n"
        : "=m" (d)
    );
    d = asin(d);
    __asm__ __volatile__ (
        "movq %0, %%xmm0\n"
        :
        : "m" (d)
    );
}

void UCRTBase::__libm_sse2_asinf() {
    float f;
    __asm__ __volatile__ (
        "movd %%xmm0, %0\n"
        : "=m" (f)
    );
    f = asinf(f);
    __asm__ __volatile__ (
        "movd %0, %%xmm0\n"
        :
        : "m" (f)
    );
}

void UCRTBase::__libm_sse2_atan() {
    double d;
    __asm__ __volatile__ (
        "movq %%xmm0, %0\n"
        : "=m" (d)
    );
    d = atan(d);
    __asm__ __volatile__ (
        "movq %0, %%xmm0\n"
        :
        : "m" (d)
    );
}

void UCRTBase::__libm_sse2_atan_precise() {
    double d;
    __asm__ __volatile__ (
        "movq %%xmm0, %0\n"
        : "=m" (d)
    );
    d = atan(d);
    __asm__ __volatile__ (
        "movq %0, %%xmm0\n"
        :
        : "m" (d)
    );
}

void UCRTBase::__libm_sse2_atanf() {
    float f;
    __asm__ __volatile__ (
        "movd %%xmm0, %0\n"
        : "=m" (f)
    );
    f = atanf(f);
    __asm__ __volatile__ (
        "movd %0, %%xmm0\n"
        :
        : "m" (f)
    );
}

void UCRTBase::__libm_sse2_atan2() {
    double y, x, result;
    __asm__ __volatile__ (
        "movq %%xmm0, %0\n"
        : "=m" (y)
    );
    __asm__ __volatile__ (
        "movq %%xmm1, %0\n"
        : "=m" (x)
    );
    result = atan2(y, x);
    __asm__ __volatile__ (
        "movq %0, %%xmm0\n"
        :
        : "m" (result)
    );
}

void UCRTBase::__libm_sse2_atan2_precise() {
    double y, x, result;
    __asm__ __volatile__ (
        "movq %%xmm0, %0\n"
        : "=m" (y)
    );
    __asm__ __volatile__ (
        "movq %%xmm1, %0\n"
        : "=m" (x)
    );
    result = atan2(y, x);
    __asm__ __volatile__ (
        "movq %0, %%xmm0\n"
        :
        : "m" (result)
    );
}

void UCRTBase::__libm_sse2_atan2f() {
    float y, x, result;
    __asm__ __volatile__ (
        "movd %%xmm0, %0\n"
        : "=m" (y)
    );
    __asm__ __volatile__ (
        "movd %%xmm1, %0\n"
        : "=m" (x)
    );
    result = atan2f(y, x);
    __asm__ __volatile__ (
        "movd %0, %%xmm0\n"
        :
        : "m" (result)
    );
}

void UCRTBase::__libm_sse2_cos() {
    double d;
    __asm__ __volatile__ (
        "movq %%xmm0, %0\n"
        : "=m" (d)
    );
    d = cos(d);
    __asm__ __volatile__ (
        "movq %0, %%xmm0\n"
        :
        : "m" (d)
    );
}

void UCRTBase::__libm_sse2_cos_precise() {
    double d;
    __asm__ __volatile__ (
        "movq %%xmm0, %0\n"
        : "=m" (d)
    );
    d = cos(d);
    __asm__ __volatile__ (
        "movq %0, %%xmm0\n"
        :
        : "m" (d)
    );
}

void UCRTBase::__libm_sse2_cosf() {
    float f;
    __asm__ __volatile__ (
        "movd %%xmm0, %0\n"
        : "=m" (f)
    );
    f = cosf(f);
    __asm__ __volatile__ (
        "movd %0, %%xmm0\n"
        :
        : "m" (f)
    );
}

void UCRTBase::__libm_sse2_sin() {
    double d;
    __asm__ __volatile__ (
        "movq %%xmm0, %0\n"
        : "=m" (d)
    );
    d = sin(d);
    __asm__ __volatile__ (
        "movq %0, %%xmm0\n"
        :
        : "m" (d)
    );
}

void UCRTBase::__libm_sse2_sin_precise() {
    double d;
    __asm__ __volatile__ (
        "movq %%xmm0, %0\n"
        : "=m" (d)
    );
    d = sin(d);
    __asm__ __volatile__ (
        "movq %0, %%xmm0\n"
        :
        : "m" (d)
    );
}

void UCRTBase::__libm_sse2_sinf() {
    float f;
    __asm__ __volatile__ (
        "movd %%xmm0, %0\n"
        : "=m" (f)
    );
    f = sinf(f);
    __asm__ __volatile__ (
        "movd %0, %%xmm0\n"
        :
        : "m" (f)
    );
}

void UCRTBase::__libm_sse2_tan() {
    double d;
    __asm__ __volatile__ (
        "movq %%xmm0, %0\n"
        : "=m" (d)
    );
    d = tan(d);
    __asm__ __volatile__ (
        "movq %0, %%xmm0\n"
        :
        : "m" (d)
    );
}

void UCRTBase::__libm_sse2_tan_precise() {
    double d;
    __asm__ __volatile__ (
        "movq %%xmm0, %0\n"
        : "=m" (d)
    );
    d = tan(d);
    __asm__ __volatile__ (
        "movq %0, %%xmm0\n"
        :
        : "m" (d)
    );
}

void UCRTBase::__libm_sse2_tanf() {
    float f;
    __asm__ __volatile__ (
        "movd %%xmm0, %0\n"
        : "=m" (f)
    );
    f = tanf(f);
    __asm__ __volatile__ (
        "movd %0, %%xmm0\n"
        :
        : "m" (f)
    );
}

void UCRTBase::__libm_sse2_exp() {
    double d;
    __asm__ __volatile__ (
        "movq %%xmm0, %0\n"
        : "=m" (d)
    );
    d = exp(d);
    __asm__ __volatile__ (
        "movq %0, %%xmm0\n"
        :
        : "m" (d)
    );
}

void UCRTBase::__libm_sse2_exp_precise() {
    double d;
    __asm__ __volatile__ (
        "movq %%xmm0, %0\n"
        : "=m" (d)
    );
    d = exp(d);
    __asm__ __volatile__ (
        "movq %0, %%xmm0\n"
        :
        : "m" (d)
    );
}

void UCRTBase::__libm_sse2_expf() {
    float f;
    __asm__ __volatile__ (
        "movd %%xmm0, %0\n"
        : "=m" (f)
    );
    f = expf(f);
    __asm__ __volatile__ (
        "movd %0, %%xmm0\n"
        :
        : "m" (f)
    );
}

void UCRTBase::__libm_sse2_log() {
    double d;
    __asm__ __volatile__ (
        "movq %%xmm0, %0\n"
        : "=m" (d)
    );
    d = log(d);
    __asm__ __volatile__ (
        "movq %0, %%xmm0\n"
        :
        : "m" (d)
    );
}

void UCRTBase::__libm_sse2_log_precise() {
    double d;
    __asm__ __volatile__ (
        "movq %%xmm0, %0\n"
        : "=m" (d)
    );
    d = log(d);
    __asm__ __volatile__ (
        "movq %0, %%xmm0\n"
        :
        : "m" (d)
    );
}

void UCRTBase::__libm_sse2_logf() {
    float f;
    __asm__ __volatile__ (
        "movd %%xmm0, %0\n"
        : "=m" (f)
    );
    f = logf(f);
    __asm__ __volatile__ (
        "movd %0, %%xmm0\n"
        :
        : "m" (f)
    );
}

void UCRTBase::__libm_sse2_log10() {
    double d;
    __asm__ __volatile__ (
        "movq %%xmm0, %0\n"
        : "=m" (d)
    );
    d = log10(d);
    __asm__ __volatile__ (
        "movq %0, %%xmm0\n"
        :
        : "m" (d)
    );
}

void UCRTBase::__libm_sse2_log10_precise() {
    double d;
    __asm__ __volatile__ (
        "movq %%xmm0, %0\n"
        : "=m" (d)
    );
    d = log10(d);
    __asm__ __volatile__ (
        "movq %0, %%xmm0\n"
        :
        : "m" (d)
    );
}

void UCRTBase::__libm_sse2_log10f() {
    float f;
    __asm__ __volatile__ (
        "movd %%xmm0, %0\n"
        : "=m" (f)
    );
    f = log10f(f);
    __asm__ __volatile__ (
        "movd %0, %%xmm0\n"
        :
        : "m" (f)
    );
}

void UCRTBase::__libm_sse2_sqrt() {
    double d;
    __asm__ __volatile__ (
        "movq %%xmm0, %0\n"
        : "=m" (d)
    );
    d = sqrt(d);
    __asm__ __volatile__ (
        "movq %0, %%xmm0\n"
        :
        : "m" (d)
    );
}

void UCRTBase::__libm_sse2_sqrt_precise() {
    double d;
    __asm__ __volatile__ (
        "movq %%xmm0, %0\n"
        : "=m" (d)
    );
    d = sqrt(d);
    __asm__ __volatile__ (
        "movq %0, %%xmm0\n"
        :
        : "m" (d)
    );
}

void UCRTBase::__libm_sse2_sqrtf() {
    float f;
    __asm__ __volatile__ (
        "movd %%xmm0, %0\n"
        : "=m" (f)
    );
    f = sqrtf(f);
    __asm__ __volatile__ (
        "movd %0, %%xmm0\n"
        :
        : "m" (f)
    );
}

void UCRTBase::__libm_sse2_pow() {
    double x, y, result;
    __asm__ __volatile__ (
        "movq %%xmm0, %0\n"
        : "=m" (x)
    );
    __asm__ __volatile__ (
        "movq %%xmm1, %0\n"
        : "=m" (y)
    );
    result = pow(x, y);
    __asm__ __volatile__ (
        "movq %0, %%xmm0\n"
        :
        : "m" (result)
    );
}

void UCRTBase::__libm_sse2_pow_precise() {
    double x, y, result;
    __asm__ __volatile__ (
        "movq %%xmm0, %0\n"
        : "=m" (x)
    );
    __asm__ __volatile__ (
        "movq %%xmm1, %0\n"
        : "=m" (y)
    );
    result = pow(x, y);
    __asm__ __volatile__ (
        "movq %0, %%xmm0\n"
        :
        : "m" (result)
    );
}

void UCRTBase::__libm_sse2_powf() {
    float x, y, result;
    __asm__ __volatile__ (
        "movd %%xmm0, %0\n"
        : "=m" (x)
    );
    __asm__ __volatile__ (
        "movd %%xmm1, %0\n"
        : "=m" (y)
    );
    result = powf(x, y);
    __asm__ __volatile__ (
        "movd %0, %%xmm0\n"
        :
        : "m" (result)
    );
}

void UCRTBase::__libm_sse2_cbrt() {
    double d;
    __asm__ __volatile__ (
        "movq %%xmm0, %0\n"
        : "=m" (d)
    );
    d = cbrt(d);
    __asm__ __volatile__ (
        "movq %0, %%xmm0\n"
        :
        : "m" (d)
    );
}

void UCRTBase::__libm_sse2_cbrt_precise() {
    double d;
    __asm__ __volatile__ (
        "movq %%xmm0, %0\n"
        : "=m" (d)
    );
    d = cbrt(d);
    __asm__ __volatile__ (
        "movq %0, %%xmm0\n"
        :
        : "m" (d)
    );
}

void UCRTBase::__libm_sse2_cbrtf() {
    float f;
    __asm__ __volatile__ (
        "movd %%xmm0, %0\n"
        : "=m" (f)
    );
    f = cbrtf(f);
    __asm__ __volatile__ (
        "movd %0, %%xmm0\n"
        :
        : "m" (f)
    );
}

double UCRTBase::_logb(double x) {
    trace("_logb called. Arguments: x=", std::to_wstring(x));
    if (x == 0.0) {
        error("Error set to: EDOM, Return value: -HUGE_VAL");
        return -HUGE_VAL;
    }
    if (std::isinf(x)) {
        ret("Error set to: -, Return value: HUGE_VAL");
        return HUGE_VAL;
    }
    if (std::isnan(x)) {
        ret("Error set to: -, Return value: NaN");
        return std::numeric_limits<double>::quiet_NaN();
    }
    int exp;
    const double mant = std::frexp(x, &exp);
    const double result = exp - 1;
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

float UCRTBase::_logbf(float x) {
    trace("_logbf called. Arguments: x=", std::to_wstring(x));
    if (x == 0.0f) {
        error("Error set to: EDOM, Return value: -HUGE_VALF");
        return -HUGE_VALF;
    }
    if (std::isinf(x)) {
        ret("Error set to: -, Return value: HUGE_VALF");
        return HUGE_VALF;
    }
    if (std::isnan(x)) {
        ret("Error set to: -, Return value: NaN");
        return std::numeric_limits<float>::quiet_NaN();
    }
    int exp;
    const float mant = std::frexp(x, &exp);
    const float result = exp - 1;
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

long double UCRTBase::_logbl(long double x) {
    trace("_logbl called. Arguments: x=", std::to_wstring(static_cast<double>(x)));
    if (x == 0.0L) {
        error("Error set to: EDOM, Return value: -HUGE_VALL");
        return -HUGE_VALL;
    }
    if (std::isinf(x)) {
        ret("Error set to: -, Return value: HUGE_VALL");
        return HUGE_VALL;
    }
    if (std::isnan(x)) {
        ret("Error set to: -, Return value: NaN");
        return std::numeric_limits<long double>::quiet_NaN();
    }
    int exp;
    std::frexp(x, &exp);
    const long double result = exp - 1;
    ret("Error set to: -, Return value: ", std::to_wstring(static_cast<double>(result)));
    return result;
}

double UCRTBase::_nextafter(double from, double to) {
    trace("_nextafter called. Arguments: from=", std::to_wstring(from), ", to=", std::to_wstring(to));
    const double result = std::nextafter(from, to);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

float UCRTBase::_nextafterf(float from, float to) {
    trace("_nextafterf called. Arguments: from=", std::to_wstring(from), ", to=", std::to_wstring(to));
    const float result = std::nextafter(from, to);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

long double UCRTBase::_nextafterl(long double from, long double to) {
    trace("_nextafterl called. Arguments: from=", std::to_wstring(static_cast<double>(from)), ", to=", std::to_wstring(static_cast<double>(to)));
    const long double result = std::nextafter(from, to);
    ret("Error set to: -, Return value: ", std::to_wstring(static_cast<double>(result)));
    return result;
}

double UCRTBase::_scalb(double x, long n) {
    trace("_scalb called. Arguments: x=", std::to_wstring(x), ", n=", std::to_wstring(n));
    const double result = std::ldexp(x, n);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

float UCRTBase::_scalbf(float x, long n) {
    trace("_scalbf called. Arguments: x=", std::to_wstring(x), ", n=", std::to_wstring(n));
    const float result = std::ldexp(x, n);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

long double UCRTBase::_scalbl(long double x, long n) {
    trace("_scalbl called. Arguments: x=", std::to_wstring(static_cast<double>(x)), ", n=", std::to_wstring(n));
    const long double result = std::ldexp(x, n);
    ret("Error set to: -, Return value: ", std::to_wstring(static_cast<double>(result)));
    return result;
}

void UCRTBase::__setusermatherr(ucrt_matherr_func func) {
    trace("__setusermatherr called. Arguments: func=<ucrt_matherr_func>[", func, "]");
    process_info[tls.process].ucrt_matherr_handler = func;
}

double UCRTBase::_j0(double x) {
    trace("_j0 called. Arguments: x=", std::to_wstring(x));
    const double result = std::cyl_bessel_j(0, x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

double UCRTBase::_j1(double x) {
    trace("_j1 called. Arguments: x=", std::to_wstring(x));
    const double result = std::cyl_bessel_j(1, x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

double UCRTBase::_jn(int n, double x) {
    trace("_jn called. Arguments: n=", std::to_wstring(n), ", x=", std::to_wstring(x));
    const double result = std::cyl_bessel_j(n, x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

double UCRTBase::_y0(double x) {
    trace("_y0 called. Arguments: x=", std::to_wstring(x));
    if (x < 0.0) {
        error("Error set to: EDOM, Return value: NaN");
        return std::numeric_limits<double>::quiet_NaN();
    }
    const double result = std::cyl_neumann(0, x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

double UCRTBase::_y1(double x) {
    trace("_y1 called. Arguments: x=", std::to_wstring(x));
    if (x < 0.0) {
        error("Error set to: EDOM, Return value: NaN");
        return std::numeric_limits<double>::quiet_NaN();
    }
    const double result = std::cyl_neumann(1, x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

double UCRTBase::_yn(int n, double x) {
    trace("_yn called. Arguments: n=", std::to_wstring(n), ", x=", std::to_wstring(x));
    if (x < 0.0) {
        error("Error set to: EDOM, Return value: NaN");
        return std::numeric_limits<double>::quiet_NaN();
    }
    const double result = std::cyl_neumann(n, x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

double UCRTBase::acos_(double x) {
    trace("acos_ called. Arguments: x=", std::to_wstring(x));
    if (x < -1.0 || x > 1.0) {
        error("Error set to: EDOM, Return value: NaN");
        return std::numeric_limits<double>::quiet_NaN();
    }
    const double result = std::acos(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

float UCRTBase::acosf_(float x) {
    trace("acosf_ called. Arguments: x=", std::to_wstring(x));
    if (x < -1.0f || x > 1.0f) {
        error("Error set to: EDOM, Return value: NaN");
        return std::numeric_limits<float>::quiet_NaN();
    }
    const float result = std::acosf(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

long double UCRTBase::acosl_(long double x) {
    trace("acosl_ called. Arguments: x=", std::to_wstring(static_cast<double>(x)));
    if (x < -1.0L || x > 1.0L) {
        error("Error set to: EDOM, Return value: NaN");
        return std::numeric_limits<long double>::quiet_NaN();
    }
    const long double result = std::acosl(x);
    ret("Error set to: -, Return value: ", std::to_wstring(static_cast<double>(result)));
    return result;
}

double UCRTBase::acosh_(double x) {
    trace("_acosh called. Arguments: x=", std::to_wstring(x));
    if (x < 1.0) {
        error("Error set to: EDOM, Return value: NaN");
        return std::numeric_limits<double>::quiet_NaN();
    }
    const double result = std::acosh(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

double UCRTBase::acoshf_(float x) {
    trace("_acoshf called. Arguments: x=", std::to_wstring(x));
    if (x < 1.0f) {
        error("Error set to: EDOM, Return value: NaN");
        return std::numeric_limits<float>::quiet_NaN();
    }
    const float result = std::acosh(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

long double UCRTBase::acoshl_(long double x) {
    trace("_acoshl called. Arguments: x=", std::to_wstring(static_cast<double>(x)));
    if (x < 1.0L) {
        error("Error set to: EDOM, Return value: NaN");
        return std::numeric_limits<long double>::quiet_NaN();
    }
    const long double result = std::acoshl(x);
    ret("Error set to: -, Return value: ", std::to_wstring(static_cast<double>(result)));
    return result;
}

double UCRTBase::asin_(double x) {
    trace("asin_ called. Arguments: x=", std::to_wstring(x));
    if (x < -1.0 || x > 1.0) {
        error("Error set to: EDOM, Return value: NaN");
        return std::numeric_limits<double>::quiet_NaN();
    }
    const double result = std::asin(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

float UCRTBase::asinf_(float x) {
    trace("asinf_ called. Arguments: x=", std::to_wstring(x));
    if (x < -1.0f || x > 1.0f) {
        error("Error set to: EDOM, Return value: NaN");
        return std::numeric_limits<float>::quiet_NaN();
    }
    const float result = std::asinf(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

long double UCRTBase::asinl_(long double x) {
    trace("asinl_ called. Arguments: x=", std::to_wstring(static_cast<double>(x)));
    if (x < -1.0L || x > 1.0L) {
        error("Error set to: EDOM, Return value: NaN");
        return std::numeric_limits<long double>::quiet_NaN();
    }
    const long double result = std::asinl(x);
    ret("Error set to: -, Return value: ", std::to_wstring(static_cast<double>(result)));
    return result;
}

double UCRTBase::asinh_(double x) {
    trace("_asinh called. Arguments: x=", std::to_wstring(x));
    const double result = std::asinh(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

float UCRTBase::asinhf_(float x) {
    trace("_asinhf called. Arguments: x=", std::to_wstring(x));
    const float result = std::asinhf(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

long double UCRTBase::asinhl_(long double x) {
    trace("_asinhl called. Arguments: x=", std::to_wstring(static_cast<double>(x)));
    const long double result = std::asinhl(x);
    ret("Error set to: -, Return value: ", std::to_wstring(static_cast<double>(result)));
    return result;
}

double UCRTBase::atan_(double x) {
    trace("atan_ called. Arguments: x=", std::to_wstring(x));
    const double result = std::atan(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

float UCRTBase::atanf_(float x) {
    trace("atanf_ called. Arguments: x=", std::to_wstring(x));
    const float result = std::atanf(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

long double UCRTBase::atanl_(long double x) {
    trace("atanl_ called. Arguments: x=", std::to_wstring(static_cast<double>(x)));
    const long double result = std::atanl(x);
    ret("Error set to: -, Return value: ", std::to_wstring(static_cast<double>(result)));
    return result;
}

double UCRTBase::atanh_(double x) {
    trace("_atanh called. Arguments: x=", std::to_wstring(x));
    if (x <= -1.0 || x >= 1.0) {
        error("Error set to: EDOM, Return value: NaN");
        return std::numeric_limits<double>::quiet_NaN();
    }
    const double result = std::atanh(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

float UCRTBase::atanhf_(float x) {
    trace("_atanhf called. Arguments: x=", std::to_wstring(x));
    if (x <= -1.0f || x >= 1.0f) {
        error("Error set to: EDOM, Return value: NaN");
        return std::numeric_limits<float>::quiet_NaN();
    }
    const float result = std::atanhf(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

long double UCRTBase::atanhl_(long double x) {
    trace("_atanhl called. Arguments: x=", std::to_wstring(static_cast<double>(x)));
    if (x <= -1.0L || x >= 1.0L) {
        error("Error set to: EDOM, Return value: NaN");
        return std::numeric_limits<long double>::quiet_NaN();
    }
    const long double result = std::atanhl(x);
    ret("Error set to: -, Return value: ", std::to_wstring(static_cast<double>(result)));
    return result;
}

double UCRTBase::atan2_(double y, double x) {
    trace("atan2_ called. Arguments: y=", std::to_wstring(y), ", x=", std::to_wstring(x));
    const double result = std::atan2(y, x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

float UCRTBase::atan2f_(float y, float x) {
    trace("atan2f_ called. Arguments: y=", std::to_wstring(y), ", x=", std::to_wstring(x));
    const float result = std::atan2f(y, x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

long double UCRTBase::atan2l_(long double y, long double x) {
    trace("atan2l_ called. Arguments: y=", std::to_wstring(static_cast<double>(y)), ", x=", std::to_wstring(static_cast<double>(x)));
    const long double result = std::atan2l(y, x);
    ret("Error set to: -, Return value: ", std::to_wstring(static_cast<double>(result)));
    return result;
}

double UCRTBase::cabs(double _Complex z) {
    const std::complex<double> c(z);
    trace("cabs called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    ret("Error set to: -, Return value: ", std::to_wstring(std::abs(c)));
    return std::abs(c);
}

float UCRTBase::cabsf(float _Complex z) {
    const std::complex<float> c(z);
    trace("cabsf called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    ret("Error set to: -, Return value: ", std::to_wstring(std::abs(c)));
    return std::abs(c);
}

long double UCRTBase::cabsl(long double _Complex z) {
    const std::complex<long double> c(z);
    trace("cabsl called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    ret("Error set to: -, Return value: ", std::to_wstring(std::abs(c)));
    return std::abs(c);
}

double _Complex UCRTBase::cacos(double _Complex z) {
    const std::complex<double> c(z);
    trace("cacos called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    const std::complex<double> result = std::acos(c);
    ret("Error set to: -, Return value: ", std::to_wstring(result.real()), "+", std::to_wstring(result.imag()), "i");
    return *reinterpret_cast<const double _Complex*>(&result);
}

float _Complex UCRTBase::cacosf(float _Complex z) {
    const std::complex<float> c(z);
    trace("cacosf called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    const std::complex<float> result = std::acos(c);
    ret("Error set to: -, Return value: ", std::to_wstring(result.real()), "+", std::to_wstring(result.imag()), "i");
    return *reinterpret_cast<const float _Complex*>(&result);
}

long double _Complex UCRTBase::cacosl(long double _Complex z) {
    const std::complex<long double> c(z);
    trace("cacosl called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    const std::complex<long double> result = std::acos(c);
    ret("Error set to: -, Return value: ", std::to_wstring(result.real()), "+", std::to_wstring(result.imag()), "i");
    return *reinterpret_cast<const long double _Complex*>(&result);
}

double _Complex UCRTBase::cacosh(double _Complex z) {
    const std::complex<double> c(z);
    trace("cacosh called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    const std::complex<double> result = std::acosh(c);
    ret("Error set to: -, Return value: ", std::to_wstring(result.real()), "+", std::to_wstring(result.imag()), "i");
    return *reinterpret_cast<const double _Complex*>(&result);
}

float _Complex UCRTBase::cacoshf(float _Complex z) {
    const std::complex<float> c(z);
    trace("cacoshf called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    const std::complex<float> result = std::acosh(c);
    ret("Error set to: -, Return value: ", std::to_wstring(result.real()), "+", std::to_wstring(result.imag()), "i");
    return *reinterpret_cast<const float _Complex*>(&result);
}

long double _Complex UCRTBase::cacoshl(long double _Complex z) {
    const std::complex<long double> c(z);
    trace("cacoshl called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    const std::complex<long double> result = std::acosh(c);
    ret("Error set to: -, Return value: ", std::to_wstring(result.real()), "+", std::to_wstring(result.imag()), "i");
    return *reinterpret_cast<const long double _Complex*>(&result);
}

double _Complex UCRTBase::casin(double _Complex z) {
    const std::complex<double> c(z);
    trace("casin called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    const std::complex<double> result = std::asin(c);
    ret("Error set to: -, Return value: ", std::to_wstring(result.real()), "+", std::to_wstring(result.imag()), "i");
    return *reinterpret_cast<const double _Complex*>(&result);
}

float _Complex UCRTBase::casinf(float _Complex z) {
    const std::complex<float> c(z);
    trace("casinf called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    const std::complex<float> result = std::asin(c);
    ret("Error set to: -, Return value: ", std::to_wstring(result.real()), "+", std::to_wstring(result.imag()), "i");
    return *reinterpret_cast<const float _Complex*>(&result);
}

long double _Complex UCRTBase::casinl(long double _Complex z) {
    const std::complex<long double> c(z);
    trace("casinl called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    const std::complex<long double> result = std::asin(c);
    ret("Error set to: -, Return value: ", std::to_wstring(result.real()), "+", std::to_wstring(result.imag()), "i");
    return *reinterpret_cast<const long double _Complex*>(&result);
}

double _Complex UCRTBase::casinh(double _Complex z) {
    const std::complex<double> c(z);
    trace("casinh called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    const std::complex<double> result = std::asinh(c);
    ret("Error set to: -, Return value: ", std::to_wstring(result.real()), "+", std::to_wstring(result.imag()), "i");
    return *reinterpret_cast<const double _Complex*>(&result);
}

float _Complex UCRTBase::casinhf(float _Complex z) {
    const std::complex<float> c(z);
    trace("casinhf called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    const std::complex<float> result = std::asinh(c);
    ret("Error set to: -, Return value: ", std::to_wstring(result.real()), "+", std::to_wstring(result.imag()), "i");
    return *reinterpret_cast<const float _Complex*>(&result);
}

long double _Complex UCRTBase::casinhl(long double _Complex z) {
    const std::complex<long double> c(z);
    trace("casinhl called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    const std::complex<long double> result = std::asinh(c);
    ret("Error set to: -, Return value: ", std::to_wstring(result.real()), "+", std::to_wstring(result.imag()), "i");
    return *reinterpret_cast<const long double _Complex*>(&result);
}

double _Complex UCRTBase::catan(double _Complex z) {
    const std::complex<double> c(z);
    trace("catan called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    const std::complex<double> result = std::atan(c);
    ret("Error set to: -, Return value: ", std::to_wstring(result.real()), "+", std::to_wstring(result.imag()), "i");
    return *reinterpret_cast<const double _Complex*>(&result);
}

float _Complex UCRTBase::catanf(float _Complex z) {
    const std::complex<float> c(z);
    trace("catanf called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    const std::complex<float> result = std::atan(c);
    ret("Error set to: -, Return value: ", std::to_wstring(result.real()), "+", std::to_wstring(result.imag()), "i");
    return *reinterpret_cast<const float _Complex*>(&result);
}

long double _Complex UCRTBase::catanl(long double _Complex z) {
    const std::complex<long double> c(z);
    trace("catanl called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    const std::complex<long double> result = std::atan(c);
    ret("Error set to: -, Return value: ", std::to_wstring(result.real()), "+", std::to_wstring(result.imag()), "i");
    return *reinterpret_cast<const long double _Complex*>(&result);
}

double _Complex UCRTBase::catanh(double _Complex z) {
    const std::complex<double> c(z);
    trace("catanh called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    const std::complex<double> result = std::atanh(c);
    ret("Error set to: -, Return value: ", std::to_wstring(result.real()), "+", std::to_wstring(result.imag()), "i");
    return *reinterpret_cast<const double _Complex*>(&result);
}

float _Complex UCRTBase::catanhf(float _Complex z) {
    const std::complex<float> c(z);
    trace("catanhf called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    const std::complex<float> result = std::atanh(c);
    ret("Error set to: -, Return value: ", std::to_wstring(result.real()), "+", std::to_wstring(result.imag()), "i");
    return *reinterpret_cast<const float _Complex*>(&result);
}

long double _Complex UCRTBase::catanhl(long double _Complex z) {
    const std::complex<long double> c(z);
    trace("catanhl called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    const std::complex<long double> result = std::atanh(c);
    ret("Error set to: -, Return value: ", std::to_wstring(result.real()), "+", std::to_wstring(result.imag()), "i");
    return *reinterpret_cast<const long double _Complex*>(&result);
}

double UCRTBase::carg(double _Complex z) {
    const std::complex<double> c(z);
    trace("carg called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    const double result = std::arg(c);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

float UCRTBase::cargf(float _Complex z) {
    const std::complex<float> c(z);
    trace("cargf called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    const float result = std::arg(c);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

long double UCRTBase::cargl(long double _Complex z) {
    const std::complex<long double> c(z);
    trace("cargl called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    const long double result = std::arg(c);
    ret("Error set to: -, Return value: ", std::to_wstring(static_cast<double>(result)));
    return result;
}

double _Complex UCRTBase::cexp(double _Complex z) {
    const std::complex<double> c(z);
    trace("cexp called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    const std::complex<double> result = std::exp(c);
    ret("Error set to: -, Return value: ", std::to_wstring(result.real()), "+", std::to_wstring(result.imag()), "i");
    return *reinterpret_cast<const double _Complex*>(&result);
}

float _Complex UCRTBase::cexpf(float _Complex z) {
    const std::complex<float> c(z);
    trace("cexpf called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    const std::complex<float> result = std::exp(c);
    ret("Error set to: -, Return value: ", std::to_wstring(result.real()), "+", std::to_wstring(result.imag()), "i");
    return *reinterpret_cast<const float _Complex*>(&result);
}

long double _Complex UCRTBase::cexpl(long double _Complex z) {
    const std::complex<long double> c(z);
    trace("cexpl called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    const std::complex<long double> result = std::exp(c);
    ret("Error set to: -, Return value: ", std::to_wstring(result.real()), "+", std::to_wstring(result.imag()), "i");
    return *reinterpret_cast<const long double _Complex*>(&result);
}

double UCRTBase::cimag(double _Complex z) {
    const std::complex<double> c(z);
    trace("cimag called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    const double result = std::imag(c);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

float UCRTBase::cimagf(float _Complex z) {
    const std::complex<float> c(z);
    trace("cimagf called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    const float result = std::imag(c);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

long double UCRTBase::cimagl(long double _Complex z) {
    const std::complex<long double> c(z);
    trace("cimagl called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    const long double result = std::imag(c);
    ret("Error set to: -, Return value: ", std::to_wstring(static_cast<double>(result)));
    return result;
}

double UCRTBase::creal(double _Complex z) {
    const std::complex<double> c(z);
    trace("creal called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    const double result = std::real(c);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

float UCRTBase::crealf(float _Complex z) {
    const std::complex<float> c(z);
    trace("crealf called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    const float result = std::real(c);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

long double UCRTBase::creall(long double _Complex z) {
    const std::complex<long double> c(z);
    trace("creall called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    const long double result = std::real(c);
    ret("Error set to: -, Return value: ", std::to_wstring(static_cast<double>(result)));
    return result;
}

double _Complex UCRTBase::clog(double _Complex z) {
    const std::complex<double> c(z);
    trace("clog called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    const std::complex<double> result = std::log(c);
    ret("Error set to: -, Return value: ", std::to_wstring(result.real()), "+", std::to_wstring(result.imag()), "i");
    return *reinterpret_cast<const double _Complex*>(&result);
}

float _Complex UCRTBase::clogf(float _Complex z) {
    const std::complex<float> c(z);
    trace("clogf called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    const std::complex<float> result = std::log(c);
    ret("Error set to: -, Return value: ", std::to_wstring(result.real()), "+", std::to_wstring(result.imag()), "i");
    return *reinterpret_cast<const float _Complex*>(&result);
}

long double _Complex UCRTBase::clogl(long double _Complex z) {
    const std::complex<long double> c(z);
    trace("clogl called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    const std::complex<long double> result = std::log(c);
    ret("Error set to: -, Return value: ", std::to_wstring(result.real()), "+", std::to_wstring(result.imag()), "i");
    return *reinterpret_cast<const long double _Complex*>(&result);
}

double _Complex UCRTBase::clog10(double _Complex z) {
    const std::complex<double> c(z);
    trace("clog10 called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    const std::complex<double> result = std::log10(c);
    ret("Error set to: -, Return value: ", std::to_wstring(result.real()), "+", std::to_wstring(result.imag()), "i");
    return *reinterpret_cast<const double _Complex*>(&result);
}

float _Complex UCRTBase::clog10f(float _Complex z) {
    const std::complex<float> c(z);
    trace("clog10f called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    const std::complex<float> result = std::log10(c);
    ret("Error set to: -, Return value: ", std::to_wstring(result.real()), "+", std::to_wstring(result.imag()), "i");
    return *reinterpret_cast<const float _Complex*>(&result);
}

long double _Complex UCRTBase::clog10l(long double _Complex z) {
    const std::complex<long double> c(z);
    trace("clog10l called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    const std::complex<long double> result = std::log10(c);
    ret("Error set to: -, Return value: ", std::to_wstring(result.real()), "+", std::to_wstring(result.imag()), "i");
    return *reinterpret_cast<const long double _Complex*>(&result);
}

double _Complex UCRTBase::conj(double _Complex z) {
    const std::complex<double> c(z);
    trace("conj called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    const std::complex<double> result = std::conj(c);
    ret("Error set to: -, Return value: ", std::to_wstring(result.real()), "+", std::to_wstring(result.imag()), "i");
    return *reinterpret_cast<const double _Complex*>(&result);
}

float _Complex UCRTBase::conjf(float _Complex z) {
    const std::complex<float> c(z);
    trace("conjf called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    const std::complex<float> result = std::conj(c);
    ret("Error set to: -, Return value: ", std::to_wstring(result.real()), "+", std::to_wstring(result.imag()), "i");
    return *reinterpret_cast<const float _Complex*>(&result);
}

long double _Complex UCRTBase::conjl(long double _Complex z) {
    const std::complex<long double> c(z);
    trace("conjl called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    const std::complex<long double> result = std::conj(c);
    ret("Error set to: -, Return value: ", std::to_wstring(result.real()), "+", std::to_wstring(result.imag()), "i");
    return *reinterpret_cast<const long double _Complex*>(&result);
}

double _Complex UCRTBase::cpow(double _Complex x, double _Complex y) {
    const std::complex<double> base(x);
    const std::complex<double> exponent(y);
    trace("cpow called. Arguments: x=", std::to_wstring(base.real()), "+", std::to_wstring(base.imag()), "i, y=", std::to_wstring(exponent.real()), "+", std::to_wstring(exponent.imag()), "i");
    const std::complex<double> result = std::pow(base, exponent);
    ret("Error set to: -, Return value: ", std::to_wstring(result.real()), "+", std::to_wstring(result.imag()), "i");
    return *reinterpret_cast<const double _Complex*>(&result);
}

float _Complex UCRTBase::cpowf(float _Complex x, float _Complex y) {
    const std::complex<float> base(x);
    const std::complex<float> exponent(y);
    trace("cpowf called. Arguments: x=", std::to_wstring(base.real()), "+", std::to_wstring(base.imag()), "i, y=", std::to_wstring(exponent.real()), "+", std::to_wstring(exponent.imag()), "i");
    const std::complex<float> result = std::pow(base, exponent);
    ret("Error set to: -, Return value: ", std::to_wstring(result.real()), "+", std::to_wstring(result.imag()), "i");
    return *reinterpret_cast<const float _Complex*>(&result);
}

long double _Complex UCRTBase::cpowl(long double _Complex x, long double _Complex y) {
    const std::complex<long double> base(x);
    const std::complex<long double> exponent(y);
    trace("cpowl called. Arguments: x=", std::to_wstring(base.real()), "+", std::to_wstring(base.imag()), "i, y=", std::to_wstring(exponent.real()), "+", std::to_wstring(exponent.imag()), "i");
    const std::complex<long double> result = std::pow(base, exponent);
    ret("Error set to: -, Return value: ", std::to_wstring(result.real()), "+", std::to_wstring(result.imag()), "i");
    return *reinterpret_cast<const long double _Complex*>(&result);
}

double _Complex UCRTBase::cproj(double _Complex z) {
    // The projection of z on the Reimann sphere.
    const std::complex<double> c(z);
    trace("cproj called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    if (std::isinf(c.real()) || std::isinf(c.imag())) {
        ret("Error set to: -, Return value: Inf + 0i");
        const std::complex<double> infComplex(INFINITY, 0.0);
        return *reinterpret_cast<const double _Complex*>(&infComplex);
    }
    const std::complex<double> res = std::proj(c);
    ret("Error set to: -, Return value: ", std::to_wstring(res.real()), "+", std::to_wstring(res.imag()), "i");
    return *reinterpret_cast<const double _Complex*>(&res);
}

float _Complex UCRTBase::cprojf(float _Complex z) {
    // The projection of z on the Reimann sphere.
    const std::complex<float> c(z);
    trace("cprojf called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    if (std::isinf(c.real()) || std::isinf(c.imag())) {
        ret("Error set to: -, Return value: Inf + 0i");
        const std::complex<float> infComplex(INFINITY, 0.0f);
        return *reinterpret_cast<const float _Complex*>(&infComplex);
    }
    const std::complex<float> res = std::proj(c);
    ret("Error set to: -, Return value: ", std::to_wstring(res.real()), "+", std::to_wstring(res.imag()), "i");
    return *reinterpret_cast<const float _Complex*>(&res);
}

long double _Complex UCRTBase::cprojl(long double _Complex z) {
    // The projection of z on the Reimann sphere.
    const std::complex<long double> c(z);
    trace("cprojl called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    if (std::isinf(c.real()) || std::isinf(c.imag())) {
        ret("Error set to: -, Return value: Inf + 0i");
        std::complex <long double> infComplex(INFINITY, 0.0L);
        return *reinterpret_cast<const long double _Complex*>(&infComplex);
    }
    const std::complex<long double> res = std::proj(c);
    ret("Error set to: -, Return value: ", std::to_wstring(res.real()), "+", std::to_wstring(res.imag()), "i");
    return *reinterpret_cast<const long double _Complex*>(&res);
}

double _Complex UCRTBase::csin(double _Complex z) {
    const std::complex<double> c(z);
    trace("csin called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    const std::complex<double> result = std::sin(c);
    ret("Error set to: -, Return value: ", std::to_wstring(result.real()), "+", std::to_wstring(result.imag()), "i");
    return *reinterpret_cast<const double _Complex*>(&result);
}

float _Complex UCRTBase::csinf(float _Complex z) {
    const std::complex<float> c(z);
    trace("csinf called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    const std::complex<float> result = std::sin(c);
    ret("Error set to: -, Return value: ", std::to_wstring(result.real()), "+", std::to_wstring(result.imag()), "i");
    return *reinterpret_cast<const float _Complex*>(&result);
}

long double _Complex UCRTBase::csinl(long double _Complex z) {
    const std::complex<long double> c(z);
    trace("csinl called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    const std::complex<long double> result = std::sin(c);
    ret("Error set to: -, Return value: ", std::to_wstring(result.real()), "+", std::to_wstring(result.imag()), "i");
    return *reinterpret_cast<const long double _Complex*>(&result);
}

double _Complex UCRTBase::csinh(double _Complex z) {
    const std::complex<double> c(z);
    trace("csinh called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    const std::complex<double> result = std::sinh(c);
    ret("Error set to: -, Return value: ", std::to_wstring(result.real()), "+", std::to_wstring(result.imag()), "i");
    return *reinterpret_cast<const double _Complex*>(&result);
}

float _Complex UCRTBase::csinhf(float _Complex z) {
    const std::complex<float> c(z);
    trace("csinhf called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    const std::complex<float> result = std::sinh(c);
    ret("Error set to: -, Return value: ", std::to_wstring(result.real()), "+", std::to_wstring(result.imag()), "i");
    return *reinterpret_cast<const float _Complex*>(&result);
}

long double _Complex UCRTBase::csinhl(long double _Complex z) {
    const std::complex<long double> c(z);
    trace("csinhl called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    const std::complex<long double> result = std::sinh(c);
    ret("Error set to: -, Return value: ", std::to_wstring(result.real()), "+", std::to_wstring(result.imag()), "i");
    return *reinterpret_cast<const long double _Complex*>(&result);
}

double _Complex UCRTBase::ccos(double _Complex z) {
    const std::complex<double> c(z);
    trace("ccos called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    const std::complex<double> result = std::cos(c);
    ret("Error set to: -, Return value: ", std::to_wstring(result.real()), "+", std::to_wstring(result.imag()), "i");
    return *reinterpret_cast<const double _Complex*>(&result);
}

float _Complex UCRTBase::ccosf(float _Complex z) {
    const std::complex<float> c(z);
    trace("ccosf called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    const std::complex<float> result = std::cos(c);
    ret("Error set to: -, Return value: ", std::to_wstring(result.real()), "+", std::to_wstring(result.imag()), "i");
    return *reinterpret_cast<const float _Complex*>(&result);
}

long double _Complex UCRTBase::ccosl(long double _Complex z) {
    const std::complex<long double> c(z);
    trace("ccosl called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    const std::complex<long double> result = std::cos(c);
    ret("Error set to: -, Return value: ", std::to_wstring(result.real()), "+", std::to_wstring(result.imag()), "i");
    return *reinterpret_cast<const long double _Complex*>(&result);
}

double _Complex UCRTBase::ccosh(double _Complex z) {
    const std::complex<double> c(z);
    trace("ccosh called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    const std::complex<double> result = std::cosh(c);
    ret("Error set to: -, Return value: ", std::to_wstring(result.real()), "+", std::to_wstring(result.imag()), "i");
    return *reinterpret_cast<const double _Complex*>(&result);
}

float _Complex UCRTBase::ccoshf(float _Complex z) {
    const std::complex<float> c(z);
    trace("ccoshf called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    const std::complex<float> result = std::cosh(c);
    ret("Error set to: -, Return value: ", std::to_wstring(result.real()), "+", std::to_wstring(result.imag()), "i");
    return *reinterpret_cast<const float _Complex*>(&result);
}

long double _Complex UCRTBase::ccoshl(long double _Complex z) {
    const std::complex<long double> c(z);
    trace("ccoshl called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    const std::complex<long double> result = std::cosh(c);
    ret("Error set to: -, Return value: ", std::to_wstring(result.real()), "+", std::to_wstring(result.imag()), "i");
    return *reinterpret_cast<const long double _Complex*>(&result);
}

double _Complex UCRTBase::ctan(double _Complex z) {
    const std::complex<double> c(z);
    trace("ctan called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    const std::complex<double> result = std::tan(c);
    ret("Error set to: -, Return value: ", std::to_wstring(result.real()), "+", std::to_wstring(result.imag()), "i");
    return *reinterpret_cast<const double _Complex*>(&result);
}

float _Complex UCRTBase::ctanf(float _Complex z) {
    const std::complex<float> c(z);
    trace("ctanf called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    const std::complex<float> result = std::tan(c);
    ret("Error set to: -, Return value: ", std::to_wstring(result.real()), "+", std::to_wstring(result.imag()), "i");
    return *reinterpret_cast<const float _Complex*>(&result);
}

long double _Complex UCRTBase::ctanl(long double _Complex z) {
    const std::complex<long double> c(z);
    trace("ctanl called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    const std::complex<long double> result = std::tan(c);
    ret("Error set to: -, Return value: ", std::to_wstring(result.real()), "+", std::to_wstring(result.imag()), "i");
    return *reinterpret_cast<const long double _Complex*>(&result);
}

double _Complex UCRTBase::ctanh(double _Complex z) {
    const std::complex<double> c(z);
    trace("ctanh called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    const std::complex<double> result = std::tanh(c);
    ret("Error set to: -, Return value: ", std::to_wstring(result.real()), "+", std::to_wstring(result.imag()), "i");
    return *reinterpret_cast<const double _Complex*>(&result);
}

float _Complex UCRTBase::ctanhf(float _Complex z) {
    const std::complex<float> c(z);
    trace("ctanhf called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    const std::complex<float> result = std::tanh(c);
    ret("Error set to: -, Return value: ", std::to_wstring(result.real()), "+", std::to_wstring(result.imag()), "i");
    return *reinterpret_cast<const float _Complex*>(&result);
}

long double _Complex UCRTBase::ctanhl(long double _Complex z) {
    const std::complex<long double> c(z);
    trace("ctanhl called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    const std::complex<long double> result = std::tanh(c);
    ret("Error set to: -, Return value: ", std::to_wstring(result.real()), "+", std::to_wstring(result.imag()), "i");
    return *reinterpret_cast<const long double _Complex*>(&result);
}

double _Complex UCRTBase::csqrt(double _Complex z) {
    const std::complex<double> c(z);
    trace("csqrt called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    const std::complex<double> result = std::sqrt(c);
    ret("Error set to: -, Return value: ", std::to_wstring(result.real()), "+", std::to_wstring(result.imag()), "i");
    return *reinterpret_cast<const double _Complex*>(&result);
}

float _Complex UCRTBase::csqrtf(float _Complex z) {
    const std::complex<float> c(z);
    trace("csqrtf called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    const std::complex<float> result = std::sqrt(c);
    ret("Error set to: -, Return value: ", std::to_wstring(result.real()), "+", std::to_wstring(result.imag()), "i");
    return *reinterpret_cast<const float _Complex*>(&result);
}

long double _Complex UCRTBase::csqrtl(long double _Complex z) {
    const std::complex<long double> c(z);
    trace("csqrtl called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    const std::complex<long double> result = std::sqrt(c);
    ret("Error set to: -, Return value: ", std::to_wstring(result.real()), "+", std::to_wstring(result.imag()), "i");
    return *reinterpret_cast<const long double _Complex*>(&result);
}

double UCRTBase::norm_(double _Complex z) {
    const std::complex<double> c(z);
    trace("norm called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    const double result = std::norm(c);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

float UCRTBase::normf_(float _Complex z) {
    const std::complex<float> c(z);
    trace("normf called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    const float result = std::norm(c);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

long double UCRTBase::norml_(long double _Complex z) {
    const std::complex<long double> c(z);
    trace("norml called. Arguments: z=", std::to_wstring(c.real()), "+", std::to_wstring(c.imag()), "i");
    const long double result = std::norm(c);
    ret("Error set to: -, Return value: ", std::to_wstring(static_cast<double>(result)));
    return result;
}

double UCRTBase::erf_(double x) {
    trace("erf_ called. Arguments: x=", std::to_wstring(x));
    const double result = std::erf(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

float UCRTBase::erff_(float x) {
    trace("erff_ called. Arguments: x=", std::to_wstring(x));
    const float result = std::erff(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

long double UCRTBase::erfl_(long double x) {
    trace("erfl_ called. Arguments: x=", std::to_wstring(static_cast<double>(x)));
    const long double result = std::erfl(x);
    ret("Error set to: -, Return value: ", std::to_wstring(static_cast<double>(result)));
    return result;
}

double UCRTBase::erfc_(double x) {
    trace("erfc_ called. Arguments: x=", std::to_wstring(x));
    const double result = std::erfc(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

float UCRTBase::erfcf_(float x) {
    trace("erfcf_ called. Arguments: x=", std::to_wstring(x));
    const float result = std::erfcf(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

long double UCRTBase::erfcl_(long double x) {
    trace("erfcl_ called. Arguments: x=", std::to_wstring(static_cast<double>(x)));
    const long double result = std::erfcl(x);
    ret("Error set to: -, Return value: ", std::to_wstring(static_cast<double>(result)));
    return result;
}

double UCRTBase::exp_(double x) {
    trace("exp_ called. Arguments: x=", std::to_wstring(x));
    const double result = std::exp(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

float UCRTBase::expf_(float x) {
    trace("expf_ called. Arguments: x=", std::to_wstring(x));
    const float result = std::expf(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

long double UCRTBase::expl_(long double x) {
    trace("expl_ called. Arguments: x=", std::to_wstring(static_cast<double>(x)));
    const long double result = std::expl(x);
    ret("Error set to: -, Return value: ", std::to_wstring(static_cast<double>(result)));
    return result;
}

double UCRTBase::exp2_(double x) {
    trace("exp2_ called. Arguments: x=", std::to_wstring(x));
    const double result = std::exp2(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

float UCRTBase::exp2f_(float x) {
    trace("exp2f_ called. Arguments: x=", std::to_wstring(x));
    const float result = std::exp2f(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

long double UCRTBase::exp2l_(long double x) {
    trace("exp2l_ called. Arguments: x=", std::to_wstring(static_cast<double>(x)));
    const long double result = std::exp2l(x);
    ret("Error set to: -, Return value: ", std::to_wstring(static_cast<double>(result)));
    return result;
}

double UCRTBase::expm1_(double x) {
    trace("expm1_ called. Arguments: x=", std::to_wstring(x));
    const double result = std::expm1(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

float UCRTBase::expm1f_(float x) {
    trace("expm1f_ called. Arguments: x=", std::to_wstring(x));
    const float result = std::expm1f(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

long double UCRTBase::expm1l_(long double x) {
    trace("expm1l_ called. Arguments: x=", std::to_wstring(static_cast<double>(x)));
    const long double result = std::expm1l(x);
    ret("Error set to: -, Return value: ", std::to_wstring(static_cast<double>(result)));
    return result;
}

double UCRTBase::fabs_(double x) {
    trace("fabs_ called. Arguments: x=", std::to_wstring(x));
    const double result = std::fabs(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

float UCRTBase::fabsf_(float x) {
    trace("fabsf_ called. Arguments: x=", std::to_wstring(x));
    const float result = std::fabsf(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

long double UCRTBase::fabsl_(long double x) {
    trace("fabsl_ called. Arguments: x=", std::to_wstring(static_cast<double>(x)));
    const long double result = std::fabsl(x);
    ret("Error set to: -, Return value: ", std::to_wstring(static_cast<double>(result)));
    return result;
}

double UCRTBase::fdim_(double x, double y) {
    trace("fdim_ called. Arguments: x=", std::to_wstring(x), ", y=", std::to_wstring(y));
    const double result = std::fdim(x, y);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

float UCRTBase::fdimf_(float x, float y) {
    trace("fdimf_ called. Arguments: x=", std::to_wstring(x), ", y=", std::to_wstring(y));
    const float result = std::fdimf(x, y);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

long double UCRTBase::fdiml_(long double x, long double y) {
    trace("fdiml_ called. Arguments: x=", std::to_wstring(static_cast<double>(x)), ", y=", std::to_wstring(static_cast<double>(y)));
    const long double result = std::fdiml(x, y);
    ret("Error set to: -, Return value: ", std::to_wstring(static_cast<double>(result)));
    return result;
}

double UCRTBase::floor_(double x) {
    trace("floor_ called. Arguments: x=", std::to_wstring(x));
    const double result = std::floor(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

float UCRTBase::floorf_(float x) {
    trace("floorf_ called. Arguments: x=", std::to_wstring(x));
    const float result = std::floorf(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

long double UCRTBase::floorl_(long double x) {
    trace("floorl_ called. Arguments: x=", std::to_wstring(static_cast<double>(x)));
    const long double result = std::floorl(x);
    ret("Error set to: -, Return value: ", std::to_wstring(static_cast<double>(result)));
    return result;
}

double UCRTBase::fma_(double x, double y, double z) {
    trace("fma_ called. Arguments: x=", std::to_wstring(x), ", y=", std::to_wstring(y), ", z=", std::to_wstring(z));
    const double result = std::fma(x, y, z);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

float UCRTBase::fmaf_(float x, float y, float z) {
    trace("fmaf_ called. Arguments: x=", std::to_wstring(x), ", y=", std::to_wstring(y), ", z=", std::to_wstring(z));
    const float result = std::fmaf(x, y, z);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

long double UCRTBase::fmal_(long double x, long double y, long double z) {
    trace("fmal_ called. Arguments: x=", std::to_wstring(static_cast<double>(x)), ", y=", std::to_wstring(static_cast<double>(y)), ", z=", std::to_wstring(static_cast<double>(z)));
    const long double result = std::fmal(x, y, z);
    ret("Error set to: -, Return value: ", std::to_wstring(static_cast<double>(result)));
    return result;
}

double UCRTBase::fmax_(double x, double y) {
    trace("fmax_ called. Arguments: x=", std::to_wstring(x), ", y=", std::to_wstring(y));
    const double result = std::fmax(x, y);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

float UCRTBase::fmaxf_(float x, float y) {
    trace("fmaxf_ called. Arguments: x=", std::to_wstring(x), ", y=", std::to_wstring(y));
    const float result = std::fmaxf(x, y);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

long double UCRTBase::fmaxl_(long double x, long double y) {
    trace("fmaxl_ called. Arguments: x=", std::to_wstring(static_cast<double>(x)), ", y=", std::to_wstring(static_cast<double>(y)));
    const long double result = std::fmaxl(x, y);
    ret("Error set to: -, Return value: ", std::to_wstring(static_cast<double>(result)));
    return result;
}

double UCRTBase::fmin_(double x, double y) {
    trace("fmin_ called. Arguments: x=", std::to_wstring(x), ", y=", std::to_wstring(y));
    const double result = std::fmin(x, y);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

float UCRTBase::fminf_(float x, float y) {
    trace("fminf_ called. Arguments: x=", std::to_wstring(x), ", y=", std::to_wstring(y));
    const float result = std::fminf(x, y);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

long double UCRTBase::fminl_(long double x, long double y) {
    trace("fminl_ called. Arguments: x=", std::to_wstring(static_cast<double>(x)), ", y=", std::to_wstring(static_cast<double>(y)));
    const long double result = std::fminl(x, y);
    ret("Error set to: -, Return value: ", std::to_wstring(static_cast<double>(result)));
    return result;
}

double UCRTBase::fmod_(double x, double y) {
    trace("fmod_ called. Arguments: x=", std::to_wstring(x), ", y=", std::to_wstring(y));
    const double result = std::fmod(x, y);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

float UCRTBase::fmodf_(float x, float y) {
    trace("fmodf_ called. Arguments: x=", std::to_wstring(x), ", y=", std::to_wstring(y));
    const float result = std::fmodf(x, y);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

long double UCRTBase::fmodl_(long double x, long double y) {
    trace("fmodl_ called. Arguments: x=", std::to_wstring(static_cast<double>(x)), ", y=", std::to_wstring(static_cast<double>(y)));
    const long double result = std::fmodl(x, y);
    ret("Error set to: -, Return value: ", std::to_wstring(static_cast<double>(result)));
    return result;
}

double UCRTBase::frexp_(double x, int *exp) {
    trace("frexp_ called. Arguments: x=", std::to_wstring(x), ", exp=", std::to_wstring(*exp));
    const double result = std::frexp(x, exp);
    ret("Error set to: -, Return value: ", std::to_wstring(result), ", exp=", std::to_wstring(*exp));
    return result;
}

float UCRTBase::frexpf_(float x, int *exp) {
    trace("frexpf_ called. Arguments: x=", std::to_wstring(x), ", exp=", std::to_wstring(*exp));
    const float result = std::frexpf(x, exp);
    ret("Error set to: -, Return value: ", std::to_wstring(result), ", exp=", std::to_wstring(*exp));
    return result;
}

long double UCRTBase::frexpl_(long double x, int *exp) {
    trace("frexpl_ called. Arguments: x=", std::to_wstring(static_cast<double>(x)), ", exp=", std::to_wstring(*exp));
    const long double result = std::frexpl(x, exp);
    ret("Error set to: -, Return value: ", std::to_wstring(static_cast<double>(result)), ", exp=", std::to_wstring(*exp));
    return result;
}

double UCRTBase::hypot_(double x, double y) {
    trace("hypot_ called. Arguments: x=", std::to_wstring(x), ", y=", std::to_wstring(y));
    const double result = std::hypot(x, y);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

float UCRTBase::hypotf_(float x, float y) {
    trace("hypotf_ called. Arguments: x=", std::to_wstring(x), ", y=", std::to_wstring(y));
    const float result = std::hypotf(x, y);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

long double UCRTBase::hypotl_(long double x, long double y) {
    trace("hypotl_ called. Arguments: x=", std::to_wstring(static_cast<double>(x)), ", y=", std::to_wstring(static_cast<double>(y)));
    const long double result = std::hypotl(x, y);
    ret("Error set to: -, Return value: ", std::to_wstring(static_cast<double>(result)));
    return result;
}

int UCRTBase::ilogb_(double x) {
    trace("ilogb_ called. Arguments: x=", std::to_wstring(x));
    const int result = std::ilogb(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

int UCRTBase::ilogbf_(float x) {
    trace("ilogbf_ called. Arguments: x=", std::to_wstring(x));
    const int result = std::ilogbf(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

int UCRTBase::ilogbl_(long double x) {
    trace("ilogbl_ called. Arguments: x=", std::to_wstring(static_cast<double>(x)));
    const int result = std::ilogbl(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

double UCRTBase::ldexp_(double x, int exp) {
    trace("ldexp_ called. Arguments: x=", std::to_wstring(x), ", exp=", std::to_wstring(exp));
    const double result = std::ldexp(x, exp);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

float UCRTBase::ldexpf_(float x, int exp) {
    trace("ldexpf_ called. Arguments: x=", std::to_wstring(x), ", exp=", std::to_wstring(exp));
    const float result = std::ldexpf(x, exp);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

long double UCRTBase::ldexpl_(long double x, int exp) {
    trace("ldexpl_ called. Arguments: x=", std::to_wstring(static_cast<double>(x)), ", exp=", std::to_wstring(exp));
    const long double result = std::ldexpl(x, exp);
    ret("Error set to: -, Return value: ", std::to_wstring(static_cast<double>(result)));
    return result;
}

double UCRTBase::lgamma_(double x) {
    trace("lgamma_ called. Arguments: x=", std::to_wstring(x));
    const double result = std::lgamma(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

float UCRTBase::lgammaf_(float x) {
    trace("lgammaf_ called. Arguments: x=", std::to_wstring(x));
    const float result = std::lgammaf(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

long double UCRTBase::lgammal_(long double x) {
    trace("lgammal_ called. Arguments: x=", std::to_wstring(static_cast<double>(x)));
    const long double result = std::lgammal(x);
    ret("Error set to: -, Return value: ", std::to_wstring(static_cast<double>(result)));
    return result;
}

int UCRTBase::rint_(double *px) {
    trace("rint_ called. Arguments: px=", std::to_wstring(*px));
    const int result = static_cast<int>(std::rint(*px));
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

int UCRTBase::rintf_(float *px) {
    trace("rintf_ called. Arguments: px=", std::to_wstring(*px));
    const int result = static_cast<int>(std::rintf(*px));
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

int UCRTBase::rintl_(long double *px) {
    trace("rintl_ called. Arguments: px=", std::to_wstring(static_cast<double>(*px)));
    const int result = static_cast<int>(std::rintl(*px));
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

LONG UCRTBase::lrint_(double x) {
    trace("lrint_ called. Arguments: x=", std::to_wstring(x));
    const LONG result = static_cast<LONG>(std::lrint(x));
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

LONG UCRTBase::lrintf_(float x) {
    trace("lrintf_ called. Arguments: x=", std::to_wstring(x));
    const LONG result = static_cast<LONG>(std::lrintf(x));
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

LONG UCRTBase::lrintl_(long double x) {
    trace("lrintl_ called. Arguments: x=", std::to_wstring(static_cast<double>(x)));
    const LONG result = static_cast<LONG>(std::lrintl(x));
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

long long UCRTBase::llrint_(double x) {
    trace("llrint_ called. Arguments: x=", std::to_wstring(x));
    const auto result = static_cast<long long>(std::llrint(x));
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

long long UCRTBase::llrintf_(float x) {
    trace("llrintf_ called. Arguments: x=", std::to_wstring(x));
    const auto result = static_cast<long long>(std::llrintf(x));
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

long long UCRTBase::llrintl_(long double x) {
    trace("llrintl_ called. Arguments: x=", std::to_wstring(static_cast<double>(x)));
    const auto result = static_cast<long long>(std::llrintl(x));
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

double UCRTBase::round_(double x) {
    trace("round_ called. Arguments: x=", std::to_wstring(x));
    const double result = std::round(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

float UCRTBase::roundf_(float x) {
    trace("roundf_ called. Arguments: x=", std::to_wstring(x));
    const float result = std::roundf(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

long double UCRTBase::roundl_(long double x) {
    trace("roundl_ called. Arguments: x=", std::to_wstring(static_cast<double>(x)));
    const long double result = std::roundl(x);
    ret("Error set to: -, Return value: ", std::to_wstring(static_cast<double>(result)));
    return result;
}

LONG UCRTBase::lround_(double x) {
    trace("lround_ called. Arguments: x=", std::to_wstring(x));
    const LONG result = static_cast<LONG>(std::lround(x));
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

LONG UCRTBase::lroundf_(float x) {
    trace("lroundf_ called. Arguments: x=", std::to_wstring(x));
    const LONG result = static_cast<LONG>(std::lroundf(x));
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

LONG UCRTBase::lroundl_(long double x) {
    trace("lroundl_ called. Arguments: x=", std::to_wstring(static_cast<double>(x)));
    const LONG result = static_cast<LONG>(std::lroundl(x));
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

long long UCRTBase::llround_(double x) {
    trace("llround_ called. Arguments: x=", std::to_wstring(x));
    const auto result = std::llround(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

long long UCRTBase::llroundf_(float x) {
    trace("llroundf_ called. Arguments: x=", std::to_wstring(x));
    const auto result = std::llroundf(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

long long UCRTBase::llroundl_(long double x) {
    trace("llroundl_ called. Arguments: x=", std::to_wstring(static_cast<double>(x)));
    const auto result = std::llroundl(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

double UCRTBase::log_(double x) {
    trace("log_ called. Arguments: x=", std::to_wstring(x));
    const double result = std::log(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

float UCRTBase::logf_(float x) {
    trace("logf_ called. Arguments: x=", std::to_wstring(x));
    const float result = std::logf(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

long double UCRTBase::logl_(long double x) {
    trace("logl_ called. Arguments: x=", std::to_wstring(static_cast<double>(x)));
    const long double result = std::logl(x);
    ret("Error set to: -, Return value: ", std::to_wstring(static_cast<double>(result)));
    return result;
}

double UCRTBase::log10_(double x) {
    trace("log10_ called. Arguments: x=", std::to_wstring(x));
    const double result = std::log10(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

float UCRTBase::log10f_(float x) {
    trace("log10f_ called. Arguments: x=", std::to_wstring(x));
    const float result = std::log10f(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

long double UCRTBase::log10l_(long double x) {
    trace("log10l_ called. Arguments: x=", std::to_wstring(static_cast<double>(x)));
    const long double result = std::log10l(x);
    ret("Error set to: -, Return value: ", std::to_wstring(static_cast<double>(result)));
    return result;
}

double UCRTBase::log1p_(double x) {
    trace("log1p_ called. Arguments: x=", std::to_wstring(x));
    const double result = std::log1p(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

float UCRTBase::log1pf_(float x) {
    trace("log1pf_ called. Arguments: x=", std::to_wstring(x));
    const float result = std::log1pf(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

long double UCRTBase::log1pl_(long double x) {
    trace("log1pl_ called. Arguments: x=", std::to_wstring(static_cast<double>(x)));
    const long double result = std::log1pl(x);
    ret("Error set to: -, Return value: ", std::to_wstring(static_cast<double>(result)));
    return result;
}

double UCRTBase::log2_(double x) {
    trace("log2_ called. Arguments: x=", std::to_wstring(x));
    const double result = std::log2(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

float UCRTBase::log2f_(float x) {
    trace("log2f_ called. Arguments: x=", std::to_wstring(x));
    const float result = std::log2f(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

long double UCRTBase::log2l_(long double x) {
    trace("log2l_ called. Arguments: x=", std::to_wstring(static_cast<double>(x)));
    const long double result = std::log2l(x);
    ret("Error set to: -, Return value: ", std::to_wstring(static_cast<double>(result)));
    return result;
}

double UCRTBase::logb_(double x) {
    trace("logb_ called. Arguments: x=", std::to_wstring(x));
    const double result = std::logb(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

float UCRTBase::logbf_(float x) {
    trace("logbf_ called. Arguments: x=", std::to_wstring(x));
    const float result = std::logbf(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

long double UCRTBase::logbl_(long double x) {
    trace("logbl_ called. Arguments: x=", std::to_wstring(static_cast<double>(x)));
    const long double result = std::logbl(x);
    ret("Error set to: -, Return value: ", std::to_wstring(static_cast<double>(result)));
    return result;
}

double UCRTBase::modf_(double x, double *intpart) {
    trace("modf_ called. Arguments: x=", std::to_wstring(x), ", intpart=", std::to_wstring(*intpart));
    const double result = std::modf(x, intpart);
    ret("Error set to: -, Return value: ", std::to_wstring(result), ", intpart=", std::to_wstring(*intpart));
    return result;
}

float UCRTBase::modff_(float x, float *intpart) {
    trace("modff_ called. Arguments: x=", std::to_wstring(x), ", intpart=", std::to_wstring(*intpart));
    const float result = std::modff(x, intpart);
    ret("Error set to: -, Return value: ", std::to_wstring(result), ", intpart=", std::to_wstring(*intpart));
    return result;
}

long double UCRTBase::modfl_(long double x, long double *intpart) {
    trace("modfl_ called. Arguments: x=", std::to_wstring(static_cast<double>(x)), ", intpart=", std::to_wstring(static_cast<double>(*intpart)));
    const long double result = std::modfl(x, intpart);
    ret("Error set to: -, Return value: ", std::to_wstring(static_cast<double>(result)), ", intpart=", std::to_wstring(static_cast<double>(*intpart)));
    return result;
}

double UCRTBase::nan_(const char *tagp) {
    trace("nan_ called. Arguments: tagp=", std::wstring(tagp, tagp + strlen(tagp)));
    const double result = std::nan(tagp);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

float UCRTBase::nanf_(const char *tagp) {
    trace("nanf_ called. Arguments: tagp=", std::wstring(tagp, tagp + strlen(tagp)));
    const float result = std::nanf(tagp);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

long double UCRTBase::nanl_(const char *tagp) {
    trace("nanl_ called. Arguments: tagp=", std::wstring(tagp, tagp + strlen(tagp)));
    const long double result = std::nanl(tagp);
    ret("Error set to: -, Return value: ", std::to_wstring(static_cast<double>(result)));
    return result;
}

double UCRTBase::nearbyint_(double x) {
    trace("nearbyint_ called. Arguments: x=", std::to_wstring(x));
    const double result = std::nearbyint(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

float UCRTBase::nearbyintf_(float x) {
    trace("nearbyintf_ called. Arguments: x=", std::to_wstring(x));
    const float result = std::nearbyintf(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

long double UCRTBase::nearbyintl_(long double x) {
    trace("nearbyintl_ called. Arguments: x=", std::to_wstring(static_cast<double>(x)));
    const long double result = std::nearbyintl(x);
    ret("Error set to: -, Return value: ", std::to_wstring(static_cast<double>(result)));
    return result;
}

double UCRTBase::nextafter_(double x, double y) {
    trace("nextafter_ called. Arguments: x=", std::to_wstring(x), ", y=", std::to_wstring(y));
    const double result = std::nextafter(x, y);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

float UCRTBase::nextafterf_(float x, float y) {
    trace("nextafterf_ called. Arguments: x=", std::to_wstring(x), ", y=", std::to_wstring(y));
    const float result = std::nextafterf(x, y);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

long double UCRTBase::nextafterl_(long double x, long double y) {
    trace("nextafterl_ called. Arguments: x=", std::to_wstring(static_cast<double>(x)), ", y=", std::to_wstring(static_cast<double>(y)));
    const long double result = std::nextafterl(x, y);
    ret("Error set to: -, Return value: ", std::to_wstring(static_cast<double>(result)));
    return result;
}

double UCRTBase::nexttoward_(double x, long double y) {
    trace("nexttoward_ called. Arguments: x=", std::to_wstring(x), ", y=", std::to_wstring(static_cast<double>(y)));
    const double result = std::nexttoward(x, y);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

float UCRTBase::nexttowardf_(float x, long double y) {
    trace("nexttowardf_ called. Arguments: x=", std::to_wstring(x), ", y=", std::to_wstring(static_cast<double>(y)));
    const float result = std::nexttowardf(x, y);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

long double UCRTBase::nexttowardl_(long double x, long double y) {
    trace("nexttowardl_ called. Arguments: x=", std::to_wstring(static_cast<double>(x)), ", y=", std::to_wstring(static_cast<double>(y)));
    const long double result = std::nexttowardl(x, y);
    ret("Error set to: -, Return value: ", std::to_wstring(static_cast<double>(result)));
    return result;
}

double UCRTBase::pow_(double x, double y) {
    trace("pow_ called. Arguments: x=", std::to_wstring(x), ", y=", std::to_wstring(y));
    const double result = std::pow(x, y);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

float UCRTBase::powf_(float x, float y) {
    trace("powf_ called. Arguments: x=", std::to_wstring(x), ", y=", std::to_wstring(y));
    const float result = std::powf(x, y);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

long double UCRTBase::powl_(long double x, long double y) {
    trace("powl_ called. Arguments: x=", std::to_wstring(static_cast<double>(x)), ", y=", std::to_wstring(static_cast<double>(y)));
    const long double result = std::powl(x, y);
    ret("Error set to: -, Return value: ", std::to_wstring(static_cast<double>(result)));
    return result;
}

double UCRTBase::remainder_(double x, double y) {
    trace("remainder_ called. Arguments: x=", std::to_wstring(x), ", y=", std::to_wstring(y));
    const double result = std::remainder(x, y);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

float UCRTBase::remainderf_(float x, float y) {
    trace("remainderf_ called. Arguments: x=", std::to_wstring(x), ", y=", std::to_wstring(y));
    const float result = std::remainderf(x, y);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

long double UCRTBase::remainderl_(long double x, long double y) {
    trace("remainderl_ called. Arguments: x=", std::to_wstring(static_cast<double>(x)), ", y=", std::to_wstring(static_cast<double>(y)));
    const long double result = std::remainderl(x, y);
    ret("Error set to: -, Return value: ", std::to_wstring(static_cast<double>(result)));
    return result;
}

double UCRTBase::remquo_(double x, double y, int *quo) {
    trace("remquo_ called. Arguments: x=", std::to_wstring(x), ", y=", std::to_wstring(y), ", quo=", std::to_wstring(*quo));
    const double result = std::remquo(x, y, quo);
    ret("Error set to: -, Return value: ", std::to_wstring(result), ", quo=", std::to_wstring(*quo));
    return result;
}

float UCRTBase::remquof_(float x, float y, int *quo) {
    trace("remquof_ called. Arguments: x=", std::to_wstring(x), ", y=", std::to_wstring(y), ", quo=", std::to_wstring(*quo));
    const float result = std::remquof(x, y, quo);
    ret("Error set to: -, Return value: ", std::to_wstring(result), ", quo=", std::to_wstring(*quo));
    return result;
}

long double UCRTBase::remquol_(long double x, long double y, int *quo) {
    trace("remquol_ called. Arguments: x=", std::to_wstring(static_cast<double>(x)), ", y=", std::to_wstring(static_cast<double>(y)), ", quo=", std::to_wstring(*quo));
    const long double result = std::remquol(x, y, quo);
    ret("Error set to: -, Return value: ", std::to_wstring(static_cast<double>(result)), ", quo=", std::to_wstring(*quo));
    return result;
}

double UCRTBase::scalbln_(double x, long exp) {
    trace("scalbln_ called. Arguments: x=", std::to_wstring(x), ", exp=", std::to_wstring(exp));
    const double result = std::scalbln(x, exp);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

float UCRTBase::scalblnf_(float x, long exp) {
    trace("scalblnf_ called. Arguments: x=", std::to_wstring(x), ", exp=", std::to_wstring(exp));
    const float result = std::scalblnf(x, exp);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

long double UCRTBase::scalblnl_(long double x, long exp) {
    trace("scalblnl_ called. Arguments: x=", std::to_wstring(static_cast<double>(x)), ", exp=", std::to_wstring(exp));
    const long double result = std::scalblnl(x, exp);
    ret("Error set to: -, Return value: ", std::to_wstring(static_cast<double>(result)));
    return result;
}

double UCRTBase::scalbn_(double x, int exp) {
    trace("scalbn_ called. Arguments: x=", std::to_wstring(x), ", exp=", std::to_wstring(exp));
    const double result = std::scalbn(x, exp);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

float UCRTBase::scalbnf_(float x, int exp) {
    trace("scalbnf_ called. Arguments: x=", std::to_wstring(x), ", exp=", std::to_wstring(exp));
    const float result = std::scalbnf(x, exp);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

long double UCRTBase::scalbnl_(long double x, int exp) {
    trace("scalbnl_ called. Arguments: x=", std::to_wstring(static_cast<double>(x)), ", exp=", std::to_wstring(exp));
    const long double result = std::scalbnl(x, exp);
    ret("Error set to: -, Return value: ", std::to_wstring(static_cast<double>(result)));
    return result;
}

double UCRTBase::cbrt_(double x) {
    trace("cbrt_ called. Arguments: x=", std::to_wstring(x));
    const double result = std::cbrt(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

double UCRTBase::ceil_(double x) {
    trace("ceil_ called. Arguments: x=", std::to_wstring(x));
    const double result = std::ceil(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

float UCRTBase::ceilf_(float x) {
    trace("ceilf_ called. Arguments: x=", std::to_wstring(x));
    const float result = std::ceilf(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

long double UCRTBase::ceill_(long double x) {
    trace("ceill_ called. Arguments: x=", std::to_wstring(static_cast<double>(x)));
    const long double result = std::ceill(x);
    ret("Error set to: -, Return value: ", std::to_wstring(static_cast<double>(result)));
    return result;
}

float UCRTBase::cbrtf_(float x) {
    trace("cbrtf_ called. Arguments: x=", std::to_wstring(x));
    const float result = std::cbrtf(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

long double UCRTBase::cbrtl_(long double x) {
    trace("cbrtl_ called. Arguments: x=", std::to_wstring(static_cast<double>(x)));
    const long double result = std::cbrtl(x);
    ret("Error set to: -, Return value: ", std::to_wstring(static_cast<double>(result)));
    return result;
}

double UCRTBase::copysign_(double x, double y) {
    trace("copysign_ called. Arguments: x=", std::to_wstring(x), ", y=", std::to_wstring(y));
    const double result = std::copysign(x, y);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

float UCRTBase::copysignf_(float x, float y) {
    trace("copysignf_ called. Arguments: x=", std::to_wstring(x), ", y=", std::to_wstring(y));
    const float result = std::copysignf(x, y);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

long double UCRTBase::copysignl_(long double x, long double y) {
    trace("copysignl_ called. Arguments: x=", std::to_wstring(static_cast<double>(x)), ", y=", std::to_wstring(static_cast<double>(y)));
    const long double result = std::copysignl(x, y);
    ret("Error set to: -, Return value: ", std::to_wstring(static_cast<double>(result)));
    return result;
}

double UCRTBase::cos_(double x) {
    trace("cos_ called. Arguments: x=", std::to_wstring(x));
    const double result = std::cos(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

float UCRTBase::cosf_(float x) {
    trace("cosf_ called. Arguments: x=", std::to_wstring(x));
    const float result = std::cosf(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

long double UCRTBase::cosl_(long double x) {
    trace("cosl_ called. Arguments: x=", std::to_wstring(static_cast<double>(x)));
    const long double result = std::cosl(x);
    ret("Error set to: -, Return value: ", std::to_wstring(static_cast<double>(result)));
    return result;
}

double UCRTBase::cosh_(double x) {
    trace("cosh_ called. Arguments: x=", std::to_wstring(x));
    const double result = std::cosh(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

float UCRTBase::coshf_(float x) {
    trace("coshf_ called. Arguments: x=", std::to_wstring(x));
    const float result = std::coshf(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

long double UCRTBase::coshl_(long double x) {
    trace("coshl_ called. Arguments: x=", std::to_wstring(static_cast<double>(x)));
    const long double result = std::coshl(x);
    ret("Error set to: -, Return value: ", std::to_wstring(static_cast<double>(result)));
    return result;
}

double UCRTBase::sin_(double x) {
    trace("sin_ called. Arguments: x=", std::to_wstring(x));
    const double result = std::sin(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

float UCRTBase::sinf_(float x) {
    trace("sinf_ called. Arguments: x=", std::to_wstring(x));
    const float result = std::sinf(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

long double UCRTBase::sinl_(long double x) {
    trace("sinl_ called. Arguments: x=", std::to_wstring(static_cast<double>(x)));
    const long double result = std::sinl(x);
    ret("Error set to: -, Return value: ", std::to_wstring(static_cast<double>(result)));
    return result;
}

double UCRTBase::sinh_(double x) {
    trace("sinh_ called. Arguments: x=", std::to_wstring(x));
    const double result = std::sinh(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

float UCRTBase::sinhf_(float x) {
    trace("sinhf_ called. Arguments: x=", std::to_wstring(x));
    const float result = std::sinhf(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

long double UCRTBase::sinhl_(long double x) {
    trace("sinhl_ called. Arguments: x=", std::to_wstring(static_cast<double>(x)));
    const long double result = std::sinhl(x);
    ret("Error set to: -, Return value: ", std::to_wstring(static_cast<double>(result)));
    return result;
}

double UCRTBase::tan_(double x) {
    trace("tan_ called. Arguments: x=", std::to_wstring(x));
    const double result = std::tan(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

float UCRTBase::tanf_(float x) {
    trace("tanf_ called. Arguments: x=", std::to_wstring(x));
    const float result = std::tanf(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

long double UCRTBase::tanl_(long double x) {
    trace("tanl_ called. Arguments: x=", std::to_wstring(static_cast<double>(x)));
    const long double result = std::tanl(x);
    ret("Error set to: -, Return value: ", std::to_wstring(static_cast<double>(result)));
    return result;
}

double UCRTBase::tanh_(double x) {
    trace("tanh_ called. Arguments: x=", std::to_wstring(x));
    const double result = std::tanh(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

float UCRTBase::tanhf_(float x) {
    trace("tanhf_ called. Arguments: x=", std::to_wstring(x));
    const float result = std::tanhf(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

long double UCRTBase::tanhl_(long double x) {
    trace("tanhl_ called. Arguments: x=", std::to_wstring(static_cast<double>(x)));
    const long double result = std::tanhl(x);
    ret("Error set to: -, Return value: ", std::to_wstring(static_cast<double>(result)));
    return result;
}

double UCRTBase::sqrt_(double x) {
    trace("sqrt_ called. Arguments: x=", std::to_wstring(x));
    const double result = std::sqrt(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

float UCRTBase::sqrtf_(float x) {
    trace("sqrtf_ called. Arguments: x=", std::to_wstring(x));
    const float result = std::sqrtf(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

long double UCRTBase::sqrtl_(long double x) {
    trace("sqrtl_ called. Arguments: x=", std::to_wstring(static_cast<double>(x)));
    const long double result = std::sqrtl(x);
    ret("Error set to: -, Return value: ", std::to_wstring(static_cast<double>(result)));
    return result;
}

double UCRTBase::tgamma_(double x) {
    trace("tgamma_ called. Arguments: x=", std::to_wstring(x));
    const double result = std::tgamma(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

float UCRTBase::tgammaf_(float x) {
    trace("tgammaf_ called. Arguments: x=", std::to_wstring(x));
    const float result = std::tgammaf(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

long double UCRTBase::tgammal_(long double x) {
    trace("tgammal_ called. Arguments: x=", std::to_wstring(static_cast<double>(x)));
    const long double result = std::tgammal(x);
    ret("Error set to: -, Return value: ", std::to_wstring(static_cast<double>(result)));
    return result;
}

double UCRTBase::trunc_(double x) {
    trace("trunc_ called. Arguments: x=", std::to_wstring(x));
    const double result = std::trunc(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

float UCRTBase::truncf_(float x) {
    trace("truncf_ called. Arguments: x=", std::to_wstring(x));
    const float result = std::truncf(x);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

long double UCRTBase::truncl_(long double x) {
    trace("truncl_ called. Arguments: x=", std::to_wstring(static_cast<double>(x)));
    const long double result = std::truncl(x);
    ret("Error set to: -, Return value: ", std::to_wstring(static_cast<double>(result)));
    return result;
}

FILE * UCRTBase::__acrt_iob_func(unsigned index) {
    trace("__acrt_iob_func called. Arguments: index=", std::to_wstring(index));
    if (index > 2) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    FILE* result = index == 0 ? stdin : index == 1 ? stdout : stderr;
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(result)));
    return result;
}

UINT * UCRTBase::__p__commode() {
    return &tls.commode;
}

INT * UCRTBase::__p__fmode() {
    return &tls.fmode;
}

int UCRTBase::__stdio_common_vfprintf(UINT64 options, FILE *file, const char *format, _locale_t locale, va_list args) {
    trace("__stdio_common_vfprintf called. Arguments: options=", std::to_wstring(options), ", file=", std::to_wstring(reinterpret_cast<uintptr_t>(file)), ", format=", std::wstring(format, format + strlen(format)), ", locale=", std::to_wstring(reinterpret_cast<uintptr_t>(locale)), ", args=va_list");
    if (file == nullptr || format == nullptr) {
        ret("Error set to: EINVAL, Return value: -1");
        errno = EINVAL;
        return -1;
    }
    const int result = vfprintf(file, format, args);
    if (result < 0) {
        ret("Error set to: EIO, Return value: -1");
        errno = EIO;
        return -1;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

int UCRTBase::__stdio_common_vfprinf_p(UINT64 options, FILE *file, const char *format, _locale_t locale, va_list args) {
    trace("__stdio_common_vfprinf_p called. Arguments: options=", std::to_wstring(options), ", file=", std::to_wstring(reinterpret_cast<uintptr_t>(file)), ", format=", std::wstring(format, format + strlen(format)), ", locale=", std::to_wstring(reinterpret_cast<uintptr_t>(locale)), ", args=va_list");
    if (file == nullptr || format == nullptr) {
        ret("Error set to: EINVAL, Return value: -1");
        errno = EINVAL;
        return -1;
    }
    const int result = vfprintf(file, format, args);
    if (result < 0) {
        ret("Error set to: EIO, Return value: -1");
        errno = EIO;
        return -1;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

int UCRTBase::__stdio_common_vfprintf_s(UINT64 options, FILE *file, const char *format, _locale_t locale,
    va_list args) {
    trace("__stdio_common_vfprintf_s called. Arguments: options=", std::to_wstring(options), ", file=", std::to_wstring(reinterpret_cast<uintptr_t>(file)), ", format=", std::wstring(format, format + strlen(format)), ", locale=", std::to_wstring(reinterpret_cast<uintptr_t>(locale)), ", args=va_list");
    if (file == nullptr || format == nullptr) {
        ret("Error set to: EINVAL, Return value: -1");
        errno = EINVAL;
        return -1;
    }
    const int result = vfprintf(file, format, args);
    if (result < 0) {
        ret("Error set to: EIO, Return value: -1");
        errno = EIO;
        return -1;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

int UCRTBase::__stdio_common_vfscanf(UINT64 options, FILE *file, const char *format, _locale_t locale, va_list args) {
    trace("__stdio_common_vfscanf called. Arguments: options=", std::to_wstring(options), ", file=", std::to_wstring(reinterpret_cast<uintptr_t>(file)), ", format=", std::wstring(format, format + strlen(format)), ", locale=", std::to_wstring(reinterpret_cast<uintptr_t>(locale)), ", args=va_list");
    if (file == nullptr || format == nullptr) {
        ret("Error set to: EINVAL, Return value: -1");
        errno = EINVAL;
        return -1;
    }
    const int result = vfscanf(file, format, args);
    if (result < 0) {
        ret("Error set to: EIO, Return value: -1");
        errno = EIO;
        return -1;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

int UCRTBase::__stdio_common_vfwprintf(uint64_t options, FILE *file, const _wchar_t *format, _locale_t locale,
    va_list args) {
    if (!file || !format) {
        errno = EINVAL;
        return -1;
    }

    // Step 1: convert _wchar_t* -> wchar_t*
    size_t len = 0;
    while (format[len]) ++len;

    const auto buf = new wchar_t[len + 1];
    for (size_t i = 0; i <= len; ++i) buf[i] = format[i];

    // Step 2: call vfwprintf
    const int result = vfwprintf(file, buf, args);

    delete[] buf;

    if (result < 0) {
        errno = EIO;
        return -1;
    }

    return result;
}

int UCRTBase::__stdio_common_vfwprintf_p(UINT64 options, FILE *file, const _wchar_t *format, _locale_t locale,
    va_list args) {
    trace("__stdio_common_vfwprintf_p called. Arguments: options=", std::to_wstring(options), ", file=", std::to_wstring(reinterpret_cast<uintptr_t>(file)), ", format=", format, ", locale=", std::to_wstring(reinterpret_cast<uintptr_t>(locale)), ", args=va_list");
    return __stdio_common_vfwprintf(options, file, format, locale, args);
}

int UCRTBase::__stdio_common_vfwprintf_s(UINT64 options, FILE *file, const _wchar_t *format, _locale_t locale,
    va_list args) {
    trace("__stdio_common_vfwprintf_s called. Arguments: options=", std::to_wstring(options), ", file=", std::to_wstring(reinterpret_cast<uintptr_t>(file)), ", format=", format, ", locale=", std::to_wstring(reinterpret_cast<uintptr_t>(locale)), ", args=va_list");
    return __stdio_common_vfwprintf(options, file, format, locale, args);
}

int UCRTBase::__stdio_common_vfwscanf(uint64_t options, FILE *file, const _wchar_t *format, _locale_t locale,
    va_list args) {
    if (!file || !format) {
        errno = EINVAL;
        return -1;
    }

    // Convert 16-bit _wchar_t* -> 32-bit wchar_t*
    size_t len = 0;
    while (format[len]) ++len;

    wchar_t* buf = new wchar_t[len + 1];
    for (size_t i = 0; i <= len; ++i) buf[i] = format[i];

    int result = vfwscanf(file, buf, args);

    delete[] buf;

    if (result < 0) {
        errno = EIO;
        return -1;
    }

    return result;
}

int UCRTBase::__stdio_common_vsnprintf(UINT64 options, char *buffer, size_t sizeOfBuffer, const char *format,
    _locale_t locale, va_list args) {
    trace("__stdio_common_vsnprintf called. Arguments: options=", std::to_wstring(options), ", buffer=", std::to_wstring(reinterpret_cast<uintptr_t>(buffer)), ", sizeOfBuffer=", std::to_wstring(sizeOfBuffer), ", format=", std::wstring(format, format + strlen(format)), ", locale=", std::to_wstring(reinterpret_cast<uintptr_t>(locale)), ", args=va_list");
    if (format == nullptr || (buffer == nullptr && sizeOfBuffer != 0)) {
        ret("Error set to: EINVAL, Return value: -1");
        errno = EINVAL;
        return -1;
    }
    const int result = vsnprintf(buffer, sizeOfBuffer, format, args);
    if (result < 0) {
        ret("Error set to: EIO, Return value: -1");
        errno = EIO;
        return -1;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

int UCRTBase::__stdio_common_vsnprintf_s(UINT64 options, char *buffer, size_t sizeOfBuffer, size_t count,
    const char *format, _locale_t locale, va_list args) {
    trace("__stdio_common_vsnprintf_s called. Arguments: options=", std::to_wstring(options), ", buffer=", std::to_wstring(reinterpret_cast<uintptr_t>(buffer)), ", sizeOfBuffer=", std::to_wstring(sizeOfBuffer), ", count=", std::to_wstring(count), ", format=", std::wstring(format, format + strlen(format)), ", locale=", std::to_wstring(reinterpret_cast<uintptr_t>(locale)), ", args=va_list");
    if (format == nullptr || (buffer == nullptr && sizeOfBuffer != 0) || (sizeOfBuffer != 0 && count > sizeOfBuffer)) {
        ret("Error set to: EINVAL, Return value: -1");
        errno = EINVAL;
        return -1;
    }
    const int result = vsnprintf(buffer, std::min(sizeOfBuffer, count), format, args);
    if (result < 0) {
        ret("Error set to: EIO, Return value: -1");
        errno = EIO;
        return -1;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

int UCRTBase::__stdio_common_vsnwprintf(uint64_t options, _wchar_t *buffer, size_t sizeOfBuffer, size_t count,
    const _wchar_t *format, _locale_t locale, va_list args) {
    // Trace logging
    std::wstring formatStr;
    if (format) {
        size_t len = 0;
        while (format[len]) ++len;
        formatStr.assign(format, format + len);
    }
    trace("__stdio_common_vsnwprintf called. Arguments: options=", std::to_wstring(options),
          ", buffer=", std::to_wstring(reinterpret_cast<uintptr_t>(buffer)),
          ", sizeOfBuffer=", std::to_wstring(sizeOfBuffer),
          ", count=", std::to_wstring(count),
          ", format=", formatStr,
          ", locale=", std::to_wstring(reinterpret_cast<uintptr_t>(locale)),
          ", args=va_list");

    if (!format || (buffer == nullptr && sizeOfBuffer != 0) || (sizeOfBuffer != 0 && count > sizeOfBuffer)) {
        ret("Error set to: EINVAL, Return value: -1");
        errno = EINVAL;
        return -1;
    }

    // Convert format from 16-bit _wchar_t -> 32-bit wchar_t
    size_t formatLen = 0;
    while (format[formatLen]) ++formatLen;
    const auto fmt32 = new wchar_t[formatLen + 1];
    for (size_t i = 0; i <= formatLen; ++i) fmt32[i] = format[i];

    // Convert buffer from 16-bit -> 32-bit
    wchar_t* buf32 = nullptr;
    if (buffer && sizeOfBuffer > 0) {
        buf32 = new wchar_t[sizeOfBuffer];
    }

    int result = vswprintf(buf32, std::min(sizeOfBuffer, count), fmt32, args);

    if (result >= 0 && buf32) {
        // Copy back to 16-bit buffer
        for (int i = 0; i < result; ++i) {
            buffer[i] = static_cast<_wchar_t>(buf32[i] & 0xFFFF);
        }
        if (static_cast<size_t>(result) < sizeOfBuffer) buffer[result] = 0;
    }

    delete[] fmt32;
    delete[] buf32;

    if (result < 0) {
        ret("Error set to: EIO, Return value: -1");
        errno = EIO;
        return -1;
    }

    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

int UCRTBase::__stdio_common_vsprintf(UINT64 options, char *buffer, const char *format, _locale_t locale,
    va_list args) {
    trace("__stdio_common_vsprintf called. Arguments: options=", std::to_wstring(options), ", buffer=", std::to_wstring(reinterpret_cast<uintptr_t>(buffer)), ", format=", std::wstring(format, format + strlen(format)), ", locale=", std::to_wstring(reinterpret_cast<uintptr_t>(locale)), ", args=va_list");
    if (format == nullptr || buffer == nullptr) {
        ret("Error set to: EINVAL, Return value: -1");
        errno = EINVAL;
        return -1;
    }
    const int result = vsprintf(buffer, format, args);
    if (result < 0) {
        ret("Error set to: EIO, Return value: -1");
        errno = EIO;
        return -1;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

int UCRTBase::__stdio_common_vsprintf_p(UINT64 options, char *buffer, const char *format, _locale_t locale,
    va_list args) {
    trace("__stdio_common_vsprintf_p called. Arguments: options=", std::to_wstring(options), ", buffer=", std::to_wstring(reinterpret_cast<uintptr_t>(buffer)), ", format=", std::wstring(format, format + strlen(format)), ", locale=", std::to_wstring(reinterpret_cast<uintptr_t>(locale)), ", args=va_list");
    if (format == nullptr || buffer == nullptr) {
        ret("Error set to: EINVAL, Return value: -1");
        errno = EINVAL;
        return -1;
    }
    const int result = vsprintf(buffer, format, args);
    if (result < 0) {
        ret("Error set to: EIO, Return value: -1");
        errno = EIO;
        return -1;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

int UCRTBase::__stdio_common_vsprintf_s(UINT64 options, char *buffer, size_t sizeOfBuffer, const char *format,
    _locale_t locale, va_list args) {
    trace("__stdio_common_vsprintf_s called. Arguments: options=", std::to_wstring(options), ", buffer=", std::to_wstring(reinterpret_cast<uintptr_t>(buffer)), ", sizeOfBuffer=", std::to_wstring(sizeOfBuffer), ", format=", std::wstring(format, format + strlen(format)), ", locale=", std::to_wstring(reinterpret_cast<uintptr_t>(locale)), ", args=va_list");
    if (format == nullptr || buffer == nullptr) {
        ret("Error set to: EINVAL, Return value: -1");
        errno = EINVAL;
        return -1;
    }
    const int result = vsnprintf(buffer, sizeOfBuffer, format, args);
    if (result < 0) {
        ret("Error set to: EIO, Return value: -1");
        errno = EIO;
        return -1;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

int UCRTBase::__stdio_common_vsscanf(UINT64 options, const char *buffer, const char *format, _locale_t locale,
    va_list args) {
    trace("__stdio_common_vsscanf called. Arguments: options=", std::to_wstring(options), ", buffer=", std::to_wstring(reinterpret_cast<uintptr_t>(buffer)), ", format=", std::wstring(format, format + strlen(format)), ", locale=", std::to_wstring(reinterpret_cast<uintptr_t>(locale)), ", args=va_list");
    if (format == nullptr || buffer == nullptr) {
        ret("Error set to: EINVAL, Return value: -1");
        errno = EINVAL;
        return -1;
    }
    const int result = vsscanf(buffer, format, args);
    if (result < 0) {
        ret("Error set to: EIO, Return value: -1");
        errno = EIO;
        return -1;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

int UCRTBase::__stdio_common_vswprintf(uint64_t options, _wchar_t *buffer, size_t sizeOfBuffer, const _wchar_t *format,
    _locale_t locale, va_list args) {
    // Trace logging
    std::wstring formatStr;
    if (format) {
        size_t len = 0; while (format[len]) ++len;
        formatStr.assign(format, format + len);
    }
    trace("__stdio_common_vswprintf called. Arguments: options=", std::to_wstring(options),
          ", buffer=", std::to_wstring(reinterpret_cast<uintptr_t>(buffer)),
          ", sizeOfBuffer=", std::to_wstring(sizeOfBuffer),
          ", format=", formatStr,
          ", locale=", std::to_wstring(reinterpret_cast<uintptr_t>(locale)),
          ", args=va_list");

    if (!format || (buffer == nullptr && sizeOfBuffer != 0)) {
        ret("Error set to: EINVAL, Return value: -1");
        errno = EINVAL;
        return -1;
    }

    // Convert format to 32-bit
    size_t fmtLen = 0; while (format[fmtLen]) ++fmtLen;
    wchar_t* fmt32 = new wchar_t[fmtLen + 1];
    for (size_t i = 0; i <= fmtLen; ++i) fmt32[i] = format[i];

    // Convert buffer to 32-bit
    wchar_t* buf32 = nullptr;
    if (buffer && sizeOfBuffer > 0) buf32 = new wchar_t[sizeOfBuffer];

    int result = vswprintf(buf32, sizeOfBuffer, fmt32, args);

    // Copy back to 16-bit
    if (result >= 0 && buf32) {
        for (int i = 0; i < result; ++i) buffer[i] = static_cast<_wchar_t>(buf32[i] & 0xFFFF);
        if (static_cast<size_t>(result) < sizeOfBuffer) buffer[result] = 0;
    }

    delete[] fmt32;
    delete[] buf32;

    if (result < 0) {
        ret("Error set to: EIO, Return value: -1");
        errno = EIO;
        return -1;
    }

    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

int UCRTBase::__stdio_common_vswscanf(uint64_t options, const _wchar_t *buffer, const _wchar_t *format,
    _locale_t locale, va_list args) {
    // Trace logging
    std::wstring formatStr;
    if (format) {
        size_t len = 0; while (format[len]) ++len;
        formatStr.assign(format, format + len);
    }
    trace("__stdio_common_vswscanf called. Arguments: options=", std::to_wstring(options),
          ", buffer=", std::to_wstring(reinterpret_cast<uintptr_t>(buffer)),
          ", format=", formatStr,
          ", locale=", std::to_wstring(reinterpret_cast<uintptr_t>(locale)),
          ", args=va_list");

    if (!format || !buffer) {
        ret("Error set to: EINVAL, Return value: -1");
        errno = EINVAL;
        return -1;
    }

    // Convert format to 32-bit
    size_t fmtLen = 0; while (format[fmtLen]) ++fmtLen;
    wchar_t* fmt32 = new wchar_t[fmtLen + 1];
    for (size_t i = 0; i <= fmtLen; ++i) fmt32[i] = format[i];

    // Convert buffer to 32-bit
    size_t bufLen = 0; while (buffer[bufLen]) ++bufLen;
    wchar_t* buf32 = new wchar_t[bufLen + 1];
    for (size_t i = 0; i <= bufLen; ++i) buf32[i] = buffer[i];

    int result = vswscanf(buf32, fmt32, args);

    delete[] fmt32;
    delete[] buf32;

    if (result < 0) {
        ret("Error set to: EIO, Return value: -1");
        errno = EIO;
        return -1;
    }

    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

int UCRTBase::__stdio_common_vswprintf_p(UINT64 options, _wchar_t *buffer, size_t sizeOfBuffer, const _wchar_t *format,
    _locale_t locale, va_list args) {
    return __stdio_common_vswprintf(options, buffer, sizeOfBuffer, format, locale, args);
}

int UCRTBase::__stdio_common_vswprintf_s(UINT64 options, _wchar_t *buffer, size_t sizeOfBuffer, const _wchar_t *format,
    _locale_t locale, va_list args) {
    return __stdio_common_vswprintf(options, buffer, sizeOfBuffer, format, locale, args);
}

int UCRTBase::_chsize(int fd, LONG size) {
    trace("_chsize_ called. Arguments: fd=", std::to_wstring(fd), ", size=", std::to_wstring(size));
    if (const int result = ftruncate(fd, size); result != 0) {
        ret("Error set to: errno, Return value: -1");
        return -1;
    }
    ret("Error set to: -, Return value: 0");
    return 0;
}

errno_t UCRTBase::_chsize_s(int fd, LONGLONG size) {
    trace("_chsize_s called. Arguments: fd=", std::to_wstring(fd), ", size=", std::to_wstring(size));
    if (const int result = ftruncate(fd, size); result != 0) {
        ret("Error set to: errno, Return value: errno");
        return errno;
    }
    ret("Error set to: -, Return value: 0");
    return 0;
}

int UCRTBase::_close(int fd) {
    trace("_close called. Arguments: fd=", std::to_wstring(fd));
    if (const int result = close(fd); result != 0) {
        ret("Error set to: errno, Return value: -1");
        return -1;
    }
    ret("Error set to: -, Return value: 0");
    return 0;
}

int UCRTBase::_commit(int fd) {
    trace("_commit called. Arguments: fd=", std::to_wstring(fd));
    if (const int result = fsync(fd); result != 0) {
        ret("Error set to: errno, Return value: -1");
        return -1;
    }
    ret("Error set to: -, Return value: 0");
    return 0;
}

int UCRTBase::_creat(const char *filename, int pmode) {
    trace("_creat called. Arguments: filename=", std::wstring(filename, filename + strlen(filename)), ", pmode=", std::to_wstring(pmode));
    const int fd = creat(filename, pmode);
    if (fd == -1) {
        ret("Error set to: errno, Return value: -1");
        return -1;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(fd));
    return fd;
}

int UCRTBase::_wcreat(const _wchar_t *filename, int pmode) {
    trace("_wcreat called. Arguments: filename=", filename, ", pmode=", std::to_wstring(pmode));
    if (!filename) {
        ret("Error set to: EINVAL, Return value: -1");
        errno = EINVAL;
        return -1;
    }

    char fname[260];
    wchar_t tmp[260];
    size_t i;
    for (i = 0; i < 259 && filename[i]; ++i) tmp[i] = filename[i];
    tmp[i] = 0;
    if (wcstombs(fname, tmp, sizeof(fname)) == static_cast<size_t>(-1)) {
        ret("Error set to: EILSEQ, Return value: -1");
        errno = EILSEQ;
        return -1;
    }

    const int fd = creat(fname, pmode);
    if (fd == -1) {
        ret("Error set to: errno, Return value: -1");
        return -1;
    }

    ret("Error set to: -, Return value: ", std::to_wstring(fd));
    return fd;
}

int UCRTBase::_dup(int fd) {
    trace("_dup called. Arguments: fd=", std::to_wstring(fd));
    const int newfd = dup(fd);
    if (newfd == -1) {
        ret("Error set to: errno, Return value: -1");
        return -1;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(newfd));
    return newfd;
}

int UCRTBase::_dup2(int fd, int fd2) {
    trace("_dup2 called. Arguments: fd=", std::to_wstring(fd), ", fd2=", std::to_wstring(fd2));
    if (fd == fd2) {
        ret("Error set to: -, Return value: ", std::to_wstring(fd2));
        return fd2;
    }
    if (const int result = dup2(fd, fd2); result == -1) {
        ret("Error set to: errno, Return value: -1");
        return -1;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(fd2));
    return fd2;
}

int UCRTBase::_eof(int fd) {
    trace("_eof called. Arguments: fd=", std::to_wstring(fd));
    const off_t current = lseek(fd, 0, SEEK_CUR);
    if (current == -1) {
        ret("Error set to: errno, Return value: -1");
        return -1;
    }
    const off_t end = lseek(fd, 0, SEEK_END);
    if (end == -1) {
        ret("Error set to: errno, Return value: -1");
        return -1;
    }
    if (lseek(fd, current, SEEK_SET) == -1) {
        ret("Error set to: errno, Return value: -1");
        return -1;
    }
    const int result = current == end ? 1 : 0;
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

int UCRTBase::_fclose_nolock(FILE *file) {
    trace("_fclose_nolock called. Arguments: file=", std::to_wstring(reinterpret_cast<uintptr_t>(file)));
    if (file == nullptr) {
        ret("Error set to: EINVAL, Return value: EOF");
        errno = EINVAL;
        return EOF;
    }
    if (const int result = fclose(file); result == EOF) {
        ret("Error set to: errno, Return value: EOF");
        return EOF;
    }
    ret("Error set to: -, Return value: 0");
    return 0;
}

int UCRTBase::_fcloseall() {
    trace("_fcloseall diserror-stub called. Arguments: -");
    ret("Error set to: -, Return value: 0");
    return 0;
}

int UCRTBase::_fflush_nolock(FILE *file) {
    trace("_fflush_nolock called. Arguments: file=", std::to_wstring(reinterpret_cast<uintptr_t>(file)));
    if (file == nullptr) {
        ret("Error set to: EINVAL, Return value: EOF");
        errno = EINVAL;
        return EOF;
    }
    if (const int result = fflush(file); result == EOF) {
        ret("Error set to: errno, Return value: EOF");
        return EOF;
    }
    ret("Error set to: -, Return value: 0");
    return 0;
}

int UCRTBase::_fgetc_nolock(FILE *file) {
    trace("_fgetc_nolock called. Arguments: file=", std::to_wstring(reinterpret_cast<uintptr_t>(file)));
    if (file == nullptr) {
        ret("Error set to: EINVAL, Return value: EOF");
        errno = EINVAL;
        return EOF;
    }
    const int result = fgetc(file);
    if (result == EOF && ferror(file)) {
        ret("Error set to: errno, Return value: EOF");
        return EOF;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

_wint_t UCRTBase::_fgetwc_nolock(FILE *file) {
    trace("_fgetwc_nolock called. Arguments: file=", std::to_wstring(reinterpret_cast<uintptr_t>(file)));
    if (file == nullptr) {
        ret("Error set to: EINVAL, Return value: _WEOF");
        errno = EINVAL;
        return _WEOF;
    }
    const _wint_t result = fgetwc(file);
    if (result == _WEOF && ferror(file)) {
        ret("Error set to: errno, Return value: _WEOF");
        return _WEOF;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

int UCRTBase::_fgetchar_nolock() {
    trace("_fgetchar_nolock called. Arguments: -");
    const int result = fgetc(stdin);
    if (result == EOF && ferror(stdin)) {
        ret("Error set to: errno, Return value: EOF");
        return EOF;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

_wint_t UCRTBase::_fgetwchar_nolock() {
    trace("_fgetwchar_nolock called. Arguments: -");
    const _wint_t result = fgetwc(stdin);
    if (result == _WEOF && ferror(stdin)) {
        ret("Error set to: errno, Return value: _WEOF");
        return _WEOF;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

LONG UCRTBase::_filelength(int fd) {
    trace("_filelength called. Arguments: fd=", std::to_wstring(fd));
    const off_t current = lseek(fd, 0, SEEK_CUR);
    if (current == -1) {
        ret("Error set to: errno, Return value: -1");
        return -1;
    }
    const off_t end = lseek(fd, 0, SEEK_END);
    if (end == -1) {
        ret("Error set to: errno, Return value: -1");
        return -1;
    }
    if (lseek(fd, current, SEEK_SET) == -1) {
        ret("Error set to: errno, Return value: -1");
        return -1;
    }
    if (end > LONG_MAX) {
        ret("Error set to: EOVERFLOW, Return value: -1");
        errno = EOVERFLOW;
        return -1;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(static_cast<LONG>(end)));
    return static_cast<LONG>(end);
}

off_t UCRTBase::_filelengthi64(int fd) {
    trace("_filelengthi64 called. Arguments: fd=", std::to_wstring(fd));
    const off_t current = lseek(fd, 0, SEEK_CUR);
    if (current == -1) {
        ret("Error set to: errno, Return value: -1");
        return -1;
    }
    const off_t end = lseek(fd, 0, SEEK_END);
    if (end == -1) {
        ret("Error set to: errno, Return value: -1");
        return -1;
    }
    if (lseek(fd, current, SEEK_SET) == -1) {
        ret("Error set to: errno, Return value: -1");
        return -1;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(end));
    return end;
}

int UCRTBase::_fileno(FILE *file) {
    trace("_fileno called. Arguments: file=", std::to_wstring(reinterpret_cast<uintptr_t>(file)));
    if (file == nullptr) {
        ret("Error set to: EINVAL, Return value: -1");
        errno = EINVAL;
        return -1;
    }
    const int fd = fileno(file);
    if (fd == -1) {
        ret("Error set to: errno, Return value: -1");
        return -1;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(fd));
    return fd;
}

int UCRTBase::_flushall() {
    trace("_flushall called. Arguments: -");
    if (const int result = fflush(nullptr); result == EOF) {
        ret("Error set to: errno, Return value: EOF");
        return EOF;
    }
    ret("Error set to: -, Return value: 0");
    return 0;
}

int UCRTBase::_fputc_nolock(int c, FILE *file) {
    trace("_fputc_nolock called. Arguments: c=", std::to_wstring(c), ", file=", std::to_wstring(reinterpret_cast<uintptr_t>(file)));
    if (file == nullptr) {
        ret("Error set to: EINVAL, Return value: EOF");
        errno = EINVAL;
        return EOF;
    }
    const int result = fputc(c, file);
    if (result == EOF) {
        ret("Error set to: errno, Return value: EOF");
        return EOF;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

_wint_t UCRTBase::_fputwc_nolock(_wchar_t c, FILE *file) {
    trace("_fputwc_nolock called. Arguments: c=", std::to_wstring(c), ", file=", std::to_wstring(reinterpret_cast<uintptr_t>(file)));
    if (file == nullptr) {
        ret("Error set to: EINVAL, Return value: _WEOF");
        errno = EINVAL;
        return _WEOF;
    }
    const _wint_t result = fputwc(c, file);
    if (result == _WEOF) {
        ret("Error set to: errno, Return value: _WEOF");
        return _WEOF;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

int UCRTBase::_fputchar(int c) {
    trace("_fputchar called. Arguments: c=", std::to_wstring(c));
    const int result = fputc(c, stdout);
    if (result == EOF) {
        ret("Error set to: errno, Return value: EOF");
        return EOF;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

_wint_t UCRTBase::_fputwchar(_wchar_t c) {
    trace("_fputwchar called. Arguments: c=", std::to_wstring(c));
    const _wint_t result = fputwc(c, stdout);
    if (result == _WEOF) {
        ret("Error set to: errno, Return value: _WEOF");
        return _WEOF;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

size_t UCRTBase::_fread_nolock(void *buffer, size_t size, size_t count, FILE *file) {
    trace("_fread_nolock called. Arguments: buffer=", std::to_wstring(reinterpret_cast<uintptr_t>(buffer)), ", size=", std::to_wstring(size), ", count=", std::to_wstring(count), ", file=", std::to_wstring(reinterpret_cast<uintptr_t>(file)));
    if (file == nullptr || buffer == nullptr || size == 0 || count == 0) {
        ret("Error set to: EINVAL, Return value: 0");
        errno = EINVAL;
        return 0;
    }
    const size_t result = fread(buffer, size, count, file);
    if (result < count && ferror(file)) {
        ret("Error set to: errno, Return value: ", std::to_wstring(result));
        return result;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

size_t UCRTBase::_fread_nolock_s(void *buffer, size_t sizeOfBuffer, size_t size, size_t count, FILE *file) {
    trace("_fread_nolock_s called. Arguments: buffer=", std::to_wstring(reinterpret_cast<uintptr_t>(buffer)), ", sizeOfBuffer=", std::to_wstring(sizeOfBuffer), ", size=", std::to_wstring(size), ", count=", std::to_wstring(count), ", file=", std::to_wstring(reinterpret_cast<uintptr_t>(file)));
    if (file == nullptr || buffer == nullptr || size == 0 || count == 0 || size * count > sizeOfBuffer) {
        ret("Error set to: EINVAL, Return value: 0");
        errno = EINVAL;
        return 0;
    }
    const size_t result = fread(buffer, size, count, file);
    if (result < count && ferror(file)) {
        ret("Error set to: errno, Return value: ", std::to_wstring(result));
        return result;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

int UCRTBase::_fseek_nolock(FILE *file, LONG offset, int origin) {
    trace("_fseek_nolock called. Arguments: file=", std::to_wstring(reinterpret_cast<uintptr_t>(file)), ", offset=", std::to_wstring(offset), ", origin=", std::to_wstring(origin));
    if (file == nullptr) {
        ret("Error set to: EINVAL, Return value: -1");
        errno = EINVAL;
        return -1;
    }
    if (const int result = fseek(file, offset, origin); result != 0) {
        ret("Error set to: errno, Return value: -1");
        return -1;
    }
    ret("Error set to: -, Return value: 0");
    return 0;
}

int UCRTBase::_fseeki64(FILE *file, LONGLONG offset, int origin) {
    trace("_fseeki64 called. Arguments: file=", std::to_wstring(reinterpret_cast<uintptr_t>(file)), ", offset=", std::to_wstring(offset), ", origin=", std::to_wstring(origin));
    if (file == nullptr) {
        ret("Error set to: EINVAL, Return value: -1");
        errno = EINVAL;
        return -1;
    }
    if (const int result = fseeko(file, offset, origin); result != 0) {
        ret("Error set to: errno, Return value: -1");
        return -1;
    }
    ret("Error set to: -, Return value: 0");
    return 0;
}

int UCRTBase::_fseeki64_nolock(FILE *file, LONGLONG offset, int origin) {
    trace("_fseeki64_nolock called. Arguments: file=", std::to_wstring(reinterpret_cast<uintptr_t>(file)), ", offset=", std::to_wstring(offset), ", origin=", std::to_wstring(origin));
    if (file == nullptr) {
        ret("Error set to: EINVAL, Return value: -1");
        errno = EINVAL;
        return -1;
    }
    if (const int result = fseeko(file, offset, origin); result != 0) {
        ret("Error set to: errno, Return value: -1");
        return -1;
    }
    ret("Error set to: -, Return value: 0");
    return 0;
}

FILE * UCRTBase::_fsopen(const char *filename, const char *mode, int shflag) {
    trace("_fsopen called. Arguments: filename=", std::wstring(filename, filename + strlen(filename)), ", mode=", std::wstring(mode, mode + strlen(mode)), ", shflag=", std::to_wstring(shflag));
    int flags = 0;
    if (strchr(mode, 'r')) {
        flags |= O_RDONLY;
    }
    if (strchr(mode, 'w')) {
        flags |= O_WRONLY | O_CREAT | O_TRUNC;
    }
    if (strchr(mode, 'a')) {
        flags |= O_WRONLY | O_CREAT | O_APPEND;
    }
    if (strchr(mode, '+')) {
        flags = (flags & ~(O_RDONLY | O_WRONLY)) | O_RDWR;
    }
    const int fd = open(filename, flags, 0666);
    if (fd == -1) {
        ret("Error set to: errno, Return value: nullptr");
        return nullptr;
    }
    FILE* file = fdopen(fd, mode);
    if (file == nullptr) {
        close(fd);
        ret("Error set to: errno, Return value: nullptr");
        return nullptr;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(file)));
    return file;
}

LONG UCRTBase::_ftell_nolock(FILE *file) {
    trace("_ftell_nolock called. Arguments: file=", std::to_wstring(reinterpret_cast<uintptr_t>(file)));
    if (file == nullptr) {
        ret("Error set to: EINVAL, Return value: -1");
        errno = EINVAL;
        return -1;
    }
    const LONG pos = static_cast<LONG>(ftell(file));
    if (pos == -1L) {
        ret("Error set to: errno, Return value: -1");
        return -1;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(pos));
    return pos;
}

LONGLONG UCRTBase::_ftelli64(FILE *file) {
    trace("_ftelli64 called. Arguments: file=", std::to_wstring(reinterpret_cast<uintptr_t>(file)));
    if (file == nullptr) {
        ret("Error set to: EINVAL, Return value: -1");
        errno = EINVAL;
        return -1;
    }
    const off_t pos = ftello(file);
    if (pos == -1) {
        ret("Error set to: errno, Return value: -1");
        return -1;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(pos));
    return pos;
}

LONGLONG UCRTBase::_ftelli64_nolock(FILE *file) {
    trace("_ftelli64_nolock called. Arguments: file=", std::to_wstring(reinterpret_cast<uintptr_t>(file)));
    if (file == nullptr) {
        ret("Error set to: EINVAL, Return value: -1");
        errno = EINVAL;
        return -1;
    }
    const off_t pos = ftello(file);
    if (pos == -1) {
        ret("Error set to: errno, Return value: -1");
        return -1;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(pos));
    return pos;
}

size_t UCRTBase::_fwrite_nolock(const void *buffer, size_t size, size_t count, FILE *file) {
    trace("_fwrite_nolock called. Arguments: buffer=", std::to_wstring(reinterpret_cast<uintptr_t>(buffer)), ", size=", std::to_wstring(size), ", count=", std::to_wstring(count), ", file=", std::to_wstring(reinterpret_cast<uintptr_t>(file)));
    if (file == nullptr || buffer == nullptr || size == 0 || count == 0) {
        ret("Error set to: EINVAL, Return value: 0");
        errno = EINVAL;
        return 0;
    }
    const size_t result = fwrite(buffer, size, count, file);
    if (result < count && ferror(file)) {
        ret("Error set to: errno, Return value: ", std::to_wstring(result));
        return result;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

errno_t UCRTBase::_get_fmode(int *pMode) {
    trace("_get_fmode called. Arguments: pMode=", std::to_wstring(reinterpret_cast<uintptr_t>(pMode)));
    if (pMode == nullptr) {
        ret("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    *pMode = tls.fmode;
    ret("Error set to: -, Return value: 0, *pMode=", std::to_wstring(*pMode));
    return 0;
}

intptr_t UCRTBase::_get_osfhandle(int fd) {
    trace("_get_osfhandle called. Arguments: fd=", std::to_wstring(fd));
    if (fd < 0) {
        ret("Error set to: EBADF, Return value: -1");
        errno = EBADF;
        return -1;
    }
    // On Unix, file descriptors are already OS handles
    ret("Error set to: -, Return value: ", std::to_wstring(fd));
    return fd;
}

int UCRTBase::_get_printf_count_output() {
    trace("_get_printf_count_output called. Arguments: -");
    ret("Error set to: -, Return value: 0");
    // is %n supported? 0 - no, 1 - yes
    return 1;
}

void UCRTBase::_get_stream_buffer_pointers(FILE *file, char ***base, char ***ptr, int **count) {
    trace("_get_stream_buffer_pointers called. Arguments: file=", std::to_wstring(reinterpret_cast<uintptr_t>(file)), ", base=", std::to_wstring(reinterpret_cast<uintptr_t>(base)), ", ptr=", std::to_wstring(reinterpret_cast<uintptr_t>(ptr)), ", count=", std::to_wstring(reinterpret_cast<uintptr_t>(count)));
    if (!file) return;

    // Thread-local counts
    thread_local int read_count;
    thread_local int write_count;

    // if a file only readable, then return the read buffer
    if ((file->_flags & O_RDONLY) && !(file->_flags & O_WRONLY) && !(file->_flags & O_RDWR)) {
        if (base)  *base  = &file->_IO_read_base;
        if (ptr)   *ptr   = &file->_IO_read_ptr;
        if (count) {
            read_count = static_cast<int>(file->_IO_read_end - file->_IO_read_ptr);
            *count = &read_count;
        }
        return;
    }
    // if a file only writable, then return write buffer
    if ((file->_flags & O_WRONLY) && !(file->_flags & O_RDONLY) && !(file->_flags & O_RDWR)) {
        if (base)  *base  = &file->_IO_write_base;
        if (ptr)   *ptr   = &file->_IO_write_ptr;
        if (count) {
            write_count = static_cast<int>(file->_IO_write_ptr - file->_IO_write_base);
            *count = &write_count;
        }
        return;
    }

    // Active read buffer
    if (file->_IO_read_ptr && file->_IO_read_ptr < file->_IO_read_end) {
        if (base)  *base  = &file->_IO_read_base;
        if (ptr)   *ptr   = &file->_IO_read_ptr;
        if (count) {
            read_count = static_cast<int>(file->_IO_read_end - file->_IO_read_ptr);
            *count = &read_count;
        }
        return;
    }

    // Active write buffer
    if (file->_IO_write_ptr && file->_IO_write_ptr > file->_IO_write_base) {
        if (base)  *base  = &file->_IO_write_base;
        if (ptr)   *ptr   = &file->_IO_write_ptr;
        if (count) {
            write_count = static_cast<int>(file->_IO_write_ptr - file->_IO_write_base);
            *count = &write_count;
        }
        return;
    }

    // Empty buffer
    if (base)  *base  = nullptr;
    if (ptr)   *ptr   = nullptr;
    if (count) *count = nullptr;
}

int UCRTBase::_getc_nolock(FILE *file) {
    trace("_getc_nolock called. Arguments: file=", std::to_wstring(reinterpret_cast<uintptr_t>(file)));
    if (file == nullptr) {
        ret("Error set to: EINVAL, Return value: EOF");
        errno = EINVAL;
        return EOF;
    }
    const int result = getc(file);
    if (result == EOF && ferror(file)) {
        ret("Error set to: errno, Return value: EOF");
        return EOF;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

char * UCRTBase::_getcwd(char *buffer, int maxlen) {
    trace("_getcwd called. Arguments: buffer=", std::to_wstring(reinterpret_cast<uintptr_t>(buffer)), ", maxlen=", std::to_wstring(maxlen));
    if (buffer == nullptr || maxlen <= 0) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    if (getcwd(buffer, maxlen) == nullptr) {
        ret("Error set to: errno, Return value: nullptr");
        return nullptr;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(buffer)));
    return buffer;
}

_wchar_t * UCRTBase::_wgetcwd(_wchar_t *buffer, int maxlen) {
    trace("_wgetcwd called. Arguments: buffer=", std::to_wstring(reinterpret_cast<uintptr_t>(buffer)), ", maxlen=", std::to_wstring(maxlen));
    if (buffer == nullptr || maxlen <= 0) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    char temp[260];
    if (getcwd(temp, sizeof(temp)) == nullptr) {
        ret("Error set to: errno, Return value: nullptr");
        return nullptr;
    }
    size_t retval;
    if (mbstowcs_s(&retval, buffer, maxlen, temp, maxlen) != 0 || retval == static_cast<size_t>(-1)) {
        ret("Error set to: EILSEQ, Return value: nullptr");
        errno = EILSEQ;
        return nullptr;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(buffer)));
    return buffer;
}

char * UCRTBase::_getdcwd(int drive, char *buffer, int maxlen) {
    trace("_getdcwd called. Arguments: drive=", std::to_wstring(drive), ", buffer=", std::to_wstring(reinterpret_cast<uintptr_t>(buffer)), ", maxlen=", std::to_wstring(maxlen));
    // getdcwd means full path for the specified drive
    if (buffer == nullptr || maxlen <= 0) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    if (getcwd(buffer, maxlen) == nullptr) {
        ret("Error set to: errno, Return value: nullptr");
        return nullptr;
    }
    // prepend
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(buffer)));
    return buffer;
}

int UCRTBase::_getmaxstdio() {
    trace("_getmaxstdio called. Arguments: -");
    ret("Error set to: -, Return value: 512");
    return 512; // Default maximum number of open files in MSVCRT
}

int UCRTBase::_getw(FILE *file) {
    trace("_getw called. Arguments: file=", std::to_wstring(reinterpret_cast<uintptr_t>(file)));
    if (file == nullptr) {
        ret("Error set to: EINVAL, Return value: _WEOF");
        errno = EINVAL;
        return EOF;
    }
    const int result = getw(file);
    if (result == EOF && ferror(file)) {
        ret("Error set to: errno, Return value: EOF");
        return EOF;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

_wint_t UCRTBase::_getwc_nolock(FILE *file) {
    trace("_getwc_nolock called. Arguments: file=", std::to_wstring(reinterpret_cast<uintptr_t>(file)));
    if (file == nullptr) {
        ret("Error set to: EINVAL, Return value: _WEOF");
        errno = EINVAL;
        return _WEOF;
    }
    const _wint_t result = getwc(file);
    if (result == _WEOF && ferror(file)) {
        ret("Error set to: errno, Return value: _WEOF");
        return _WEOF;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

char * UCRTBase::_gets(char *buffer) {
    trace("_gets called. Arguments: buffer=", std::to_wstring(reinterpret_cast<uintptr_t>(buffer)));
    if (buffer == nullptr) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    if (fgets(buffer, 4096, stdin) == nullptr) { // assuming a max line length of 4096
        if (ferror(stdin)) {
            ret("Error set to: errno, Return value: nullptr");
            return nullptr;
        }
        // EOF reached
        buffer[0] = '\0';
        ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(buffer)));
        return buffer;
    }
    // Remove the newline if present
    buffer[strcspn(buffer, "\n")] = '\0';
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(buffer)));
    return buffer;
}

char * UCRTBase::_gets_s(char *buffer, int size) {
    trace("_gets_s called. Arguments: buffer=", std::to_wstring(reinterpret_cast<uintptr_t>(buffer)), ", size=", std::to_wstring(size));
    if (buffer == nullptr || size <= 0) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    if (fgets(buffer, size, stdin) == nullptr) {
        if (ferror(stdin)) {
            ret("Error set to: errno, Return value: nullptr");
            return nullptr;
        }
        // EOF reached
        buffer[0] = '\0';
        ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(buffer)));
        return buffer;
    }
    // Remove the newline if present
    buffer[strcspn(buffer, "\n")] = '\0';
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(buffer)));
    return buffer;
}

_wchar_t * UCRTBase::_getws(_wchar_t *buffer) {
    trace("_getws called. Arguments: buffer=", std::to_wstring(reinterpret_cast<uintptr_t>(buffer)));
    if (buffer == nullptr) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    char temp[4096];
    if (fgets(temp, sizeof(temp), stdin) == nullptr) { // assuming a max line length of 4096
        if (ferror(stdin)) {
            ret("Error set to: errno, Return value: nullptr");
            return nullptr;
        }
        // EOF reached
        buffer[0] = L'\0';
        ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(buffer)));
        return buffer;
    }
    // Remove the newline if present
    temp[strcspn(temp, "\n")] = '\0';
    mbstowcs_(buffer, temp, 4096);
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(buffer)));
    return buffer;
}

_wchar_t * UCRTBase::_getws_s(_wchar_t *buffer, int size) {
    trace("_getws_s called. Arguments: buffer=", std::to_wstring(reinterpret_cast<uintptr_t>(buffer)), ", size=", std::to_wstring(size));
    if (buffer == nullptr || size <= 0) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    char temp[4096];
    if (fgets(temp, sizeof(temp), stdin) == nullptr) { // assuming a max line length of 4096
        if (ferror(stdin)) {
            ret("Error set to: errno, Return value: nullptr");
            return nullptr;
        }
        // EOF reached
        buffer[0] = L'\0';
        ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(buffer)));
        return buffer;
    }
    // Remove the newline if present
    temp[strcspn(temp, "\n")] = '\0';
    mbstowcs_(buffer, temp, size);
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(buffer)));
    return buffer;
}

int UCRTBase::_isatty(int fd) {
    trace("_isatty called. Arguments: fd=", std::to_wstring(fd));
    if (fd < 0) {
        ret("Error set to: EBADF, Return value: 0");
        errno = EBADF;
        return 0;
    }
    const int result = isatty(fd);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

int UCRTBase::_kbhit() {
    trace("_kbhit called. Arguments: -");
    if (!isatty(fileno(stdin))) {
        ret("Error set to: ENOTTY, Return value: 0");
        errno = ENOTTY;
        return 0;
    }
    // Non-blocking check for input
    fd_set set;
    struct timeval timeout = {0, 0};
    FD_ZERO(&set);
    FD_SET(fileno(stdin), &set);
    const int result = select(fileno(stdin) + 1, &set, nullptr, nullptr, &timeout);
    if (result == -1) {
        ret("Error set to: errno, Return value: 0");
        return 0;
    }
    ret("Error set to: ", std::to_wstring(errno), ", Return value: ", std::to_wstring(result > 0 ? 1 : 0));
    return result > 0 ? 1 : 0;
}

int UCRTBase::_locking(int fd, int mode, long nbytes) {
    trace("_locking called. Arguments: fd=", std::to_wstring(fd), ", mode=", std::to_wstring(mode), ", nbytes=", std::to_wstring(nbytes));
    if (fd < 0 || nbytes < 0) {
        ret("Error set to: EINVAL, Return value: -1");
        errno = EINVAL;
        return -1;
    }
    flock fl{};
    fl.l_type = mode & _LK_LOCK ? F_WRLCK : mode & _LK_RLCK ? F_RDLCK : F_UNLCK;
    fl.l_whence = SEEK_CUR;
    fl.l_start = 0;
    fl.l_len = nbytes;
    if (fcntl(fd, F_SETLK, &fl) == -1) {
        ret("Error set to: errno, Return value: -1");
        return -1;
    }
    ret("Error set to: -, Return value: 0");
    return 0;
}

LONG UCRTBase::_lseek(int fd, LONG offset, int origin) {
    trace("_lseek called. Arguments: fd=", std::to_wstring(fd), ", offset=", std::to_wstring(offset), ", origin=", std::to_wstring(origin));
    if (fd < 0) {
        ret("Error set to: EBADF, Return value: -1");
        errno = EBADF;
        return -1;
    }
    const off_t result = lseek(fd, offset, origin);
    if (result == -1) {
        ret("Error set to: errno, Return value: -1");
        return -1;
    }
    if (result > LONG_MAX) {
        ret("Error set to: EOVERFLOW, Return value: -1");
        errno = EOVERFLOW;
        return -1;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(static_cast<LONG>(result)));
    return static_cast<LONG>(result);
}

off_t UCRTBase::_lseeki64(int fd, off_t offset, int origin) {
    trace("_lseeki64 called. Arguments: fd=", std::to_wstring(fd), ", offset=", std::to_wstring(offset), ", origin=", std::to_wstring(origin));
    if (fd < 0) {
        ret("Error set to: EBADF, Return value: -1");
        errno = EBADF;
        return -1;
    }
    const off_t result = lseek(fd, offset, origin);
    if (result == -1) {
        ret("Error set to: errno, Return value: -1");
        return -1;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

char * UCRTBase::_mktemp(char *templateStr) {
    trace("_mktemp called. Arguments: templateStr=", std::to_wstring(reinterpret_cast<uintptr_t>(templateStr)));
    if (templateStr == nullptr) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    // Ensure template ends with "XXXXXX"
    if (const size_t len = strlen(templateStr); len < 6 || strcmp(&templateStr[len - 6], "XXXXXX") != 0) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    if (mktemp(templateStr) == nullptr) {
        ret("Error set to: errno, Return value: nullptr");
        return nullptr;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(templateStr)));
    return templateStr;
}

_wchar_t * UCRTBase::_wmktemp(_wchar_t *templateStr) {
    trace("_wmktemp called. Arguments: templateStr=", std::to_wstring(reinterpret_cast<uintptr_t>(templateStr)));
    if (templateStr == nullptr) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    // Ensure template ends with "XXXXXX"
    const size_t len = wcslen_(templateStr);
    constexpr _wchar_t suffix[] = { 'X', 'X', 'X', 'X', 'X', 'X', '\0' };
    if (len < 6 || wcscmp_(&templateStr[len - 6], suffix) != 0) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    char temp[260];
    wcstombs_(temp, templateStr, sizeof(temp));
    if (mktemp(temp) == nullptr) {
        ret("Error set to: errno, Return value: nullptr");
        return nullptr;
    }
    mbstowcs_(templateStr, temp, len + 1);
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(templateStr)));
    return templateStr;
}

errno_t UCRTBase::_mktemp_s(char *templateStr, size_t size) {
    trace("_mktemp_s called. Arguments: templateStr=", std::to_wstring(reinterpret_cast<uintptr_t>(templateStr)), ", size=", std::to_wstring(size));
    if (templateStr == nullptr || size < 7) { // at least "X\0"
        ret("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    // Ensure template ends with "XXXXXX"
    const size_t len = strnlen(templateStr, size);
    if (len < 6 || strcmp(&templateStr[len - 6], "XXXXXX") != 0) {
        ret("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    if (mktemp(templateStr) == nullptr) {
        ret("Error set to: errno, Return value: errno");
        return errno;
    }
    ret("Error set to: -, Return value: 0");
    return 0;
}

errno_t UCRTBase::_wmktemp_s(_wchar_t *templateStr, size_t size) {
    trace("_wmktemp_s called. Arguments: templateStr=", std::to_wstring(reinterpret_cast<uintptr_t>(templateStr)), ", size=", std::to_wstring(size));
    if (templateStr == nullptr || size < 7) { // at least "X\0"
        ret("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    // Ensure template ends with "XXXXXX"
    const size_t len = wcsnlen_(templateStr, size);
    constexpr _wchar_t suffix[] = { 'X', 'X', 'X', 'X', 'X', 'X', '\0' };
    if (len < 6 || wcscmp_(&templateStr[len - 6], suffix) != 0) {
        ret("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    char temp[260];
    wcstombs_(temp, templateStr, sizeof(temp));
    if (mktemp(temp) == nullptr) {
        ret("Error set to: errno, Return value: errno");
        return errno;
    }
    mbstowcs_(templateStr, temp, size);
    ret("Error set to: -, Return value: 0");
    return 0;
}

int UCRTBase::_open(const char *filename, int oflag, int pmode) {
    trace("_open called. Arguments: filename=", std::wstring(filename, filename + strlen(filename)), ", oflag=", std::to_wstring(oflag), ", pmode=", std::to_wstring(pmode));
    int flags = 0;
    if (oflag & _O_RDONLY) flags |= O_RDONLY;
    if (oflag & _O_WRONLY) flags |= O_WRONLY;
    if (oflag & _O_RDWR)   flags |= O_RDWR;
    if (oflag & _O_APPEND) flags |= O_APPEND;
    if (oflag & _O_CREAT)  flags |= O_CREAT;
    if (oflag & _O_TRUNC)  flags |= O_TRUNC;
    if (oflag & _O_EXCL)   flags |= O_EXCL;
    if (oflag & _O_BINARY) {} // no effect on Unix
    if (oflag & _O_TEXT) {} // no effect on Unix
    const int fd = open(filename, flags, pmode);
    if (fd == -1) {
        ret("Error set to: errno, Return value: -1");
        return -1;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(fd));
    return fd;
}

int UCRTBase::_wopen(const _wchar_t *filename, int oflag, int pmode) {
    trace("_wopen called. Arguments: filename=", std::wstring(filename, filename + wcslen_(filename)), ", oflag=", std::to_wstring(oflag), ", pmode=", std::to_wstring(pmode));
    if (filename == nullptr) {
        ret("Error set to: EINVAL, Return value: -1");
        errno = EINVAL;
        return -1;
    }
    char fname[1024];
    wcstombs_(fname, filename, sizeof(fname));
    int flags = 0;
    if (oflag & _O_RDONLY) flags |= O_RDONLY;
    if (oflag & _O_WRONLY) flags |= O_WRONLY;
    if (oflag & _O_RDWR)   flags |= O_RDWR;
    if (oflag & _O_APPEND) flags |= O_APPEND;
    if (oflag & _O_CREAT)  flags |= O_CREAT;
    if (oflag & _O_TRUNC)  flags |= O_TRUNC;
    if (oflag & _O_EXCL)   flags |= O_EXCL;
    if (oflag & _O_BINARY) {} // no effect on Unix
    if (oflag & _O_TEXT) {} // no effect on Unix
    const int fd = open(fname, flags, pmode);
    if (fd == -1) {
        ret("Error set to: errno, Return value: -1");
        return -1;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(fd));
    return fd;
}

int UCRTBase::_open_osfhandle(intptr_t osfhandle, int flags) {
    trace("_open_osfhandle called. Arguments: osfhandle=", std::to_wstring(osfhandle), ", flags=", std::to_wstring(flags));
    if (osfhandle < 0) {
        ret("Error set to: EINVAL, Return value: -1");
        errno = EINVAL;
        return -1;
    }
    // On Unix, file descriptors are already OS handles
    ret("Error set to: -, Return value: ", std::to_wstring(static_cast<int>(osfhandle)));
    return static_cast<int>(osfhandle);
}

int UCRTBase::_pclose(FILE *stream) {
    trace("_pclose called. Arguments: stream=", std::to_wstring(reinterpret_cast<uintptr_t>(stream)));
    if (stream == nullptr) {
        ret("Error set to: EINVAL, Return value: -1");
        errno = EINVAL;
        return -1;
    }
    const int result = pclose(stream);
    if (result == -1) {
        ret("Error set to: errno, Return value: -1");
        return -1;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

int UCRTBase::_pipe(int *pfds, unsigned int size, int textmode) {
    trace("_pipe called. Arguments: pfds=", std::to_wstring(reinterpret_cast<uintptr_t>(pfds)), ", size=", std::to_wstring(size), ", textmode=", std::to_wstring(textmode));
    if (pfds == nullptr || size < 2) {
        ret("Error set to: EINVAL, Return value: -1");
        errno = EINVAL;
        return -1;
    }
    if (pipe(pfds) == -1) {
        ret("Error set to: errno, Return value: -1");
        return -1;
    }
    ret("Error set to: -, Return value: 0, pfds[0]=", std::to_wstring(pfds[0]), ", pfds[1]=", std::to_wstring(pfds[1]));
    return 0;
}

int UCRTBase::_popen(const char *command, const char *mode) {
    trace("_popen diserror-stub called. Arguments: command=", std::wstring(command, command + strlen(command)), ", mode=", std::wstring(mode, mode + strlen(mode)));
    if (command == nullptr || mode == nullptr) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return -1;
    }
    // return early; we cannot currently execute any command
    return -1;
    /*FILE* stream = popen(command, mode);
        if (stream == nullptr) {
            ret("Error set to: errno, Return value: nullptr");
            return -1;
        }
        const int fd = fileno(stream);
        if (fd == -1) {
            pclose(stream);
            ret("Error set to: errno, Return value: -1");
            return -1;
        }
        ret("Error set to: -, Return value: ", std::to_wstring(fd));
        return fd;*/
}

int UCRTBase::_wpopen(const _wchar_t *command, const _wchar_t *mode) {
    trace("_wpopen diserror-stub called. Arguments: command=", std::wstring(command, command + wcslen_(command)), ", mode=", std::wstring(mode, mode + wcslen_(mode)));
    if (command == nullptr || mode == nullptr) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return -1;
    }
    // return early; we cannot currently execute any command
    return -1;
    /*char cmd[1024];
        char md[4];
        wcstombs(cmd, command, sizeof(cmd));
        wcstombs(md, mode, sizeof(md));
        FILE* stream = popen(cmd, md);
        if (stream == nullptr) {
            ret("Error set to: errno, Return value: nullptr");
            return -1;
        }
        const int fd = fileno(stream);
        if (fd == -1) {
            pclose(stream);
            ret("Error set to: errno, Return value: -1");
            return -1;
        }
        ret("Error set to: -, Return value: ", std::to_wstring(fd));
        return fd;*/
}

int UCRTBase::_putc_nolock(int ch, FILE *file) {
    trace("_putc_nolock called. Arguments: ch=", std::to_wstring(ch), ", file=", std::to_wstring(reinterpret_cast<uintptr_t>(file)));
    if (file == nullptr) {
        ret("Error set to: EINVAL, Return value: EOF");
        errno = EINVAL;
        return EOF;
    }
    const int result = putc(ch, file);
    if (result == EOF && ferror(file)) {
        ret("Error set to: errno, Return value: EOF");
        return EOF;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

int UCRTBase::_putwc_nolock(_wint_t ch, FILE *file) {
    trace("_putwc_nolock called. Arguments: ch=", std::to_wstring(ch), ", file=", std::to_wstring(reinterpret_cast<uintptr_t>(file)));
    if (file == nullptr) {
        ret("Error set to: EINVAL, Return value: _WEOF");
        errno = EINVAL;
        return _WEOF;
    }
    const _wint_t result = putwc(ch, file);
    if (result == _WEOF && ferror(file)) {
        ret("Error set to: errno, Return value: _WEOF");
        return _WEOF;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

int UCRTBase::_putw(int w, FILE *file) {
    trace("_putw called. Arguments: w=", std::to_wstring(w), ", file=", std::to_wstring(reinterpret_cast<uintptr_t>(file)));
    if (file == nullptr) {
        ret("Error set to: EINVAL, Return value: EOF");
        errno = EINVAL;
        return EOF;
    }
    const int result = putw(w, file);
    if (result == EOF && ferror(file)) {
        ret("Error set to: errno, Return value: EOF");
        return EOF;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

int UCRTBase::_putws(const _wchar_t *str) {
    trace("_putws called. Arguments: str=", std::to_wstring(reinterpret_cast<uintptr_t>(str)));
    if (str == nullptr) {
        ret("Error set to: EINVAL, Return value: -1");
        errno = EINVAL;
        return -1;
    }
    if (fputws_(str, stdout) == _WEOF) {
        ret("Error set to: errno, Return value: -1");
        return -1;
    }
    if (fputwc_(L'\n', stdout) == _WEOF) {
        ret("Error set to: errno, Return value: -1");
        return -1;
    }
    ret("Error set to: -, Return value: 0");
    return 0;
}

int UCRTBase::_read(const int fd, void * const buffer, const unsigned int count) {
    trace("_read called. Arguments: fd=", std::to_wstring(fd), ", buffer=", std::to_wstring(reinterpret_cast<uintptr_t>(buffer)), ", count=", std::to_wstring(count));
    if (fd < 0 || buffer == nullptr || count == 0) {
        ret("Error set to: EINVAL, Return value: -1");
        errno = EINVAL;
        return -1;
    }
    const ssize_t result = read(fd, buffer, count);
    if (result == -1) {
        ret("Error set to: errno, Return value: -1");
        return -1;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return static_cast<int>(result);
}

int UCRTBase::_rmtmp() {
    trace("_rmtmp called. Arguments: -");
    // idk
    ret("Error set to: -, Return value: 0");
    return 0;
}

errno_t UCRTBase::set_fmode(int mode) {
    trace("set_fmode called. Arguments: mode=", std::to_wstring(mode));
    if (mode != _O_TEXT && mode != _O_BINARY) {
        ret("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    tls.fmode = mode;
    ret("Error set to: -, Return value: 0, fmode=", std::to_wstring(tls.fmode));
    return 0;
}

int UCRTBase::_set_printf_count_output(const int value) {
    trace("_set_printf_count_output called. Arguments: value=", std::to_wstring(value));
    // is %n supported? 0 - no, 1 - yes
    if (value != 0 && value != 1) {
        ret("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    // we always support it
    ret("Error set to: -, Return value: 0");
    return 0;
}

int UCRTBase::_setmaxstdio(int max) {
    trace("_setmaxstdio called. Arguments: max=", std::to_wstring(max));
    if (max < 20 || max > 2048) {
        ret("Error set to: EINVAL, Return value: -1");
        errno = EINVAL;
        return -1;
    }
    // we don't actually limit the number of open files
    ret("Error set to: -, Return value: ", std::to_wstring(max));
    return max;
}

int UCRTBase::_sopen(const char *filename, int oflag, int shflag, int pmode) {
    trace("_sopen called. Arguments: filename=", std::wstring(filename, filename + strlen(filename)), ", oflag=", std::to_wstring(oflag), ", shflag=", std::to_wstring(shflag), ", pmode=", std::to_wstring(pmode));
    int flags = 0;
    if (oflag & _O_RDONLY) flags |= O_RDONLY;
    if (oflag & _O_WRONLY) flags |= O_WRONLY;
    if (oflag & _O_RDWR)   flags |= O_RDWR;
    if (oflag & _O_APPEND) flags |= O_APPEND;
    if (oflag & _O_CREAT)  flags |= O_CREAT;
    if (oflag & _O_TRUNC)  flags |= O_TRUNC;
    if (oflag & _O_EXCL)   flags |= O_EXCL;
    if (oflag & _O_BINARY) {} // no effect on Unix
    if (oflag & _O_TEXT) {} // no effect on Unix
    // shflag is ignored on Unix
    const int fd = open(filename, flags, pmode);
    if (fd == -1) {
        ret("Error set to: errno, Return value: -1");
        return -1;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(fd));
    return fd;
}

int UCRTBase::_wsopen(const _wchar_t *filename, int oflag, int pmode) {
    trace("_wsopen called. Arguments: filename=", std::wstring(filename, filename + wcslen_(filename)), ", oflag=", std::to_wstring(oflag), ", pmode=", std::to_wstring(pmode));
    if (filename == nullptr) {
        ret("Error set to: EINVAL, Return value: -1");
        errno = EINVAL;
        return -1;
    }
    char fname[1024];
    wcstombs_(fname, filename, sizeof(fname));
    int flags = 0;
    if (oflag & _O_RDONLY) flags |= O_RDONLY;
    if (oflag & _O_WRONLY) flags |= O_WRONLY;
    if (oflag & _O_RDWR)   flags |= O_RDWR;
    if (oflag & _O_APPEND) flags |= O_APPEND;
    if (oflag & _O_CREAT)  flags |= O_CREAT;
    if (oflag & _O_TRUNC)  flags |= O_TRUNC;
    if (oflag & _O_EXCL)   flags |= O_EXCL;
    if (oflag & _O_BINARY) {} // no effect on Unix
    if (oflag & _O_TEXT) {} // no effect on Unix
    const int fd = open(fname, flags, pmode);
    if (fd == -1) {
        ret("Error set to: errno, Return value: -1");
        return -1;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(fd));
    return fd;
}

int UCRTBase::_sopen_dispatch(const char *filename, int oflag, int shflag, int pmode) {
    return _sopen(filename, oflag, shflag, pmode);
}

int UCRTBase::_wsopen_dispatch(const _wchar_t *filename, int oflag, int pmode) {
    return _wsopen(filename, oflag, pmode);
}

errno_t UCRTBase::_sopen_s(int *pfd, const char *filename, int oflag, int shflag, int pmode) {
    trace("_sopen_s called. Arguments: pfd=", std::to_wstring(reinterpret_cast<uintptr_t>(pfd)), ", filename=", std::wstring(filename, filename + strlen(filename)), ", oflag=", std::to_wstring(oflag), ", shflag=", std::to_wstring(shflag), ", pmode=", std::to_wstring(pmode));
    if (pfd == nullptr || filename == nullptr) {
        ret("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    int flags = 0;
    if (oflag & _O_RDONLY) flags |= O_RDONLY;
    if (oflag & _O_WRONLY) flags |= O_WRONLY;
    if (oflag & _O_RDWR)   flags |= O_RDWR;
    if (oflag & _O_APPEND) flags |= O_APPEND;
    if (oflag & _O_CREAT)  flags |= O_CREAT;
    if (oflag & _O_TRUNC)  flags |= O_TRUNC;
    if (oflag & _O_EXCL)   flags |= O_EXCL;
    if (oflag & _O_BINARY) {} // no effect on Unix
    if (oflag & _O_TEXT) {} // no effect on Unix
    // shflag is ignored on Unix
    const int fd = open(filename, flags, pmode);
    if (fd == -1) {
        ret("Error set to: errno, Return value: errno");
        return errno;
    }
    *pfd = fd;
    ret("Error set to: -, Return value: 0, *pfd=", std::to_wstring(*pfd));
    return 0;
}

errno_t UCRTBase::_wsopen_s(int *pfd, const _wchar_t *filename, int oflag, int pmode) {
    trace("_wsopen_s called. Arguments: pfd=", std::to_wstring(reinterpret_cast<uintptr_t>(pfd)), ", filename=", std::wstring(filename, filename + wcslen_(filename)), ", oflag=", std::to_wstring(oflag), ", pmode=", std::to_wstring(pmode));
    if (pfd == nullptr || filename == nullptr) {
        ret("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    char fname[1024];
    wcstombs_(fname, filename, sizeof(fname));
    int flags = 0;
    if (oflag & _O_RDONLY) flags |= O_RDONLY;
    if (oflag & _O_WRONLY) flags |= O_WRONLY;
    if (oflag & _O_RDWR)   flags |= O_RDWR;
    if (oflag & _O_APPEND) flags |= O_APPEND;
    if (oflag & _O_CREAT)  flags |= O_CREAT;
    if (oflag & _O_TRUNC)  flags |= O_TRUNC;
    if (oflag & _O_EXCL)   flags |= O_EXCL;
    if (oflag & _O_BINARY) {} // no effect on Unix
    if (oflag & _O_TEXT) {} // no effect on Unix
    const int fd = open(fname, flags, pmode);
    if (fd == -1) {
        ret("Error set to: errno, Return value: errno");
        return errno;
    }
    *pfd = fd;
    ret("Error set to: -, Return value: 0, *pfd=", std::to_wstring(*pfd));
    return 0;
}

LONG UCRTBase::_tell(int fd) {
    trace("_tell called. Arguments: fd=", std::to_wstring(fd));
    if (fd < 0) {
        ret("Error set to: EBADF, Return value: -1");
        errno = EBADF;
        return -1;
    }
    const off_t result = lseek(fd, 0, SEEK_CUR);
    if (result == -1) {
        ret("Error set to: errno, Return value: -1");
        return -1;
    }
    if (result > LONG_MAX) {
        ret("Error set to: EOVERFLOW, Return value: -1");
        errno = EOVERFLOW;
        return -1;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(static_cast<LONG>(result)));
    return static_cast<LONG>(result);
}

off_t UCRTBase::_telli64(int fd) {
    trace("_telli64 called. Arguments: fd=", std::to_wstring(fd));
    if (fd < 0) {
        ret("Error set to: EBADF, Return value: -1");
        errno = EBADF;
        return -1;
    }
    const off_t result = lseek(fd, 0, SEEK_CUR);
    if (result == -1) {
        ret("Error set to: errno, Return value: -1");
        return -1;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

char * UCRTBase::_tempnam(const char *dir, const char *pfx) {
    trace("_tempnam called. Arguments: dir=", std::wstring(dir ? dir : "(null)", dir ? dir + strlen(dir) : "(null)"), ", pfx=", std::wstring(pfx ? pfx : "(null)", pfx ? pfx + strlen(pfx) : "(null)"));
    const char* tmpdir = dir;
    if (tmpdir == nullptr || strlen(tmpdir) == 0) {
        tmpdir = getenv("TMPDIR");
        if (tmpdir == nullptr || strlen(tmpdir) == 0) {
            tmpdir = "/tmp";
        }
    }
    char templateStr[1024];
    if (pfx != nullptr && strlen(pfx) > 0) {
        snprintf(templateStr, sizeof(templateStr), "%s/%sXXXXXX", tmpdir, pfx);
    } else {
        snprintf(templateStr, sizeof(templateStr), "%s/tmpXXXXXX", tmpdir);
    }
    if (strlen(templateStr) >= sizeof(templateStr)) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    char* result = strdup(templateStr);
    if (result == nullptr) {
        ret("Error set to: errno, Return value: nullptr");
        return nullptr;
    }
    if (mktemp(result) == nullptr) {
        free(result);
        ret("Error set to: errno, Return value: nullptr");
        return nullptr;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(result)));
    return result;
}

_wchar_t * UCRTBase::_wtempnam(const _wchar_t *dir, const _wchar_t *pfx) {
    constexpr _wchar_t dir_default[] = { '(' , 'n', 'u', 'l', 'l', ')', '\0' };
    trace("_wtempnam called. Arguments: dir=", std::wstring(dir ? dir : dir_default, dir ? dir + wcslen_(dir) : dir_default), ", pfx=", std::wstring(pfx ? pfx : dir_default, pfx ? pfx + wcslen_(pfx) : dir_default));
    const _wchar_t* tmpdir = dir;
    thread_local char envbuf[260];
    thread_local _wchar_t wenvbuf[260];
    if (tmpdir == nullptr || wcslen_(tmpdir) == 0) {
        if (const char* env = getenv("TMPDIR"); env != nullptr && strlen(env) > 0) {
            strncpy(envbuf, env, sizeof(envbuf));
            envbuf[sizeof(envbuf)-1] = '\0';
            mbstowcs_(wenvbuf, envbuf, sizeof(wenvbuf)/sizeof(_wchar_t));
            tmpdir = wenvbuf;
        } else {
            constexpr _wchar_t tmpdir_default[] = { '/', 't', 'm', 'p', '\0' };
            wcscpy_(wenvbuf, tmpdir_default);
        }
    }
    _wchar_t templateStr[1024];
    if (pfx != nullptr && wcslen_(pfx) > 0) {
        constexpr _wchar_t fmt[] = { '%', 's', '/', '%', 's', 'X', 'X', 'X', 'X', 'X', 'X', '\0' };
        swprintf_(templateStr, sizeof(templateStr)/sizeof(_wchar_t), fmt, tmpdir, pfx);
    } else {
        constexpr _wchar_t fmt[] = { '%', 's', '/', 't', 'm', 'p', 'X', 'X', 'X', 'X', 'X', 'X', '\0' };
        swprintf_(templateStr, sizeof(templateStr)/sizeof(_wchar_t), fmt, tmpdir);
    }
    if (wcslen_(templateStr) >= sizeof(templateStr)/sizeof(_wchar_t)) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    auto result = static_cast<_wchar_t *>(malloc((wcslen_(templateStr) + 1) * sizeof(_wchar_t)));
    if (result == nullptr) {
        ret("Error set to: errno, Return value: nullptr");
        return nullptr;
    }
    wcscpy_(result, templateStr);
    char temp[1024];
    wcstombs_(temp, result, sizeof(temp));
    if (mktemp(temp) == nullptr) {
        free(result);
        ret("Error set to: errno, Return value: nullptr");
        return nullptr;
    }
    mbstowcs_(result, temp, wcslen_(result)+1);
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(result)));
    return result;
}

int UCRTBase::_ungetc_nolock(int ch, FILE *file) {
    trace("_ungetc_nolock called. Arguments: ch=", std::to_wstring(ch), ", file=", std::to_wstring(reinterpret_cast<uintptr_t>(file)));
    if (file == nullptr) {
        ret("Error set to: EINVAL, Return value: EOF");
        errno = EINVAL;
        return EOF;
    }
    const int result = ungetc(ch, file);
    if (result == EOF && ferror(file)) {
        ret("Error set to: errno, Return value: EOF");
        return EOF;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

_wint_t UCRTBase::_ungetwc_nolock(_wint_t ch, FILE *file) {
    trace("_ungetwc_nolock called. Arguments: ch=", std::to_wstring(ch), ", file=", std::to_wstring(reinterpret_cast<uintptr_t>(file)));
    if (file == nullptr) {
        ret("Error set to: EINVAL, Return value: _WEOF");
        errno = EINVAL;
        return _WEOF;
    }
    const _wint_t result = ungetwc(ch, file);
    if (result == _WEOF && ferror(file)) {
        ret("Error set to: errno, Return value: _WEOF");
        return _WEOF;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

FILE * UCRTBase::_fdopen(int fd, const char *mode) {
    trace("_fdopen called. Arguments: fd=", std::to_wstring(fd), ", mode=", std::wstring(mode, mode + strlen(mode)));
    if (fd < 0 || mode == nullptr) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    FILE* file = fdopen(fd, mode);
    if (file == nullptr) {
        ret("Error set to: errno, Return value: nullptr");
        return nullptr;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(file)));
    return file;
}

FILE * UCRTBase::_wfdopen(int fd, const _wchar_t *mode) {
    constexpr _wchar_t mode_default[] = { '(', 'n', 'u', 'l', 'l', ')', '\0' };
    trace("_wfdopen called. Arguments: fd=", std::to_wstring(fd), ", mode=", std::wstring(mode ? mode : mode_default, mode ? mode + wcslen_(mode) : mode_default));
    if (fd < 0 || mode == nullptr) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    char m[16];
    wcstombs_(m, mode, sizeof(m));
    FILE* file = fdopen(fd, m);
    if (file == nullptr) {
        ret("Error set to: errno, Return value: nullptr");
        return nullptr;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(file)));
    return file;
}

FILE * UCRTBase::_wfopen(const _wchar_t *filename, const _wchar_t *mode) {
    constexpr _wchar_t mode_default[] = { '(', 'n', 'u', 'l', 'l', ')', '\0' };
    trace("_wfopen called. Arguments: filename=", std::wstring(filename ? filename : mode_default, filename ? filename + wcslen_(filename) : mode_default), ", mode=", std::wstring(mode ? mode : mode_default , mode ? mode + wcslen_(mode) : mode_default));
    if (filename == nullptr || mode == nullptr) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    char fname[1024];
    char m[16];
    wcstombs_(fname, filename, sizeof(fname));
    wcstombs_(m, mode, sizeof(m));
    FILE* file = fopen(fname, m);
    if (file == nullptr) {
        ret("Error set to: errno, Return value: nullptr");
        return nullptr;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(file)));
    return file;
}

errno_t UCRTBase::_wfopen_s(FILE **pFile, const _wchar_t *filename, const _wchar_t *mode) {
    constexpr _wchar_t mode_default[] = { '(', 'n', 'u', 'l', 'l', ')', '\0' };
    trace("_wfopen_s called. Arguments: pFile=", std::to_wstring(reinterpret_cast<uintptr_t>(pFile)), ", filename=", std::wstring(filename ? filename : mode_default, filename ? filename + wcslen_(filename) : mode_default), ", mode=", std::wstring(mode ? mode : mode_default, mode ? mode + wcslen_(mode) : mode_default));
    if (pFile == nullptr || filename == nullptr || mode == nullptr) {
        ret("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    char fname[1024];
    char m[16];
    wcstombs_(fname, filename, sizeof(fname));
    wcstombs_(m, mode, sizeof(m));
    FILE* file = fopen(fname, m);
    if (file == nullptr) {
        ret("Error set to: errno, Return value: errno");
        return errno;
    }
    *pFile = file;
    ret("Error set to: -, Return value: 0, *pFile=", std::to_wstring(reinterpret_cast<uintptr_t>(*pFile)));
    return 0;
}

FILE * UCRTBase::_wfreopen(const _wchar_t *filename, const _wchar_t *mode, FILE *file) {
    constexpr _wchar_t mode_default[] = { '(', 'n', 'u', 'l', 'l', ')', '\0' };
    trace("_wfreopen called. Arguments: filename=", std::wstring(filename ? filename : mode_default, filename ? filename + wcslen_(filename) : mode_default), ", mode=", std::wstring(mode ? mode : mode_default, mode ? mode + wcslen_(mode) : mode_default), ", file=", std::to_wstring(reinterpret_cast<uintptr_t>(file)));
    if (filename == nullptr || mode == nullptr || file == nullptr) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    char fname[1024];
    char m[16];
    wcstombs_(fname, filename, sizeof(fname));
    wcstombs_(m, mode, sizeof(m));
    FILE* newFile = freopen(fname, m, file);
    if (newFile == nullptr) {
        ret("Error set to: errno, Return value: nullptr");
        return nullptr;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(newFile)));
    return newFile;
}

errno_t UCRTBase::_wfreopen_s(FILE **pFile, const _wchar_t *filename, const _wchar_t *mode, FILE *file) {
    constexpr _wchar_t mode_default[] = { '(', 'n', 'u', 'l', 'l', ')', '\0' };
    trace("_wfreopen_s called. Arguments: pFile=", std::to_wstring(reinterpret_cast<uintptr_t>(pFile)), ", filename=", std::wstring(filename ? filename : mode_default, filename ? filename + wcslen_(filename) : mode_default), ", mode=", std::wstring(mode ? mode : mode_default, mode ? mode + wcslen_(mode) : mode_default), ", file=", std::to_wstring(reinterpret_cast<uintptr_t>(file)));
    if (pFile == nullptr || filename == nullptr || mode == nullptr || file == nullptr) {
        ret("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    char fname[1024];
    char m[16];
    wcstombs_(fname, filename, sizeof(fname));
    wcstombs_(m, mode, sizeof(m));
    FILE* newFile = freopen(fname, m, file);
    if (newFile == nullptr) {
        ret("Error set to: errno, Return value: errno");
        return errno;
    }
    *pFile = newFile;
    ret("Error set to: -, Return value: 0, *pFile=", std::to_wstring(reinterpret_cast<uintptr_t>(*pFile)));
    return 0;
}

int UCRTBase::_write(const int fd, const void * const buffer, const unsigned int count) {
    trace("_write called. Arguments: fd=", std::to_wstring(fd), ", buffer=", std::to_wstring(reinterpret_cast<uintptr_t>(buffer)), ", count=", std::to_wstring(count));
    if (fd < 0 || buffer == nullptr || count == 0) {
        ret("Error set to: EINVAL, Return value: -1");
        errno = EINVAL;
        return -1;
    }
    const ssize_t result = write(fd, buffer, count);
    if (result == -1) {
        ret("Error set to: errno, Return value: -1");
        return -1;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return static_cast<int>(result);
}

char * UCRTBase::_tmpnam(char *str) {
    trace("_tmpnam called. Arguments: str=", std::to_wstring(reinterpret_cast<uintptr_t>(str)));

    static thread_local char temp[L_tmpnam];
    if (tmpnam(temp) == nullptr) {
        ret("Error set to: errno, Return value: nullptr");
        return nullptr;
    }

    if (str == nullptr) {
        return temp;
    } else {
        strncpy(str, temp, L_tmpnam);
        ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(str)));
        return str;
    }
}

_wchar_t * UCRTBase::_wtmpnam(_wchar_t *str) {
    trace("_wtmpnam called. Arguments: str=", std::to_wstring(reinterpret_cast<uintptr_t>(str)));

    static thread_local _wchar_t temp[L_tmpnam];
    char tempc[L_tmpnam];
    if (tmpnam(tempc) == nullptr) {
        ret("Error set to: errno, Return value: nullptr");
        return nullptr;
    }
    mbstowcs_(temp, tempc, L_tmpnam);

    if (str == nullptr) {
        return temp;
    } else {
        wcsncpy_(str, temp, L_tmpnam);
        ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(str)));
        return str;
    }
}

void UCRTBase::clearerr_(FILE *file) {
    trace("clearerr_ called. Arguments: file=", std::to_wstring(reinterpret_cast<uintptr_t>(file)));
    if (file == nullptr) {
        ret("Error set to: EINVAL");
        errno = EINVAL;
        return;
    }
    clearerr(file);
    ret("Error set to: -");
}

errno_t UCRTBase::clearerr_s(FILE *file) {
    trace("clearerr_s called. Arguments: file=", std::to_wstring(reinterpret_cast<uintptr_t>(file)));
    if (file == nullptr) {
        ret("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    clearerr(file);
    ret("Error set to: -, Return value: 0");
    return 0;
}

int UCRTBase::fclose_(FILE *file) {
    trace("fclose_ called. Arguments: file=", std::to_wstring(reinterpret_cast<uintptr_t>(file)));
    if (file == nullptr) {
        ret("Error set to: EINVAL, Return value: EOF");
        errno = EINVAL;
        return EOF;
    }
    const int result = fclose(file);
    if (result == EOF) {
        ret("Error set to: errno, Return value: EOF");
        return EOF;
    }
    ret("Error set to: -, Return value: 0");
    return 0;
}

int UCRTBase::feof_(FILE *file) {
    trace("feof_ called. Arguments: file=", std::to_wstring(reinterpret_cast<uintptr_t>(file)));
    if (file == nullptr) {
        ret("Error set to: EINVAL, Return value: -1");
        errno = EINVAL;
        return -1;
    }
    const int result = feof(file);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

int UCRTBase::ferror_(FILE *file) {
    trace("ferror_ called. Arguments: file=", std::to_wstring(reinterpret_cast<uintptr_t>(file)));
    if (file == nullptr) {
        ret("Error set to: EINVAL, Return value: -1");
        errno = EINVAL;
        return -1;
    }
    const int result = ferror(file);
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

int UCRTBase::fflush_(FILE *file) {
    trace("fflush_ called. Arguments: file=", std::to_wstring(reinterpret_cast<uintptr_t>(file)));
    if (file == nullptr) {
        ret("Error set to: EINVAL, Return value: EOF");
        errno = EINVAL;
        return EOF;
    }
    if (const int result = fflush(file); result == EOF) {
        ret("Error set to: errno, Return value: EOF");
        return EOF;
    }
    ret("Error set to: -, Return value: 0");
    return 0;
}

int UCRTBase::fgetc_(FILE *file) {
    trace("fgetc_ called. Arguments: file=", std::to_wstring(reinterpret_cast<uintptr_t>(file)));
    if (file == nullptr) {
        ret("Error set to: EINVAL, Return value: EOF");
        errno = EINVAL;
        return EOF;
    }
    const int result = fgetc(file);
    if (result == EOF && ferror(file)) {
        ret("Error set to: errno, Return value: EOF");
        return EOF;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

int UCRTBase::fgetpos_(FILE *file, fpos_t *pos) {
    trace("fgetpos_ called. Arguments: file=", std::to_wstring(reinterpret_cast<uintptr_t>(file)), ", pos=", std::to_wstring(reinterpret_cast<uintptr_t>(pos)));
    if (file == nullptr || pos == nullptr) {
        ret("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    if (fgetpos(file, pos) != 0) {
        ret("Error set to: errno, Return value: errno");
        return errno;
    }
    ret("Error set to: -, Return value: 0, *pos=", pos);
    return 0;
}

char * UCRTBase::fgets_(char *str, int num, FILE *file) {
    trace("fgets_ called. Arguments: str=", std::to_wstring(reinterpret_cast<uintptr_t>(str)), ", num=", std::to_wstring(num), ", file=", std::to_wstring(reinterpret_cast<uintptr_t>(file)));
    if (str == nullptr || num <= 0 || file == nullptr) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    char* result = fgets(str, num, file);
    if (result == nullptr && ferror(file)) {
        ret("Error set to: errno, Return value: nullptr");
        return nullptr;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(result)));
    return result;
}

_wint_t UCRTBase::fgetwc_(FILE *file) {
    trace("fgetwc_ called. Arguments: file=", std::to_wstring(reinterpret_cast<uintptr_t>(file)));
    if (file == nullptr) {
        ret("Error set to: EINVAL, Return value: _WEOF");
        errno = EINVAL;
        return _WEOF;
    }
    const _wint_t result = fgetwc(file);
    if (result == _WEOF && ferror(file)) {
        ret("Error set to: errno, Return value: _WEOF");
        return _WEOF;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

_wchar_t * UCRTBase::fgetws_(_wchar_t *str, int num, FILE *file) {
    trace("fgetws_ called. Arguments: str=", std::to_wstring(reinterpret_cast<uintptr_t>(str)), ", num=", std::to_wstring(num), ", file=", std::to_wstring(reinterpret_cast<uintptr_t>(file)));
    if (str == nullptr || num <= 0 || file == nullptr) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    _wchar_t *result = fgetws_(str, num, file);
    if (result == nullptr && ferror(file)) {
        ret("Error set to: errno, Return value: nullptr");
        return nullptr;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(result)));
    return result;
}

FILE * UCRTBase::fopen_(const char *filename, const char *mode) {
    trace("fopen_ called. Arguments: filename=", std::wstring(filename ? filename : "(null)", filename ? filename + strlen(filename) : "(null)"), ", mode=", std::wstring(mode ? mode : "(null)", mode ? mode + strlen(mode) : "(null)"));
    if (filename == nullptr || mode == nullptr) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    FILE* file = fopen(filename, mode);
    if (file == nullptr) {
        ret("Error set to: errno, Return value: nullptr");
        return nullptr;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(file)));
    return file;
}

errno_t UCRTBase::fopen_s(FILE **pFile, const char *filename, const char *mode) {
    trace("fopen_s called. Arguments: pFile=", std::to_wstring(reinterpret_cast<uintptr_t>(pFile)), ", filename=", std::wstring(filename ? filename : "(null)", filename ? filename + strlen(filename) : "(null)"), ", mode=", std::wstring(mode ? mode : "(null)", mode ? mode + strlen(mode) : "(null)"));
    if (pFile == nullptr || filename == nullptr || mode == nullptr) {
        ret("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    FILE* file = fopen(filename, mode);
    if (file == nullptr) {
        ret("Error set to: errno, Return value: errno");
        return errno;
    }
    *pFile = file;
    ret("Error set to: -, Return value: 0, *pFile=", std::to_wstring(reinterpret_cast<uintptr_t>(*pFile)));
    return 0;
}

size_t UCRTBase::fread_(void *ptr, size_t size, size_t count, FILE *file) {
    trace("fread_ called. Arguments: ptr=", std::to_wstring(reinterpret_cast<uintptr_t>(ptr)), ", size=", std::to_wstring(size), ", count=", std::to_wstring(count), ", file=", std::to_wstring(reinterpret_cast<uintptr_t>(file)));
    if (ptr == nullptr || size == 0 || count == 0 || file == nullptr) {
        ret("Error set to: EINVAL, Return value: 0");
        errno = EINVAL;
        return 0;
    }
    const size_t result = fread(ptr, size, count, file);
    if (result < count && ferror(file)) {
        ret("Error set to: errno, Return value: ", std::to_wstring(result));
        return result;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

errno_t UCRTBase::fread_s(void *ptr, size_t ptrSize, size_t size, size_t count, FILE *file) {
    trace("fread_s called. Arguments: ptr=", std::to_wstring(reinterpret_cast<uintptr_t>(ptr)), ", ptrSize=", std::to_wstring(ptrSize), ", size=", std::to_wstring(size), ", count=", std::to_wstring(count), ", file=", std::to_wstring(reinterpret_cast<uintptr_t>(file)));
    if (ptr == nullptr || ptrSize == 0 || size == 0 || count == 0 || file == nullptr) {
        ret("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    if (size > ptrSize || count > ptrSize / size) {
        ret("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    const size_t result = fread(ptr, size, count, file);
    if (result < count && ferror(file)) {
        ret("Error set to: errno, Return value: errno");
        return errno;
    }
    ret("Error set to: -, Return value: 0");
    return 0;
}

int UCRTBase::fputc_(int ch, FILE *file) {
    trace("fputc_ called. Arguments: ch=", std::to_wstring(ch), ", file=", std::to_wstring(reinterpret_cast<uintptr_t>(file)));
    if (file == nullptr) {
        ret("Error set to: EINVAL, Return value: EOF");
        errno = EINVAL;
        return EOF;
    }
    const int result = fputc(ch, file);
    if (result == EOF && ferror(file)) {
        ret("Error set to: errno, Return value: EOF");
        return EOF;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

int UCRTBase::fputs_(const char *str, FILE *file) {
    trace("fputs_ called. Arguments: str=", std::to_wstring(reinterpret_cast<uintptr_t>(str)), ", file=", std::to_wstring(reinterpret_cast<uintptr_t>(file)));
    if (str == nullptr || file == nullptr) {
        ret("Error set to: EINVAL, Return value: EOF");
        errno = EINVAL;
        return EOF;
    }
    const int result = fputs(str, file);
    if (result == EOF && ferror(file)) {
        ret("Error set to: errno, Return value: EOF");
        return EOF;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

_wint_t UCRTBase::fputwc_(_wint_t ch, FILE *file) {
    trace("fputwc_ called. Arguments: ch=", std::to_wstring(ch), ", file=", std::to_wstring(reinterpret_cast<uintptr_t>(file)));
    if (file == nullptr) {
        ret("Error set to: EINVAL, Return value: _WEOF");
        errno = EINVAL;
        return _WEOF;
    }
    const _wint_t result = fputwc(ch, file);
    if (result == _WEOF && ferror(file)) {
        ret("Error set to: errno, Return value: _WEOF");
        return _WEOF;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

int UCRTBase::fputws_(const _wchar_t *str, FILE *file) {
    trace("fputws_ called. Arguments: str=", std::to_wstring(reinterpret_cast<uintptr_t>(str)), ", file=", std::to_wstring(reinterpret_cast<uintptr_t>(file)));
    if (str == nullptr || file == nullptr) {
        ret("Error set to: EINVAL, Return value: _WEOF");
        errno = EINVAL;
        return _WEOF;
    }
    const int result = fputws_(str, file);
    if (result == _WEOF && ferror(file)) {
        ret("Error set to: errno, Return value: _WEOF");
        return _WEOF;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

FILE * UCRTBase::freopen_(const char *filename, const char *mode, FILE *file) {
    trace("freopen_ called. Arguments: filename=", std::wstring(filename ? filename : "(null)", filename ? filename + strlen(filename) : "(null)"), ", mode=", std::wstring(mode ? mode : "(null)", mode ? mode + strlen(mode) : "(null)"), ", file=", std::to_wstring(reinterpret_cast<uintptr_t>(file)));
    if (filename == nullptr || mode == nullptr || file == nullptr) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    FILE* newFile = freopen(filename, mode, file);
    if (newFile == nullptr) {
        ret("Error set to: errno, Return value: nullptr");
        return nullptr;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(newFile)));
    return newFile;
}

errno_t UCRTBase::freopen_s(FILE **pFile, const char *filename, const char *mode, FILE *file) {
    trace("freopen_s called. Arguments: pFile=", std::to_wstring(reinterpret_cast<uintptr_t>(pFile)), ", filename=", std::wstring(filename ? filename : "(null)", filename ? filename + strlen(filename) : "(null)"), ", mode=", std::wstring(mode ? mode : "(null)", mode ? mode + strlen(mode) : "(null)"), ", file=", std::to_wstring(reinterpret_cast<uintptr_t>(file)));
    if (pFile == nullptr || filename == nullptr || mode == nullptr || file == nullptr) {
        ret("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    FILE* newFile = freopen(filename, mode, file);
    if (newFile == nullptr) {
        ret("Error set to: errno, Return value: errno");
        return errno;
    }
    *pFile = newFile;
    ret("Error set to: -, Return value: 0, *pFile=", std::to_wstring(reinterpret_cast<uintptr_t>(*pFile)));
    return 0;
}

int UCRTBase::fseek_(FILE *file, long offset, int origin) {
    trace("fseek_ called. Arguments: file=", std::to_wstring(reinterpret_cast<uintptr_t>(file)), ", offset=", std::to_wstring(offset), ", origin=", std::to_wstring(origin));
    if (file == nullptr || (origin != SEEK_SET && origin != SEEK_CUR && origin != SEEK_END)) {
        ret("Error set to: EINVAL, Return value: -1");
        errno = EINVAL;
        return -1;
    }
    if (fseek(file, offset, origin) != 0) {
        ret("Error set to: errno, Return value: -1");
        return -1;
    }
    ret("Error set to: -, Return value: 0");
    return 0;
}

int UCRTBase::fsetpos_(FILE *file, const fpos_t *pos) {
    trace("fsetpos_ called. Arguments: file=", std::to_wstring(reinterpret_cast<uintptr_t>(file)), ", pos=", std::to_wstring(reinterpret_cast<uintptr_t>(pos)));
    if (file == nullptr || pos == nullptr) {
        ret("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    if (fsetpos(file, pos) != 0) {
        ret("Error set to: errno, Return value: errno");
        return errno;
    }
    ret("Error set to: -, Return value: 0");
    return 0;
}

LONG UCRTBase::ftell_(FILE *file) {
    trace("ftell_ called. Arguments: file=", std::to_wstring(reinterpret_cast<uintptr_t>(file)));
    if (file == nullptr) {
        ret("Error set to: EINVAL, Return value: -1");
        errno = EINVAL;
        return -1;
    }
    const LONG result = static_cast<LONG>(ftell(file));
    if (result == -1L) {
        ret("Error set to: errno, Return value: -1");
        return -1;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

off_t UCRTBase::ftelli64(FILE *file) {
    trace("ftelli64 called. Arguments: file=", std::to_wstring(reinterpret_cast<uintptr_t>(file)));
    if (file == nullptr) {
        ret("Error set to: EINVAL, Return value: -1");
        errno = EINVAL;
        return -1;
    }
    const off_t result = ftello(file);
    if (result == -1) {
        ret("Error set to: errno, Return value: -1");
        return -1;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

size_t UCRTBase::fwrite_(const void *ptr, size_t size, size_t count, FILE *file) {
    trace("fwrite_ called. Arguments: ptr=", std::to_wstring(reinterpret_cast<uintptr_t>(ptr)), ", size=", std::to_wstring(size), ", count=", std::to_wstring(count), ", file=", std::to_wstring(reinterpret_cast<uintptr_t>(file)));
    if (ptr == nullptr || size == 0 || count == 0 || file == nullptr) {
        ret("Error set to: EINVAL, Return value: 0");
        errno = EINVAL;
        return 0;
    }
    const size_t result = fwrite(ptr, size, count, file);
    if (result < count && ferror(file)) {
        ret("Error set to: errno, Return value: ", std::to_wstring(result));
        return result;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

int UCRTBase::getc_(FILE *file) {
    trace("getc_ called. Arguments: file=", std::to_wstring(reinterpret_cast<uintptr_t>(file)));
    if (file == nullptr) {
        ret("Error set to: EINVAL, Return value: EOF");
        errno = EINVAL;
        return EOF;
    }
    const int result = getc(file);
    if (result == EOF && ferror(file)) {
        ret("Error set to: errno, Return value: EOF");
        return EOF;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

int UCRTBase::getchar_() {
    trace("getchar_ called. Arguments: -");
    const int result = getchar();
    if (result == EOF && ferror(stdin)) {
        ret("Error set to: errno, Return value: EOF");
        return EOF;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

char * UCRTBase::gets_(char *str) {
    trace("gets_ called. Arguments: str=", std::to_wstring(reinterpret_cast<uintptr_t>(str)));
    if (str == nullptr) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    char* result = std::fgets(str, INT_MAX, stdin);
    if (result == nullptr && ferror(stdin)) {
        ret("Error set to: errno, Return value: nullptr");
        return nullptr;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(result)));
    return result;
}

errno_t UCRTBase::gets_s(char *str, size_t size) {
    trace("gets_s called. Arguments: str=", std::to_wstring(reinterpret_cast<uintptr_t>(str)), ", size=", std::to_wstring(size));
    if (str == nullptr || size == 0) {
        ret("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    if (const char *result = std::fgets(str, static_cast<int>(size), stdin); result == nullptr) {
        if (ferror(stdin)) {
            ret("Error set to: errno, Return value: errno");
            return errno;
        }
        // EOF reached
        str[0] = '\0';
        ret("Error set to: -, Return value: 0, str=", std::to_wstring(reinterpret_cast<uintptr_t>(str)));
        return 0;
    }
    ret("Error set to: -, Return value: 0, str=", std::to_wstring(reinterpret_cast<uintptr_t>(str)));
    return 0;
}

_wint_t UCRTBase::getwc_(FILE *file) {
    trace("getwc_ called. Arguments: file=", std::to_wstring(reinterpret_cast<uintptr_t>(file)));
    if (file == nullptr) {
        ret("Error set to: EINVAL, Return value: _WEOF");
        errno = EINVAL;
        return _WEOF;
    }
    const _wint_t result = getwc(file);
    if (result == _WEOF && ferror(file)) {
        ret("Error set to: errno, Return value: _WEOF");
        return _WEOF;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

_wint_t UCRTBase::getwchar_() {
    trace("getwchar_ called. Arguments: -");
    const _wint_t result = getwchar();
    if (result == _WEOF && ferror(stdin)) {
        ret("Error set to: errno, Return value: _WEOF");
        return _WEOF;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

int UCRTBase::putc_(int ch, FILE *file) {
    trace("putc_ called. Arguments: ch=", std::to_wstring(ch), ", file=", std::to_wstring(reinterpret_cast<uintptr_t>(file)));
    if (file == nullptr) {
        ret("Error set to: EINVAL, Return value: EOF");
        errno = EINVAL;
        return EOF;
    }
    const int result = putc(ch, file);
    if (result == EOF && ferror(file)) {
        ret("Error set to: errno, Return value: EOF");
        return EOF;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

int UCRTBase::putchar_(int ch) {
    trace("putchar_ called. Arguments: ch=", std::to_wstring(ch));
    const int result = putchar(ch);
    if (result == EOF && ferror(stdout)) {
        ret("Error set to: errno, Return value: EOF");
        return EOF;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

int UCRTBase::puts_(const char *str) {
    trace("puts_ called. Arguments: str=", std::to_wstring(reinterpret_cast<uintptr_t>(str)));
    if (str == nullptr) {
        ret("Error set to: EINVAL, Return value: EOF");
        errno = EINVAL;
        return EOF;
    }
    const int result = puts(str);
    if (result == EOF && ferror(stdout)) {
        ret("Error set to: errno, Return value: EOF");
        return EOF;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

_wint_t UCRTBase::putwc_(_wint_t ch, FILE *file) {
    trace("putwc_ called. Arguments: ch=", std::to_wstring(ch), ", file=", std::to_wstring(reinterpret_cast<uintptr_t>(file)));
    if (file == nullptr) {
        ret("Error set to: EINVAL, Return value: _WEOF");
        errno = EINVAL;
        return _WEOF;
    }
    const _wint_t result = putwc(ch, file);
    if (result == _WEOF && ferror(file)) {
        ret("Error set to: errno, Return value: _WEOF");
        return _WEOF;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

_wint_t UCRTBase::putwchar_(_wint_t ch) {
    trace("putwchar_ called. Arguments: ch=", std::to_wstring(ch));
    const _wint_t result = putwchar(ch);
    if (result == _WEOF && ferror(stdout)) {
        ret("Error set to: errno, Return value: _WEOF");
        return _WEOF;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

void UCRTBase::rewind_(FILE *file) {
    trace("rewind_ called. Arguments: file=", std::to_wstring(reinterpret_cast<uintptr_t>(file)));
    if (file == nullptr) {
        ret("Error set to: EINVAL");
        errno = EINVAL;
        return;
    }
    rewind(file);
    ret("Error set to: -");
}

void UCRTBase::setbuf_(FILE *file, char *buffer) {
    trace("setbuf_ called. Arguments: file=", std::to_wstring(reinterpret_cast<uintptr_t>(file)), ", buffer=", std::to_wstring(reinterpret_cast<uintptr_t>(buffer)));
    if (file == nullptr) {
        ret("Error set to: EINVAL");
        errno = EINVAL;
        return;
    }
    setbuf(file, buffer);
    ret("Error set to: -");
}

int UCRTBase::setvbuf_(FILE *file, char *buffer, int mode, size_t size) {
    trace("setvbuf_ called. Arguments: file=", std::to_wstring(reinterpret_cast<uintptr_t>(file)), ", buffer=", std::to_wstring(reinterpret_cast<uintptr_t>(buffer)), ", mode=", std::to_wstring(mode), ", size=", std::to_wstring(size));
    if (file == nullptr || (mode != _IOFBF && mode != _IOLBF && mode != _IONBF) || (mode != _IONBF && size == 0)) {
        ret("Error set to: EINVAL, Return value: -1");
        errno = EINVAL;
        return -1;
    }
    if (setvbuf(file, buffer, mode, size) != 0) {
        ret("Error set to: errno, Return value: -1");
        return -1;
    }
    ret("Error set to: -, Return value: 0");
    return 0;
}

FILE * UCRTBase::tmpfile_() {
    trace("tmpfile_ called. Arguments: -");
    FILE* file = tmpfile();
    if (file == nullptr) {
        ret("Error set to: errno, Return value: nullptr");
        return nullptr;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(file)));
    return file;
}

errno_t UCRTBase::tmpfile_s(FILE **pFile) {
    trace("tmpfile_s called. Arguments: pFile=", std::to_wstring(reinterpret_cast<uintptr_t>(pFile)));
    if (pFile == nullptr) {
        ret("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    FILE* file = tmpfile();
    if (file == nullptr) {
        ret("Error set to: errno, Return value: errno");
        return errno;
    }
    *pFile = file;
    ret("Error set to: -, Return value: 0, *pFile=", std::to_wstring(reinterpret_cast<uintptr_t>(*pFile)));
    return 0;
}

char * UCRTBase::tmpnam_(char *str) {
    trace("tmpnam_ called. Arguments: str=", std::to_wstring(reinterpret_cast<uintptr_t>(str)));

    return _tmpnam(str);
}

errno_t UCRTBase::tmpnam_s(char *str, size_t size) {
    trace("tmpnam_s called. Arguments: str=", std::to_wstring(reinterpret_cast<uintptr_t>(str)), ", size=", std::to_wstring(size));
    if (str == nullptr || size < L_tmpnam) {
        ret("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    if (_tmpnam(str) == nullptr) {
        ret("Error set to: errno, Return value: errno");
        return errno;
    }
    ret("Error set to: -, Return value: 0, str=", std::to_wstring(reinterpret_cast<uintptr_t>(str)));
    return 0;
}

int UCRTBase::ungetc_(int ch, FILE *file) {
    trace("ungetc_ called. Arguments: ch=", std::to_wstring(ch), ", file=", std::to_wstring(reinterpret_cast<uintptr_t>(file)));
    if (file == nullptr) {
        ret("Error set to: EINVAL, Return value: EOF");
        errno = EINVAL;
        return EOF;
    }
    const int result = ungetc(ch, file);
    if (result == EOF && ferror(file)) {
        ret("Error set to: errno, Return value: EOF");
        return EOF;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

_wint_t UCRTBase::ungetwc_(_wint_t ch, FILE *file) {
    trace("ungetwc_ called. Arguments: ch=", std::to_wstring(ch), ", file=", std::to_wstring(reinterpret_cast<uintptr_t>(file)));
    if (file == nullptr) {
        ret("Error set to: EINVAL, Return value: _WEOF");
        errno = EINVAL;
        return _WEOF;
    }
    const _wint_t result = ungetwc(ch, file);
    if (result == _WEOF && ferror(file)) {
        ret("Error set to: errno, Return value: _WEOF");
        return _WEOF;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(result));
    return result;
}

UINT UCRTBase::___lc_codepage_func() {
    trace("___lc_codepage_func called. Arguments: -");
    // On POSIX, use UTF-8 as default
    return 65001; // CP_UTF8
}

UINT UCRTBase::___lc_collate_cp_func() {
    trace("___lc_collate_cp_func called. Arguments: -");
    return 65001; // CP_UTF8
}

_wchar_t ** UCRTBase::___lc_locale_name_func() {
    trace("___lc_locale_name_func called. Arguments: -");
    // check for lc name in env
    // tls.locale_name
    return &tls.locale_name;
}

int UCRTBase::___mb_cur_max_func() {
    trace("___mb_cur_max_func called. Arguments: -");
    return 4; // UTF-8 max is 4 bytes
}

int UCRTBase::___mb_cur_max_l_func(_locale_t locale) {
    trace("___mb_cur_max_l_func called. Arguments: locale=", std::to_wstring(reinterpret_cast<uintptr_t>(locale)));
    return 4; // UTF-8 max is 4 bytes
}

int UCRTBase::__initialize_lconv_for_unsigned_char() {
    trace("__initialize_lconv_for_unsigned_char called. Arguments: -");
    tls.locale_info.decimal_point = const_cast<char*>(".");
    tls.locale_info.thousands_sep = const_cast<char*>("");
    tls.locale_info.grouping = const_cast<char*>("");
    tls.locale_info.int_curr_symbol = const_cast<char*>("");
    tls.locale_info.currency_symbol = const_cast<char*>("");
    tls.locale_info.mon_decimal_point = const_cast<char*>("");
    tls.locale_info.mon_thousands_sep = const_cast<char*>("");
    tls.locale_info.mon_grouping = const_cast<char*>("");
    tls.locale_info.positive_sign = const_cast<char*>("");
    tls.locale_info.negative_sign = const_cast<char*>("");
    tls.locale_info.int_frac_digits = static_cast<char>(UCHAR_MAX);
    tls.locale_info.frac_digits = static_cast<char>(UCHAR_MAX);
    tls.locale_info.p_cs_precedes = static_cast<char>(UCHAR_MAX);
    tls.locale_info.p_sep_by_space = static_cast<char>(UCHAR_MAX);
    tls.locale_info.n_cs_precedes = static_cast<char>(UCHAR_MAX);
    tls.locale_info.n_sep_by_space = static_cast<char>(UCHAR_MAX);
    tls.locale_info.p_sign_posn = static_cast<char>(UCHAR_MAX);
    tls.locale_info.n_sign_posn = static_cast<char>(UCHAR_MAX);
    return 0;
}

const unsigned short * UCRTBase::___pctype_func() {
    trace("___pctype_func called. Arguments: -");
    return _ctype;
}

const unsigned short * UCRTBase::__pwctype_func() {
    trace("__pwctype_func called. Arguments: -");
    return _wctype;
}

int UCRTBase::_configthreadlocale(int flag) {
    trace("_configthreadlocale called. Arguments: flag=", std::to_wstring(flag));
    if (flag == _ENABLE_PER_THREAD_LOCALE) {
        process_info[tls.process].is_locale_per_thread = true;
        ret("Error set to: -, Return value: 0");
        return 0;
    }
    if (flag == _DISABLE_PER_THREAD_LOCALE) {
        process_info[tls.process].is_locale_per_thread = false;
        ret("Error set to: -, Return value: 0");
        return 0;
    }
    if (!flag) {
        ret("Error set to: -, Return value: 0");
        return process_info[tls.process].is_locale_per_thread ? _ENABLE_PER_THREAD_LOCALE : _DISABLE_PER_THREAD_LOCALE;
    }
    ret("Error set to: EINVAL, Return value: -1");
    errno = EINVAL;
    return -1;
}

_locale_t UCRTBase::_create_locale(int category, const char *locale) {
    trace("_create_locale diserror-stub called. Arguments: category=", std::to_wstring(category), ", locale=", std::wstring(locale ? locale : "(null)", locale ? locale + strlen(locale) : "(null)"));
    return reinterpret_cast<_locale_t>(0x69420); // some non-null value
}

_locale_t UCRTBase::_wcreate_locale(int category, const _wchar_t *locale) {
    constexpr _wchar_t default_locale[] = { '(', 'n', 'u', 'l', 'l', ')', '\0' };
    trace("_wcreate_locale diserror-stub called. Arguments: category=", std::to_wstring(category), ", locale=", std::wstring(locale ? locale : default_locale, locale ? locale + wcslen_(locale) : default_locale));
    return reinterpret_cast<_locale_t>(0x69420); // some non-null value
}

void UCRTBase::_free_locale(_locale_t locale) {
    trace("_free_locale diserror-stub called. Arguments: locale=", std::to_wstring(reinterpret_cast<uintptr_t>(locale)));
    // no-op
    ret("Error set to: -");
}

_locale_t UCRTBase::_get_current_locale() {
    trace("_get_current_locale diserror-stub called. Arguments: -");
    return reinterpret_cast<_locale_t>(0x69420); // some non-null value`
}

int UCRTBase::_getmbcp() {
    trace("_getmbcp called. Arguments: -");
    ret("Error set to: -, Return value: 65001");
    return 65001; // CP_UTF8
}

void UCRTBase::_lock_locales() {
    trace("_lock_locales diserror-stub called. Arguments: -");
    // no-op
    ret("Error set to: -");
}

void UCRTBase::_unlock_locales() {
    trace("_unlock_locales diserror-stub called. Arguments: -");
    // no-op
    ret("Error set to: -");
}

int UCRTBase::_setmbcp(int codepage) {
    trace("_setmbcp called. Arguments: codepage=", std::to_wstring(codepage));
    // no-op, always UTF-8
    ret("Error set to: -, Return value: 0");
    return 0; // CP_UTF8
}

char * UCRTBase::setlocale_(int category, const char *locale) {
    trace("setlocale_ called. Arguments: category=", std::to_wstring(category), ", locale=", std::wstring(locale ? locale : "(null)", locale ? locale + strlen(locale) : "(null)"));

    char *res = setlocale(category, locale);

    if (res == nullptr) {
        ret("Error set to: errno, Return value: nullptr");
        return nullptr;
    }
    ret("Error set to: -, Return value: ", std::wstring(res, res + strlen(res)));
    return res; // return the result of the setlocale call
}

_wchar_t * UCRTBase::_wsetlocale(int category, const _wchar_t *locale) {
    constexpr _wchar_t default_locale[] = { '(', 'n', 'u', 'l', 'l', ')', '\0' };
    trace("_wsetlocale called. Arguments: category=", std::to_wstring(category), ", locale=", std::wstring(locale ? locale : default_locale, locale ? locale + wcslen_(locale) : default_locale));
    char narrowLocale[256];
    if (locale) {
        if (const size_t converted = wcstombs_(narrowLocale, locale, sizeof(narrowLocale)); converted == static_cast<size_t>(-1) || converted == sizeof(narrowLocale)) {
            ret("Error set to: EINVAL, Return value: nullptr");
            errno = EINVAL;
            return nullptr;
        }
    }
    const char *res = setlocale(category, locale ? narrowLocale : nullptr);
    if (res == nullptr) {
        ret("Error set to: errno, Return value: nullptr");
        return nullptr;
    }
    thread_local _wchar_t wideRes[256];
    const size_t convertedBack = mbstowcs_(wideRes, res, std::size(wideRes));
    if (convertedBack == static_cast<size_t>(-1) || convertedBack == std::size(wideRes)) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    ret("Error set to: -, Return value: ", std::wstring(wideRes, wideRes + convertedBack));
    return wideRes; // return the result of the setlocale call
}

lconv * UCRTBase::localeconv_() {
    trace("localeconv_ called. Arguments: -");
    // Ensure locale_info is initialized
    if (tls.locale_info.decimal_point == nullptr) {
        _configthreadlocale(0); // ensure thread locale config is up to date
    }
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(&tls.locale_info)));
    return &tls.locale_info;
}

void UCRTBase::_aligned_free(void *memblock) {
    trace("_aligned_free called. Arguments: memblock=", std::to_wstring(reinterpret_cast<uintptr_t>(memblock)));
    free(memblock);
    ret("Error set to: -");
}

void * UCRTBase::_aligned_malloc(size_t size, size_t alignment) {
    trace("_aligned_malloc called. Arguments: size=", std::to_wstring(size), ", alignment=", std::to_wstring(alignment));
    if (alignment == 0 || (alignment & (alignment - 1)) != 0 || alignment > static_cast<size_t>(1) << 30) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    void* ptr = nullptr;
    if (posix_memalign(&ptr, alignment, size) != 0) {
        ret("Error set to: errno, Return value: nullptr");
        return nullptr;
    }
    process_info[tls.process].aligned_mem[ptr] = {
        .size = size,
        .alignment = alignment
    };
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(ptr)));
    return ptr;
}

void * UCRTBase::_aligned_calloc(size_t count, size_t size, size_t alignment) {
    trace("_aligned_calloc called. Arguments: count=", std::to_wstring(count), ", size=", std::to_wstring(size), ", alignment=", std::to_wstring(alignment));
    if (alignment == 0 || (alignment & (alignment - 1)) != 0 || alignment > static_cast<size_t>(1) << 30) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    void* ptr = nullptr;
    const size_t totalSize = count * size;
    if (posix_memalign(&ptr, alignment, totalSize) != 0) {
        ret("Error set to: errno, Return value: nullptr");
        return nullptr;
    }
    std::memset(ptr, 0, totalSize);
    process_info[tls.process].aligned_mem[ptr] = {
        .size = totalSize,
        .alignment = alignment
    };
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(ptr)));
    return ptr;
}

void * UCRTBase::_aligned_realloc(void *memblock, size_t size, size_t alignment) {
    trace("_aligned_realloc called. Arguments: memblock=", std::to_wstring(reinterpret_cast<uintptr_t>(memblock)), ", size=", std::to_wstring(size), ", alignment=", std::to_wstring(alignment));
    if (memblock == nullptr || alignment == 0 || (alignment & (alignment - 1)) != 0 || alignment > static_cast<size_t>(1) << 30) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    if (!process_info[tls.process].aligned_mem.contains(memblock)) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    void* newPtr = nullptr;
    if (posix_memalign(&newPtr, alignment, size) != 0) {
        ret("Error set to: errno, Return value: nullptr");
        return nullptr;
    }
    std::memcpy(newPtr, memblock, std::min(size, process_info[tls.process].aligned_mem[memblock].size));
    free(memblock);
    process_info[tls.process].aligned_mem.erase(memblock);
    process_info[tls.process].aligned_mem[newPtr] = {
        .size = size,
        .alignment = alignment
    };
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(newPtr)));
    return newPtr;
}

void * UCRTBase::_aligned_recalloc(void *memblock, size_t count, size_t size, size_t alignment) {
    trace("_aligned_recalloc called. Arguments: memblock=", std::to_wstring(reinterpret_cast<uintptr_t>(memblock)), ", count=", std::to_wstring(count), ", size=", std::to_wstring(size), ", alignment=", std::to_wstring(alignment));
    if (memblock == nullptr || alignment == 0 || (alignment & (alignment - 1)) != 0 || alignment > static_cast<size_t>(1) << 30) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    if (!process_info[tls.process].aligned_mem.contains(memblock)) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    void* newPtr = nullptr;
    const size_t newSize = count * size;
    if (posix_memalign(&newPtr, alignment, newSize) != 0) {
        ret("Error set to: errno, Return value: nullptr");
        return nullptr;
    }
    const size_t oldSize = process_info[tls.process].aligned_mem[memblock].size;
    std::memcpy(newPtr, memblock, std::min(newSize, oldSize));
    if (newSize > oldSize) {
        std::memset(static_cast<char*>(newPtr) + oldSize, 0, newSize - oldSize);
    }
    free(memblock);
    process_info[tls.process].aligned_mem.erase(memblock);
    process_info[tls.process].aligned_mem[newPtr] = {
        .size = newSize,
        .alignment = alignment
    };
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(newPtr)));
    return newPtr;
}

size_t UCRTBase::_aligned_msize(void *memblock, size_t alignment, size_t offset) {
    trace("_aligned_msize called. Arguments: memblock=", std::to_wstring(reinterpret_cast<uintptr_t>(memblock)), ", alignment=", std::to_wstring(alignment), ", offset=", std::to_wstring(offset));
    if (memblock == nullptr || alignment == 0 || (alignment & (alignment - 1)) != 0 || alignment > static_cast<size_t>(1) << 30 || offset >= alignment) {
        ret("Error set to: EINVAL, Return value: (size_t)-1");
        errno = EINVAL;
        return static_cast<size_t>(-1);
    }
    return process_info[tls.process].aligned_mem.contains(memblock) ? process_info[tls.process].aligned_mem[memblock].size - offset : static_cast<size_t>(-1);
}

void * UCRTBase::_aligned_offset_malloc(size_t size, size_t alignment, size_t offset) {
    trace("_aligned_offset_malloc called. Arguments: size=", std::to_wstring(size), ", alignment=", std::to_wstring(alignment), ", offset=", std::to_wstring(offset));
    if (alignment == 0 || (alignment & (alignment - 1)) != 0 || alignment > static_cast<size_t>(1) << 30 || offset >= alignment) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    void* ptr = nullptr;
    if (posix_memalign(&ptr, alignment, size + offset) != 0) {
        ret("Error set to: errno, Return value: nullptr");
        return nullptr;
    }
    void* adjustedPtr = static_cast<char*>(ptr) + offset;
    process_info[tls.process].aligned_mem[adjustedPtr] = {
        .size = size + offset,
        .alignment = alignment
    };
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(adjustedPtr)));
    return adjustedPtr;
}

void * UCRTBase::_aligned_offset_realloc(void *memblock, size_t size, size_t alignment, size_t offset) {
    trace("_aligned_offset_realloc called. Arguments: memblock=", std::to_wstring(reinterpret_cast<uintptr_t>(memblock)), ", size=", std::to_wstring(size), ", alignment=", std::to_wstring(alignment), ", offset=", std::to_wstring(offset));
    if (memblock == nullptr || alignment == 0 || (alignment & (alignment - 1)) != 0 || alignment > static_cast<size_t>(1) << 30 || offset >= alignment) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    if (!process_info[tls.process].aligned_mem.contains(memblock)) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    void* originalPtr = static_cast<char*>(memblock) - offset;
    void* newPtr = nullptr;
    if (posix_memalign(&newPtr, alignment, size + offset) != 0) {
        ret("Error set to: errno, Return value: nullptr");
        return nullptr;
    }
    std::memcpy(static_cast<char*>(newPtr) + offset, memblock, std::min(size, process_info[tls.process].aligned_mem[memblock].size - offset));
    free(originalPtr);
    process_info[tls.process].aligned_mem.erase(memblock);
    void* adjustedPtr = static_cast<char*>(newPtr) + offset;
    process_info[tls.process].aligned_mem[adjustedPtr] = {
        .size = size + offset,
        .alignment = alignment
    };
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(adjustedPtr)));
    return adjustedPtr;
}

void * UCRTBase::_aligned_offset_recalloc(void *memblock, size_t count, size_t size, size_t alignment, size_t offset) {
    trace("_aligned_offset_recalloc called. Arguments: memblock=", std::to_wstring(reinterpret_cast<uintptr_t>(memblock)), ", count=", std::to_wstring(count), ", size=", std::to_wstring(size), ", alignment=", std::to_wstring(alignment), ", offset=", std::to_wstring(offset));
    if (memblock == nullptr || alignment == 0 || (alignment & (alignment - 1)) != 0 || alignment > static_cast<size_t>(1) << 30 || offset >= alignment) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    if (!process_info[tls.process].aligned_mem.contains(memblock)) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    void* originalPtr = static_cast<char*>(memblock) - offset;
    void* newPtr = nullptr;
    const size_t newSize = count * size;
    if (posix_memalign(&newPtr, alignment, newSize + offset) != 0) {
        ret("Error set to: errno, Return value: nullptr");
        return nullptr;
    }
    const size_t oldSize = process_info[tls.process].aligned_mem[memblock].size - offset;
    std::memcpy(static_cast<char*>(newPtr) + offset, memblock, std::min(newSize, oldSize));
    if (newSize > oldSize) {
        std::memset(static_cast<char*>(newPtr) + offset + oldSize, 0, newSize - oldSize);
    }
    free(originalPtr);
    process_info[tls.process].aligned_mem.erase(memblock);
    void* adjustedPtr = static_cast<char*>(newPtr) + offset;
    process_info[tls.process].aligned_mem[adjustedPtr] = {
        .size = newSize + offset,
        .alignment = alignment
    };
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(adjustedPtr)));
    return adjustedPtr;
}

int UCRTBase::_callnewh(const size_t size) {
    trace("_callnewh called. Arguments: -");
    const int res = process_info[tls.process].new_handler(static_cast<int>(size));
    ret("Error set to: -, Return value: ", std::to_wstring(res));
    return res;
}

void * UCRTBase::_calloc_base(size_t count, size_t size) {
    trace("_calloc_base called. Arguments: count=", std::to_wstring(count), ", size=", std::to_wstring(size));
    void* res = calloc(count, size);
    process_info[tls.process].c_mem[res] = {
        .size = count * size
    };
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(res)));
    return res;
}

void * UCRTBase::_expand(void *memblock, size_t newsize) {
    trace("_expand called semi-diserror-stub called. Arguments: memblock=", std::to_wstring(reinterpret_cast<uintptr_t>(memblock)), ", newsize=", std::to_wstring(newsize));
    if (memblock == nullptr) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    void* res = realloc(memblock, newsize);
    if (res == nullptr) {
        ret("Error set to: errno, Return value: nullptr");
        return nullptr;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(res)));
    return res;
}

void UCRTBase::_free_base(void *memblock) {
    trace("_free_base called. Arguments: memblock=", std::to_wstring(reinterpret_cast<uintptr_t>(memblock)));
    process_info[tls.process].c_mem.erase(memblock);
    free(memblock);
    ret("Error set to: -");
}

intptr_t UCRTBase::_get_heap_handle() {
    trace("_get_heap_handle diserror-stub called. Arguments: -");
    return reinterpret_cast<intptr_t>(process_info[tls.process].default_heap);
}

int UCRTBase::_heapchk() {
    trace("_heapchk diserror-stub called. Arguments: -");
    ret("Error set to: -, Return value: _HEAPOK");
    return _HEAPOK;
}

int UCRTBase::_heapmin() {
    trace("_heapmin diserror-stub called. Arguments: -");
    ret("Error set to: -, Return value: 0");
    return 0;
}

int UCRTBase::_heapwalk(_HEAPINFO *entryinfo) {
    trace("_heapwalk diserror-stub called. Arguments: entryinfo=", std::to_wstring(reinterpret_cast<uintptr_t>(entryinfo)));
    if (entryinfo == nullptr) {
        ret("Error set to: EINVAL, Return value: _HEAPBADBEGIN");
        errno = EINVAL;
        return _HEAPBADBEGIN;
    }
    // Indicate no more entries
    ret("Error set to: -, Return value: _HEAPEND");
    return _HEAPEND;
}

void * UCRTBase::_malloc_base(size_t size) {
    trace("_malloc_base called. Arguments: size=", std::to_wstring(size));
    void* res = malloc(size);
    process_info[tls.process].c_mem[res] = {
        .size = size
    };
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(res)));
    return res;
}

size_t UCRTBase::_msize(void *memblock) {
    trace("_msize called. Arguments: memblock=", std::to_wstring(reinterpret_cast<uintptr_t>(memblock)));
    if (memblock == nullptr) {
        ret("Error set to: EINVAL, Return value: (size_t)-1");
        errno = EINVAL;
        return static_cast<size_t>(-1);
    }
    if (!process_info[tls.process].c_mem.contains(memblock)) {
        ret("Error set to: EINVAL, Return value: (size_t)-1");
        errno = EINVAL;
        return static_cast<size_t>(-1);
    }
    const size_t size = process_info[tls.process].c_mem[memblock].size;
    ret("Error set to: -, Return value: ", std::to_wstring(size));
    return size;
}

_PNH UCRTBase::_query_new_handler() {
    trace("_query_new_handler called. Arguments: -");
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(process_info[tls.process].new_handler)));
    return process_info[tls.process].new_handler;
}

int UCRTBase::_query_new_mode() {
    trace("_query_new_mode called. Arguments: -");
    ret("Error set to: -, Return value: ", std::to_wstring(process_info[tls.process].new_mode));
    return process_info[tls.process].new_mode;
}

int UCRTBase::_set_new_mode(int newmode) {
    trace("_set_new_mode called. Arguments: newmode=", std::to_wstring(newmode));
    if (newmode != 0 && newmode != 1) {
        ret("Error set to: EINVAL, Return value: -1");
        errno = EINVAL;
        return -1;
    }
    process_info[tls.process].new_mode = newmode;
    ret("Error set to: -, Return value: 0");
    return 0;
}

void * UCRTBase::_realloc_base(void *memblock, size_t size) {
    trace("_realloc_base called. Arguments: memblock=", std::to_wstring(reinterpret_cast<uintptr_t>(memblock)), ", size=", std::to_wstring(size));
    if (memblock != nullptr && !process_info[tls.process].c_mem.contains(memblock)) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    void* res = realloc(memblock, size);
    if (res == nullptr) {
        ret("Error set to: errno, Return value: nullptr");
        return nullptr;
    }
    if (memblock != res) {
        process_info[tls.process].c_mem.erase(memblock);
    }
    process_info[tls.process].c_mem[res] = {
        .size = size
    };
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(res)));
    return res;
}

void * UCRTBase::_recalloc(void *memblock, size_t num, size_t size) {
    trace("_recalloc called. Arguments: memblock=", std::to_wstring(reinterpret_cast<uintptr_t>(memblock)), ", num=", std::to_wstring(num), ", size=", std::to_wstring(size));
    if (memblock != nullptr && !process_info[tls.process].c_mem.contains(memblock)) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    void* res = realloc(memblock, num * size);
    if (res == nullptr) {
        ret("Error set to: errno, Return value: nullptr");
        return nullptr;
    }
    if (memblock != res) {
        process_info[tls.process].c_mem.erase(memblock);
    }
    if (num * size > (memblock ? process_info[tls.process].c_mem[memblock].size : 0)) {
        std::memset(static_cast<char*>(res) + (memblock ? process_info[tls.process].c_mem[memblock].size : 0), 0, num * size - (memblock ? process_info[tls.process].c_mem[memblock].size : 0));
    }
    process_info[tls.process].c_mem[res] = {
        .size = num * size
    };
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(res)));
    return res;
}

void * UCRTBase::calloc(size_t count, size_t size) {
    return _calloc_base(count, size);
}

void UCRTBase::free(void *memblock) {
    _free_base(memblock);
}

size_t UCRTBase::wcslen_(const _wchar_t *str) {
    if (str == nullptr) {
        return 0;
    }
    const _wchar_t* s = str;
    while (*s) ++s;
    return s - str;
}

_wchar_t * UCRTBase::wcscpy_(_wchar_t *dest, const _wchar_t *src) {
    if (dest == nullptr || src == nullptr) {
        return nullptr;
    }
    _wchar_t* originalDest = dest;
    while ((*dest++ = *src++) != 0);
    return originalDest;
}

void * UCRTBase::malloc(size_t size) {
    return _malloc_base(size);
}

void * UCRTBase::realloc(void *memblock, size_t size) {
    return _realloc_base(memblock, size);
}

int UCRTBase::__isascii_(int c) {
    return (c >= 0 && c <= 0x7F);
}

int UCRTBase::iswascii(_wint_t c) {
    return (c >= 0 && c <= 0x7F);
}

int UCRTBase::__iscsym(int c) {
    return is_ctype(c, _ALPHA) || is_ctype(c, _DIGIT) || c == '_';
}

int UCRTBase::__iscsymf(int c) {
    return is_ctype(c, _ALPHA) || c == '_';
}

int UCRTBase::__iswcsym(_wint_t c) {
    return is_ctype(c, _ALPHA) || is_ctype(c, _DIGIT) || c == L'_';
}

int UCRTBase::__iswcsymf(_wint_t c) {
    return is_ctype(c, _ALPHA) || c == L'_';
}

size_t UCRTBase::__strncnt(const char *str, size_t maxsize) {
    if (str == nullptr) {
        return 0;
    }
    size_t count = 0;
    while (count < maxsize && str[count] != '\0') {
        ++count;
    }
    return count;
}

size_t UCRTBase::__wcsncnt(const _wchar_t *str, size_t maxsize) {
    if (str == nullptr) {
        return 0;
    }
    size_t count = 0;
    while (count < maxsize && str[count] != L'\0') {
        ++count;
    }
    return count;
}

int UCRTBase::_isalnum_l(int c, _locale_t locale) {
    return is_ctype(c, _ALPHA);
}

int UCRTBase::_isalpha_l(int c, _locale_t locale) {
    return is_ctype(c, _ALPHA | _DIGIT);
}

int UCRTBase::_isblank_l(int c, _locale_t locale) {
    return is_ctype(c, _BLANK);
}

int UCRTBase::_iscntrl_l(int c, _locale_t locale) {
    return is_ctype(c, _CONTROL);
}

int UCRTBase::_isctype_l(int c, int mask, _locale_t locale) {
    return isctype(c, mask);
}

int UCRTBase::_isctype(int c, int mask) {
    return isctype(c, mask);
}

int UCRTBase::_isdigit_l(int c, _locale_t locale) {
    return is_ctype(c, _DIGIT);
}

int UCRTBase::_isgraph_l(int c, _locale_t locale) {
    return is_ctype(c, _PUNCT | _ALPHA | _DIGIT);
}

int UCRTBase::_isleadbyte_l(int c) {
    // In UTF-8, there are no lead bytes in the traditional sense
    return 0;
}

int UCRTBase::_islower_l(int c, _locale_t locale) {
    return (c >= 'a' && c <= 'z');
}

int UCRTBase::_isprint_l(int c, _locale_t locale) {
    return is_ctype(c, _BLANK | _PUNCT | _ALPHA | _DIGIT);
}

int UCRTBase::_ispunct_l(int c, _locale_t locale) {
    return is_ctype(c, _PUNCT);
}

int UCRTBase::_isspace_l(int c, _locale_t locale) {
    return is_ctype(c, _SPACE);
}

int UCRTBase::_isxdigit_l(int c, _locale_t locale) {
    return is_ctype(c, _HEX);
}

int UCRTBase::_isupper_l(int c, _locale_t locale) {
    return (c >= 'A' && c <= 'Z');
}

int UCRTBase::_iswalnum_l(_wint_t c, _locale_t locale) {
    return iswctype(c, _ALPHA | _DIGIT);
}

int UCRTBase::_iswalpha_l(_wint_t c, _locale_t locale) {
    return iswctype(c, _ALPHA | _DIGIT);
}

int UCRTBase::_iswblank_l(_wint_t c, _locale_t locale) {
    return iswctype(c, _BLANK);
}

int UCRTBase::_iswcntrl_l(_wint_t c, _locale_t locale) {
    return iswctype(c, _CONTROL);
}

int UCRTBase::_iswcsymf_l(_wint_t c, _locale_t locale) {
    return iswctype(c, _ALPHA) || c == L'_';
}

int UCRTBase::_iswctype_l(_wint_t c, int mask, _locale_t locale) {
    return iswctype(c, mask);
}

int UCRTBase::_iswdigit_l(_wint_t c, _locale_t locale) {
    return iswctype(c, _DIGIT);
}

int UCRTBase::_iswgraph_l(_wint_t c, _locale_t locale) {
    return iswctype(c, _PUNCT | _ALPHA | _DIGIT);
}

int UCRTBase::_iswlower_l(_wint_t c, _locale_t locale) {
    return iswctype(c, _LOWER);
}

int UCRTBase::_iswprint_l(_wint_t c, _locale_t locale) {
    return iswctype(c, _BLANK | _PUNCT | _ALPHA | _DIGIT);
}

int UCRTBase::_iswpunct_l(_wint_t c, _locale_t locale) {
    return iswctype(c, _PUNCT);
}

int UCRTBase::_iswspace_l(_wint_t c, _locale_t locale) {
    return iswctype(c, _SPACE);
}

int UCRTBase::_iswxdigit_l(_wint_t c, _locale_t locale) {
    return iswctype(c, _HEX);
}

void * UCRTBase::_memccpy(void *dest, const void *src, int c, size_t n) {
    trace("_memccpy called. Arguments: dest=", std::to_wstring(reinterpret_cast<uintptr_t>(dest)), ", nt_apiset_cpp_hooks=", std::to_wstring(reinterpret_cast<uintptr_t>(src)), ", c=", std::to_wstring(c), ", n=", std::to_wstring(n));
    if (dest == nullptr || src == nullptr || n == 0) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    auto d = static_cast<unsigned char*>(dest);
    const auto s = static_cast<const unsigned char*>(src);
    for (size_t i = 0; i < n; ++i) {
        d[i] = s[i];
        if (s[i] == static_cast<unsigned char>(c)) {
            ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(d + i + 1)));
            return d + i + 1;
        }
    }
    ret("Error set to: -, Return value: nullptr");
    return nullptr;
}

int UCRTBase::_memicmp(const void *buf1, const void *buf2, size_t count) {
    trace("_memicmp called. Arguments: buf1=", std::to_wstring(reinterpret_cast<uintptr_t>(buf1)), ", buf2=", std::to_wstring(reinterpret_cast<uintptr_t>(buf2)), ", count=", std::to_wstring(count));
    if (buf1 == nullptr || buf2 == nullptr) {
        ret("Error set to: EINVAL, Return value: -1");
        errno = EINVAL;
        return -1;
    }
    const auto* p1 = static_cast<const unsigned char*>(buf1);
    const auto* p2 = static_cast<const unsigned char*>(buf2);
    for (size_t i = 0; i < count; ++i) {
        unsigned char c1 = std::tolower(p1[i]);
        unsigned char c2 = std::tolower(p2[i]);
        if (c1 != c2) {
            ret("Error set to: -, Return value: ", std::to_wstring(c1 < c2 ? -1 : 1));
            return (c1 < c2) ? -1 : 1;
        }
    }
    ret("Error set to: -, Return value: 0");
    return 0;
}

int UCRTBase::_memicmp_l(const void *buf1, const void *buf2, size_t count, _locale_t locale) {
    trace("_memicmp_l called. Arguments: buf1=", std::to_wstring(reinterpret_cast<uintptr_t>(buf1)), ", buf2=", std::to_wstring(reinterpret_cast<uintptr_t>(buf2)), ", count=", std::to_wstring(count), ", locale=", reinterpret_cast<intptr_t>(locale));
    return _memicmp(buf1, buf2, count);
}

int UCRTBase::_strcoll_l(const char *str1, const char *str2, _locale_t locale) { // simplified, locale is ignored
    trace("_strcoll_l called. Arguments: str1=", std::wstring(str1 ? str1 : "(null)", str1 ? str1 + strlen(str1) : "(null)"), ", str2=", std::wstring(str2 ? str2 : "(null)", str2 ? str2 + strlen(str2) : "(null)"), ", locale=", reinterpret_cast<intptr_t>(locale));
    if (str1 == nullptr || str2 == nullptr) {
        ret("Error set to: EINVAL, Return value: -1");
        errno = EINVAL;
        return -1;
    }
    const int res = strcmp(str1, str2);
    ret("Error set to: -, Return value: ", std::to_wstring((res < 0) ? -1 : (res > 0) ? 1 : 0));
    return (res < 0) ? -1 : (res > 0) ? 1 : 0;
}

int UCRTBase::_mbscoll(const unsigned char *str1, const unsigned char *str2) { // simplified, locale is ignored
    trace("_mbscoll called. Arguments: str1=", std::wstring(str1 ? reinterpret_cast<const char*>(str1) : "(null)", str1 ? reinterpret_cast<const char*>(str1) + strlen(reinterpret_cast<const char*>(str1)) : "(null)"), ", str2=", std::wstring(str2 ? reinterpret_cast<const char*>(str2) : "(null)", str2 ? reinterpret_cast<const char*>(str2) + strlen(reinterpret_cast<const char*>(str2)) : "(null)"));
    if (str1 == nullptr || str2 == nullptr) {
        ret("Error set to: EINVAL, Return value: -1");
        errno = EINVAL;
        return -1;
    }
    const int res = strcmp(reinterpret_cast<const char*>(str1), reinterpret_cast<const char*>(str2));
    ret("Error set to: -, Return value: ", std::to_wstring((res < 0) ? -1 : (res > 0) ? 1 : 0));
    return (res < 0) ? -1 : (res > 0) ? 1 : 0;
}

int UCRTBase::_mbscoll_l(const unsigned char *str1, const unsigned char *str2, _locale_t locale) { // simplified, locale is ignored
    trace("_mbscoll_l called. Arguments: str1=", std::wstring(str1 ? reinterpret_cast<const char*>(str1) : "(null)", str1 ? reinterpret_cast<const char*>(str1) + strlen(reinterpret_cast<const char*>(str1)) : "(null)"), ", str2=", std::wstring(str2 ? reinterpret_cast<const char*>(str2) : "(null)", str2 ? reinterpret_cast<const char*>(str2) + strlen(reinterpret_cast<const char*>(str2)) : "(null)"), ", locale=", reinterpret_cast<intptr_t>(locale));
    if (str1 == nullptr || str2 == nullptr) {
        ret("Error set to: EINVAL, Return value: -1");
        errno = EINVAL;
        return -1;
    }
    const int res = strcmp(reinterpret_cast<const char*>(str1), reinterpret_cast<const char*>(str2));
    ret("Error set to: -, Return value: ", std::to_wstring((res < 0) ? -1 : (res > 0) ? 1 : 0));
    return (res < 0) ? -1 : (res > 0) ? 1 : 0;
}

std::wstring UCRTBase::LPCWSTR_TO_WSTRING(LPCWSTR str) {
    if (str == nullptr) {
        return L"(null)";
    }
    std::wstring ws(wcslen_(str), L'\0');
    for (size_t i = 0; i < wcslen_(str); ++i) {
        ws[i] = static_cast<wchar_t>(str[i]);
    }
    return ws;
}

int UCRTBase::_wcscoll(const _wchar_t *str1, const _wchar_t *str2) {
    const std::wstring wstr1 = LPCWSTR_TO_WSTRING(str1);
    const std::wstring wstr2 = LPCWSTR_TO_WSTRING(str2);
    trace("_wcscoll called. Arguments: str1=", wstr1, ", str2=", wstr2);
    if (str1 == nullptr || str2 == nullptr) {
        ret("Error set to: EINVAL, Return value: -1");
        errno = EINVAL;
        return -1;
    }
    const int res = wcscmp(wstr1.c_str(), wstr2.c_str());
    ret("Error set to: -, Return value: ", std::to_wstring((res < 0) ? -1 : (res > 0) ? 1 : 0));
    return (res < 0) ? -1 : (res > 0) ? 1 : 0;
}

int UCRTBase::_wcscoll_l(const _wchar_t *str1, const _wchar_t *str2, _locale_t locale) {
    trace("_wcscoll_l called. Arguments: str1=", std::wstring(str1 ? str1 : null, str1 ? str1 + wcslen_(str1) : null), ", str2=", std::wstring(str2 ? str2 : null, str2 ? str2 + wcslen_(str2) : null), ", locale=", reinterpret_cast<intptr_t>(locale));
    return _wcscoll(str1, str2);
}

int UCRTBase::_stricoll(const char *str1, const char *str2) {
    trace("_stricoll called. Arguments: str1=", std::wstring(str1 ? str1 : "(null)", str1 ? str1 + strlen(str1) : "(null)"), ", str2=", std::wstring(str2 ? str2 : "(null)", str2 ? str2 + strlen(str2) : "(null)"));
    if (str1 == nullptr || str2 == nullptr) {
        ret("Error set to: EINVAL, Return value: -1");
        errno = EINVAL;
        return -1;
    }
    const int res = strcasecmp(str1, str2);
    ret("Error set to: -, Return value: ", std::to_wstring((res < 0) ? -1 : (res > 0) ? 1 : 0));
    return (res < 0) ? -1 : (res > 0) ? 1 : 0;
}

int UCRTBase::_stricoll_l(const char *str1, const char *str2, _locale_t locale) {
    trace("_stricoll_l called. Arguments: str1=", std::wstring(str1 ? str1 : "(null)", str1 ? str1 + strlen(str1) : "(null)"), ", str2=", std::wstring(str2 ? str2 : "(null)", str2 ? str2 + strlen(str2) : "(null)"), ", locale=", reinterpret_cast<intptr_t>(locale));
    return _stricoll(str1, str2);
}

int UCRTBase::_wcsicoll(const _wchar_t *str1, const _wchar_t *str2) {
    trace("_wcsicoll called. Arguments: str1=", std::wstring(str1 ? str1 : null, str1 ? str1 + wcslen_(str1) : null), ", str2=", std::wstring(str2 ? str2 : null, str2 ? str2 + wcslen_(str2) : null));
    if (str1 == nullptr || str2 == nullptr) {
        ret("Error set to: EINVAL, Return value: -1");
        errno = EINVAL;
        return -1;
    }
    const std::wstring wtr1 = LPCWSTR_TO_WSTRING(str1);
    const std::wstring wstr2 = LPCWSTR_TO_WSTRING(str2);
    const int res = wcscasecmp(wtr1.c_str(), wstr2.c_str());
    ret("Error set to: -, Return value: ", std::to_wstring((res < 0) ? -1 : (res > 0) ? 1 : 0));
    return (res < 0) ? -1 : (res > 0) ? 1 : 0;
}

int UCRTBase::_wcsicoll_l(const _wchar_t *str1, const _wchar_t *str2, _locale_t locale) {
    trace("_wcsicoll_l called. Arguments: str1=", std::wstring(str1 ? str1 : null, str1 ? str1 + wcslen_(str1) : null), ", str2=", std::wstring(str2 ? str2 : null, str2 ? str2 + wcslen_(str2) : null), ", locale=", reinterpret_cast<intptr_t>(locale));
    return _wcsicoll(str1, str2);
}

int UCRTBase::_mbsicoll(const unsigned char *str1, const unsigned char *str2) {
    trace("_mbsicoll called. Arguments: str1=", std::wstring(str1 ? reinterpret_cast<const char*>(str1) : "(null)", str1 ? reinterpret_cast<const char*>(str1) + strlen(reinterpret_cast<const char*>(str1)) : "(null)"), ", str2=", std::wstring(str2 ? reinterpret_cast<const char*>(str2) : "(null)", str2 ? reinterpret_cast<const char*>(str2) + strlen(reinterpret_cast<const char*>(str2)) : "(null)"));
    if (str1 == nullptr || str2 == nullptr) {
        ret("Error set to: EINVAL, Return value: -1");
        errno = EINVAL;
        return -1;
    }
    const int res = strcasecmp(reinterpret_cast<const char*>(str1), reinterpret_cast<const char*>(str2));
    ret("Error set to: -, Return value: ", std::to_wstring((res < 0) ? -1 : (res > 0) ? 1 : 0));
    return (res < 0) ? -1 : (res > 0) ? 1 : 0;
}

int UCRTBase::_mbsicoll_l(const unsigned char *str1, const unsigned char *str2, _locale_t locale) {
    trace("_mbsicoll_l called. Arguments: str1=", std::wstring(str1 ? reinterpret_cast<const char*>(str1) : "(null)", str1 ? reinterpret_cast<const char*>(str1) + strlen(reinterpret_cast<const char*>(str1)) : "(null)"), ", str2=", std::wstring(str2 ? reinterpret_cast<const char*>(str2) : "(null)", str2 ? reinterpret_cast<const char*>(str2) + strlen(reinterpret_cast<const char*>(str2)) : "(null)"), ", locale=", reinterpret_cast<intptr_t>(locale));
    return _mbsicoll(str1, str2);
}

char * UCRTBase::_strdup(const char *str) {
    trace("_strdup called. Arguments: str=", std::wstring(str ? str : "(null)", str ? str + strlen(str) : "(null)"));
    if (str == nullptr) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    char* res = strdup(str);
    if (res == nullptr) {
        ret("Error set to: errno, Return value: nullptr");
        return nullptr;
    }
    process_info[tls.process].c_mem[res] = {
        .size = strlen(res) + 1
    };
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(res)));
    return res;
}

_wchar_t * UCRTBase::_wcsdup(const _wchar_t *str) {
    trace("_wcsdup called. Arguments: str=", std::wstring(str ? str : null, str ? str + wcslen_(str) : null));
    if (str == nullptr) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    const size_t len = wcslen_(str);
    auto res = static_cast<_wchar_t*>(malloc((len + 1) * sizeof(_wchar_t)));
    if (res == nullptr) {
        ret("Error set to: errno, Return value: nullptr");
        return nullptr;
    }
    wcscpy_(res, str);
    process_info[tls.process].c_mem[res] = {
        .size = (len + 1) * sizeof(_wchar_t)
    };
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(res)));
    return res;
}

unsigned char * UCRTBase::_mbsdup(const unsigned char *str) {
    trace("_mbsdup called. Arguments: str=", std::wstring(str ? reinterpret_cast<const char*>(str) : "(null)", str ? reinterpret_cast<const char*>(str) + strlen(reinterpret_cast<const char*>(str)) : "(null)"));
    if (str == nullptr) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    auto res = reinterpret_cast<unsigned char*>(strdup(reinterpret_cast<const char*>(str)));
    if (res == nullptr) {
        ret("Error set to: errno, Return value: nullptr");
        return nullptr;
    }
    process_info[tls.process].c_mem[res] = {
        .size = strlen(reinterpret_cast<const char*>(res)) + 1
    };
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(res)));
    return res;
}

int UCRTBase::_stricmp(const char *str1, const char *str2) {
    trace("_stricmp called. Arguments: str1=", std::wstring(str1 ? str1 : "(null)", str1 ? str1 + strlen(str1) : "(null)"), ", str2=", std::wstring(str2 ? str2 : "(null)", str2 ? str2 + strlen(str2) : "(null)"));
    if (str1 == nullptr || str2 == nullptr) {
        ret("Error set to: EINVAL, Return value: -1");
        errno = EINVAL;
        return -1;
    }
    const int res = strcasecmp(str1, str2);
    ret("Error set to: -, Return value: ", std::to_wstring((res < 0) ? -1 : (res > 0) ? 1 : 0));
    return (res < 0) ? -1 : (res > 0) ? 1 : 0;
}

int UCRTBase::_stricmp_l(const char *str1, const char *str2, _locale_t locale) {
    trace("_stricmp_l called. Arguments: str1=", std::wstring(str1 ? str1 : "(null)", str1 ? str1 + strlen(str1) : "(null)"), ", str2=", std::wstring(str2 ? str2 : "(null)", str2 ? str2 + strlen(str2) : "(null)"), ", locale=", reinterpret_cast<intptr_t>(locale));
    return _stricmp(str1, str2);
}

int UCRTBase::_wcsicmp(const _wchar_t *str1, const _wchar_t *str2) {
    trace("_wcsicmp called. Arguments: str1=", std::wstring(str1 ? str1 : null, str1 ? str1 + wcslen_(str1) : null), ", str2=", std::wstring(str2 ? str2 : null, str2 ? str2 + wcslen_(str2) : null));
    if (str1 == nullptr || str2 == nullptr) {
        ret("Error set to: EINVAL, Return value: -1");
        errno = EINVAL;
        return -1;
    }
    // Simplified implementation: case-sensitive comparison
    const int res = wcscmp_(str1, str2);
    ret("Error set to: -, Return value: ", std::to_wstring((res < 0) ? -1 : (res > 0) ? 1 : 0));
    return (res < 0) ? -1 : (res > 0) ? 1 : 0;
}

int UCRTBase::_wcsicmp_l(const _wchar_t *str1, const _wchar_t *str2, _locale_t locale) {
    trace("_wcsicmp_l called. Arguments: str1=", std::wstring(str1 ? str1 : null, str1 ? str1 + wcslen_(str1) : null), ", str2=", std::wstring(str2 ? str2 : null, str2 ? str2 + wcslen_(str2) : null), ", locale=", reinterpret_cast<intptr_t>(locale));
    return _wcsicmp(str1, str2);
}

int UCRTBase::_mbsicmp(const unsigned char *str1, const unsigned char *str2) {
    trace("_mbsicmp called. Arguments: str1=", std::wstring(str1 ? reinterpret_cast<const char*>(str1) : "(null)", str1 ? reinterpret_cast<const char*>(str1) + strlen(reinterpret_cast<const char*>(str1)) : "(null)"), ", str2=", std::wstring(str2 ? reinterpret_cast<const char*>(str2) : "(null)", str2 ? reinterpret_cast<const char*>(str2) + strlen(reinterpret_cast<const char*>(str2)) : "(null)"));
    if (str1 == nullptr || str2 == nullptr) {
        ret("Error set to: EINVAL, Return value: -1");
        errno = EINVAL;
        return -1;
    }
    const int res = strcasecmp(reinterpret_cast<const char*>(str1), reinterpret_cast<const char*>(str2));
    ret("Error set to: -, Return value: ", std::to_wstring((res < 0) ? -1 : (res > 0) ? 1 : 0));
    return (res < 0) ? -1 : (res > 0) ? 1 : 0;
}

int UCRTBase::_mbsicmp_l(const unsigned char *str1, const unsigned char *str2, _locale_t locale) {
    trace("_mbsicmp_l called. Arguments: str1=", std::wstring(str1 ? reinterpret_cast<const char*>(str1) : "(null)", str1 ? reinterpret_cast<const char*>(str1) + strlen(reinterpret_cast<const char*>(str1)) : "(null)"), ", str2=", std::wstring(str2 ? reinterpret_cast<const char*>(str2) : "(null)", str2 ? reinterpret_cast<const char*>(str2) + strlen(reinterpret_cast<const char*>(str2)) : "(null)"), ", locale=", reinterpret_cast<intptr_t>(locale));
    return _mbsicmp(str1, str2);
}

char * UCRTBase::_strlwr(char *str) {
    trace("_strlwr called. Arguments: str=", std::wstring(str ? str : "(null)", str ? str + strlen(str) : "(null)"));
    if (str == nullptr) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    for (char* p = str; *p; ++p) {
        *p = static_cast<char>(tolower(*p));
    }
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(str)));
    return str;
}

char * UCRTBase::_strlwr_l(char *str, _locale_t locale) {
    trace("_strlwr_l called. Arguments: str=", std::wstring(str ? str : "(null)", str ? str + strlen(str) : "(null)"), ", locale=", reinterpret_cast<intptr_t>(locale));
    return _strlwr(str);
}

char * UCRTBase::_strlwr_s(char *str, size_t size) {
    trace("_strlwr_s called. Arguments: str=", std::wstring(str ? str : "(null)", str ? str + strlen(str) : "(null)"), ", size=", std::to_wstring(size));
    if (str == nullptr || size == 0) {
        ret("Error set to: EINVAL, Return value: -1");
        errno = EINVAL;
        return nullptr;
    }
    for (size_t i = 0; i < size && str[i] != '\0'; ++i) {
        str[i] = static_cast<char>(tolower(str[i]));
    }
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(str)));
    return str;
}

char * UCRTBase::_strlwr_s_l(char *str, size_t size, _locale_t locale) {
    trace("_strlwr_s_l called. Arguments: str=", std::wstring(str ? str : "(null)", str ? str + strlen(str) : "(null)"), ", size=", std::to_wstring(size), ", locale=", reinterpret_cast<intptr_t>(locale));
    return _strlwr_s(str, size);
}

_wchar_t * UCRTBase::_wcslwr(_wchar_t *str) {
    trace("_wcslwr called. Arguments: str=", std::wstring(str ? str : null, str ? str + wcslen_(str) : null));
    if (str == nullptr) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    for (_wchar_t* p = str; *p; ++p) {
        *p = static_cast<_wchar_t>(towlower(*p));
    }
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(str)));
    return str;
}

_wchar_t * UCRTBase::_wcslwr_l(_wchar_t *str, _locale_t locale) {
    trace("_wcslwr_l called. Arguments: str=", std::wstring(str ? str : null, str ? str + wcslen_(str) : null), ", locale=", reinterpret_cast<intptr_t>(locale));
    return _wcslwr(str);
}

_wchar_t * UCRTBase::_wcslwr_s(_wchar_t *str, size_t size) {
    trace("_wcslwr_s called. Arguments: str=", std::wstring(str ? str : null, str ? str + wcslen_(str) : null), ", size=", std::to_wstring(size));
    if (str == nullptr || size == 0) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    for (size_t i = 0; i < size && str[i] != L'\0'; ++i) {
        str[i] = static_cast<_wchar_t>(towlower(str[i]));
    }
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(str)));
    return str;
}

_wchar_t * UCRTBase::_wcslwr_s_l(_wchar_t *str, size_t size, _locale_t locale) {
    trace("_wcslwr_s_l called. Arguments: str=", std::wstring(str ? str : null, str ? str + wcslen_(str) : null), ", size=", std::to_wstring(size), ", locale=", reinterpret_cast<intptr_t>(locale));
    return _wcslwr_s(str, size);
}

unsigned char * UCRTBase::_mbslwr(unsigned char *str) {
    trace("_mbslwr called. Arguments: str=", std::wstring(str ? reinterpret_cast<const char*>(str) : "(null)", str ? reinterpret_cast<const char*>(str) + strlen(reinterpret_cast<const char*>(str)) : "(null)"));
    if (str == nullptr) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    for (unsigned char* p = str; *p; ++p) {
        *p = static_cast<unsigned char>(tolower(*p));
    }
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(str)));
    return str;
}

unsigned char * UCRTBase::_mbslwr_l(unsigned char *str, _locale_t locale) {
    trace("_mbslwr_l called. Arguments: str=", std::wstring(str ? reinterpret_cast<const char*>(str) : "(null)", str ? reinterpret_cast<const char*>(str) + strlen(reinterpret_cast<const char*>(str)) : "(null)"), ", locale=", reinterpret_cast<intptr_t>(locale));
    return _mbslwr(str);
}

unsigned char * UCRTBase::_mbslwr_s(unsigned char *str, size_t size) {
    trace("_mbslwr_s called. Arguments: str=", std::wstring(str ? reinterpret_cast<const char*>(str) : "(null)", str ? reinterpret_cast<const char*>(str) + strlen(reinterpret_cast<const char*>(str)) : "(null)"), ", size=", std::to_wstring(size));
    if (str == nullptr || size == 0) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    for (size_t i = 0; i < size && str[i] != '\0'; ++i) {
        str[i] = static_cast<unsigned char>(tolower(str[i]));
    }
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(str)));
    return str;
}

unsigned char * UCRTBase::_mbslwr_s_l(unsigned char *str, size_t size, _locale_t locale) {
    trace("_mbslwr_s_l called. Arguments: str=", std::wstring(str ? reinterpret_cast<const char*>(str) : "(null)", str ? reinterpret_cast<const char*>(str) + strlen(reinterpret_cast<const char*>(str)) : "(null)"), ", size=", std::to_wstring(size), ", locale=", reinterpret_cast<intptr_t>(locale));
    return _mbslwr_s(str, size);
}

int UCRTBase::wcscmp_(const _wchar_t *str1, const _wchar_t *str2) {
    if (str1 == nullptr || str2 == nullptr) {
        if (str1 == str2) return 0; // both null
        return (str1 == nullptr) ? -1 : 1; // one is null
    }
    while (*str1 && (*str1 == *str2)) {
        ++str1;
        ++str2;
    }
    return *reinterpret_cast<const UINT*>(str1) < *reinterpret_cast<const UINT*>(str2) ? -1 : *reinterpret_cast<const UINT*>(str1) > *reinterpret_cast<const UINT*>(str2) ? 1 : 0;
}

int UCRTBase::_mbscmp(const unsigned char *str1, const unsigned char *str2) {
    trace("_mbscmp called. Arguments: str1=", std::wstring(str1 ? reinterpret_cast<const char*>(str1) : "(null)", str1 ? reinterpret_cast<const char*>(str1) + strlen(reinterpret_cast<const char*>(str1)) : "(null)"), ", str2=", std::wstring(str2 ? reinterpret_cast<const char*>(str2) : "(null)", str2 ? reinterpret_cast<const char*>(str2) + strlen(reinterpret_cast<const char*>(str2)) : "(null)"));
    if (str1 == nullptr || str2 == nullptr) {
        if (str1 == str2) {
            ret("Error set to: -, Return value: 0");
            return 0; // both null
        }
        ret("Error set to: EINVAL, Return value: ", std::to_wstring((str1 == nullptr) ? -1 : 1));
        errno = EINVAL;
        return (str1 == nullptr) ? -1 : 1; // one is null
    }
    const int res = strcmp(reinterpret_cast<const char*>(str1), reinterpret_cast<const char*>(str2));
    ret("Error set to: -, Return value: ", std::to_wstring((res < 0) ? -1 : (res > 0) ? 1 : 0));
    return (res < 0) ? -1 : (res > 0) ? 1 : 0;
}

int UCRTBase::_mbscmp_l(const unsigned char *str1, const unsigned char *str2, _locale_t locale) {
    trace("_mbscmp_l called. Arguments: str1=", std::wstring(str1 ? reinterpret_cast<const char*>(str1) : "(null)", str1 ? reinterpret_cast<const char*>(str1) + strlen(reinterpret_cast<const char*>(str1)) : "(null)"), ", str2=", std::wstring(str2 ? reinterpret_cast<const char*>(str2) : "(null)", str2 ? reinterpret_cast<const char*>(str2) + strlen(reinterpret_cast<const char*>(str2)) : "(null)"), ", locale=", reinterpret_cast<intptr_t>(locale));
    return _mbscmp(str1, str2);
}

int UCRTBase::_strncoll(const char *str1, const char *str2, size_t count) {
    trace("_strncoll called. Arguments: str1=", std::wstring(str1 ? str1 : "(null)", str1 ? str1 + strlen(str1) : "(null)"), ", str2=", std::wstring(str2 ? str2 : "(null)", str2 ? str2 + strlen(str2) : "(null)"), ", count=", std::to_wstring(count));
    if (str1 == nullptr || str2 == nullptr) {
        ret("Error set to: EINVAL, Return value: -1");
        errno = EINVAL;
        return -1;
    }
    const int res = strncmp(str1, str2, count);
    ret("Error set to: -, Return value: ", std::to_wstring((res < 0) ? -1 : (res > 0) ? 1 : 0));
    return (res < 0) ? -1 : (res > 0) ? 1 : 0;
}

int UCRTBase::_strncoll_l(const char *str1, const char *str2, size_t count, _locale_t locale) {
    trace("_strncoll_l called. Arguments: str1=", std::wstring(str1 ? str1 : "(null)", str1 ? str1 + strlen(str1) : "(null)"), ", str2=", std::wstring(str2 ? str2 : "(null)", str2 ? str2 + strlen(str2) : "(null)"), ", count=", std::to_wstring(count), ", locale=", reinterpret_cast<intptr_t>(locale));
    return _strncoll(str1, str2, count);
}

int UCRTBase::_wcsncoll(const _wchar_t *str1, const _wchar_t *str2, size_t count) {
    trace("_wcsncoll called. Arguments: str1=", std::wstring(str1 ? str1 : null, str1 ? str1 + wcslen_(str1) : null), ", str2=", std::wstring(str2 ? str2 : null, str2 ? str2 + wcslen_(str2) : null), ", count=", std::to_wstring(count));
    if (str1 == nullptr || str2 == nullptr) {
        ret("Error set to: EINVAL, Return value: -1");
        errno = EINVAL;
        return -1;
    }
    size_t i = 0;
    for (; i < count; ++i) {
        if (str1[i] != str2[i] || str1[i] == L'\0' || str2[i] == L'\0') {
            break;
        }
    }
    int res = 0;
    if (i < count) {
        res = (str1[i] < str2[i]) ? -1 : (str1[i] > str2[i]) ? 1 : 0;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(res));
    return res;
}

int UCRTBase::_wcsncoll_l(const _wchar_t *str1, const _wchar_t *str2, size_t count, _locale_t locale) {
    trace("_wcsncoll_l called. Arguments: str1=", std::wstring(str1 ? str1 : null, str1 ? str1 + wcslen_(str1) : null), ", str2=", std::wstring(str2 ? str2 : null, str2 ? str2 + wcslen_(str2) : null), ", count=", std::to_wstring(count), ", locale=", reinterpret_cast<intptr_t>(locale));
    return _wcsncoll(str1, str2, count);
}

int UCRTBase::_mbsncoll(const unsigned char *str1, const unsigned char *str2, size_t count) {
    trace("_mbsncoll called. Arguments: str1=", std::wstring(str1 ? reinterpret_cast<const char*>(str1) : "(null)", str1 ? reinterpret_cast<const char*>(str1) + strlen(reinterpret_cast<const char*>(str1)) : "(null)"), ", str2=", std::wstring(str2 ? reinterpret_cast<const char*>(str2) : "(null)", str2 ? reinterpret_cast<const char*>(str2) + strlen(reinterpret_cast<const char*>(str2)) : "(null)"), ", count=", std::to_wstring(count));
    if (str1 == nullptr || str2 == nullptr) {
        ret("Error set to: EINVAL, Return value: -1");
        errno = EINVAL;
        return -1;
    }
    const int res = strncmp(reinterpret_cast<const char*>(str1), reinterpret_cast<const char*>(str2), count);
    ret("Error set to: -, Return value: ", std::to_wstring((res < 0) ? -1 : (res > 0) ? 1 : 0));
    return (res < 0) ? -1 : (res > 0) ? 1 : 0;
}

int UCRTBase::_mbsncoll_l(const unsigned char *str1, const unsigned char *str2, size_t count, _locale_t locale) {
    trace("_mbsncoll_l called. Arguments: str1=", std::wstring(str1 ? reinterpret_cast<const char*>(str1) : "(null)", str1 ? reinterpret_cast<const char*>(str1) + strlen(reinterpret_cast<const char*>(str1)) : "(null)"), ", str2=", std::wstring(str2 ? reinterpret_cast<const char*>(str2) : "(null)", str2 ? reinterpret_cast<const char*>(str2) + strlen(reinterpret_cast<const char*>(str2)) : "(null)"), ", count=", std::to_wstring(count), ", locale=", reinterpret_cast<intptr_t>(locale));
    return _mbsncoll(str1, str2, count);
}

int UCRTBase::_strnicoll(const char *str1, const char *str2, size_t count) {
    trace("_strnicoll called. Arguments: str1=", std::wstring(str1 ? str1 : "(null)", str1 ? str1 + strlen(str1) : "(null)"), ", str2=", std::wstring(str2 ? str2 : "(null)", str2 ? str2 + strlen(str2) : "(null)"), ", count=", std::to_wstring(count));
    if (str1 == nullptr || str2 == nullptr) {
        ret("Error set to: EINVAL, Return value: -1");
        errno = EINVAL;
        return -1;
    }
    const int res = strncasecmp(str1, str2, count);
    ret("Error set to: -, Return value: ", std::to_wstring((res < 0) ? -1 : (res > 0) ? 1 : 0));
    return (res < 0) ? -1 : (res > 0) ? 1 : 0;
}

int UCRTBase::_strnicoll_l(const char *str1, const char *str2, size_t count, _locale_t locale) {
    trace("_strnicoll_l called. Arguments: str1=", std::wstring(str1 ? str1 : "(null)", str1 ? str1 + strlen(str1) : "(null)"), ", str2=", std::wstring(str2 ? str2 : "(null)", str2 ? str2 + strlen(str2) : "(null)"), ", count=", std::to_wstring(count), ", locale=", reinterpret_cast<intptr_t>(locale));
    return _strnicoll(str1, str2, count);
}

int UCRTBase::_wcsnicoll(const _wchar_t *str1, const _wchar_t *str2, size_t count) {
    trace("_wcsnicoll called. Arguments: str1=", std::wstring(str1 ? str1 : null, str1 ? str1 + wcslen_(str1) : null), ", str2=", std::wstring(str2 ? str2 : null, str2 ? str2 + wcslen_(str2) : null), ", count=", std::to_wstring(count));
    if (str1 == nullptr || str2 == nullptr) {
        ret("Error set to: EINVAL, Return value: -1");
        errno = EINVAL;
        return -1;
    }
    size_t i = 0;
    for (; i < count; ++i) {
        if (towlower(str1[i]) != towlower(str2[i]) || str1[i] == L'\0' || str2[i] == L'\0') {
            break;
        }
    }
    int res = 0;
    if (i < count) {
        res = (str1[i] < str2[i]) ? -1 : (str1[i] > str2[i]) ? 1 : 0;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(res));
    return res;
}

int UCRTBase::_wcsnicoll_l(const _wchar_t *str1, const _wchar_t *str2, size_t count, _locale_t locale) {
    trace("_wcsnicoll_l called. Arguments: str1=", std::wstring(str1 ? str1 : null, str1 ? str1 + wcslen_(str1) : null), ", str2=", std::wstring(str2 ? str2 : null, str2 ? str2 + wcslen_(str2) : null), ", count=", std::to_wstring(count), ", locale=", reinterpret_cast<intptr_t>(locale));
    return _wcsnicoll(str1, str2, count);
}

int UCRTBase::_mbsnicoll(const unsigned char *str1, const unsigned char *str2, size_t count) {
    trace("_mbsnicoll called. Arguments: str1=", std::wstring(str1 ? reinterpret_cast<const char*>(str1) : "(null)", str1 ? reinterpret_cast<const char*>(str1) + strlen(reinterpret_cast<const char*>(str1)) : "(null)"), ", str2=", std::wstring(str2 ? reinterpret_cast<const char*>(str2) : "(null)", str2 ? reinterpret_cast<const char*>(str2) + strlen(reinterpret_cast<const char*>(str2)) : "(null)"), ", count=", std::to_wstring(count));
    if (str1 == nullptr || str2 == nullptr) {
        ret("Error set to: EINVAL, Return value: -1");
        errno = EINVAL;
        return -1;
    }
    const int res = strncasecmp(reinterpret_cast<const char*>(str1), reinterpret_cast<const char*>(str2), count);
    ret("Error set to: -, Return value: ", std::to_wstring((res < 0) ? -1 : (res > 0) ? 1 : 0));
    return (res < 0) ? -1 : (res > 0) ? 1 : 0;
}

int UCRTBase::_mbsnicoll_l(const unsigned char *str1, const unsigned char *str2, size_t count, _locale_t locale) {
    trace("_mbsnicoll_l called. Arguments: str1=", std::wstring(str1 ? reinterpret_cast<const char*>(str1) : "(null)", str1 ? reinterpret_cast<const char*>(str1) + strlen(reinterpret_cast<const char*>(str1)) : "(null)"), ", str2=", std::wstring(str2 ? reinterpret_cast<const char*>(str2) : "(null)", str2 ? reinterpret_cast<const char*>(str2) + strlen(reinterpret_cast<const char*>(str2)) : "(null)"), ", count=", std::to_wstring(count), ", locale=", reinterpret_cast<intptr_t>(locale));
    return _mbsnicoll(str1, str2, count);
}

char * UCRTBase::_strnset(char *str, int c, size_t count) {
    trace("_strnset called. Arguments: str=", std::wstring(str ? str : "(null)", str ? str + strlen(str) : "(null)"), ", c=", std::to_wstring(c), ", count=", std::to_wstring(count));
    if (str == nullptr) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    for (size_t i = 0; i < count && str[i] != '\0'; ++i) {
        str[i] = static_cast<char>(c);
    }
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(str)));
    return str;
}

char * UCRTBase::_strnset_l(char *str, int c, size_t count, _locale_t locale) {
    trace("_strnset_l called. Arguments: str=", std::wstring(str ? str : "(null)", str ? str + strlen(str) : "(null)"), ", c=", std::to_wstring(c), ", count=", std::to_wstring(count), ", locale=", reinterpret_cast<intptr_t>(locale));
    return _strnset(str, c, count);
}

errno_t UCRTBase::_strnset_s(char *str, size_t size, int c, size_t count) {
    trace("_strnset_s called. Arguments: str=", std::wstring(str ? str : "(null)", str ? str + strlen(str) : "(null)"), ", size=", std::to_wstring(size), ", c=", std::to_wstring(c), ", count=", std::to_wstring(count));
    if (str == nullptr || size == 0 || count > size) {
        ret("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    for (size_t i = 0; i < count && i < size && str[i] != '\0'; ++i) {
        str[i] = static_cast<char>(c);
    }
    ret("Error set to: -, Return value: 0");
    return 0;
}

errno_t UCRTBase::_strnset_s_l(char *str, size_t size, int c, size_t count, _locale_t locale) {
    trace("_strnset_s_l called. Arguments: str=", std::wstring(str ? str : "(null)", str ? str + strlen(str) : "(null)"), ", size=", std::to_wstring(size), ", c=", std::to_wstring(c), ", count=", std::to_wstring(count), ", locale=", reinterpret_cast<intptr_t>(locale));
    return _strnset_s(str, size, c, count);
}

_wchar_t * UCRTBase::_wcsnset(_wchar_t *str, _wchar_t c, size_t count) {
    trace("_wcsnset called. Arguments: str=", std::wstring(str ? str : null, str ? str + wcslen_(str) : null), ", c=", std::to_wstring(c), ", count=", std::to_wstring(count));
    if (str == nullptr) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    for (size_t i = 0; i < count && str[i] != L'\0'; ++i) {
        str[i] = c;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(str)));
    return str;
}

_wchar_t * UCRTBase::_wcsnset_l(_wchar_t *str, _wchar_t c, size_t count, _locale_t locale) {
    trace("_wcsnset_l called. Arguments: str=", std::wstring(str ? str : null, str ? str + wcslen_(str) : null), ", c=", std::to_wstring(c), ", count=", std::to_wstring(count), ", locale=", reinterpret_cast<intptr_t>(locale));
    return _wcsnset(str, c, count);
}

errno_t UCRTBase::_wcsnset_s(_wchar_t *str, size_t size, _wchar_t c, size_t count) {
    trace("_wcsnset_s called. Arguments: str=", std::wstring(str ? str : null, str ? str + wcslen_(str) : null), ", size=", std::to_wstring(size), ", c=", std::to_wstring(c), ", count=", std::to_wstring(count));
    if (str == nullptr || size == 0 || count > size) {
        ret("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    for (size_t i = 0; i < count && i < size && str[i] != L'\0'; ++i) {
        str[i] = c;
    }
    ret("Error set to: -, Return value: 0");
    return 0;
}

errno_t UCRTBase::_wcsnset_s_l(_wchar_t *str, size_t size, _wchar_t c, size_t count, _locale_t locale) {
    trace("_wcsnset_s_l called. Arguments: str=", std::wstring(str ? str : null, str ? str + wcslen_(str) : null), ", size=", std::to_wstring(size), ", c=", std::to_wstring(c), ", count=", std::to_wstring(count), ", locale=", reinterpret_cast<intptr_t>(locale));
    return _wcsnset_s(str, size, c, count);
}

unsigned char * UCRTBase::_mbsnset(unsigned char *str, unsigned char c, size_t count) {
    trace("_mbsnset called. Arguments: str=", std::wstring(str ? reinterpret_cast<const char*>(str) : "(null)", str ? reinterpret_cast<const char*>(str) + strlen(reinterpret_cast<const char*>(str)) : "(null)"), ", c=", std::to_wstring(c), ", count=", std::to_wstring(count));
    if (str == nullptr) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    for (size_t i = 0; i < count && str[i] != '\0'; ++i) {
        str[i] = c;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(str)));
    return str;
}

unsigned char * UCRTBase::_mbsnset_l(unsigned char *str, unsigned char c, size_t count, _locale_t locale) {
    trace("_mbsnset_l called. Arguments: str=", std::wstring(str ? reinterpret_cast<const char*>(str) : "(null)", str ? reinterpret_cast<const char*>(str) + strlen(reinterpret_cast<const char*>(str)) : "(null)"), ", c=", std::to_wstring(c), ", count=", std::to_wstring(count), ", locale=", reinterpret_cast<intptr_t>(locale));
    return _mbsnset(str, c, count);
}

errno_t UCRTBase::_mbsnset_s(unsigned char *str, size_t size, unsigned char c, size_t count) {
    trace("_mbsnset_s called. Arguments: str=", std::wstring(str ? reinterpret_cast<const char*>(str) : "(null)", str ? reinterpret_cast<const char*>(str) + strlen(reinterpret_cast<const char*>(str)) : "(null)"), ", size=", std::to_wstring(size), ", c=", std::to_wstring(c), ", count=", std::to_wstring(count));
    if (str == nullptr || size == 0 || count > size) {
        ret("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    for (size_t i = 0; i < count && i < size && str[i] != '\0'; ++i) {
        str[i] = c;
    }
    ret("Error set to: -, Return value: 0");
    return 0;
}

errno_t UCRTBase::_mbsnset_s_l(unsigned char *str, size_t size, unsigned char c, size_t count, _locale_t locale) {
    trace("_mbsnset_s_l called. Arguments: str=", std::wstring(str ? reinterpret_cast<const char*>(str) : "(null)", str ? reinterpret_cast<const char*>(str) + strlen(reinterpret_cast<const char*>(str)) : "(null)"), ", size=", std::to_wstring(size), ", c=", std::to_wstring(c), ", count=", std::to_wstring(count), ", locale=", reinterpret_cast<intptr_t>(locale));
    return _mbsnset_s(str, size, c, count);
}

char * UCRTBase::_strset(char *str, int c) {
    trace("_strset called. Arguments: str=", std::wstring(str ? str : "(null)", str ? str + strlen(str) : "(null)"), ", c=", std::to_wstring(c));
    if (str == nullptr) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    for (char* p = str; *p; ++p) {
        *p = static_cast<char>(c);
    }
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(str)));
    return str;
}

char * UCRTBase::_strset_l(char *str, int c, _locale_t locale) {
    trace("_strset_l called. Arguments: str=", std::wstring(str ? str : "(null)", str ? str + strlen(str) : "(null)"), ", c=", std::to_wstring(c), ", locale=", reinterpret_cast<intptr_t>(locale));
    return _strset(str, c);
}

errno_t UCRTBase::_strset_s(char *str, size_t size, int c) {
    trace("_strset_s called. Arguments: str=", std::wstring(str ? str : "(null)", str ? str + strlen(str) : "(null)"), ", size=", std::to_wstring(size), ", c=", std::to_wstring(c));
    if (str == nullptr || size == 0) {
        ret("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    for (size_t i = 0; i < size && str[i] != '\0'; ++i) {
        str[i] = static_cast<char>(c);
    }
    ret("Error set to: -, Return value: 0");
    return 0;
}

errno_t UCRTBase::_strset_s_l(char *str, size_t size, int c, _locale_t locale) {
    trace("_strset_s_l called. Arguments: str=", std::wstring(str ? str : "(null)", str ? str + strlen(str) : "(null)"), ", size=", std::to_wstring(size), ", c=", std::to_wstring(c), ", locale=", reinterpret_cast<intptr_t>(locale));
    return _strset_s(str, size, c);
}

_wchar_t * UCRTBase::_wcsset(_wchar_t *str, _wchar_t c) {
    trace("_wcsset called. Arguments: str=", std::wstring(str ? str : null, str ? str + wcslen_(str) : null), ", c=", std::to_wstring(c));
    if (str == nullptr) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    for (_wchar_t* p = str; *p; ++p) {
        *p = c;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(str)));
    return str;
}

_wchar_t * UCRTBase::_wcsset_l(_wchar_t *str, _wchar_t c, _locale_t locale) {
    trace("_wcsset_l called. Arguments: str=", std::wstring(str ? str : null, str ? str + wcslen_(str) : null), ", c=", std::to_wstring(c), ", locale=", reinterpret_cast<intptr_t>(locale));
    return _wcsset(str, c);
}

errno_t UCRTBase::_wcsset_s(_wchar_t *str, size_t size, _wchar_t c) {
    trace("_wcsset_s called. Arguments: str=", std::wstring(str ? str : null, str ? str + wcslen_(str) : null), ", size=", std::to_wstring(size), ", c=", std::to_wstring(c));
    if (str == nullptr || size == 0) {
        ret("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    for (size_t i = 0; i < size && str[i] != L'\0'; ++i) {
        str[i] = c;
    }
    ret("Error set to: -, Return value: 0");
    return 0;
}

errno_t UCRTBase::_wcsset_s_l(_wchar_t *str, size_t size, _wchar_t c, _locale_t locale) {
    trace("_wcsset_s_l called. Arguments: str=", std::wstring(str ? str : null, str ? str + wcslen_(str) : null), ", size=", std::to_wstring(size), ", c=", std::to_wstring(c), ", locale=", reinterpret_cast<intptr_t>(locale));
    return _wcsset_s(str, size, c);
}

unsigned char * UCRTBase::_mbsset(unsigned char *str, unsigned char c) {
    trace("_mbsset called. Arguments: str=", std::wstring(str ? reinterpret_cast<const char*>(str) : "(null)", str ? reinterpret_cast<const char*>(str) + strlen(reinterpret_cast<const char*>(str)) : "(null)"), ", c=", std::to_wstring(c));
    if (str == nullptr) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    for (unsigned char* p = str; *p; ++p) {
        *p = c;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(str)));
    return str;
}

unsigned char * UCRTBase::_mbsset_l(unsigned char *str, unsigned char c, _locale_t locale) {
    trace("_mbsset_l called. Arguments: str=", std::wstring(str ? reinterpret_cast<const char*>(str) : "(null)", str ? reinterpret_cast<const char*>(str) + strlen(reinterpret_cast<const char*>(str)) : "(null)"), ", c=", std::to_wstring(c), ", locale=", reinterpret_cast<intptr_t>(locale));
    return _mbsset(str, c);
}

errno_t UCRTBase::_mbsset_s(unsigned char *str, size_t size, unsigned char c) {
    trace("_mbsset_s called. Arguments: str=", std::wstring(str ? reinterpret_cast<const char*>(str) : "(null)", str ? reinterpret_cast<const char*>(str) + strlen(reinterpret_cast<const char*>(str)) : "(null)"), ", size=", std::to_wstring(size), ", c=", std::to_wstring(c));
    if (str == nullptr || size == 0) {
        ret("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    for (size_t i = 0; i < size && str[i] != '\0'; ++i) {
        str[i] = c;
    }
    ret("Error set to: -, Return value: 0");
    return 0;
}

errno_t UCRTBase::_mbsset_s_l(unsigned char *str, size_t size, unsigned char c, _locale_t locale) {
    trace("_mbsset_s_l called. Arguments: str=", std::wstring(str ? reinterpret_cast<const char*>(str) : "(null)", str ? reinterpret_cast<const char*>(str) + strlen(reinterpret_cast<const char*>(str)) : "(null)"), ", size=", std::to_wstring(size), ", c=", std::to_wstring(c), ", locale=", reinterpret_cast<intptr_t>(locale));
    return _mbsset_s(str, size, c);
}

char * UCRTBase::_strrev(char *str) {
    trace("_strrev called. Arguments: str=", std::wstring(str ? str : "(null)", str ? str + strlen(str) : "(null)"));
    if (str == nullptr) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    std::reverse(str, str + strlen(str));
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(str)));
    return str;
}

_wchar_t * UCRTBase::_wcsrev(_wchar_t *str) {
    trace("_wcsrev called. Arguments: str=", std::wstring(str ? str : null, str ? str + wcslen_(str) : null));
    if (str == nullptr) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    std::reverse(str, str + wcslen_(str));
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(str)));
    return str;
}

unsigned char * UCRTBase::_mbsrev(unsigned char *str) {
    trace("_mbsrev called. Arguments: str=", std::wstring(str ? reinterpret_cast<const char*>(str) : "(null)", str ? reinterpret_cast<const char*>(str) + strlen(reinterpret_cast<const char*>(str)) : "(null)"));
    if (str == nullptr) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    std::reverse(str, str + strlen(reinterpret_cast<const char*>(str)));
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(str)));
    return str;
}

unsigned char * UCRTBase::_mbsrev_l(unsigned char *str, _locale_t locale) {
    trace("_mbsrev_l called. Arguments: str=", std::wstring(str ? reinterpret_cast<const char*>(str) : "(null)", str ? reinterpret_cast<const char*>(str) + strlen(reinterpret_cast<const char*>(str)) : "(null)"), ", locale=", reinterpret_cast<intptr_t>(locale));
    return _mbsrev(str);
}

char * UCRTBase::_strupr(char *str) {
    trace("_strupr called. Arguments: str=", std::wstring(str ? str : "(null)", str ? str + strlen(str) : "(null)"));
    if (str == nullptr) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    for (char* p = str; *p; ++p) {
        *p = static_cast<char>(toupper(*p));
    }
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(str)));
    return str;
}

char * UCRTBase::_strupr_l(char *str, _locale_t locale) {
    trace("_strupr_l called. Arguments: str=", std::wstring(str ? str : "(null)", str ? str + strlen(str) : "(null)"), ", locale=", reinterpret_cast<intptr_t>(locale));
    return _strupr(str);
}

errno_t UCRTBase::_strupr_s(char *str, size_t size) {
    trace("_strupr_s called. Arguments: str=", std::wstring(str ? str : "(null)", str ? str + strlen(str) : "(null)"), ", size=", std::to_wstring(size));
    if (str == nullptr || size == 0) {
        ret("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    for (size_t i = 0; i < size && str[i] != '\0'; ++i) {
        str[i] = static_cast<char>(toupper(str[i]));
    }
    ret("Error set to: -, Return value: 0");
    return 0;
}

errno_t UCRTBase::_strupr_s_l(char *str, size_t size, _locale_t locale) {
    trace("_strupr_s_l called. Arguments: str=", std::wstring(str ? str : "(null)", str ? str + strlen(str) : "(null)"), ", size=", std::to_wstring(size), ", locale=", reinterpret_cast<intptr_t>(locale));
    return _strupr_s(str, size);
}

_wchar_t * UCRTBase::_wcsupr(_wchar_t *str) {
    trace("_wcsupr called. Arguments: str=", std::wstring(str ? str : null, str ? str + wcslen_(str) : null));
    if (str == nullptr) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    for (_wchar_t* p = str; *p; ++p) {
        *p = static_cast<_wchar_t>(towupper(*p));
    }
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(str)));
    return str;
}

_wchar_t * UCRTBase::_wcsupr_l(_wchar_t *str, _locale_t locale) {
    trace("_wcsupr_l called. Arguments: str=", std::wstring(str ? str : null, str ? str + wcslen_(str) : null), ", locale=", reinterpret_cast<intptr_t>(locale));
    return _wcsupr(str);
}

errno_t UCRTBase::_wcsupr_s(_wchar_t *str, size_t size) {
    trace("_wcsupr_s called. Arguments: str=", std::wstring(str ? str : null, str ? str + wcslen_(str) : null), ", size=", std::to_wstring(size));
    if (str == nullptr || size == 0) {
        ret("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    for (size_t i = 0; i < size && str[i] != L'\0'; ++i) {
        str[i] = static_cast<_wchar_t>(towupper(str[i]));
    }
    ret("Error set to: -, Return value: 0");
    return 0;
}

errno_t UCRTBase::_wcsupr_s_l(_wchar_t *str, size_t size, _locale_t locale) {
    trace("_wcsupr_s_l called. Arguments: str=", std::wstring(str ? str : null, str ? str + wcslen_(str) : null), ", size=", std::to_wstring(size), ", locale=", reinterpret_cast<intptr_t>(locale));
    return _wcsupr_s(str, size);
}

size_t UCRTBase::strxfrm(char *dest, const char *src, size_t count) {
    trace("strxfrm called. Arguments: dest=", std::wstring(dest ? dest : "(null)", dest ? dest + strlen(dest) : "(null)"), ", nt_apiset_cpp_hooks=", std::wstring(src ? src : "(null)", src ? src + strlen(src) : "(null)"), ", count=", std::to_wstring(count));
    if (dest == nullptr || src == nullptr) {
        ret("Error set to: EINVAL, Return value: 0");
        errno = EINVAL;
        return 0;
    }
    size_t i = 0;
    for (; i < count - 1 && src[i] != '\0'; ++i) {
        dest[i] = src[i];
    }
    if (count > 0) {
        dest[i] = '\0';
    }
    while (src[i] != '\0') {
        ++i;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(i));
    return i;
}

size_t UCRTBase::_strxfrm_l(char *dest, const char *src, size_t count, _locale_t locale) {
    trace("_strxfrm_l called. Arguments: dest=", std::wstring(dest ? dest : "(null)", dest ? dest + strlen(dest) : "(null)"), ", nt_apiset_cpp_hooks=", std::wstring(src ? src : "(null)", src ? src + strlen(src) : "(null)"), ", count=", std::to_wstring(count), ", locale=", reinterpret_cast<intptr_t>(locale));
    return strxfrm(dest, src, count);
}

size_t UCRTBase::wcsxfrm(_wchar_t *dest, const _wchar_t *src, size_t count) {
    trace("wcsxfrm called. Arguments: dest=", std::wstring(dest ? dest : null, dest ? dest + wcslen_(dest) : null), ", nt_apiset_cpp_hooks=", std::wstring(src ? src : null, src ? src + wcslen_(src) : null), ", count=", std::to_wstring(count));
    if (dest == nullptr || src == nullptr) {
        ret("Error set to: EINVAL, Return value: 0");
        errno = EINVAL;
        return 0;
    }
    size_t i = 0;
    for (; i < count - 1 && src[i] != L'\0'; ++i) {
        dest[i] = src[i];
    }
    if (count > 0) {
        dest[i] = L'\0';
    }
    while (src[i] != L'\0') {
        ++i;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(i));
    return i;
}

size_t UCRTBase::_wcsxfrm_l(_wchar_t *dest, const _wchar_t *src, size_t count, _locale_t locale) {
    trace("_wcsxfrm_l called. Arguments: dest=", std::wstring(dest ? dest : null, dest ? dest + wcslen_(dest) : null), ", nt_apiset_cpp_hooks=", std::wstring(src ? src : null, src ? src + wcslen_(src) : null), ", count=", std::to_wstring(count), ", locale=", reinterpret_cast<intptr_t>(locale));
    return wcsxfrm(dest, src, count);
}

int UCRTBase::_tolower(int c) {
    trace("_tolower called. Arguments: c=", std::to_wstring(c));
    if (c < 0 || c > 255) {
        ret("Error set to: EINVAL, Return value: ", std::to_wstring(c));
        errno = EINVAL;
        return c;
    }
    const int res = tolower(c);
    ret("Error set to: -, Return value: ", std::to_wstring(res));
    return res;
}

int UCRTBase::_tolower_l(int c, _locale_t locale) {
    trace("_tolower_l called. Arguments: c=", std::to_wstring(c), ", locale=", reinterpret_cast<intptr_t>(locale));
    return _tolower(c);
}

int UCRTBase::_toupper(int c) {
    trace("_toupper called. Arguments: c=", std::to_wstring(c));
    if (c < 0 || c > 255) {
        ret("Error set to: EINVAL, Return value: ", std::to_wstring(c));
        errno = EINVAL;
        return c;
    }
    const int res = toupper(c);
    ret("Error set to: -, Return value: ", std::to_wstring(res));
    return res;
}

int UCRTBase::_toupper_l(int c, _locale_t locale) {
    trace("_toupper_l called. Arguments: c=", std::to_wstring(c), ", locale=", reinterpret_cast<intptr_t>(locale));
    return _toupper(c);
}

int UCRTBase::towlower_(_wint_t c) {
    trace("towlower called. Arguments: c=", std::to_wstring(c));
    if (c < 0 || c > 0x10FFFF) {
        ret("Error set to: EINVAL, Return value: ", std::to_wstring(c));
        errno = EINVAL;
        return c;
    }
    const int res = std::towlower(c);
    ret("Error set to: -, Return value: ", std::to_wstring(res));
    return res;
}

int UCRTBase::_towlower_l(_wint_t c, _locale_t locale) {
    trace("_towlower_l called. Arguments: c=", std::to_wstring(c), ", locale=", reinterpret_cast<intptr_t>(locale));
    return towlower_(c);
}

int UCRTBase::towupper_(_wint_t c) {
    trace("towupper called. Arguments: c=", std::to_wstring(c));
    if (c < 0 || c > 0x10FFFF) {
        ret("Error set to: EINVAL, Return value: ", std::to_wstring(c));
        errno = EINVAL;
        return c;
    }
    const int res = std::towupper(c);
    ret("Error set to: -, Return value: ", std::to_wstring(res));
    return res;
}

int UCRTBase::_towupper_l(_wint_t c, _locale_t locale) {
    trace("_towupper_l called. Arguments: c=", std::to_wstring(c), ", locale=", reinterpret_cast<intptr_t>(locale));
    return towupper_(c);
}

int UCRTBase::is_ctype(int c, int ctype) {
    trace("is_ctype called. Arguments: c=", std::to_wstring(c), ", ctype=", std::to_wstring(ctype));
    return isctype(c, ctype);
}

int UCRTBase::is_wctype(_wint_t c, _wctype_t ctype) {
    trace("is_wctype called. Arguments: c=", std::to_wstring(c), ", ctype=", std::to_wstring(ctype));
    return iswctype(c, ctype);
}

int UCRTBase::isalpha_(int c) {
    trace("isalpha called. Arguments: c=", std::to_wstring(c));
    if (c < 0 || c > 255) {
        ret("Error set to: EINVAL, Return value: 0");
        errno = EINVAL;
        return 0;
    }
    const int res = isalpha(c);
    ret("Error set to: -, Return value: ", std::to_wstring(res));
    return res;
}

int UCRTBase::isblank_(int c) {
    trace("isblank called. Arguments: c=", std::to_wstring(c));
    if (c < 0 || c > 255) {
        ret("Error set to: EINVAL, Return value: 0");
        errno = EINVAL;
        return 0;
    }
    const int res = (c == ' ' || c == '\t') ? 1 : 0;
    ret("Error set to: -, Return value: ", std::to_wstring(res));
    return res;
}

int UCRTBase::iscntrl_(int c) {
    trace("iscntrl called. Arguments: c=", std::to_wstring(c));
    if (c < 0 || c > 255) {
        ret("Error set to: EINVAL, Return value: 0");
        errno = EINVAL;
        return 0;
    }
    const int res = iscntrl(c);
    ret("Error set to: -, Return value: ", std::to_wstring(res));
    return res;
}

int UCRTBase::isdigit_(int c) {
    trace("isdigit called. Arguments: c=", std::to_wstring(c));
    if (c < 0 || c > 255) {
        ret("Error set to: EINVAL, Return value: 0");
        errno = EINVAL;
        return 0;
    }
    const int res = isdigit(c);
    ret("Error set to: -, Return value: ", std::to_wstring(res));
    return res;

}

int UCRTBase::isgraph_(int c) {
    trace("isgraph called. Arguments: c=", std::to_wstring(c));
    if (c < 0 || c > 255) {
        ret("Error set to: EINVAL, Return value: 0");
        errno = EINVAL;
        return 0;
    }
    const int res = isgraph(c);
    ret("Error set to: -, Return value: ", std::to_wstring(res));
    return res;
}

int UCRTBase::isleadbyte_(int c) {
    trace("isleadbyte called. Arguments: c=", std::to_wstring(c));
    if (c < 0 || c > 255) {
        ret("Error set to: EINVAL, Return value: 0");
        errno = EINVAL;
        return 0;
    }
    // assume utf-8
    constexpr int res = 0;
    ret("Error set to: -, Return value: ", std::to_wstring(res));
    return res;
}

int UCRTBase::islower_(int c) {
    trace("islower called. Arguments: c=", std::to_wstring(c));
    if (c < 0 || c > 255) {
        ret("Error set to: EINVAL, Return value: 0");
        errno = EINVAL;
        return 0;
    }
    const int res = islower(c);
    ret("Error set to: -, Return value: ", std::to_wstring(res));
    return res;
}
int UCRTBase::isprint_(int c) {
    trace("isprint called. Arguments: c=", std::to_wstring(c));
    if (c < 0 || c > 255) {
        ret("Error set to: EINVAL, Return value: 0");
        errno = EINVAL;
        return 0;
    }
    const int res = isprint(c);
    ret("Error set to: -, Return value: ", std::to_wstring(res));
    return res;
}

int UCRTBase::ispunct_(int c) {
    trace("ispunct called. Arguments: c=", std::to_wstring(c));
    if (c < 0 || c > 255) {
        ret("Error set to: EINVAL, Return value: 0");
        errno = EINVAL;
        return 0;
    }
    const int res = ispunct(c);
    ret("Error set to: -, Return value: ", std::to_wstring(res));
    return res;
}


int UCRTBase::isspace_(int c) {
    trace("isspace called. Arguments: c=", std::to_wstring(c));
    if (c < 0 || c > 255) {
        ret("Error set to: EINVAL, Return value: 0");
        errno = EINVAL;
        return 0;
    }
    const int res = isspace(c);
    ret("Error set to: -, Return value: ", std::to_wstring(res));
    return res;
}

int UCRTBase::isupper_(int c) {
    trace("isupper called. Arguments: c=", std::to_wstring(c));
    if (c < 0 || c > 255) {
        ret("Error set to: EINVAL, Return value: 0");
        errno = EINVAL;
        return 0;
    }
    const int res = isupper(c);
    ret("Error set to: -, Return value: ", std::to_wstring(res));
    return res;
}

int UCRTBase::isxdigit_(int c) {
    trace("isxdigit called. Arguments: c=", std::to_wstring(c));
    if (c < 0 || c > 255) {
        ret("Error set to: EINVAL, Return value: 0");
        errno = EINVAL;
        return 0;
    }
    const int res = isxdigit(c);
    ret("Error set to: -, Return value: ", std::to_wstring(res));
    return res;
}

int UCRTBase::iswalnum_(_wint_t c) {
    trace("iswalnum called. Arguments: c=", std::to_wstring(c));
    if (c < 0 || c > 0x10FFFF) {
        ret("Error set to: EINVAL, Return value: 0");
        errno = EINVAL;
        return 0;
    }
    const int res = iswalnum(c);
    ret("Error set to: -, Return value: ", std::to_wstring(res));
    return res;
}

int UCRTBase::iswalpha_(_wint_t c) {
    trace("iswalpha called. Arguments: c=", std::to_wstring(c));
    if (c < 0 || c > 0x10FFFF) {
        ret("Error set to: EINVAL, Return value: 0");
        errno = EINVAL;
        return 0;
    }
    const int res = iswalpha(c);
    ret("Error set to: -, Return value: ", std::to_wstring(res));
    return res;
}

int UCRTBase::iswblank_(_wint_t c) {
    trace("iswblank called. Arguments: c=", std::to_wstring(c));
    if (c < 0 || c > 0x10FFFF) {
        ret("Error set to: EINVAL, Return value: 0");
        errno = EINVAL;
        return 0;
    }
    const int res = iswblank(c);
    ret("Error set to: -, Return value: ", std::to_wstring(res));
    return res;
}

int UCRTBase::iswcntrl_(_wint_t c) {
    trace("iswcntrl called. Arguments: c=", std::to_wstring(c));
    if (c < 0 || c > 0x10FFFF) {
        ret("Error set to: EINVAL, Return value: 0");
        errno = EINVAL;
        return 0;
    }
    const int res = iswcntrl(c);
    ret("Error set to: -, Return value: ", std::to_wstring(res));
    return res;
}

int UCRTBase::iswctype_(_wint_t c, _wctype_t ctype) {
    trace("iswctype called. Arguments: c=", std::to_wstring(c), ", ctype=", std::to_wstring(ctype));
    if (c < 0 || c > 0x10FFFF) {
        ret("Error set to: EINVAL, Return value: 0");
        errno = EINVAL;
        return 0;
    }
    const int res = iswctype(c, ctype);
    ret("Error set to: -, Return value: ", std::to_wstring(res));
    return res;
}

int UCRTBase::iswdigit_(_wint_t c) {
    trace("iswdigit called. Arguments: c=", std::to_wstring(c));
    if (c < 0 || c > 0x10FFFF) {
        ret("Error set to: EINVAL, Return value: 0");
        errno = EINVAL;
        return 0;
    }
    const int res = iswdigit(c);
    ret("Error set to: -, Return value: ", std::to_wstring(res));
    return res;
}

int UCRTBase::iswgraph_(_wint_t c) {
    trace("iswgraph called. Arguments: c=", std::to_wstring(c));
    if (c < 0 || c > 0x10FFFF) {
        ret("Error set to: EINVAL, Return value: 0");
        errno = EINVAL;
        return 0;
    }
    const int res = iswgraph(c);
    ret("Error set to: -, Return value: ", std::to_wstring(res));
    return res;
}

int UCRTBase::iswlower_(_wint_t c) {
    trace("iswlower called. Arguments: c=", std::to_wstring(c));
    if (c < 0 || c > 0x10FFFF) {
        ret("Error set to: EINVAL, Return value: 0");
        errno = EINVAL;
        return 0;
    }
    const int res = iswlower(c);
    ret("Error set to: -, Return value: ", std::to_wstring(res));
    return res;
}

int UCRTBase::iswprint_(_wint_t c) {
    trace("iswprint called. Arguments: c=", std::to_wstring(c));
    if (c < 0 || c > 0x10FFFF) {
        ret("Error set to: EINVAL, Return value: 0");
        errno = EINVAL;
        return 0;
    }
    const int res = iswprint(c);
    ret("Error set to: -, Return value: ", std::to_wstring(res));
    return res;
}

int UCRTBase::iswpunct_(_wint_t c) {
    trace("iswpunct called. Arguments: c=", std::to_wstring(c));
    if (c < 0 || c > 0x10FFFF) {
        ret("Error set to: EINVAL, Return value: 0");
        errno = EINVAL;
        return 0;
    }
    const int res = iswpunct(c);
    ret("Error set to: -, Return value: ", std::to_wstring(res));
    return res;
}

int UCRTBase::iswspace_(_wint_t c) {
    trace("iswspace called. Arguments: c=", std::to_wstring(c));
    if (c < 0 || c > 0x10FFFF) {
        ret("Error set to: EINVAL, Return value: 0");
        errno = EINVAL;
        return 0;
    }
    const int res = iswspace(c);
    ret("Error set to: -, Return value: ", std::to_wstring(res));
    return res;
}

int UCRTBase::iswupper_(_wint_t c) {
    trace("iswupper called. Arguments: c=", std::to_wstring(c));
    if (c < 0 || c > 0x10FFFF) {
        ret("Error set to: EINVAL, Return value: 0");
        errno = EINVAL;
        return 0;
    }
    const int res = iswupper(c);
    ret("Error set to: -, Return value: ", std::to_wstring(res));
    return res;
}

int UCRTBase::iswxdigit_(_wint_t c) {
    trace("iswxdigit called. Arguments: c=", std::to_wstring(c));
    if (c < 0 || c > 0x10FFFF) {
        ret("Error set to: EINVAL, Return value: 0");
        errno = EINVAL;
        return 0;
    }
    const int res = iswxdigit(c);
    ret("Error set to: -, Return value: ", std::to_wstring(res));
    return res;
}

errno_t UCRTBase::_mbscat_s(unsigned char *dest, size_t destSize, const unsigned char *src) {
    trace("_mbscat_s called. Arguments: dest=", std::wstring(dest ? reinterpret_cast<const char*>(dest) : "(null)", dest ? reinterpret_cast<const char*>(dest) + strlen(reinterpret_cast<const char*>(dest)) : "(null)"), ", destSize=", std::to_wstring(destSize), ", nt_apiset_cpp_hooks=", std::wstring(src ? reinterpret_cast<const char*>(src) : "(null)", src ? reinterpret_cast<const char*>(src) + strlen(reinterpret_cast<const char*>(src)) : "(null)"));
    if (dest == nullptr || src == nullptr || destSize == 0) {
        ret("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    size_t destLen = strlen(reinterpret_cast<const char*>(dest));
    size_t srcLen = strlen(reinterpret_cast<const char*>(src));
    if (destLen + srcLen + 1 > destSize) {
        ret("Error set to: ERANGE, Return value: ERANGE");
        return ERANGE;
    }
    std::memcpy(dest + destLen, src, srcLen + 1);
    ret("Error set to: -, Return value: 0");
    return 0;
}

errno_t UCRTBase::_mbscat_s_l(unsigned char *dest, size_t destSize, const unsigned char *src, _locale_t locale) {
    trace("_mbscat_s_l called. Arguments: dest=", std::wstring(dest ? reinterpret_cast<const char*>(dest) : "(null)", dest ? reinterpret_cast<const char*>(dest) + strlen(reinterpret_cast<const char*>(dest)) : "(null)"), ", destSize=", std::to_wstring(destSize), ", nt_apiset_cpp_hooks=", std::wstring(src ? reinterpret_cast<const char*>(src) : "(null)", src ? reinterpret_cast<const char*>(src) + strlen(reinterpret_cast<const char*>(src)) : "(null)"), ", locale=", reinterpret_cast<intptr_t>(locale));
    return _mbscat_s(dest, destSize, src);
}

unsigned char *UCRTBase::_mbscpy(unsigned char *dest, const unsigned char *src) {
    trace("_mbscpy called. Arguments: dest=", std::wstring(dest ? reinterpret_cast<const char*>(dest) : "(null)", dest ? reinterpret_cast<const char*>(dest) + strlen(reinterpret_cast<const char*>(dest)) : "(null)"), ", nt_apiset_cpp_hooks=", std::wstring(src ? reinterpret_cast<const char*>(src) : "(null)", src ? reinterpret_cast<const char*>(src) + strlen(reinterpret_cast<const char*>(src)) : "(null)"));
    if (dest == nullptr || src == nullptr) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    std::strcpy(reinterpret_cast<char*>(dest), reinterpret_cast<const char*>(src));
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(dest)));
    return dest;
}

errno_t UCRTBase::_mbscpy_s(unsigned char *dest, size_t destSize, const unsigned char *src) {
    trace("_mbscpy_s called. Arguments: dest=", std::wstring(dest ? reinterpret_cast<const char*>(dest) : "(null)", dest ? reinterpret_cast<const char*>(dest) + strlen(reinterpret_cast<const char*>(dest)) : "(null)"), ", destSize=", std::to_wstring(destSize), ", nt_apiset_cpp_hooks=", std::wstring(src ? reinterpret_cast<const char*>(src) : "(null)", src ? reinterpret_cast<const char*>(src) + strlen(reinterpret_cast<const char*>(src)) : "(null)"));
    if (dest == nullptr || src == nullptr || destSize == 0) {
        ret("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    size_t srcLen = strlen(reinterpret_cast<const char*>(src));
    if (srcLen + 1 > destSize) {
        ret("Error set to: ERANGE, Return value: ERANGE");
        return ERANGE;
    }
    std::strcpy(reinterpret_cast<char*>(dest), reinterpret_cast<const char*>(src));
    ret("Error set to: -, Return value: 0");
    return 0;
}

size_t UCRTBase::_mbscspn(const unsigned char *str1, const unsigned char *str2) {
    trace("_mbscspn called. Arguments: str1=", std::wstring(str1 ? reinterpret_cast<const char*>(str1) : "(null)", str1 ? reinterpret_cast<const char*>(str1) + strlen(reinterpret_cast<const char*>(str1)) : "(null)"), ", str2=", std::wstring(str2 ? reinterpret_cast<const char*>(str2) : "(null)", str2 ? reinterpret_cast<const char*>(str2) + strlen(reinterpret_cast<const char*>(str2)) : "(null)"));
    if (str1 == nullptr || str2 == nullptr) {
        ret("Error set to: EINVAL, Return value: 0");
        errno = EINVAL;
        return 0;
    }
    size_t len = 0;
    while (str1[len] != '\0' && std::strchr(reinterpret_cast<const char*>(str2), str1[len]) == nullptr) {
        ++len;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(len));
    return len;
}

size_t UCRTBase::_mbscspn_l(const unsigned char *str1, const unsigned char *str2, _locale_t locale) {
    trace("_mbscspn_l called. Arguments: str1=", std::wstring(str1 ? reinterpret_cast<const char*>(str1) : "(null)", str1 ? reinterpret_cast<const char*>(str1) + strlen(reinterpret_cast<const char*>(str1)) : "(null)"), ", str2=", std::wstring(str2 ? reinterpret_cast<const char*>(str2) : "(null)", str2 ? reinterpret_cast<const char*>(str2) + strlen(reinterpret_cast<const char*>(str2)) : "(null)"), ", locale=", reinterpret_cast<intptr_t>(locale));
    return _mbscspn(str1, str2);
}

size_t UCRTBase::_mbslen(const unsigned char *str) {
    trace("_mbslen called. Arguments: str=", std::wstring(str ? reinterpret_cast<const char*>(str) : "(null)", str ? reinterpret_cast<const char*>(str) + strlen(reinterpret_cast<const char*>(str)) : "(null)"));
    if (str == nullptr) {
        ret("Error set to: EINVAL, Return value: 0");
        errno = EINVAL;
        return 0;
    }
    size_t len = strlen(reinterpret_cast<const char*>(str));
    ret("Error set to: -, Return value: ", std::to_wstring(len));
    return len;
}

size_t UCRTBase::_mbslen_l(const unsigned char *str, _locale_t locale) {
    trace("_mbslen_l called. Arguments: str=", std::wstring(str ? reinterpret_cast<const char*>(str) : "(null)", str ? reinterpret_cast<const char*>(str) + strlen(reinterpret_cast<const char*>(str)) : "(null)"), ", locale=", reinterpret_cast<intptr_t>(locale));
    return _mbslen(str);
}

int UCRTBase::_mbsnbcmp(const unsigned char *str1, const unsigned char *str2, size_t count) {
    trace("_mbsnbcmp called. Arguments: str1=", std::wstring(str1 ? reinterpret_cast<const char*>(str1) : "(null)", str1 ? reinterpret_cast<const char*>(str1) + strlen(reinterpret_cast<const char*>(str1)) : "(null)"), ", str2=", std::wstring(str2 ? reinterpret_cast<const char*>(str2) : "(null)", str2 ? reinterpret_cast<const char*>(str2) + strlen(reinterpret_cast<const char*>(str2)) : "(null)"), ", count=", std::to_wstring(count));
    if (str1 == nullptr || str2 == nullptr) {
        ret("Error set to: EINVAL, Return value: 0");
        errno = EINVAL;
        return 0;
    }
    int res = std::strncmp(reinterpret_cast<const char*>(str1), reinterpret_cast<const char*>(str2), count);
    ret("Error set to: -, Return value: ", std::to_wstring(res));
    return res;
}

int UCRTBase::_mbsnbcmp_l(const unsigned char *str1, const unsigned char *str2, size_t count, _locale_t locale) {
    trace("_mbsnbcmp_l called. Arguments: str1=", std::wstring(str1 ? reinterpret_cast<const char*>(str1) : "(null)", str1 ? reinterpret_cast<const char*>(str1) + strlen(reinterpret_cast<const char*>(str1)) : "(null)"), ", str2=", std::wstring(str2 ? reinterpret_cast<const char*>(str2) : "(null)", str2 ? reinterpret_cast<const char*>(str2) + strlen(reinterpret_cast<const char*>(str2)) : "(null)"), ", count=", std::to_wstring(count), ", locale=", reinterpret_cast<intptr_t>(locale));
    return _mbsnbcmp(str1, str2, count);
}

unsigned char *UCRTBase::_mbsncat(unsigned char *dest, const unsigned char *src, size_t count) {
    trace("_mbsncat called. Arguments: dest=", std::wstring(dest ? reinterpret_cast<const char*>(dest) : "(null)", dest ? reinterpret_cast<const char*>(dest) + strlen(reinterpret_cast<const char*>(dest)) : "(null)"), ", nt_apiset_cpp_hooks=", std::wstring(src ? reinterpret_cast<const char*>(src) : "(null)", src ? reinterpret_cast<const char*>(src) + strlen(reinterpret_cast<const char*>(src)) : "(null)"), ", count=", std::to_wstring(count));
    if (dest == nullptr || src == nullptr) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    size_t destLen = strlen(reinterpret_cast<const char*>(dest));
    size_t srcLen = strlen(reinterpret_cast<const char*>(src));
    size_t toCopy = (srcLen < count) ? srcLen : count;
    std::memcpy(dest + destLen, src, toCopy);
    dest[destLen + toCopy] = '\0';
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(dest)));
    return dest;
}

unsigned char *UCRTBase::_mbsncat_l(unsigned char *dest, const unsigned char *src, size_t count, _locale_t locale) {
    trace("_mbsncat_l called. Arguments: dest=", std::wstring(dest ? reinterpret_cast<const char*>(dest) : "(null)", dest ? reinterpret_cast<const char*>(dest) + strlen(reinterpret_cast<const char*>(dest)) : "(null)"), ", nt_apiset_cpp_hooks=", std::wstring(src ? reinterpret_cast<const char*>(src) : "(null)", src ? reinterpret_cast<const char*>(src) + strlen(reinterpret_cast<const char*>(src)) : "(null)"), ", count=", std::to_wstring(count), ", locale=", reinterpret_cast<intptr_t>(locale));
    return _mbsncat(dest, src, count);
}

errno_t UCRTBase::_mbsncat_s(unsigned char *dest, size_t destSize, const unsigned char *src, size_t count) {
    trace("_mbsncat_s called. Arguments: dest=", std::wstring(dest ? reinterpret_cast<const char*>(dest) : "(null)", dest ? reinterpret_cast<const char*>(dest) + strlen(reinterpret_cast<const char*>(dest)) : "(null)"), ", destSize=", std::to_wstring(destSize), ", nt_apiset_cpp_hooks=", std::wstring(src ? reinterpret_cast<const char*>(src) : "(null)", src ? reinterpret_cast<const char*>(src) + strlen(reinterpret_cast<const char*>(src)) : "(null)"), ", count=", std::to_wstring(count));
    if (dest == nullptr || src == nullptr || destSize == 0) {
        ret("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    size_t destLen = strlen(reinterpret_cast<const char*>(dest));
    size_t srcLen = strlen(reinterpret_cast<const char*>(src));
    size_t toCopy = (srcLen < count) ? srcLen : count;
    if (destLen + toCopy + 1 > destSize) {
        ret("Error set to: ERANGE, Return value: ERANGE");
        return ERANGE;
    }
    std::memcpy(dest + destLen, src, toCopy);
    dest[destLen + toCopy] = '\0';
    ret("Error set to: -, Return value: 0");
    return 0;
}


errno_t UCRTBase::_mbsncat_s_l(unsigned char *dest, size_t destSize, const unsigned char *src, size_t count, _locale_t locale) {
    trace("_mbsncat_s_l called. Arguments: dest=", std::wstring(dest ? reinterpret_cast<const char*>(dest) : "(null)", dest ? reinterpret_cast<const char*>(dest) + strlen(reinterpret_cast<const char*>(dest)) : "(null)"), ", destSize=", std::to_wstring(destSize), ", nt_apiset_cpp_hooks=", std::wstring(src ? reinterpret_cast<const char*>(src) : "(null)", src ? reinterpret_cast<const char*>(src) + strlen(reinterpret_cast<const char*>(src)) : "(null)"), ", count=", std::to_wstring(count), ", locale=", reinterpret_cast<intptr_t>(locale));
    return _mbsncat_s(dest, destSize, src, count);
}

unsigned char *UCRTBase::_mbsncpy(unsigned char *dest, const unsigned char *src, size_t count) {
    trace("_mbsncpy called. Arguments: dest=", std::wstring(dest ? reinterpret_cast<const char*>(dest) : "(null)", dest ? reinterpret_cast<const char*>(dest) + strlen(reinterpret_cast<const char*>(dest)) : "(null)"), ", nt_apiset_cpp_hooks=", std::wstring(src ? reinterpret_cast<const char*>(src) : "(null)", src ? reinterpret_cast<const char*>(src) + strlen(reinterpret_cast<const char*>(src)) : "(null)"), ", count=", std::to_wstring(count));
    if (dest == nullptr || src == nullptr) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    std::strncpy(reinterpret_cast<char*>(dest), reinterpret_cast<const char*>(src), count);
    dest[count - 1] = '\0'; // ensure null termination
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(dest)));
    return dest;
}

unsigned char *UCRTBase::_mbsncpy_l(unsigned char *dest, const unsigned char *src, size_t count, _locale_t locale) {
    trace("_mbsncpy_l called. Arguments: dest=", std::wstring(dest ? reinterpret_cast<const char*>(dest) : "(null)", dest ? reinterpret_cast<const char*>(dest) + strlen(reinterpret_cast<const char*>(dest)) : "(null)"), ", nt_apiset_cpp_hooks=", std::wstring(src ? reinterpret_cast<const char*>(src) : "(null)", src ? reinterpret_cast<const char*>(src) + strlen(reinterpret_cast<const char*>(src)) : "(null)"), ", count=", std::to_wstring(count), ", locale=", reinterpret_cast<intptr_t>(locale));
    return _mbsncpy(dest, src, count);
}

size_t UCRTBase::_mbsnlen(const unsigned char *str, size_t maxsize) {
    trace("_mbsnlen called. Arguments: str=", std::wstring(str ? reinterpret_cast<const char*>(str) : "(null)", str ? reinterpret_cast<const char*>(str) + strlen(reinterpret_cast<const char*>(str)) : "(null)"), ", maxsize=", std::to_wstring(maxsize));
    if (str == nullptr) {
        ret("Error set to: EINVAL, Return value: 0");
        errno = EINVAL;
        return 0;
    }
    size_t len = 0;
    while (len < maxsize && str[len] != '\0') {
        ++len;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(len));
    return len;
}

size_t UCRTBase::_mbsnlen_l(const unsigned char *str, size_t maxsize, _locale_t locale) {
    trace("_mbsnlen_l called. Arguments: str=", std::wstring(str ? reinterpret_cast<const char*>(str) : "(null)", str ? reinterpret_cast<const char*>(str) + strlen(reinterpret_cast<const char*>(str)) : "(null)"), ", maxsize=", std::to_wstring(maxsize), ", locale=", reinterpret_cast<intptr_t>(locale));
    return _mbsnlen(str, maxsize);
}

unsigned char *UCRTBase::_mbspbrk(const unsigned char *str1, const unsigned char *str2) {
    trace("_mbspbrk called. Arguments: str1=", std::wstring(str1 ? reinterpret_cast<const char*>(str1) : "(null)", str1 ? reinterpret_cast<const char*>(str1) + strlen(reinterpret_cast<const char*>(str1)) : "(null)"), ", str2=", std::wstring(str2 ? reinterpret_cast<const char*>(str2) : "(null)", str2 ? reinterpret_cast<const char*>(str2) + strlen(reinterpret_cast<const char*>(str2)) : "(null)"));
    if (str1 == nullptr || str2 == nullptr) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    const char *res = std::strpbrk(reinterpret_cast<const char*>(str1), reinterpret_cast<const char*>(str2));
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(res)));
    return reinterpret_cast<unsigned char*>(const_cast<char*>(res));
}

unsigned char *UCRTBase::_mbspbrk_l(const unsigned char *str1, const unsigned char *str2, _locale_t locale) {
    trace("_mbspbrk_l called. Arguments: str1=", std::wstring(str1 ? reinterpret_cast<const char*>(str1) : "(null)", str1 ? reinterpret_cast<const char*>(str1) + strlen(reinterpret_cast<const char*>(str1)) : "(null)"), ", str2=", std::wstring(str2 ? reinterpret_cast<const char*>(str2) : "(null)", str2 ? reinterpret_cast<const char*>(str2) + strlen(reinterpret_cast<const char*>(str2)) : "(null)"), ", locale=", reinterpret_cast<intptr_t>(locale));
    return _mbspbrk(str1, str2);
}

size_t UCRTBase::_mbsspn(const unsigned char *str1, const unsigned char *str2) {
    trace("_mbsspn called. Arguments: str1=", std::wstring(str1 ? reinterpret_cast<const char*>(str1) : "(null)", str1 ? reinterpret_cast<const char*>(str1) + strlen(reinterpret_cast<const char*>(str1)) : "(null)"), ", str2=", std::wstring(str2 ? reinterpret_cast<const char*>(str2) : "(null)", str2 ? reinterpret_cast<const char*>(str2) + strlen(reinterpret_cast<const char*>(str2)) : "(null)"));
    if (str1 == nullptr || str2 == nullptr) {
        ret("Error set to: EINVAL, Return value: 0");
        errno = EINVAL;
        return 0;
    }
    size_t len = 0;
    while (str1[len] != '\0' && std::strchr(reinterpret_cast<const char*>(str2), str1[len]) != nullptr) {
        ++len;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(len));
    return len;
}

size_t UCRTBase::_mbsspn_l(const unsigned char *str1, const unsigned char *str2, _locale_t locale) {
    trace("_mbsspn_l called. Arguments: str1=", std::wstring(str1 ? reinterpret_cast<const char*>(str1) : "(null)", str1 ? reinterpret_cast<const char*>(str1) + strlen(reinterpret_cast<const char*>(str1)) : "(null)"), ", str2=", std::wstring(str2 ? reinterpret_cast<const char*>(str2) : "(null)", str2 ? reinterpret_cast<const char*>(str2) + strlen(reinterpret_cast<const char*>(str2)) : "(null)"), ", locale=", reinterpret_cast<intptr_t>(locale));
    return _mbsspn(str1, str2);
}

unsigned char *UCRTBase::_mbstok(unsigned char *str, const unsigned char *delimiters, unsigned char **context) {
    trace("_mbstok called. Arguments: str=", std::wstring(str ? reinterpret_cast<const char*>(str) : "(null)", str ? reinterpret_cast<const char*>(str) + strlen(reinterpret_cast<const char*>(str)) : "(null)"), ", delimiters=", std::wstring(delimiters ? reinterpret_cast<const char*>(delimiters) : "(null)", delimiters ? reinterpret_cast<const char*>(delimiters) + strlen(reinterpret_cast<const char*>(delimiters)) : "(null)"), ", context=", std::to_wstring(reinterpret_cast<uintptr_t>(context)));
    if (delimiters == nullptr || context == nullptr) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    char *strStart = reinterpret_cast<char*>(str);
    if (strStart == nullptr) {
        strStart = reinterpret_cast<char*>(*context);
    }
    if (strStart == nullptr) {
        ret("Error set to: -, Return value: nullptr");
        return nullptr;
    }
    // Skip leading delimiters
    strStart += strspn(strStart, reinterpret_cast<const char*>(delimiters));
    if (*strStart == '\0') {
        *context = nullptr;
        ret("Error set to: -, Return value: nullptr");
        return nullptr;
    }
    // Find the end of the token
    char *tokenEnd = strpbrk(strStart, reinterpret_cast<const char*>(delimiters));
    if (tokenEnd != nullptr) {
        *tokenEnd = '\0';
        *context = reinterpret_cast<unsigned char*>(tokenEnd + 1);
    } else {
        *context = nullptr;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(strStart)));
    return reinterpret_cast<unsigned char*>(strStart);
}

unsigned char *UCRTBase::_mbstok_l(unsigned char *str, const unsigned char *delimiters, unsigned char **context, _locale_t locale) {
    trace("_mbstok_l called. Arguments: str=", std::wstring(str ? reinterpret_cast<const char*>(str) : "(null)", str ? reinterpret_cast<const char*>(str) + strlen(reinterpret_cast<const char*>(str)) : "(null)"), ", delimiters=", std::wstring(delimiters ? reinterpret_cast<const char*>(delimiters) : "(null)", delimiters ? reinterpret_cast<const char*>(delimiters) + strlen(reinterpret_cast<const char*>(delimiters)) : "(null)"), ", context=", std::to_wstring(reinterpret_cast<uintptr_t>(context)), ", locale=", reinterpret_cast<intptr_t>(locale));
    return _mbstok(str, delimiters, context);
}

unsigned char *UCRTBase::_mbstok_s(unsigned char *str, const unsigned char *delimiters, unsigned char **context) {
    trace("_mbstok_s called. Arguments: str=", std::wstring(str ? reinterpret_cast<const char*>(str) : "(null)", str ? reinterpret_cast<const char*>(str) + strlen(reinterpret_cast<const char*>(str)) : "(null)"), ", delimiters=", std::wstring(delimiters ? reinterpret_cast<const char*>(delimiters) : "(null)", delimiters ? reinterpret_cast<const char*>(delimiters) + strlen(reinterpret_cast<const char*>(delimiters)) : "(null)"), ", context=", std::to_wstring(reinterpret_cast<uintptr_t>(context)));
    return _mbstok(str, delimiters, context);
}

unsigned char *UCRTBase::_mbstok_s_l(unsigned char *str, const unsigned char *delimiters, unsigned char **context, _locale_t locale) {
    trace("_mbstok_s_l called. Arguments: str=", std::wstring(str ? reinterpret_cast<const char*>(str) : "(null)", str ? reinterpret_cast<const char*>(str) + strlen(reinterpret_cast<const char*>(str)) : "(null)"), ", delimiters=", std::wstring(delimiters ? reinterpret_cast<const char*>(delimiters) : "(null)", delimiters ? reinterpret_cast<const char*>(delimiters) + strlen(reinterpret_cast<const char*>(delimiters)) : "(null)"), ", context=", std::to_wstring(reinterpret_cast<uintptr_t>(context)), ", locale=", reinterpret_cast<intptr_t>(locale));
    return _mbstok(str, delimiters, context);
}

size_t UCRTBase::_mbstrlen(const char *str) {
    trace("_mbstrlen called. Arguments: str=", std::wstring(str ? str : "(null)", str ? str + strlen(str) : "(null)"));
    if (str == nullptr) {
        ret("Error set to: EINVAL, Return value: 0");
        errno = EINVAL;
        return 0;
    }
    size_t len = strlen(str);
    ret("Error set to: -, Return value: ", std::to_wstring(len));
    return len;
}

size_t UCRTBase::_mbstrlen_l(const unsigned char *str, _locale_t locale) {
    trace("_mbstrlen_l called. Arguments: str=", std::wstring(str ? reinterpret_cast<const char*>(str) : "(null)", str ? reinterpret_cast<const char*>(str) + strlen(reinterpret_cast<const char*>(str)) : "(null)"), ", locale=", reinterpret_cast<intptr_t>(locale));
    return _mbstrlen(reinterpret_cast<const char*>(str));
}

size_t UCRTBase::_mbstrnlen(const char *str, size_t maxsize) {
    trace("_mbstrnlen called. Arguments: str=", std::wstring(str ? str : "(null)", str ? str + strlen(str) : "(null)"), ", maxsize=", std::to_wstring(maxsize));
    if (str == nullptr) {
        ret("Error set to: EINVAL, Return value: 0");
        errno = EINVAL;
        return 0;
    }
    size_t len = 0;
    while (len < maxsize && str[len] != '\0') {
        ++len;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(len));
    return len;
}

size_t UCRTBase::_mbstrnlen_l(const char *str, size_t maxsize, _locale_t locale) {
    trace("_mbstrnlen_l called. Arguments: str=", std::wstring(str ? str : "(null)", str ? str + strlen(str) : "(null)"), ", maxsize=", std::to_wstring(maxsize), ", locale=", reinterpret_cast<intptr_t>(locale));
    return _mbstrnlen(str, maxsize);
}

char *UCRTBase::_strncpy_l(char *dest, const char *src, size_t count, _locale_t locale) {
    trace("_strncpy_l called. Arguments: dest=", std::wstring(dest ? dest : "(null)", dest ? dest + strlen(dest) : "(null)"), ", nt_apiset_cpp_hooks=", std::wstring(src ? src : "(null)", src ? src + strlen(src) : "(null)"), ", count=", std::to_wstring(count), ", locale=", reinterpret_cast<intptr_t>(locale));
    if (dest == nullptr || src == nullptr) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    std::strncpy(dest, src, count);
    dest[count - 1] = '\0'; // ensure null termination
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(dest)));
    return dest;
}

char *UCRTBase::_strtok_s_l(char *str, const char *delimiters, char **context, _locale_t locale) {
    trace("_strtok_s_l called. Arguments: str=", std::wstring(str ? str : "(null)", str ? str + strlen(str) : "(null)"), ", delimiters=", std::wstring(delimiters ? delimiters : "(null)", delimiters ? delimiters + strlen(delimiters) : "(null)"), ", context=", std::to_wstring(reinterpret_cast<uintptr_t>(context)), ", locale=", reinterpret_cast<intptr_t>(locale));
    if (delimiters == nullptr || context == nullptr) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    char *strStart = str;
    if (strStart == nullptr) {
        strStart = *context;
    }
    if (strStart == nullptr) {
        ret("Error set to: -, Return value: nullptr");
        return nullptr;
    }
    // Skip leading delimiters
    strStart += strspn(strStart, delimiters);
    if (*strStart == '\0') {
        *context = nullptr;
        ret("Error set to: -, Return value: nullptr");
        return nullptr;
    }
    // Find the end of the token
    char *tokenEnd = strpbrk(strStart, delimiters);
    if (tokenEnd != nullptr) {
        *tokenEnd = '\0';
        *context = tokenEnd + 1;
    } else {
        *context = nullptr;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(strStart)));
    return strStart;
}

_wchar_t *UCRTBase::_wcsncpy_l(_wchar_t *dest, const _wchar_t *src, size_t count, _locale_t locale) {
    trace("_wcsncpy_l called. Arguments: dest=", dest, ", count=", std::to_wstring(count), ", locale=", reinterpret_cast<intptr_t>(locale));
    if (dest == nullptr || src == nullptr) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    wcsncpy_(dest, src, count);
    dest[count - 1] = L'\0'; // ensure null termination
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(dest)));
    return dest;
}

_wchar_t *UCRTBase::_wcstok_s_l(_wchar_t *str, const _wchar_t *delimiters, _wchar_t **context, _locale_t locale) {
    trace("_wcstok_s_l called. Arguments: str=", str, ", delimiters=", delimiters, ", context=", std::to_wstring(reinterpret_cast<uintptr_t>(context)), ", locale=", reinterpret_cast<intptr_t>(locale));
    if (delimiters == nullptr || context == nullptr) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    _wchar_t *strStart = str;
    if (strStart == nullptr) {
        strStart = *context;
    }
    if (strStart == nullptr) {
        ret("Error set to: -, Return value: nullptr");
        return nullptr;
    }
    // Skip leading delimiters
    strStart += wcsspn_(strStart, delimiters);
    if (*strStart == L'\0') {
        *context = nullptr;
        ret("Error set to: -, Return value: nullptr");
        return nullptr;
    }
    // Find the end of the token
    _wchar_t *tokenEnd = wcspbrk_(strStart, delimiters);
    if (tokenEnd != nullptr) {
        *tokenEnd = L'\0';
        *context = tokenEnd + 1;
    } else {
        *context = nullptr;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(strStart)));
    return strStart;
}

int UCRTBase::mblen_(const char *str, size_t n) {
    trace("mblen called. Arguments: str=", std::wstring(str ? str : "(null)", str ? str + strlen(str) : "(null)"), ", n=", std::to_wstring(n));
    if (str == nullptr) {
        ret("Error set to: 0, Return value: 0");
        return 0;
    }
    if (n == 0) {
        ret("Error set to: 0, Return value: 0");
        return 0;
    }
    // For simplicity, assume a single-byte character set
    if (static_cast<unsigned char>(str[0]) <= 0x7F) {
        ret("Error set to: -, Return value: 1");
        return 1;
    } else {
        ret("Error set to: -, Return value: -1");
        return -1; // Invalid multibyte character in this simple implementation
    }
}

int UCRTBase::mbrlen_(const char *str, size_t n, mbstate_t *ps) {
    trace("mbrlen called. Arguments: str=", std::wstring(str ? str : "(null)", str ? str + strlen(str) : "(null)"), ", n=", std::to_wstring(n), ", ps=", ps ? "not null" : "null");
    if (str == nullptr) {
        ret("Error set to: 0, Return value: 0");
        return 0;
    }
    if (n == 0) {
        ret("Error set to: 0, Return value: 0");
        return 0;
    }
    // For simplicity, assume a single-byte character set
    if (static_cast<unsigned char>(str[0]) <= 0x7F) {
        ret("Error set to: -, Return value: 1");
        return 1;
    } else {
        ret("Error set to: -, Return value: -1");
        return -1; // Invalid multibyte character in this simple implementation
    }
}

errno_t UCRTBase::memcpy_s(void *dest, size_t destSize, const void *src, size_t count) {
    trace("memcpy_s called. Arguments: dest=", std::to_wstring(reinterpret_cast<uintptr_t>(dest)), ", destSize=", std::to_wstring(destSize), ", nt_apiset_cpp_hooks=", std::to_wstring(reinterpret_cast<uintptr_t>(src)), ", count=", std::to_wstring(count));
    if (dest == nullptr || src == nullptr || destSize == 0 || count > destSize) {
        ret("Error set to: EINVAL or ERANGE, Return value: EINVAL or ERANGE");
        return (dest == nullptr || src == nullptr || destSize == 0) ? EINVAL : ERANGE;
    }
    std::memcpy(dest, src, count);
    ret("Error set to: -, Return value: 0");
    return 0;
}

errno_t UCRTBase::memmove_s(void *dest, size_t destSize, const void *src, size_t count) {
    trace("memmove_s called. Arguments: dest=", std::to_wstring(reinterpret_cast<uintptr_t>(dest)), ", destSize=", std::to_wstring(destSize), ", nt_apiset_cpp_hooks=", std::to_wstring(reinterpret_cast<uintptr_t>(src)), ", count=", std::to_wstring(count));
    if (dest == nullptr || src == nullptr || destSize == 0 || count > destSize) {
        ret("Error set to: EINVAL or ERANGE, Return value: EINVAL or ERANGE");
        return (dest == nullptr || src == nullptr || destSize == 0) ? EINVAL : ERANGE;
    }
    std::memmove(dest, src, count);
    ret("Error set to: -, Return value: 0");
    return 0;
}

errno_t UCRTBase::strcat_s(char *dest, size_t destSize, const char *src) {
    trace("strcat_s called. Arguments: dest=", std::wstring(dest ? dest : "(null)", dest ? dest + strlen(dest) : "(null)"), ", destSize=", std::to_wstring(destSize), ", nt_apiset_cpp_hooks=", std::wstring(src ? src : "(null)", src ? src + strlen(src) : "(null)"));
    if (dest == nullptr || src == nullptr || destSize == 0) {
        ret("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    size_t destLen = strlen(dest);
    size_t srcLen = strlen(src);
    if (destLen + srcLen + 1 > destSize) {
        ret("Error set to: ERANGE, Return value: ERANGE");
        return ERANGE;
    }
    std::strcat(dest, src);
    ret("Error set to: -, Return value: 0");
    return 0;
}

int UCRTBase::strcoll_(const char *str1, const char *str2) {
    trace("strcoll called. Arguments: str1=", std::wstring(str1 ? str1 : "(null)", str1 ? str1 + strlen(str1) : "(null)"), ", str2=", std::wstring(str2 ? str2 : "(null)", str2 ? str2 + strlen(str2) : "(null)"));
    if (str1 == nullptr || str2 == nullptr) {
        ret("Error set to: EINVAL, Return value: 0");
        errno = EINVAL;
        return 0;
    }
    int res = std::strcmp(str1, str2);
    ret("Error set to: -, Return value: ", std::to_wstring(res));
    return res;
}

errno_t UCRTBase::strcpy_s(char *dest, size_t destSize, const char *src) {
    trace("strcpy_s called. Arguments: dest=", std::wstring(dest ? dest : "(null)", dest ? dest + strlen(dest) : "(null)"), ", destSize=", std::to_wstring(destSize), ", nt_apiset_cpp_hooks=", std::wstring(src ? src : "(null)", src ? src + strlen(src) : "(null)"));
    if (dest == nullptr || src == nullptr || destSize == 0) {
        ret("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    size_t srcLen = strlen(src);
    if (srcLen + 1 > destSize) {
        ret("Error set to: ERANGE, Return value: ERANGE");
        return ERANGE;
    }
    std::strcpy(dest, src);
    ret("Error set to: -, Return value: 0");
    return 0;
}

size_t UCRTBase::strcspn_(const char *str1, const char *str2) {
    trace("strcspn called. Arguments: str1=", std::wstring(str1 ? str1 : "(null)", str1 ? str1 + strlen(str1) : "(null)"), ", str2=", std::wstring(str2 ? str2 : "(null)", str2 ? str2 + strlen(str2) : "(null)"));
    if (str1 == nullptr || str2 == nullptr) {
        ret("Error set to: EINVAL, Return value: 0");
        errno = EINVAL;
        return 0;
    }
    size_t len = 0;
    while (str1[len] != '\0' && std::strchr(str2, str1[len]) == nullptr) {
        ++len;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(len));
    return len;
}

errno_t UCRTBase::strncat_s(char *dest, size_t destSize, const char *src, size_t count) {
    trace("strncat_s called. Arguments: dest=", std::wstring(dest ? dest : "(null)", dest ? dest + strlen(dest) : "(null)"), ", destSize=", std::to_wstring(destSize), ", nt_apiset_cpp_hooks=", std::wstring(src ? src : "(null)", src ? src + strlen(src) : "(null)"), ", count=", std::to_wstring(count));
    if (dest == nullptr || src == nullptr || destSize == 0) {
        ret("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    size_t destLen = strlen(dest);
    size_t srcLen = strlen(src);
    size_t toCopy = (srcLen < count) ? srcLen : count;
    if (destLen + toCopy + 1 > destSize) {
        ret("Error set to: ERANGE, Return value: ERANGE");
        return ERANGE;
    }
    std::strncat(dest, src, toCopy);
    ret("Error set to: -, Return value: 0");
    return 0;
}

errno_t UCRTBase::strncpy_s(char *dest, size_t destSize, const char *src, size_t count) {
    trace("strncpy_s called. Arguments: dest=", std::wstring(dest ? dest : "(null)", dest ? dest + strlen(dest) : "(null)"), ", destSize=", std::to_wstring(destSize), ", nt_apiset_cpp_hooks=", std::wstring(src ? src : "(null)", src ? src + strlen(src) : "(null)"), ", count=", std::to_wstring(count));
    if (dest == nullptr || src == nullptr || destSize == 0) {
        ret("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    if (count >= destSize) {
        ret("Error set to: ERANGE, Return value: ERANGE");
        return ERANGE;
    }
    std::strncpy(dest, src, count);
    dest[count] = '\0'; // ensure null termination
    ret("Error set to: -, Return value: 0");
    return 0;
}

size_t UCRTBase::strnlen_(const char *str, size_t maxsize) {
    trace("strnlen called. Arguments: str=", std::wstring(str ? str : "(null)", str ? str + strlen(str) : "(null)"), ", maxsize=", std::to_wstring(maxsize));
    if (str == nullptr) {
        ret("Error set to: EINVAL, Return value: 0");
        errno = EINVAL;
        return 0;
    }
    size_t len = 0;
    while (len < maxsize && str[len] != '\0') {
        ++len;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(len));
    return len;
}

size_t UCRTBase::strnlen_s(const char *str, size_t maxsize) {
    trace("strnlen_s called. Arguments: str=", std::wstring(str ? str : "(null)", str ? str + strlen(str) : "(null)"), ", maxsize=", std::to_wstring(maxsize));
    return strnlen_(str, maxsize);
}

char *UCRTBase::strpbrk_(const char *str1, const char *str2) {
    trace("strpbrk called. Arguments: str1=", std::wstring(str1 ? str1 : "(null)", str1 ? str1 + strlen(str1) : "(null)"), ", str2=", std::wstring(str2 ? str2 : "(null)", str2 ? str2 + strlen(str2) : "(null)"));
    if (str1 == nullptr || str2 == nullptr) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    const char *res = std::strpbrk(str1, str2);
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(res)));
    return const_cast<char*>(res);
}

size_t UCRTBase::strspn_(const char *str1, const char *str2) {
    trace("strspn called. Arguments: str1=", std::wstring(str1 ? str1 : "(null)", str1 ? str1 + strlen(str1) : "(null)"), ", str2=", std::wstring(str2 ? str2 : "(null)", str2 ? str2 + strlen(str2) : "(null)"));
    if (str1 == nullptr || str2 == nullptr) {
        ret("Error set to: EINVAL, Return value: 0");
        errno = EINVAL;
        return 0;
    }
    size_t len = 0;
    while (str1[len] != '\0' && std::strchr(str2, str1[len]) != nullptr) {
        ++len;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(len));
    return len;
}

char *UCRTBase::strtok_(char *str, const char *delimiters, char **context) {
    trace("strtok called. Arguments: str=", std::wstring(str ? str : "(null)", str ? str + strlen(str) : "(null)"), ", delimiters=", std::wstring(delimiters ? delimiters : "(null)", delimiters ? delimiters + strlen(delimiters) : "(null)"), ", context=", std::to_wstring(reinterpret_cast<uintptr_t>(context)));
    if (delimiters == nullptr || context == nullptr) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    char *strStart = str;
    if (strStart == nullptr) {
        strStart = *context;
    }
    if (strStart == nullptr) {
        ret("Error set to: -, Return value: nullptr");
        return nullptr;
    }
    // Skip leading delimiters
    strStart += strspn_(strStart, delimiters);
    if (*strStart == '\0') {
        *context = nullptr;
        ret("Error set to: -, Return value: nullptr");
        return nullptr;
    }
    // Find the end of the token
    char *tokenEnd = strpbrk_(strStart, delimiters);
    if (tokenEnd != nullptr) {
        *tokenEnd = '\0';
        *context = tokenEnd + 1;
    } else {
        *context = nullptr;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(strStart)));
    return strStart;
}

char *UCRTBase::strtok_s(char *str, const char *delimiters, char **context) {
    trace("strtok_s called. Arguments: str=", std::wstring(str ? str : "(null)", str ? str + strlen(str) : "(null)"), ", delimiters=", std::wstring(delimiters ? delimiters : "(null)", delimiters ? delimiters + strlen(delimiters) : "(null)"), ", context=", std::to_wstring(reinterpret_cast<uintptr_t>(context)));
    return strtok_(str, delimiters, context);
}

int UCRTBase::tolower_(int c) {
    trace("tolower called. Arguments: c=", std::to_wstring(c));
    return tolower(c);
    return c;
}

int UCRTBase::toupper_(int c) {
    trace("toupper called. Arguments: c=", std::to_wstring(c));
    return toupper(c);
}

_wint_t UCRTBase::towctrans_(_wint_t c, wctrans_t desc) {
    trace("towctrans called. Arguments: c=", std::to_wstring(c), ", desc=", reinterpret_cast<intptr_t>(desc));
    return towctrans(c, desc);
    ret("Error set to: EINVAL, Return value: c");
    errno = EINVAL;
    return c;
}

_wchar_t *UCRTBase::wcscat_(_wchar_t *dest, const _wchar_t *src) {
    trace("wcscat called. Arguments: dest=", dest, ", nt_apiset_cpp_hooks=", src);
    if (dest == nullptr || src == nullptr) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    _wchar_t *originalDest = dest;
    while (*dest != L'\0') {
        ++dest;
    }
    while ((*dest++ = *src++) != L'\0');
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(originalDest)));
    return originalDest;
}

errno_t UCRTBase::wcscat_s(_wchar_t *dest, size_t destSize, const _wchar_t *src) {
    trace("wcscat_s called. Arguments: dest=", dest, ", destSize=", std::to_wstring(destSize), ", nt_apiset_cpp_hooks=", src);
    if (dest == nullptr || src == nullptr || destSize == 0) {
        ret("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    size_t destLen = wcslen_(dest);
    size_t srcLen = wcslen_(src);
    if (destLen + srcLen + 1 > destSize) {
        ret("Error set to: ERANGE, Return value: ERANGE");
        return ERANGE;
    }
    wcscat_(dest, src);
    ret("Error set to: -, Return value: 0");
    return 0;
}

int UCRTBase::wcscoll_(const _wchar_t *str1, const _wchar_t *str2) {
    trace("wcscoll called. Arguments: str1=", str1, ", str2=", str2);
    if (str1 == nullptr || str2 == nullptr) {
        ret("Error set to: EINVAL, Return value: 0");
        errno = EINVAL;
        return 0;
    }
    int res = wcscmp_(str1, str2);
    ret("Error set to: -, Return value: ", std::to_wstring(res));
    return res;
}

errno_t UCRTBase::wcscpy_s(_wchar_t *dest, size_t destSize, const _wchar_t *src) {
    trace("wcscpy_s called. Arguments: dest=", dest, ", destSize=", std::to_wstring(destSize), ", nt_apiset_cpp_hooks=", src);
    if (dest == nullptr || src == nullptr || destSize == 0) {
        ret("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    size_t srcLen = wcslen_(src);
    if (srcLen + 1 > destSize) {
        ret("Error set to: ERANGE, Return value: ERANGE");
        return ERANGE;
    }
    wcscpy_(dest, src);
    ret("Error set to: -, Return value: 0");
    return 0;
}

size_t UCRTBase::wcscspn_(const _wchar_t *str1, const _wchar_t *str2) {
    trace("wcscspn called. Arguments: str1=", str1, ", str2=", str2);
    if (str1 == nullptr || str2 == nullptr) {
        ret("Error set to: EINVAL, Return value: 0");
        errno = EINVAL;
        return 0;
    }
    size_t len = 0;
    while (str1[len] != L'\0' && wcschr_(str2, str1[len]) == nullptr) {
        ++len;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(len));
    return len;
}

_wchar_t *UCRTBase::wcsncat_(_wchar_t *dest, const _wchar_t *src, size_t count) {
    trace("wcsncat called. Arguments: dest=", dest, ", nt_apiset_cpp_hooks=", src, ", count=", std::to_wstring(count));
    if (dest == nullptr || src == nullptr) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    _wchar_t *originalDest = dest;
    while (*dest != L'\0') {
        ++dest;
    }
    while (count-- && (*dest++ = *src++) != L'\0');
    if (*(dest - 1) != L'\0') {
        *dest = L'\0'; // ensure null termination
    }
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(originalDest)));
    return originalDest;
}

errno_t UCRTBase::wcsncat_s(_wchar_t *dest, size_t destSize, const _wchar_t *src, size_t count) {
    trace("wcsncat_s called. Arguments: dest=", dest, ", destSize=", std::to_wstring(destSize), ", nt_apiset_cpp_hooks=", src, ", count=", std::to_wstring(count));
    if (dest == nullptr || src == nullptr || destSize == 0) {
        ret("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    size_t destLen = wcslen_(dest);
    size_t srcLen = wcslen_(src);
    size_t toCopy = (srcLen < count) ? srcLen : count;
    if (destLen + toCopy + 1 > destSize) {
        ret("Error set to: ERANGE, Return value: ERANGE");
        return ERANGE;
    }
    wcsncat_(dest, src, count);
    ret("Error set to: -, Return value: 0");
    return 0;
}

int UCRTBase::wcsncmp_(const _wchar_t *str1, const _wchar_t *str2, size_t count) {
    trace("wcsncmp called. Arguments: str1=", str1, ", str2=", str2, ", count=", std::to_wstring(count));
    if (str1 == nullptr || str2 == nullptr) {
        ret("Error set to: EINVAL, Return value: 0");
        errno = EINVAL;
        return 0;
    }
    int res = wcsncmp_(str1, str2, count);
    ret("Error set to: -, Return value: ", std::to_wstring(res));
    return res;
}

_wchar_t *UCRTBase::wcsncpy_(_wchar_t *dest, const _wchar_t *src, size_t count) {
    trace("wcsncpy called. Arguments: dest=", dest, ", nt_apiset_cpp_hooks=", src, ", count=", std::to_wstring(count));
    if (dest == nullptr || src == nullptr) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    _wchar_t *originalDest = dest;
    while (count-- && (*dest++ = *src++) != L'\0');
    if (*(dest - 1) != L'\0') {
        *dest = L'\0'; // ensure null termination
    }
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(originalDest)));
    return originalDest;
}

errno_t UCRTBase::wcsncpy_s(_wchar_t *dest, size_t destSize, const _wchar_t *src, size_t count) {
    trace("wcsncpy_s called. Arguments: dest=", dest, ", destSize=", std::to_wstring(destSize), ", nt_apiset_cpp_hooks=", src, ", count=", std::to_wstring(count));
    if (dest == nullptr || src == nullptr || destSize == 0) {
        ret("Error set to: EINVAL, Return value: EINVAL");
        return EINVAL;
    }
    if (count >= destSize) {
        ret("Error set to: ERANGE, Return value: ERANGE");
        return ERANGE;
    }
    wcsncpy_(dest, src, count);
    dest[count] = L'\0'; // ensure null termination
    ret("Error set to: -, Return value: 0");
    return 0;
}

size_t UCRTBase::wcsnlen_(const _wchar_t *str, size_t maxsize) {
    trace("wcsnlen called. Arguments: str=", str, ", maxsize=", std::to_wstring(maxsize));
    if (str == nullptr) {
        ret("Error set to: EINVAL, Return value: 0");
        errno = EINVAL;
        return 0;
    }
    size_t len = 0;
    while (len < maxsize && str[len] != L'\0') {
        ++len;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(len));
    return len;
}

size_t UCRTBase::wcsnlen_s(const _wchar_t *str, size_t maxsize) {
    trace("wcsnlen_s called. Arguments: str=", str, ", maxsize=", std::to_wstring(maxsize));
    return wcsnlen_(str, maxsize);
}

_wchar_t *UCRTBase::wcspbrk_(const _wchar_t *str1, const _wchar_t *str2) {
    trace("wcspbrk called. Arguments: str1=", str1, ", str2=", str2);
    if (str1 == nullptr || str2 == nullptr) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    const _wchar_t *res = wcspbrk_(str1, str2);
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(res)));
    return const_cast<_wchar_t*>(res);
}

size_t UCRTBase::wcsspn_(const _wchar_t *str1, const _wchar_t *str2) {
    trace("wcsspn called. Arguments: str1=", str1, ", str2=", str2);
    if (str1 == nullptr || str2 == nullptr) {
        ret("Error set to: EINVAL, Return value: 0");
        errno = EINVAL;
        return 0;
    }
    size_t len = 0;
    while (str1[len] != L'\0' && wcschr_(str2, str1[len]) != nullptr) {
        ++len;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(len));
    return len;
}

_wchar_t *UCRTBase::wcstok_(_wchar_t *str, const _wchar_t *delimiters, _wchar_t **context) {
    trace("wcstok called. Arguments: str=", str, ", delimiters=", delimiters, ", context=", std::to_wstring(reinterpret_cast<uintptr_t>(context)));
    if (delimiters == nullptr || context == nullptr) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    _wchar_t *strStart = str;
    if (strStart == nullptr) {
        strStart = *context;
    }
    if (strStart == nullptr) {
        ret("Error set to: -, Return value: nullptr");
        return nullptr;
    }
    // Skip leading delimiters
    strStart += wcsspn_(strStart, delimiters);
    if (*strStart == L'\0') {
        *context = nullptr;
        ret("Error set to: -, Return value: nullptr");
        return nullptr;
    }
    // Find the end of the token
    _wchar_t *tokenEnd = wcspbrk_(strStart, delimiters);
    if (tokenEnd != nullptr) {
        *tokenEnd = L'\0';
        *context = tokenEnd + 1;
    } else {
        *context = nullptr;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(strStart)));
    return strStart;
}

_wchar_t *UCRTBase::wcstok_s(_wchar_t *str, const _wchar_t *delimiters, _wchar_t **context) {
    trace("wcstok_s called. Arguments: str=", str, ", delimiters=", delimiters, ", context=", std::to_wstring(reinterpret_cast<uintptr_t>(context)));
    return wcstok_(str, delimiters, context);
}

_wctype_t UCRTBase::wctype_(const char *str) {
    trace("wctype called. Arguments: str=", std::wstring(str ? str : "(null)", str ? str + strlen(str) : "(null)"));
    ret("Error set to: -, Return value: ", std::to_wstring(wctype(str)));
    return wctype(str);
}

_wchar_t *UCRTBase::wmemcpy(_wchar_t *dest, const _wchar_t *src, size_t count) {
    trace("wmemcpy called. Arguments: dest=", dest, ", nt_apiset_cpp_hooks=", src, ", count=", std::to_wstring(count));
    if (dest == nullptr || src == nullptr) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    _wchar_t *originalDest = dest;
    while (count--) {
        *dest++ = *src++;
    }
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(originalDest)));
    return originalDest;
}

_wchar_t *UCRTBase::wmemmove(_wchar_t *dest, const _wchar_t *src, size_t count) {
    trace("wmemmove called. Arguments: dest=", dest, ", nt_apiset_cpp_hooks=", src, ", count=", std::to_wstring(count));
    if (dest == nullptr || src == nullptr) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    _wchar_t *originalDest = dest;
    if (dest < src) {
        while (count--) {
            *dest++ = *src++;
        }
    } else {
        dest += count;
        src += count;
        while (count--) {
            *(--dest) = *(--src);
        }
    }
    ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(originalDest)));
    return originalDest;
}

unsigned char *UCRTBase::_mbschr(const unsigned char *str, unsigned int c) {
    trace("_mbschr called. Arguments: str=", std::wstring(str ? reinterpret_cast<const char*>(str) : "(null)", str ? reinterpret_cast<const char*>(str) + strlen(reinterpret_cast<const char*>(str)) : "(null)"), ", c=", std::to_wstring(c));
    if (str == nullptr) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    while (*str != '\0') {
        if (*str == static_cast<unsigned char>(c)) {
            ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(const_cast<unsigned char*>(str))));
            return const_cast<unsigned char*>(str);
        }
        ++str;
    }
    ret("Error set to: -, Return value: nullptr");
    return nullptr;
}

_wchar_t *UCRTBase::wcschr_(const _wchar_t *str, _wint_t c) {
    trace("wcschr called. Arguments: str=", str, ", c=", std::to_wstring(c));
    if (str == nullptr) {
        ret("Error set to: EINVAL, Return value: nullptr");
        errno = EINVAL;
        return nullptr;
    }
    while (*str != L'\0') {
        if (*str == static_cast<_wchar_t>(c)) {
            ret("Error set to: -, Return value: ", std::to_wstring(reinterpret_cast<uintptr_t>(const_cast<_wchar_t*>(str))));
            return const_cast<_wchar_t*>(str);
        }
        ++str;
    }
    ret("Error set to: -, Return value: nullptr");
    return nullptr;
}


unsigned char *UCRTBase::_mbschr_l(const unsigned char *str, unsigned int c, _locale_t locale) {
    trace("_mbschr_l called. Arguments: str=", std::wstring(str ? reinterpret_cast<const char*>(str) : "(null)", str ? reinterpret_cast<const char*>(str) + strlen(reinterpret_cast<const char*>(str)) : "(null)"), ", c=", std::to_wstring(c), ", locale=", reinterpret_cast<intptr_t>(locale));
    return _mbschr(str, c);
}

// swprintf_
int UCRTBase::swprintf_(_wchar_t *buffer, size_t sizeOfBuffer, const _wchar_t *format, ...) {
    trace("swprintf_ called. Arguments: buffer=", buffer, ", sizeOfBuffer=", std::to_wstring(sizeOfBuffer), ", format=", format);
    va_list va;
    va_start(va, format);
    const int res = __stdio_common_vswprintf(0, buffer, sizeOfBuffer, format, nullptr, va);
    va_end(va);
    ret("Error set to: -, Return value: ", std::to_wstring(res));
    return res;
}













































