//
// Created by wojtek on 9/17/25.
//

#ifndef _VS2022_RUNNER__VCRUNTIME140_CPP
#define _VS2022_RUNNER__VCRUNTIME140_CPP

#include "vcruntime140.hpp"

std::unordered_map<std::wstring, EmulatedExport> VCRuntime140::get_exports_detailed() {
    return {
        {L"__C_specific_handler", { L"__C_specific_handler", reinterpret_cast<uintptr_t>(&VCRuntime140::__C_specific_handler), true, 0 }},
        {L"__current_exception", { L"__current_exception", reinterpret_cast<uintptr_t>(&VCRuntime140::__current_exception), true, 0 }},
        {L"__current_exception_context", { L"__current_exception_context", reinterpret_cast<uintptr_t>(&VCRuntime140::__current_exception_context), true, 0 }},
        {L"memset", { L"memset", reinterpret_cast<uintptr_t>(&VCRuntime140::memset_), true, 0 }},
        {L"memcpy", { L"memcpy", reinterpret_cast<uintptr_t>(&VCRuntime140::memcpy_), true, 0 }},
    };
}


EXCEPTION_DISPOSITION VCRuntime140::__C_specific_handler(EXCEPTION_RECORD *ExceptionRecord, void *EstablisherFrame, CONTEXT *ContextRecord, DISPATCHER_CONTEXT *DispatcherContext) {
    fixme("VCRuntime140::__C_specific_handler called - unimplemented");
    return ExceptionContinueSearch;
}


EXCEPTION_RECORD **VCRuntime140::__current_exception() {
    static EXCEPTION_RECORD* current_exception = nullptr;
    return &current_exception;
}

CONTEXT **VCRuntime140::__current_exception_context() {
    static CONTEXT* current_exception_context = nullptr;
    return &current_exception_context;
}

void *VCRuntime140::memset_(void *dest, int c, size_t count) {
    return memset(dest, c, count);
}

void *VCRuntime140::memcpy_(void *dest, const void *src, size_t count) {
    return memcpy(dest, src, count);
}

#endif //_VS2022_RUNNER__VCRUNTIME140_CPP