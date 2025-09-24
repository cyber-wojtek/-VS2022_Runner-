//
// Created by wojtek on 9/12/25.
//
#pragma ONCE

#include <semaphore.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <pthread.h>
#include <mutex>
#include <chrono>
#include "global.h"
#include <dirent.h>
#include <sys/statvfs.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "log.h"

#ifndef _VS2022_RUNNER__VCRUNTIME140_HPP
#define _VS2022_RUNNER__VCRUNTIME140_HPP

class VCRuntime140 {
public:
    static std::unordered_map<std::wstring, EmulatedExport> get_exports_detailed();

    static EXCEPTION_DISPOSITION WINAPI __C_specific_handler(
        EXCEPTION_RECORD* ExceptionRecord,
        void* EstablisherFrame,
        CONTEXT* ContextRecord,
        DISPATCHER_CONTEXT* DispatcherContext);

    static EXCEPTION_RECORD** __current_exception();

    static CONTEXT** __current_exception_context();

    static void *memset_(void *dest, int c, size_t count);

    static void *memcpy_(void *dest, const void *src, size_t count);
};

#endif //_VS2022_RUNNER__VCRUNTIME140_HPP