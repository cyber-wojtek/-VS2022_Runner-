//
// Created by wojtek on 9/10/25.
//

#include <iostream>

#ifndef _VS2022_RUNNER__LOG_H
#define _VS2022_RUNNER__LOG_H

enum LogLevel {
    LOG_TRACE,
    LOG_FIXME,
    LOG_WARN,
    LOG_ERROR,
    LOG_FATAL
};

#ifndef LOG_LEVEL
#define LOG_LEVEL LOG_TRACE
#endif

template <typename ...ArgsTypes>
void trace(const ArgsTypes &...args) {
    if constexpr (LOG_LEVEL >= LOG_TRACE) {
        std::wcout << L"\033[36mTRACE: ";
        ((std::wcout << args), ...);
        std::wcout << std::endl;
    }
}

template <typename ...ArgsTypes>
void ret(const ArgsTypes &...args) {
    if constexpr (LOG_LEVEL >= LOG_TRACE) {
        std::wcout << L"\033[32mRETURN: ";
        ((std::wcout << args), ...);
        std::wcout << std::endl;
    }
}

template <typename ...ArgsTypes>
void fixme(const ArgsTypes &...args) {
    if constexpr (LOG_LEVEL >= LOG_FIXME) {
        std::wcout << L"\033[33mFIXME: ";
        ((std::wcout << args), ...);
        std::wcout << std::endl;
    }
}

template <typename ...ArgsTypes>
void warn(const ArgsTypes &...args) {
    if constexpr (LOG_LEVEL >= LOG_WARN) {
        std::wcout << L"\033[35mWARN: ";
        ((std::wcout << args), ...);
        std::wcout << std::endl;
    }
}

template <typename ...ArgsTypes>
void error(const ArgsTypes &...args) {
    if constexpr (LOG_LEVEL >= LOG_ERROR) {
        std::wcout << L"\033[31mERROR: ";
        ((std::wcout << args), ...);
        std::wcout << std::endl;
    }
}

template <typename ...ArgsTypes>
void fatal(const ArgsTypes &...args) {
    if constexpr (LOG_LEVEL >= LOG_FATAL) {
        std::wcout << L"\033[41mFATAL: ";
        ((std::wcout << args), ...);
        std::wcout << std::endl;
        std::exit(1);
    }
}


#endif //_VS2022_RUNNER__LOG_H