cmake_minimum_required(VERSION 4.0)
project(_VS2022_Runner_)

set(CMAKE_CXX_EXTENSIONS ON)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(.)

add_executable(_VS2022_Runner_
        log.h
        main.cpp
        global.cpp
        kernel32.cpp
        ucrtbase.cpp
        vcruntime140.hpp
        vcruntime140.cpp
        nt_apiset_cpp_hooks.hpp
)

project(whisky_)

set(CMAKE_CXX_EXTENSIONS ON)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(whisky_ "whisky_.cpp")

target_include_directories(whisky_ PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# target_compile_options(_VS2022_Runner_ PRIVATE -Wall -Wextra -g -g3 -ggdb -ggdb3)

target_include_directories(_VS2022_Runner_ PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# for rust integration of nt_apiset (i was too lazy to rewrite it in c++, so it is rust)
find_package(PkgConfig REQUIRED)

add_custom_target(nt_apiset_cpp_hooks_ ALL
    COMMAND cargo build --release --lib
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/nt_apiset_cpp_hooks
    COMMAND cp ${CMAKE_CURRENT_SOURCE_DIR}/target/release/libnt_apiset_cpp_hooks.so ${CMAKE_CURRENT_BINARY_DIR}/libnt_apiset_cpp_hooks.so
    COMMENT "Building nt_apiset_cpp_hooks..."
    BYPRODUCTS ${CMAKE_CURRENT_BINARY_DIR}/libnt_apiset_cpp_hooks.so
)

add_library(nt_apiset_cpp_hooks SHARED IMPORTED)
set_target_properties(nt_apiset_cpp_hooks PROPERTIES IMPORTED_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/libnt_apiset_cpp_hooks.so)
add_dependencies(nt_apiset_cpp_hooks nt_apiset_cpp_hooks_)

# for _Ux86_
# target_link_libraries(_VS2022_Runner_ LIEF ssl crypto unicode icuuc unwind dl pthread z)
add_dependencies(whisky_ nt_apiset_cpp_hooks)
target_link_libraries(whisky_ LIEF ssl crypto unicode icuuc unwind dl pthread z nt_apiset_cpp_hooks capstone)
target_link_libraries(_VS2022_Runner_ LIEF ssl crypto unicode icuuc unwind dl pthread z)

# For rust, add the following to your CMakeLists.txt
