//
// Created by wojtek on 9/21/25.
//

#ifndef WHISKY__NT_APISET_CPP_HOOKS_HPP
#define WHISKY__NT_APISET_CPP_HOOKS_HPP

extern "C" {
    void get_base_dll(
        const char* filename,
        const char* funcname,
        char* result
    );
}

#endif //WHISKY__NT_APISET_CPP_HOOKS_HPP