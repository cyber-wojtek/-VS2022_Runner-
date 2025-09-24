use nt_apiset::ApiSetMap;
use std::fs::read;
use std::ptr::{null, null_mut};
use std::ffi::{CString, CStr};
use std::io::{Error, Read};
use std::os::raw::c_char;
use std::sync::{Once, OnceLock};
use std::env;

// Use OnceLock for thread-safe initialization
static DATA: OnceLock<Result<Vec<u8>, Error>> = OnceLock::new();
static MAP: OnceLock<nt_apiset::Result<ApiSetMap>> = OnceLock::new();

#[unsafe(no_mangle)]
pub extern "C" fn get_base_dll(filename: *const c_char, funcname: *const c_char, result: *mut c_char) {
    let c_str = unsafe {
        assert!(!filename.is_null());
        CStr::from_ptr(filename)
    };

    let fname = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => {
            unsafe {
                std::ptr::copy_nonoverlapping(b"\0".as_ptr(), result as *mut u8, 1);
            }
            println!("Error 0");
            return;
        }
    };

    let c_str = unsafe {
        assert!(!funcname.is_null());
        CStr::from_ptr(funcname)
    };

    let funcname = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => {
            unsafe {
                std::ptr::copy_nonoverlapping(b"\0".as_ptr(), result as *mut u8, 1);
            }
            return;
        }
    };

    // Initialize data if not already done
    let data = DATA.get_or_init(|| {
        println!("{}", env::current_dir().unwrap().to_str().unwrap_or(""));
        read("apisetschema.dll")
    });

    if (data.is_err()) {
        unsafe {
            std::ptr::copy_nonoverlapping(b"\0".as_ptr(), result as *mut u8, 1);
        }
        println!("Error 1");
        return;
    }

    let data = data.as_ref().unwrap();

    // Initialize map if not already done
    let map = MAP.get_or_init(|| {
        let pe = pelite::pe64::PeFile::from_bytes(data);
        if (pe.is_err()) {
            panic!("Error 1.5");
        }
        ApiSetMap::try_from_pe64(pe.unwrap())
    });

    if (map.is_err()) {
        unsafe {
            std::ptr::copy_nonoverlapping(b"\0".as_ptr(), result as *mut u8, 1);
        }
        println!("Error 3");
        return;
    }

    let map = map.as_ref().unwrap();

    let namespace_entry = match map.find_namespace_entry(funcname) {
        Some(entry) => entry,
        None => {
            unsafe {
                std::ptr::copy_nonoverlapping(b"\0".as_ptr(), result as *mut u8, 1);
            }
            return;
        }
    }.unwrap();

    let value_entries = match namespace_entry.value_entries() {
        Ok(entries) => entries,
        Err(_) => {
            unsafe {
                std::ptr::copy_nonoverlapping(b"\0".as_ptr(), result as *mut u8, 1);
            }
            return;
        }
    };

    for entry in value_entries {
        if let (Ok(name), Ok(value)) = (entry.name(), entry.value()) {
            println!("Value Entry: {} -> {}", name, value);

            if name == fname {
                if let Ok(value_str) = value.to_string() {
                    if let Ok(c_string) = CString::new(value_str) {
                        let bytes = c_string.as_bytes_with_nul(); // Includes null terminator
                        unsafe {
                            std::ptr::copy_nonoverlapping(
                                bytes.as_ptr(),
                                result as *mut u8,
                                bytes.len()
                            );
                        }
                        return;
                    }
                }
            }
        }
    }

    // If we reach here, no match was found
    unsafe {
        std::ptr::copy_nonoverlapping(b"\0".as_ptr(), result as *mut u8, 1);
    }
}