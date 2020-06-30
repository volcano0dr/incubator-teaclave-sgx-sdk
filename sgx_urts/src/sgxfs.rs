// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License..

#![allow(deprecated)]
use libc::{self, c_char, c_int, c_void, int64_t, uint32_t, uint64_t, uint8_t};
use sgx_uspfs as uspfs;
use sgx_uspfs::{File, RecoveryFile};
use std::ffi::CStr;
use std::mem::ManuallyDrop;
use std::ptr;
use std::slice;

#[inline]
unsafe fn set_error(error: *mut c_int, code: c_int) {
    if !error.is_null() {
        *error = code;
    }
}

#[no_mangle]
pub extern "C" fn u_sgxfs_open_ocall(
    error: *mut c_int,
    filename: *const c_char,
    read_only: uint8_t,
    file_size: *mut int64_t,
) -> *mut c_void {
    if filename.is_null() || file_size.is_null() {
        unsafe {
            set_error(error, libc::EINVAL);
        }
        return ptr::null_mut();
    }

    let filename = unsafe { CStr::from_ptr(filename) };
    let read_only = if read_only != 0 { true } else { false };
    let file_size = unsafe { &mut *file_size };
    match File::open(filename, read_only, file_size) {
        Ok(file) => file.into_raw(),
        Err(err) => {
            unsafe {
                set_error(error, err);
            }
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn u_sgxfs_read_ocall(
    error: *mut c_int,
    file: *mut c_void,
    node_number: uint64_t,
    node: *mut uint8_t,
    node_size: uint32_t,
) -> uint8_t {
    let mut file = match unsafe { File::from_raw(file) } {
        Some(file) => ManuallyDrop::new(file),
        None => {
            unsafe {
                set_error(error, libc::EINVAL);
            }
            return 0;
        }
    };
    if node.is_null() || node_size == 0 {
        unsafe {
            set_error(error, libc::EINVAL);
        }
        return 0;
    }
    let node = unsafe { slice::from_raw_parts_mut(node, node_size as usize) };
    match file.read(node_number, node) {
        Ok(_) => 1,
        Err(err) => {
            unsafe {
                set_error(error, err);
            }
            0
        }
    }
}

#[no_mangle]
pub extern "C" fn u_sgxfs_write_ocall(
    error: *mut c_int,
    file: *mut c_void,
    node_number: uint64_t,
    node: *const uint8_t,
    node_size: uint32_t,
) -> uint8_t {
    let mut file = match unsafe { File::from_raw(file) } {
        Some(file) => ManuallyDrop::new(file),
        None => {
            unsafe {
                set_error(error, libc::EINVAL);
            }
            return 0;
        }
    };
    if node.is_null() || node_size == 0 {
        unsafe {
            set_error(error, libc::EINVAL);
        }
        return 0;
    }
    let node = unsafe { slice::from_raw_parts(node, node_size as usize) };
    match file.write(node_number, node) {
        Ok(_) => 1,
        Err(err) => {
            unsafe {
                set_error(error, err);
            }
            0
        }
    }
}

#[no_mangle]
pub extern "C" fn u_sgxfs_flush_ocall(error: *mut c_int, file: *mut c_void) -> uint8_t {
    let mut file = match unsafe { File::from_raw(file) } {
        Some(file) => ManuallyDrop::new(file),
        None => {
            unsafe {
                set_error(error, libc::EINVAL);
            }
            return 0;
        }
    };
    match file.flush() {
        Ok(_) => 1,
        Err(err) => {
            unsafe {
                set_error(error, err);
            }
            0
        }
    }
}

#[no_mangle]
pub extern "C" fn u_sgxfs_close_ocall(error: *mut c_int, file: *mut c_void) -> uint8_t {
    let mut file = match unsafe { File::from_raw(file) } {
        Some(file) => file,
        None => {
            unsafe {
                set_error(error, libc::EINVAL);
            }
            return 0;
        }
    };
    match file.close() {
        Ok(_) => 1,
        Err(err) => {
            unsafe {
                set_error(error, err);
            }
            0
        }
    }
}

#[no_mangle]
pub extern "C" fn u_sgxfs_open_recovery_ocall(
    error: *mut c_int,
    filename: *const c_char,
) -> *mut c_void {
    if filename.is_null() {
        unsafe {
            set_error(error, libc::EINVAL);
        }
        return ptr::null_mut();
    }

    let filename = unsafe { CStr::from_ptr(filename) };
    match RecoveryFile::open(filename) {
        Ok(file) => file.into_raw(),
        Err(err) => {
            unsafe {
                set_error(error, err);
            }
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn u_sgxfs_write_recovery_ocall(
    error: *mut c_int,
    file: *mut c_void,
    data: *const u8,
    data_size: uint32_t,
) -> uint8_t {
    let mut file = match unsafe { RecoveryFile::from_raw(file) } {
        Some(file) => ManuallyDrop::new(file),
        None => {
            unsafe {
                set_error(error, libc::EINVAL);
            }
            return 0;
        }
    };
    if data.is_null() || data_size == 0 {
        unsafe {
            set_error(error, libc::EINVAL);
        }
        return 0;
    }
    let data = unsafe { slice::from_raw_parts(data, data_size as usize) };
    match file.write(data) {
        Ok(_) => 1,
        Err(err) => {
            unsafe {
                set_error(error, err);
            }
            0
        }
    }
}

#[no_mangle]
pub extern "C" fn u_sgxfs_close_recovery_ocall(
    error: *mut c_int,
    file: *mut c_void,
) -> uint8_t {
    let mut file = match unsafe { RecoveryFile::from_raw(file) } {
        Some(file) => file,
        None => {
            unsafe {
                set_error(error, libc::EINVAL);
            }
            return 0;
        }
    };
    match file.close() {
        Ok(_) => 1,
        Err(err) => {
            unsafe {
                set_error(error, err);
            }
            0
        }
    }
}

#[no_mangle]
pub extern "C" fn u_sgxfs_exists_ocall(error: *mut c_int, filename: *const c_char) -> uint8_t {
    if filename.is_null() {
        unsafe {
            set_error(error, libc::EINVAL);
        }
        return 0;
    }

    let filename = unsafe { CStr::from_ptr(filename) };
    match uspfs::exists(filename) {
        Ok(exists) => {
            if exists { 1 } else { 0 }
        }
        Err(err) => {
            unsafe {
                set_error(error, err);
            }
            0
        }
    }
}

#[no_mangle]
pub extern "C" fn u_sgxfs_remove_ocall(error: *mut c_int, filename: *const c_char) -> uint8_t {
    if filename.is_null() {
        unsafe {
            set_error(error, libc::EINVAL);
        }
        return 0;
    }

    let filename = unsafe { CStr::from_ptr(filename) };
    match uspfs::remove(filename) {
        Ok(_) => 1,
        Err(err) => {
            unsafe {
                set_error(error, err);
            }
            0
        }
    }
}

#[no_mangle]
pub extern "C" fn u_sgxfs_recovery_ocall(
    error: *mut c_int,
    filename: *const c_char,
    recovery_filename: *const c_char,
) -> uint8_t {
    if filename.is_null() || recovery_filename.is_null() {
        unsafe {
            set_error(error, libc::EINVAL);
        }
        return 0;
    }

    let filename = unsafe { CStr::from_ptr(filename) };
    let recovery_filename = unsafe { CStr::from_ptr(recovery_filename) };
    match uspfs::recovery(filename, recovery_filename) {
        Ok(_) => 1,
        Err(err) => {
            unsafe {
                set_error(error, err);
            }
            0
        }
    }
}
