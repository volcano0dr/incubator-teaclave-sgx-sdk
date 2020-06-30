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

use crate::core::nodes::AsSlice;
use crate::error::{Error, FsError, FsResult};
use libc::{c_char, c_int, c_void, int64_t, uint32_t, uint64_t, uint8_t};
use std::ffi::CString;
use std::mem;
use std::ptr;
use types::sgx_status_t::{self, *};

extern "C" {
    pub fn u_sgxfs_open_ocall(
        file: *mut *mut c_void,
        error: *mut c_int,
        name: *const c_char,
        read_only: uint8_t,
        size: *mut int64_t,
    ) -> sgx_status_t;

    pub fn u_sgxfs_read_ocall(
        result: *mut uint8_t,
        error: *mut c_int,
        file: *mut c_void,
        number: uint64_t,
        node: *mut uint8_t,
        size: uint32_t,
    ) -> sgx_status_t;

    pub fn u_sgxfs_write_ocall(
        result: *mut uint8_t,
        error: *mut c_int,
        file: *mut c_void,
        number: uint64_t,
        node: *const uint8_t,
        size: uint32_t,
    ) -> sgx_status_t;

    pub fn u_sgxfs_close_ocall(
        result: *mut uint8_t,
        error: *mut c_int,
        file: *mut c_void,
    ) -> sgx_status_t;

    pub fn u_sgxfs_flush_ocall(
        result: *mut uint8_t,
        error: *mut c_int,
        file: *mut c_void,
    ) -> sgx_status_t;

    pub fn u_sgxfs_exists_ocall(
        result: *mut uint8_t,
        error: *mut c_int,
        name: *const c_char,
    ) -> sgx_status_t;

    pub fn u_sgxfs_remove_ocall(
        result: *mut uint8_t,
        error: *mut c_int,
        name: *const c_char,
    ) -> sgx_status_t;

    pub fn u_sgxfs_open_recovery_ocall(
        file: *mut *mut c_void,
        error: *mut c_int,
        name: *const c_char,
    ) -> sgx_status_t;

    pub fn u_sgxfs_write_recovery_ocall(
        result: *mut uint8_t,
        error: *mut c_int,
        file: *mut c_void,
        data: *const u8,
        data_size: uint32_t,
    ) -> sgx_status_t;

    pub fn u_sgxfs_close_recovery_ocall(
        result: *mut uint8_t,
        error: *mut c_int,
        file: *mut c_void,
    ) -> sgx_status_t;

    pub fn u_sgxfs_recovery_ocall(
        result: *mut uint8_t,
        error: *mut c_int,
        name: *const c_char,
        recovery: *const c_char,
    ) -> sgx_status_t;
}

fn cstr(name: &str) -> FsResult<CString> {
    CString::new(name.as_bytes()).map_err(|_| Error::from(libc::EINVAL))
}

fn get_error(status: sgx_status_t, error: i32, default: i32) -> Error {
    if status != SGX_SUCCESS {
        Error::from(status)
    } else {
        if error != 0 {
            Error::from(error)
        } else {
            Error::from(default)
        }
    }
}

pub struct OsFile {
    file: *mut c_void,
}

impl OsFile {
    pub fn new_null() -> OsFile {
        OsFile {
            file: ptr::null_mut(),
        }
    }

    pub fn open(name: &str, read_only: bool, size: &mut i64) -> FsResult<OsFile> {
        let mut error: c_int = 0;
        let mut file: *mut c_void = ptr::null_mut();
        let name = cstr(name)?;

        let status = unsafe {
            u_sgxfs_open_ocall(
                &mut file as *mut *mut c_void,
                &mut error as *mut c_int,
                name.as_ptr(),
                read_only as uint8_t,
                size as *mut int64_t,
            )
        };
        if status != SGX_SUCCESS {
            Err(Error::from(status))
        } else if file == ptr::null_mut() {
            if error != 0 {
                Err(Error::from(error))
            } else {
                Err(Error::from(libc::EACCES))
            }
        } else {
            Ok(OsFile { file: file })
        }
    }

    pub fn read<T: AsSlice>(&mut self, number: u64, node: &mut T) -> FsError {
        if self.file.is_null() {
            return Err(Error::from(libc::EINVAL));
        }

        let mut error: c_int = 0;
        let mut result: uint8_t = 0;
        let status = unsafe {
            u_sgxfs_read_ocall(
                &mut result as *mut uint8_t,
                &mut error as *mut c_int,
                self.file,
                number,
                node as *mut _ as *mut uint8_t,
                mem::size_of_val(node) as uint32_t,
            )
        };
        if status != SGX_SUCCESS || result == 0 {
            Err(get_error(status, error, libc::EIO))
        } else {
            Ok(())
        }
    }

    pub fn write<T: AsSlice>(&mut self, number: u64, node: &T) -> FsError {
        if self.file.is_null() {
            return Err(Error::from(libc::EINVAL));
        }

        let mut error: c_int = 0;
        let mut result: uint8_t = 0;
        let status = unsafe {
            u_sgxfs_write_ocall(
                &mut result as *mut uint8_t,
                &mut error as *mut c_int,
                self.file,
                number,
                node as *const _ as *const uint8_t,
                mem::size_of_val(node) as uint32_t,
            )
        };
        if status != SGX_SUCCESS || result == 0 {
            Err(get_error(status, error, libc::EIO))
        } else {
            Ok(())
        }
    }

    pub fn flush(&mut self) -> FsError {
        if self.file.is_null() {
            return Err(Error::from(libc::EINVAL));
        }

        let mut error: c_int = 0;
        let mut result: uint8_t = 0;
        let status = unsafe {
            u_sgxfs_flush_ocall(
                &mut result as *mut uint8_t,
                &mut error as *mut c_int,
                self.file,
            )
        };
        if status != SGX_SUCCESS {
            Err(Error::from(status))
        } else if result == 0 {
            Err(Error::from(SGX_ERROR_FILE_FLUSH_FAILED))
        } else {
            Ok(())
        }
    }

    pub fn close(&mut self) -> FsError {
        if self.file.is_null() {
            return Err(Error::from(libc::EINVAL));
        }

        let mut error: c_int = 0;
        let mut result: uint8_t = 0;
        let status = unsafe {
            u_sgxfs_close_ocall(
                &mut result as *mut uint8_t,
                &mut error as *mut c_int,
                self.file,
            )
        };

        // set file is null
        self.file = ptr::null_mut();
        if status != SGX_SUCCESS {
            Err(Error::from(status))
        } else if result == 0 {
            if error != 0 {
                Err(Error::from(error))
            } else {
                Err(Error::from(SGX_ERROR_FILE_CLOSE_FAILED))
            }
        } else {
            Ok(())
        }
    }
}

impl Drop for OsFile {
    fn drop(&mut self) {
        if !self.file.is_null() {
            let mut error: c_int = 0;
            let mut result: uint8_t = 0;
            unsafe {
                u_sgxfs_close_ocall(
                    &mut result as *mut uint8_t,
                    &mut error as *mut c_int,
                    self.file,
                );
            }
        }
    }
}

pub struct OsRecoveryFile {
    file: *mut c_void,
}

impl OsRecoveryFile {
    pub fn open(name: &str) -> FsResult<OsRecoveryFile> {
        let mut error: c_int = 0;
        let mut file: *mut c_void = ptr::null_mut();
        let name = cstr(name)?;

        let status = unsafe {
            u_sgxfs_open_recovery_ocall(
                &mut file as *mut *mut c_void,
                &mut error as *mut c_int,
                name.as_ptr(),
            )
        };
        if status != SGX_SUCCESS {
            Err(Error::from(status))
        } else if file == ptr::null_mut() {
            Err(Error::from(SGX_ERROR_FILE_CANT_OPEN_RECOVERY_FILE))
        } else {
            Ok(OsRecoveryFile { file: file })
        }
    }

    pub fn write<T: AsSlice>(&mut self, data: &T) -> FsError {
        let mut error: c_int = 0;
        let mut result: uint8_t = 0;
        let status = unsafe {
            u_sgxfs_write_recovery_ocall(
                &mut result as *mut uint8_t,
                &mut error as *mut c_int,
                self.file,
                data as *const _ as *const uint8_t,
                mem::size_of_val(data) as uint32_t,
            )
        };
        if status != SGX_SUCCESS {
            Err(Error::from(status))
        } else if result == 0 {
            Err(Error::from(SGX_ERROR_FILE_CANT_WRITE_RECOVERY_FILE))
        } else {
            Ok(())
        }
    }

    pub fn close(&mut self) -> FsError {
        let mut error: c_int = 0;
        let mut result: uint8_t = 0;
        let status = unsafe {
            u_sgxfs_close_recovery_ocall(
                &mut result as *mut uint8_t,
                &mut error as *mut c_int,
                self.file,
            )
        };

        // set file is null
        self.file = ptr::null_mut();
        if status != SGX_SUCCESS {
            Err(Error::from(status))
        } else if result == 0 {
            if error != 0 {
                Err(Error::from(error))
            } else {
                Err(Error::from(SGX_ERROR_FILE_CLOSE_FAILED))
            }
        } else {
            Ok(())
        }
    }
}

impl Drop for OsRecoveryFile {
    fn drop(&mut self) {
        if !self.file.is_null() {
            let mut error: c_int = 0;
            let mut result: uint8_t = 0;
            unsafe {
                u_sgxfs_close_recovery_ocall(
                    &mut result as *mut uint8_t,
                    &mut error as *mut c_int,
                    self.file,
                );
            }
        }
    }
}

pub fn exists(name: &str) -> FsResult<bool> {
    let mut error: c_int = 0;
    let mut result: uint8_t = 0;
    let name = cstr(name)?;

    let status = unsafe {
        u_sgxfs_exists_ocall(
            &mut result as *mut uint8_t,
            &mut error as *mut c_int,
            name.as_ptr(),
        )
    };
    if status != SGX_SUCCESS {
        Err(Error::from(status))
    } else if error != 0 {
        Err(Error::from(error))
    } else {
        Ok(if result != 0 { true } else { false })
    }
}

pub fn remove(name: &str) -> FsError {
    let mut error: c_int = 0;
    let mut result: uint8_t = 0;
    let name = cstr(name)?;

    let status = unsafe {
        u_sgxfs_remove_ocall(
            &mut result as *mut uint8_t,
            &mut error as *mut c_int,
            name.as_ptr(),
        )
    };
    if status != SGX_SUCCESS || result == 0 {
        Err(get_error(status, error, libc::EPERM))
    } else {
        Ok(())
    }
}

pub fn recovery(name: &str, recovery: &str) -> FsError {
    let mut error: c_int = 0;
    let mut result: uint8_t = 0;
    let name = cstr(name)?;
    let recov_name = cstr(recovery)?;

    let status = unsafe {
        u_sgxfs_recovery_ocall(
            &mut result as *mut uint8_t,
            &mut error as *mut c_int,
            name.as_ptr(),
            recov_name.as_ptr(),
        )
    };
    if status != SGX_SUCCESS || result == 0 {
        Err(get_error(status, error, libc::EINVAL))
    } else {
        Ok(())
    }
}
