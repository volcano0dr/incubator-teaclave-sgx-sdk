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
use libc;
use std::ffi::CString;
use std::ptr;
use types::sgx_status_t::*;
use uspfs;

fn cstr(name: &str) -> FsResult<CString> {
    CString::new(name.as_bytes()).map_err(|_| Error::from(libc::EINVAL))
}

#[inline]
fn get_error(err: i32, default: i32) -> i32 {
    if err != 0 {
        err
    } else {
        default
    }
}

pub fn exists(name: &str) -> FsResult<bool> {
    uspfs::exists(&cstr(name)?).map_err(|err| Error::from(get_error(err, libc::EINVAL)))
}

pub fn remove(name: &str) -> FsError {
    uspfs::remove(&cstr(name)?).map_err(|err| Error::from(get_error(err, libc::EPERM)))
}

pub fn recovery(name: &str, recovery: &str) -> FsError {
    uspfs::recovery(&cstr(name)?, &cstr(recovery)?)
        .map_err(|err| Error::from(get_error(err, libc::EINVAL)))
}

pub struct OsFile {
    file: uspfs::File,
}

impl OsFile {
    pub fn new_null() -> OsFile {
        OsFile {
            file: unsafe { uspfs::File::from_raw_unchecked(ptr::null_mut()) },
        }
    }

    pub fn open(name: &str, read_only: bool, size: &mut i64) -> FsResult<OsFile> {
        let mut file_size = 0_i64;
        uspfs::File::open(&cstr(name)?, read_only, &mut file_size)
            .map(|file| {
                *size = file_size;
                OsFile { file: file }
            })
            .map_err(|err| Error::from(get_error(err, libc::EACCES)))
    }

    pub fn read<T: AsSlice>(&mut self, number: u64, node: &mut T) -> FsError {
        if self.file.raw().is_null() {
            return Err(Error::from(libc::EINVAL));
        }
        self.file
            .read(number, node.as_mut_slice())
            .map_err(|err| Error::from(get_error(err, libc::EIO)))
    }

    pub fn write<T: AsSlice>(&mut self, number: u64, node: &T) -> FsError {
        if self.file.raw().is_null() {
            return Err(Error::from(libc::EINVAL));
        }
        self.file
            .write(number, node.as_slice())
            .map_err(|err| Error::from(get_error(err, libc::EIO)))
    }

    pub fn flush(&mut self) -> FsError {
        if self.file.raw().is_null() {
            return Err(Error::from(libc::EINVAL));
        }
        self.file.flush().map_err(|err| {
            if err != 0 {
                Error::from(err)
            } else {
                Error::from(SGX_ERROR_FILE_FLUSH_FAILED)
            }
        })
    }

    pub fn close(&mut self) -> FsError {
        if self.file.raw().is_null() {
            return Err(Error::from(libc::EINVAL));
        }
        self.file
            .close()
            .map_err(|_| Error::from(SGX_ERROR_FILE_CLOSE_FAILED))
    }
}

pub struct OsRecoveryFile {
    file: uspfs::RecoveryFile,
}

impl OsRecoveryFile {
    pub fn open(name: &str) -> FsResult<OsRecoveryFile> {
        uspfs::RecoveryFile::open(&cstr(name)?)
            .map(|file| OsRecoveryFile { file: file })
            .map_err(|err| Error::from(get_error(err, libc::EACCES)))
    }

    pub fn write<T: AsSlice>(&mut self, data: &T) -> FsError {
        self.file.write(data.as_slice()).map_err(|err| {
            if err != 0 {
                Error::from(err)
            } else {
                Error::from(SGX_ERROR_FILE_CANT_WRITE_RECOVERY_FILE)
            }
        })
    }

    pub fn close(&mut self) -> FsError {
        self.file
            .close()
            .map_err(|_| Error::from(SGX_ERROR_FILE_CLOSE_FAILED))
    }
}
