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

use crate::core::file as file_imp;
use crate::core::file::ProtectedFsStatus;
use crate::deps::set_errno;
use crate::deps::Mutex;
use crate::error::{Error, FsError, FsResult};
use types::{
    sgx_aes_gcm_128bit_key_t,
    sgx_aes_gcm_128bit_tag_t,
    sgx_key_128bit_t,
};
use types::sgx_status_t::*;

pub struct ProtectedFile {
    file: Mutex<file_imp::ProtectedFile>,
}

impl ProtectedFile {
    pub fn open(
        filename: &str,
        mode: &str,
        auto_key: Option<&sgx_aes_gcm_128bit_key_t>,
        kdk_key: Option<&sgx_aes_gcm_128bit_key_t>,
        integrity_only: bool,
    ) -> FsResult<ProtectedFile> {
        let mut file = file_imp::ProtectedFile::new();
        file.open(filename, mode, auto_key, kdk_key, integrity_only)
            .map_err(|err| {
                set_errno(file.get_error());
                err
            })?;
        Ok(ProtectedFile {
            file: Mutex::new(file),
        })
    }

    pub fn write(&self, data: &[u8]) -> FsResult<usize> {
        let mut file = self.file.lock().map_err(|p_err| {
            let mut file = p_err.into_inner();
            file.set_last_error(Error::from(SGX_ERROR_UNEXPECTED));
            file.set_file_status(ProtectedFsStatus::SGX_FILE_STATUS_MEMORY_CORRUPTED);
            SGX_ERROR_UNEXPECTED
        })?;
        file.write(data)
    }

    pub fn read(&self, data: &mut [u8]) -> FsResult<usize> {
        let mut file = self.file.lock().map_err(|p_err| {
            let mut file = p_err.into_inner();
            file.set_last_error(Error::from(SGX_ERROR_UNEXPECTED));
            file.set_file_status(ProtectedFsStatus::SGX_FILE_STATUS_MEMORY_CORRUPTED);
            SGX_ERROR_UNEXPECTED
        })?;
        file.read(data)
    }

    pub fn tell(&self) -> FsResult<i64> {
        let mut file = self.file.lock().unwrap_or_else(|p_err| p_err.into_inner());
        file.tell()
    }

    pub fn seek(&self, new_offset: i64, origin: i32) -> FsError {
        let mut file = self.file.lock().unwrap_or_else(|p_err| p_err.into_inner());
        file.seek(new_offset, origin)
    }

    pub fn get_eof(&self) -> bool {
        let file = self.file.lock().unwrap_or_else(|p_err| p_err.into_inner());
        file.get_eof()
    }

    pub fn get_error(&self) -> i32 {
        let file = self.file.lock().unwrap_or_else(|p_err| p_err.into_inner());
        file.get_error()
    }

    pub fn clear_error(&self) {
        let mut file = self.file.lock().unwrap_or_else(|p_err| p_err.into_inner());
        file.clear_error()
    }

    pub fn clear_cache(&self) -> FsError {
        let mut file = self.file.lock().unwrap_or_else(|p_err| p_err.into_inner());
        file.clear_cache()
    }

    pub fn flush(&self) -> FsError {
        let mut file = self.file.lock().map_err(|p_err| {
            let mut file = p_err.into_inner();
            file.set_last_error(Error::from(SGX_ERROR_UNEXPECTED));
            file.set_file_status(ProtectedFsStatus::SGX_FILE_STATUS_MEMORY_CORRUPTED);
            SGX_ERROR_UNEXPECTED
        })?;
        file.flush()
    }

    pub fn pre_close(&self, key: Option<&mut sgx_key_128bit_t>, import: bool) -> bool {
        let mut file = self.file.lock().unwrap_or_else(|p_err| p_err.into_inner());
        file.pre_close(key, import)
    }

    pub fn get_meta_mac(&self) -> FsResult<sgx_aes_gcm_128bit_tag_t> {
        let mut file = self.file.lock().map_err(|p_err| {
            let mut file = p_err.into_inner();
            file.set_last_error(Error::from(SGX_ERROR_UNEXPECTED));
            file.set_file_status(ProtectedFsStatus::SGX_FILE_STATUS_MEMORY_CORRUPTED);
            SGX_ERROR_UNEXPECTED
        })?;
        file.get_meta_mac()
    }

    pub fn rename_meta(&self, old_name: &str, new_name: &str) -> FsError {
        let mut file = self.file.lock().unwrap_or_else(|p_err| p_err.into_inner());
        file.rename_meta(old_name, new_name)
    }

    pub fn remove(filename: &str) -> FsError {
        file_imp::ProtectedFile::remove(filename)
    }

    #[cfg(feature = "mesalock_sgx")]
    pub fn export_auto_key(filename: &str) -> FsResult<sgx_key_128bit_t> {
        let file = Self::open(filename, "r", None, None, false)?;
        let mut key = sgx_key_128bit_t::default();
        if file.pre_close(Some(&mut key), false) {
            Ok(key)
        } else {
            Err(Error::from(SGX_ERROR_UNEXPECTED))
        }
    }

    #[cfg(feature = "mesalock_sgx")]
    pub fn import_auto_key(filename: &str, key: &sgx_key_128bit_t) -> FsError {
        let file = Self::open(filename, "r+", Some(key), None, false)?;
        if file.pre_close(None, true) {
            Ok(())
        } else {
            Err(Error::from(SGX_ERROR_UNEXPECTED))
        }
    }
}

#[macro_use]
mod macros;

mod cache;
mod consts;
mod crypto;
mod file;
mod link;
mod meta;
mod nodes;
mod ups;
