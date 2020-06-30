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

use crate::core::consts::*;
use crate::core::file::{ProtectedFile, ProtectedFsStatus};
use crate::core::ups;
use crate::deps::set_errno;
use crate::error::{Error, FsError, FsResult};
use types::sgx_aes_gcm_128bit_tag_t;
use types::sgx_status_t::*;

impl ProtectedFile {
    // this function returns 0 only if the specified file existed and it was actually deleted
    // before we do that, we try to see if the file contained a monotonic counter, and if it did, we delete it from the system
    pub fn remove(filename: &str) -> FsError {
        ups::remove(filename).map_err(|err| {
            set_errno(err.raw_error());
            err
        })
    }

    pub fn get_error(&self) -> i32 {
        if self.is_last_error_ok() {
            if self.is_file_ok() {
                i32!(SGX_SUCCESS)
            } else {
                i32!(SGX_ERROR_FILE_BAD_STATUS)
            }
        } else {
            self.raw_last_error()
        }
    }

    pub fn clear_error(&mut self) {
        match self.file_status {
            ProtectedFsStatus::SGX_FILE_STATUS_NOT_INITIALIZED
            | ProtectedFsStatus::SGX_FILE_STATUS_CLOSED
            | ProtectedFsStatus::SGX_FILE_STATUS_CRYPTO_ERROR
            | ProtectedFsStatus::SGX_FILE_STATUS_CORRUPTED
            | ProtectedFsStatus::SGX_FILE_STATUS_MEMORY_CORRUPTED => return, // can't fix these...
            ProtectedFsStatus::SGX_FILE_STATUS_FLUSH_ERROR => {
                let _ = self
                    .internal_flush(true)
                    .map(|_| self.set_file_status(ProtectedFsStatus::SGX_FILE_STATUS_OK));
            }
            ProtectedFsStatus::SGX_FILE_STATUS_WRITE_TO_DISK_FAILED => {
                let _ = self
                    .write_all_changes_to_disk(true)
                    .map_err(|err| self.set_last_error(err))
                    .map(|_| {
                        self.need_writing = false;
                        self.set_file_status(ProtectedFsStatus::SGX_FILE_STATUS_OK)
                    });
            }
            ProtectedFsStatus::SGX_FILE_STATUS_OK => {
                self.set_last_error(Error::from(SGX_SUCCESS));
                self.end_of_file = false;
            }
        }
    }

    pub fn get_eof(&self) -> bool {
        self.end_of_file
    }

    pub fn tell(&mut self) -> FsResult<i64> {
        if !self.is_file_ok() {
            set_errno(libc::EPERM);
            self.set_last_error(Error::from(SGX_ERROR_FILE_BAD_STATUS));
            Err(self.last_error())
        } else {
            Ok(self.offset)
        }
    }

    pub fn seek(&mut self, new_offset: i64, origin: i32) -> FsError {
        if !self.is_file_ok() {
            self.set_last_error(Error::from(SGX_ERROR_FILE_BAD_STATUS));
            return Err(self.last_error());
        }
        let result = match origin {
            SEEK_SET
	    	    if (new_offset >= 0)
		            && (new_offset <= self.encrypted_part_plain.size) =>
	        {
                self.offset = new_offset;
                Ok(())
            }
            SEEK_CUR
                if (new_offset + self.offset >= 0)
                    && (new_offset + self.offset <= self.encrypted_part_plain.size) =>
            {
                self.offset += new_offset;
                Ok(())
            }
            SEEK_END 
                if (new_offset <= 0)
                    && (new_offset >= (0 - self.encrypted_part_plain.size)) =>
            {
                self.offset = self.encrypted_part_plain.size + new_offset;
                Ok(())
            }
            _ => {
                self.set_last_error(Error::from(libc::EINVAL));
                Err(self.last_error())
            }
        };

        if result.is_ok() {
            self.end_of_file = false;
        }
        result
    }

    // clears the cache with all the plain data that was in it
    // doesn't clear the meta-data and first node, which are part of the 'main' structure
    pub fn clear_cache(&mut self) -> FsError {
        if !self.is_file_ok() {
            // attempt to fix the file, will also flush it
            self.clear_error();
        } else {
            let _ = self.internal_flush(true);
        }

        if !self.is_file_ok() {
            // clearing the cache might lead to losing un-saved data
            return Err(Error::from(SGX_ERROR_FILE_BAD_STATUS));
        }

        while let Some(data) = self.cache.pop_back() {
            if data.borrow().is_need_writing() {
                return Err(Error::from(SGX_ERROR_FILE_BAD_STATUS));
            }
            data.borrow_mut().clean_plain();
        }
        Ok(())
    }

    pub fn get_meta_mac(&mut self) -> FsResult<sgx_aes_gcm_128bit_tag_t> {
        self.flush()?;
        Ok(self.meta_data.meta_node.plain_part.meta_data_gmac.clone())
    }

    pub fn rename_meta(&mut self, old_name: &str, new_name: &str) -> FsError {
        self.try_error(
            !self.is_valid_path_length(old_name.len()),
            libc::ENAMETOOLONG,
        )?;
        self.try_error(
            !self.is_valid_path_length(new_name.len()),
            libc::ENAMETOOLONG,
        )?;

        let len = get_str_array_len(&self.encrypted_part_plain.clean_filename);
        self.try_error(
            self.encrypted_part_plain.clean_filename[0..len].ne(old_name.as_bytes()),
            SGX_ERROR_FILE_NAME_MISMATCH,
        )?;

        self.encrypted_part_plain.clean_filename[..].copy_from_slice(&[0; FILENAME_MAX_LEN]);
        self.encrypted_part_plain.clean_filename[0..new_name.len()]
            .copy_from_slice(new_name.as_bytes());

        self.need_writing = true;
        let result = self.internal_flush(true);
        self.try_result(result)?;
        Ok(())
    }
}

pub fn get_str_array_len(array: &[u8]) -> usize {
    //duanran
    array
        .iter()
        .try_fold(
            0,
            |count, &x| {
                if x != 0 {
                    Ok(count + 1)
                } else {
                    Err(count)
                }
            },
        )
        .unwrap_or_else(|n| n)
}
