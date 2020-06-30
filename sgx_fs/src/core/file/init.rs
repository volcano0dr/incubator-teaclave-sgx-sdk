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
#[cfg(feature = "mesalock_sgx")]
use crate::core::crypto::generate_report;
use crate::core::file::other::get_str_array_len;
use crate::core::file::{ProtectedFile, ProtectedFsStatus};
use crate::core::ups::{self, OsFile};
use crate::deps::ConsttimeMemEq;
use crate::deps::{errno, set_errno};
use crate::error::{Error, FsError, FsResult};
use libc;
use std::convert::Into;
use std::ffi::OsStr;
use std::path::Path;
use std::string::ToString;
use types::sgx_aes_gcm_128bit_key_t;
use types::sgx_status_t::*;

impl ProtectedFile {
    #[inline]
    pub fn try_result<T, E: Into<Error>>(&mut self, result: Result<T, E>) -> FsResult<T> {
        match result {
            Ok(val) => Ok(val),
            Err(error) => {
                let err = error.into();
                self.set_last_error(err);
                Err(err)
            }
        }
    }

    #[inline]
    pub fn try_error<E: Into<Error>>(&mut self, check: bool, error: E) -> FsError {
        if check {
            let err = error.into();
            self.set_last_error(err);
            Err(err)
        } else {
            Ok(())
        }
    }

    #[inline]
    pub fn try_close<E: Into<Error>>(&mut self, check: bool, error: E) -> FsError {
        if check {
            if !self.is_file_ok() {
                let _ = self.file.close();
            }
            let err = error.into();
            self.set_last_error(err);
            Err(err)
        } else {
            Ok(())
        }
    }

    pub fn open(
        &mut self,
        filename: &str,
        mode: &str,
        import_key: Option<&sgx_aes_gcm_128bit_key_t>,
        kdk_key: Option<&sgx_aes_gcm_128bit_key_t>,
        integrity_only: bool,
    ) -> FsError {
        self.try_error(
            filename.len() <= 0 || mode.len() <= 0,
            libc::EINVAL,
        )?;
        self.try_error(
            !self.is_valid_path_length(filename.len()),
            libc::ENAMETOOLONG,
        )?;
        self.try_error(
            import_key.is_some() && kdk_key.is_some(),
            libc::EINVAL,
        )?;
        self.try_error(
            integrity_only && (import_key.is_some() || kdk_key.is_some()),
            libc::EINVAL,
        )?;

        #[cfg(feature = "mesalock_sgx")]
        {
            self.report = Some(self.try_result(generate_report())?);
        }

        // init session_key
        let result = self.session_key.init();
        self.try_result(result)?;

        if let Some(kdk_key) = kdk_key {
            // for new file, this value will later be saved in the meta data plain part (init_new_file)
            // for existing file, we will later compare this value with the value from the file (init_existing_file)
            self.set_user_kdk_key(*kdk_key);
        }

        // get the clean file name (original name might be clean or with relative path or with absolute path...)
        let clean_filename = self.cleanup_filename(filename)?;

        if let Some(key) = import_key {
            // verify the key is not empty - note from SAFE review
            let empty_aes_key = sgx_aes_gcm_128bit_key_t::default();
            self.try_error(empty_aes_key.consttime_memeq(key), libc::EINVAL)?;
        }

        self.parse_mode(mode)?;
        self.check_file_exist(import_key, filename)?;

        self.integrity_only = integrity_only;
        // now open the file
        // read only files can be opened simultaneously by many enclaves
        self.read_only = self.open_mode.read && !self.open_mode.update;

        // open file
        let mut real_file_size = 0;
        self.file = self.try_result(OsFile::open(filename, self.read_only, &mut real_file_size))?;
        self.real_file_size = real_file_size;

        self.try_close(self.real_file_size < 0, libc::EINVAL)?;
        self.try_close(
            self.real_file_size % i64!(NODE_SIZE) != 0,
            SGX_ERROR_FILE_NOT_SGX_FILE,
        )?;

        self.recovery_filename = filename.to_string().clone();
        self.recovery_filename.push_str("_recovery");

        if self.real_file_size > 0 {
            // existing file
            self.try_close(self.open_mode.write, libc::EACCES)?;
            self.init_existing_file(filename, &clean_filename, import_key)
                .map_err(|err| {
                    let _ = self.try_close(true, err);
                    err
                })?;

            if self.open_mode.append && !self.open_mode.update {
                self.offset = self.encrypted_part_plain.size;
            }
        } else {
            // new file
            self.init_new_file(&clean_filename).map_err(|err| {
                let _ = self.try_close(true, err);
                err
            })?;
        }
        self.set_file_status(ProtectedFsStatus::SGX_FILE_STATUS_OK);
        Ok(())
    }

    // remove the file path if it's there, leave only the filename, null terminated
    fn cleanup_filename<'a>(&mut self, src: &'a str) -> FsResult<&'a str> {
        let path = Path::new(src);
        let name = self.try_result(
            path.file_name()
                .unwrap_or_else(|| OsStr::new(src))
                .to_str()
                .ok_or(Error::from(libc::EINVAL)),
        )?;

        self.try_error(name.len() > FILENAME_MAX_LEN - 1, libc::ENAMETOOLONG)?;
        self.try_error(name.len() == 0, libc::EINVAL)?;
        Ok(name)
    }

    fn parse_mode(&mut self, mode: &str) -> FsError {
        self.try_error(
            mode.len() <= 0 || mode.len() > MAX_MODE_STRING_LEN,
            libc::EINVAL,
        )?;
        for c in mode.chars() {
            match c {
                'r' => {
                    self.try_error(
                        self.open_mode.write || self.open_mode.read || self.open_mode.append,
                        libc::EINVAL,
                    )?;
                    self.open_mode.read = true;
                }
                'w' => {
                    self.try_error(
                        self.open_mode.write || self.open_mode.read || self.open_mode.append,
                        libc::EINVAL,
                    )?;
                    self.open_mode.write = true;
                }
                'a' => {
                    self.try_error(
                        self.open_mode.write || self.open_mode.read || self.open_mode.append,
                        libc::EINVAL,
                    )?;
                    self.open_mode.append = true;
                }
                'b' => {
                    self.try_error(self.open_mode.binary, libc::EINVAL)?;
                    self.open_mode.binary = true;
                }
                '+' => {
                    self.try_error(self.open_mode.update, libc::EINVAL)?;
                    self.open_mode.update = true;
                }
                _ => {
                    self.try_error(true, libc::EINVAL)?;
                }
            }
        }
        self.try_error(
            !self.open_mode.write && !self.open_mode.read && !self.open_mode.append,
            libc::EINVAL,
        )?;
        Ok(())
    }

    pub fn check_file_exist(
        &mut self,
        import_key: Option<&sgx_aes_gcm_128bit_key_t>,
        filename: &str,
    ) -> FsError {
        let file_exist = self.try_result(ups::exists(filename))?;

        // file must exists
        self.try_error(self.open_mode.read && !file_exist, libc::ENOENT)?;
        // file must exists - otherwise the user key is not used
        self.try_error(import_key.is_some() && !file_exist, libc::ENOENT)?;

        if self.open_mode.write && file_exist {
            let mut saved_errno = 0_i32;
            // try to delete existing file
            if ProtectedFile::remove(filename).is_err() {
                // either can't delete or the file was already deleted by someone else
                saved_errno = errno();
                set_errno(0);
            }

            // re-check
            match ups::exists(filename) {
                Ok(file_exist) => {
                    if file_exist {
                        let error = if saved_errno != 0 {
                            saved_errno
                        } else {
                            libc::EACCES
                        };
                        self.set_last_error(Error::from(error));
                        return Err(Error::from(error));
                    }
                }
                Err(err) => {
                    self.set_last_error(err);
                    return Err(err);
                }
            }
        }
        Ok(())
    }

    fn file_recovery(&mut self, filename: &str) -> FsError {
        let result = self.file.close();
        self.try_result(result)?;

        self.try_result(ups::recovery(filename, &self.recovery_filename))?;

        let mut new_file_size = 0_i64;
        self.file = self.try_result(OsFile::open(filename, self.read_only, &mut new_file_size))?;

        // recovery only change existing data, it does not shrink or grow the file
        self.try_error(new_file_size != self.real_file_size, SGX_ERROR_UNEXPECTED)?;
        let result = self
            .file
            .read(META_DATA_PHY_NUM, &mut self.meta_data.meta_node);
        self.try_result(result)?;
        Ok(())
    }

    fn init_existing_file(
        &mut self,
        filename: &str,
        clean_filename: &str,
        import_key: Option<&sgx_aes_gcm_128bit_key_t>,
    ) -> FsError {
        let result = self
            .file
            .read(META_DATA_PHY_NUM, &mut self.meta_data.meta_node);
        self.try_result(result)?;

        // such a file exists, but it is not an SGX file
        self.try_error(self.file_id() != SGX_FILE_ID, SGX_ERROR_FILE_NOT_SGX_FILE)?;
        self.try_error(
            self.major_version() != SGX_FILE_MAJOR_VERSION,
            libc::ENOTSUP,
        )?;

        if self.update_flag() {
            // file was in the middle of an update, must do a recovery
            self.file_recovery(filename)
                .map_err(|_| SGX_ERROR_FILE_RECOVERY_NEEDED)?;
            // recovery failed, flag is still set!
            // recovery didn't clear the flag
            self.try_error(self.update_flag(), SGX_ERROR_FILE_RECOVERY_NEEDED)?;
            // re-check after recovery
            self.try_error(
                self.major_version() != SGX_FILE_MAJOR_VERSION,
                libc::ENOTSUP,
            )?;
        }
        self.try_error(
            self.meta_data.use_user_kdk_key() != self.use_user_kdk_key(),
            libc::EINVAL,
        )?;

        self.try_error(
            self.meta_data.integrity_only() != self.integrity_only,
            libc::EINVAL,
        )?;
        self.root_mht
            .borrow_mut()
            .set_integrity_only(self.integrity_only);

        //get cur_key
        if let Some(key) = import_key {
            if self.integrity_only {
                self.cur_key = sgx_aes_gcm_128bit_key_t::default();
            } else {
                self.cur_key = *key;
            }
        } else {
            let user_key = self.user_kdk_key();
            let result = self.meta_data.restore_key(user_key.as_ref());
            self.cur_key = self.try_result(result)?;
        }

        // decrypt the encrypted part of the meta-data
        let result = self.meta_data.decrypt(
            &self.cur_key,
            &mut self.encrypted_part_plain,
            &self.empty_iv,
        );
        self.try_result(result)?;

        let len = get_str_array_len(&self.encrypted_part_plain.clean_filename);
        self.try_error(
            self.encrypted_part_plain.clean_filename[0..len].ne(clean_filename.as_bytes()),
            SGX_ERROR_FILE_NAME_MISMATCH,
        )?;

        if self.encrypted_part_plain.size > i64!(MD_USER_DATA_SIZE) {
            // read the root node of the mht
            let result = self.file.read(
                ROOT_MHT_PHY_NUM,
                self.root_mht.borrow_mut().encrypted_data_mut(),
            );
            self.try_result(result)?;

            // this also verifies the root mht gmac against the gmac in the meta-data encrypted part
            let result = {
                let root_mht = &mut *self.root_mht.borrow_mut();
                root_mht.decrypt(
                    &self.encrypted_part_plain.mht_key,
                    &self.encrypted_part_plain.mht_gmac,
                    &self.empty_iv,
                )
            };
            self.try_result(result)?;
            self.root_mht.borrow_mut().set_new_node(false);
        }
        Ok(())
    }

    fn init_new_file(&mut self, clean_filename: &str) -> FsError {
        self.meta_data.meta_node.plain_part.file_id = SGX_FILE_ID;
        self.meta_data.meta_node.plain_part.major_version = SGX_FILE_MAJOR_VERSION;
        self.meta_data.meta_node.plain_part.minor_version = SGX_FILE_MINOR_VERSION;
        self.meta_data.set_use_user_kdk_key(self.use_user_kdk_key());
        self.meta_data.set_integrity_only(self.integrity_only);

        self.root_mht
            .borrow_mut()
            .set_integrity_only(self.integrity_only);

        self.encrypted_part_plain.clean_filename[0..clean_filename.len()]
            .copy_from_slice(clean_filename.as_bytes());

        self.root_mht
            .borrow_mut()
            .set_integrity_only(self.integrity_only);
        self.need_writing = true;
        Ok(())
    }
}
