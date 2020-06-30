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
use crate::core::nodes::*;
use crate::core::ups::{self, OsRecoveryFile};
use crate::error::{Error, FsError};
use std::vec::Vec;
use types::sgx_key_128bit_t;
use types::sgx_status_t::*;

impl ProtectedFile {
    pub fn flush(&mut self) -> FsError {
        self.try_error(!self.is_file_ok(), SGX_ERROR_FILE_BAD_STATUS)?;

        let result = self.internal_flush(true);
        if result.is_err() && self.is_file_ok() {
            // for release set this anyway
            self.set_file_status(ProtectedFsStatus::SGX_FILE_STATUS_FLUSH_ERROR);
        }
        result
    }

    pub fn internal_flush(&mut self, flush: bool) -> FsError {
        if !self.need_writing {
            // no changes at all
            return Ok(());
        }

        // otherwise it's just one write - the meta-data node
        if self.is_need_write_node() {
            self.write_recovery_file().map_err(|err| {
                self.set_last_error(err);
                self.set_file_status(ProtectedFsStatus::SGX_FILE_STATUS_FLUSH_ERROR);
                err
            })?;

            self.set_update_flag(flush).map_err(|err| {
                self.set_last_error(err);
                self.set_file_status(ProtectedFsStatus::SGX_FILE_STATUS_FLUSH_ERROR);
                err
            })?;

            self.update_all_data_and_mht_nodes().map_err(|err| {
                self.set_last_error(err);
                self.clear_update_flag();
                // this is something that shouldn't happen, can't fix this...
                self.set_file_status(ProtectedFsStatus::SGX_FILE_STATUS_CRYPTO_ERROR);
                err
            })?;
        }

        self.update_meta_data_node().map_err(|err| {
            self.set_last_error(err);
            self.clear_update_flag();
            // this is something that shouldn't happen, can't fix this...
            self.set_file_status(ProtectedFsStatus::SGX_FILE_STATUS_CRYPTO_ERROR);
            err
        })?;

        self.write_all_changes_to_disk(flush).map_err(|err| {
            self.set_last_error(err);
            // special case, need only to repeat write_all_changes_to_disk in order to repair it
            self.set_file_status(ProtectedFsStatus::SGX_FILE_STATUS_WRITE_TO_DISK_FAILED);
            err
        })?;

        self.need_writing = false;
        Ok(())
    }

    pub fn pre_close(&mut self, key: Option<&mut sgx_key_128bit_t>, import: bool) -> bool {
        let mut retval = true;
        if import {
            if self.use_user_kdk_key() {
                // import file is only needed for auto-key
                retval = false;
            } else {
                // will re-encrypt the meta-data node with local key
                self.need_writing = true;
            }
        }

        if !self.is_file_ok() {
            // last attempt to fix it
            self.clear_error();
        } else {
            let _ = self.internal_flush(true);
        }

        if !self.is_file_ok() {
            retval = false;
        }

        let _ = self.file.close().map_err(|err| {
            self.set_last_error(err);
            retval = false;
            err
        });

        if self.is_file_ok() && self.is_last_error_ok() {
            self.erase_recovery_file();
        }

        key.map(|k| {
            if self.use_user_kdk_key() {
                // export key is only used for auto-key
                retval = false;
            } else {
                let result = self.meta_data.restore_key(None);
                match result {
                    Ok(restore_key) => {
                        self.cur_key = restore_key;
                        *k = restore_key;
                    }
                    Err(err) => {
                        self.set_last_error(err);
                        retval = false;
                    }
                }
            }
        });

        self.set_file_status(ProtectedFsStatus::SGX_FILE_STATUS_CLOSED);
        retval
    }

    pub fn write_all_changes_to_disk(&mut self, flush: bool) -> FsError {
        if self.is_need_write_node() {
            for node in self.cache.iter_mut() {
                if !node.borrow().is_need_writing() {
                    continue;
                }
                self.file.write(
                    node.borrow().physical_node_number(),
                    node.borrow().encrypted_data(),
                )?;

                node.borrow_mut().set_need_writing(false);
                node.borrow_mut().set_new_node(false);
            }

            self.file
                .write(ROOT_MHT_PHY_NUM, self.root_mht.borrow().encrypted_data())?;

            self.root_mht.borrow_mut().set_need_writing(false);
            self.root_mht.borrow_mut().set_new_node(false);
        }

        self.file
            .write(META_DATA_PHY_NUM, &self.meta_data.meta_node)?;

        if flush {
            self.file.flush()?;
        }
        Ok(())
    }

    fn write_recovery_file_node(&mut self) -> FsError {
        let mut file = OsRecoveryFile::open(&self.recovery_filename)?;
        for node in self.cache.iter() {
            if node.borrow().is_need_writing() && !node.borrow().is_new_node() {
                file.write(node.borrow().encrypted_node())?;
            }
        }

        if self.root_mht.borrow().is_need_writing() && !self.root_mht.borrow().is_new_node() {
            file.write(self.root_mht.borrow().encrypted_node())?;
        }
        file.write(&self.meta_data)
    }

    fn write_recovery_file(&mut self) -> FsError {
        self.write_recovery_file_node().map_err(|err| {
            let _ = ups::remove(&self.recovery_filename);
            err
        })
    }

    fn set_update_flag(&mut self, flush: bool) -> FsError {
        self.meta_data.meta_node.plain_part.update_flag = 1;
        let result = self
            .file
            .write(META_DATA_PHY_NUM, &self.meta_data.meta_node);
        // turn it off in memory. at the end of the flush, when we'll write the meta-data to disk, this flag will also be cleared there.
        self.meta_data.meta_node.plain_part.update_flag = 0;
        result?;

        if flush {
            self.file.flush().map_err(|err| {
                let _ = self
                    .file
                    .write(META_DATA_PHY_NUM, &self.meta_data.meta_node);
                err
            })?;
        }
        Ok(())
    }

    // this function is called if we had an error after we updated the update flag
    // in normal flow, the flag is cleared when the meta-data is written to disk
    fn clear_update_flag(&mut self) {
        assert!(self.update_flag() == false);
        let _ = self
            .file
            .write(META_DATA_PHY_NUM, &self.meta_data.meta_node);
        let _ = self.file.flush();
    }

    fn update_all_data_and_mht_nodes(&mut self) -> FsError {
        // 1. encrypt the changed data
        // 2. set the IV+GMAC in the parent MHT
        // 3. set the need_writing flag for all the parents
        for node in self.cache.iter_mut() {
            if node.borrow().is_data() && node.borrow().is_need_writing() {
                self.cur_key = node.borrow().derive_key(&self.session_key.update()?)?;

                let mht_node = node
                    .borrow()
                    .parent()
                    .ok_or(Error::from(SGX_ERROR_UNEXPECTED))?;

                let index = usize!(node.borrow().node_number()) % ATTACHED_DATA_NODES_COUNT;
                let mut gcm_crypto_data = mht_node
                    .borrow()
                    .data_nodes_crypto(index)
                    .ok_or(Error::from(SGX_ERROR_UNEXPECTED))?;

                // encrypt data_node
                {
                    let data = &mut *node.borrow_mut();
                    data.encrypt(&self.cur_key, gcm_crypto_data.gmac_mut(), &self.empty_iv)?;
                }

                gcm_crypto_data.set_key(self.cur_key);
                mht_node
                    .borrow_mut()
                    .set_data_nodes_crypto(index, gcm_crypto_data);

                let mut parent = node.borrow().parent();
                while let Some(mht) = parent {
                    if mht.borrow().node_number() != 0 {
                        mht.borrow_mut().set_need_writing(true);
                        parent = mht.borrow().parent();
                    } else {
                        break;
                    }
                }
            }
        }

        // add all the mht nodes that needs writing to a list
        let mut mht_vec: Vec<NodeRef<FileNode>> = Vec::new();
        for data in self.cache.iter() {
            if data.borrow().is_mht() && data.borrow().is_need_writing() {
                mht_vec.push(data.clone());
            }
        }
        // sort the list from the last node to the first (bottom layers first)
        mht_vec.sort_by(|a, b| b.borrow().node_number().cmp(&a.borrow().node_number()));

        // update the gmacs in the parents
        for mht in mht_vec {
            let parent = mht
                .borrow()
                .parent()
                .ok_or(Error::from(SGX_ERROR_UNEXPECTED))?;

            let index = usize!(mht.borrow().node_number() - 1) % CHILD_MHT_NODES_COUNT;
            let mut gcm_crypto_data = parent
                .borrow()
                .mht_nodes_crypto(index)
                .ok_or(Error::from(SGX_ERROR_UNEXPECTED))?;

            self.cur_key = mht.borrow().derive_key(&self.session_key.update()?)?;

            {
                let data = &mut *mht.borrow_mut();
                data.encrypt(&self.cur_key, gcm_crypto_data.gmac_mut(), &self.empty_iv)?;
            }

            gcm_crypto_data.set_key(self.cur_key);
            parent
                .borrow_mut()
                .set_mht_nodes_crypto(index, gcm_crypto_data);
        }

        // update mht root gmac in the meta data node
        self.cur_key = self
            .root_mht
            .borrow()
            .derive_key(&self.session_key.update()?)?;

        {
            let data = &mut *self.root_mht.borrow_mut();
            data.encrypt(
                &self.cur_key,
                &mut self.encrypted_part_plain.mht_gmac,
                &self.empty_iv,
            )?;
        }

        self.encrypted_part_plain.mht_key = self.cur_key;
        Ok(())
    }

    fn update_meta_data_node(&mut self) -> FsError {
        // randomize a new key, saves the key _id_ in the meta data plain part
        let user_key = self.user_kdk_key();
        self.cur_key = self.meta_data.derive_key(user_key.as_ref(), self.report.as_ref())?;

        self.meta_data
            .encrypt(&self.cur_key, &self.encrypted_part_plain, &self.empty_iv)
    }

    #[inline]
    fn is_need_write_node(&self) -> bool {
        self.encrypted_part_plain.size > i64!(MD_USER_DATA_SIZE)
            && self.root_mht.borrow().is_need_writing()
    }

    // don't care if it succeeded or failed...just remove the warning
    fn erase_recovery_file(&mut self) {
        if self.recovery_filename.len() > 0 {
            let _ = ups::remove(&self.recovery_filename);
        }
    }
}
