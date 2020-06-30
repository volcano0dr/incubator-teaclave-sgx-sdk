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
use crate::error::{Error, FsError};
use std::mem;
use types::sgx_status_t::*;

fn get_node_numbers(offset: u64) -> (u64, u64, u64, u64) {
    if usize!(offset) < MD_USER_DATA_SIZE {
        return (0, 0, 0, 0);
    }
    // node 0 - meta data node
    // node 1 - mht
    // nodes 2-97 - data (ATTACHED_DATA_NODES_COUNT == 96)
    // node 98 - mht
    // node 99-195 - data
    // etc.
    let data_node_number: u64 = u64!((usize!(offset) - MD_USER_DATA_SIZE) / NODE_SIZE); //4096
    let mht_node_number: u64 = data_node_number / u64!(ATTACHED_DATA_NODES_COUNT); // 96
    let physical_data_node_number: u64 = data_node_number
                                        + 1 // meta data node
                                        + 1 // mht root
                                        + mht_node_number; // number of mht nodes in the middle (the root mht mht_node_number is 0)
    let physical_mht_node_number: u64 = physical_data_node_number
                                        - data_node_number % u64!(ATTACHED_DATA_NODES_COUNT) // now we are at the first data node attached to this mht node
                                        - 1; // and now at the mht node itself!

    (
        mht_node_number,
        data_node_number,
        physical_mht_node_number,
        physical_data_node_number,
    )
}

fn get_data_node_numbers(offset: u64) -> (u64, u64) {
    let (_, logic, _, physical) = get_node_numbers(offset);
    (logic, physical)
}

fn get_mht_node_numbers(offset: u64) -> (u64, u64) {
    let (logic, _, physical, _) = get_node_numbers(offset);
    (logic, physical)
}

impl ProtectedFile {
    pub fn get_data_node(&mut self) -> Option<NodeRef<FileNode>> {
        if usize!(self.offset) < MD_USER_DATA_SIZE {
            self.set_last_error(Error::from(SGX_ERROR_UNEXPECTED));
            return None;
        }

        let file_data_node = if ((usize!(self.offset) - MD_USER_DATA_SIZE) % NODE_SIZE == 0)
            && (self.offset == self.encrypted_part_plain.size)
        {
            // new node
            self.append_data_node()
        } else {
            // existing node
            self.read_data_node()
        };

        file_data_node.as_ref().map(|node| self.bump_mht_node(node));
        self.remove_last_node().ok()?;

        file_data_node
    }

    fn get_mht_node(&mut self) -> Option<NodeRef<FileNode>> {
        if usize!(self.offset) < MD_USER_DATA_SIZE {
            self.set_last_error(Error::from(SGX_ERROR_UNEXPECTED));
            return None;
        }

        let (node_number, _) = get_mht_node_numbers(u64!(self.offset));
        if node_number == 0 {
            return Some(self.root_mht.clone());
        }

        // file is constructed from 128*4KB = 512KB per MHT node.
        if ((usize!(self.offset) - MD_USER_DATA_SIZE) % (ATTACHED_DATA_NODES_COUNT * NODE_SIZE)
            == 0)
            && (self.offset == self.encrypted_part_plain.size)
        {
            self.append_mht_node(node_number)
        } else {
            self.read_mht_node(node_number)
        }
    }

    fn append_mht_node(&mut self, mht_node_number: u64) -> Option<NodeRef<FileNode>> {
        let parent_mht_node =
            self.read_mht_node((mht_node_number - 1) / u64!(CHILD_MHT_NODES_COUNT))?;
        let physical_node_number: u64 = 1 // meta data node
                                        + mht_node_number * u64!(1 + ATTACHED_DATA_NODES_COUNT); // the '1' is for the mht node preceding every 96 data nodes

        let file_mht_node = build_filenode_ref(
            NodeType::Mht,
            mht_node_number,
            physical_node_number,
            self.integrity_only,
        );
        file_mht_node
            .borrow_mut()
            .set_parent(parent_mht_node.clone());

        if !self.cache.add(physical_node_number, file_mht_node.clone()) {
            self.set_last_error(Error::from(libc::ENOMEM));
            return None;
        }
        Some(file_mht_node)
    }

    fn read_mht_node(&mut self, mht_node_number: u64) -> Option<NodeRef<FileNode>> {
        if mht_node_number == 0 {
            return Some(self.root_mht.clone());
        }

        let physical_node_number: u64 = 1 + // meta data node
										mht_node_number * u64!(1 + ATTACHED_DATA_NODES_COUNT); // the '1' is for the mht node preceding every 96 data nodes
        let file_mht_node = self.cache.find(physical_node_number);
        if file_mht_node.is_some() {
            return file_mht_node;
        }

        let parent_mht_node =
            self.read_mht_node(u64!(usize!(mht_node_number - 1) / CHILD_MHT_NODES_COUNT))?;
        let file_mht_node = build_filenode_ref(
            NodeType::Mht,
            mht_node_number,
            physical_node_number,
            self.integrity_only,
        );
        file_mht_node
            .borrow_mut()
            .set_parent(parent_mht_node.clone());

        self.file
            .read(
                physical_node_number,
                file_mht_node.borrow_mut().encrypted_data_mut(),
            )
            .map_err(|err| {
                self.set_last_error(err);
                err
            })
            .ok()?;

        let index = usize!(file_mht_node.borrow().node_number() - 1) % CHILD_MHT_NODES_COUNT;
        let gcm_crypto_data = parent_mht_node.borrow().mht_nodes_crypto(index)?;

        // decrypt the encrypted part of the meta-data
        {
            let file_node = &mut *file_mht_node.borrow_mut();
            file_node
                .decrypt(
                    gcm_crypto_data.key(),
                    gcm_crypto_data.gmac(),
                    &self.empty_iv,
                )
                .map_err(|err| {
                    self.set_last_error(err);
                    err
                })
                .ok()?;
        }

        if !self.cache.add(physical_node_number, file_mht_node.clone()) {
            file_mht_node.borrow_mut().clean_plain();
            self.set_last_error(Error::from(libc::ENOMEM));
            return None;
        }
        Some(file_mht_node)
    }

    fn append_data_node(&mut self) -> Option<NodeRef<FileNode>> {
        let file_mht_node = self.get_mht_node()?;
        let (node_number, physical_node_number) = get_data_node_numbers(u64!(self.offset));

        let file_data_node = build_filenode_ref(
            NodeType::Data,
            node_number,
            physical_node_number,
            self.integrity_only,
        );
        file_data_node
            .borrow_mut()
            .set_parent(file_mht_node.clone());

        if !self.cache.add(physical_node_number, file_data_node.clone()) {
            self.set_last_error(Error::from(libc::ENOMEM));
            return None;
        }

        Some(file_data_node)
    }

    fn read_data_node(&mut self) -> Option<NodeRef<FileNode>> {
        let (node_number, physical_node_number) = get_data_node_numbers(u64!(self.offset));

        let file_data_node = self.cache.find(physical_node_number);
        if file_data_node.is_some() {
            return file_data_node;
        }

        // need to read the data node from the disk
        let file_mht_node = self.get_mht_node()?;
        let file_data_node = build_filenode_ref(
            NodeType::Data,
            node_number,
            physical_node_number,
            self.integrity_only,
        );
        file_data_node
            .borrow_mut()
            .set_parent(file_mht_node.clone());

        self.file
            .read(
                physical_node_number,
                file_data_node.borrow_mut().encrypted_data_mut(),
            )
            .map_err(|err| {
                self.set_last_error(err);
                err
            })
            .ok()?;

        let index = usize!(file_data_node.borrow().node_number()) % ATTACHED_DATA_NODES_COUNT;
        let gcm_crypto_data = file_mht_node.borrow().data_nodes_crypto(index)?;

        // decrypt the encrypted part of the meta-data
        {
            let file_node = &mut *file_data_node.borrow_mut();
            file_node
                .decrypt(
                    gcm_crypto_data.key(),
                    gcm_crypto_data.gmac(),
                    &self.empty_iv,
                )
                .map_err(|err| {
                    self.set_last_error(err);
                    err
                })
                .ok()?;
        }

        if !self.cache.add(physical_node_number, file_data_node.clone()) {
            file_data_node.borrow_mut().clean_plain();
            self.set_last_error(Error::from(libc::ENOMEM));
            return None;
        }

        Some(file_data_node)
    }

    fn bump_mht_node(&mut self, node: &NodeRef<FileNode>) {
        // bump all the parents mht to reside before the data node in the cache
        let mut parent = node.borrow().parent();
        while let Some(mht) = parent {
            if mht.borrow().node_number() != 0 {
                // bump the mht node to the head of the lru
                self.cache.bump(mht.borrow().physical_node_number());
                parent = mht.borrow().parent();
            } else {
                break;
            }
        }
    }

    fn remove_last_node(&mut self) -> FsError {
        // even if we didn't get the required data_node, we might have read other nodes in the process
        while self.cache.len() > MAX_PAGES_IN_CACHE {
            let data = self
                .cache
                .back_mut()
                .ok_or(Error::from(SGX_ERROR_UNEXPECTED))?;
            if data.borrow().is_need_writing() == false {
                // need_writing is in the same offset in both node types
                // before deleting the memory, need to scrub the plain secrets
                data.borrow_mut().clean_plain();
                let node = self.cache.pop_back();
                mem::drop(node);
            } else {
                self.internal_flush(false).map_err(|err| {
                    // error, can't flush cache, file status changed to error
                    if self.is_file_ok() {
                        // for release set this anyway
                        self.set_file_status(ProtectedFsStatus::SGX_FILE_STATUS_FLUSH_ERROR);
                    }
                    err
                })?;
            }
        }
        Ok(())
    }
}
