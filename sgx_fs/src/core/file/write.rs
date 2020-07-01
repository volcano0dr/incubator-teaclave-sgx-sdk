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
use crate::core::file::ProtectedFile;
use crate::error::FsResult;
use libc;
#[cfg(feature = "mesalock_sgx")]
use trts::trts::rsgx_slice_is_outside_enclave;
use types::sgx_status_t::*;

impl ProtectedFile {
    pub fn write(&mut self, data: &[u8]) -> FsResult<usize> {
        if data.is_empty() {
            return Ok(0);
        }

        #[cfg(feature = "mesalock_sgx")]
        self.try_error(
            rsgx_slice_is_outside_enclave(data),
            SGX_ERROR_INVALID_PARAMETER,
        )?;

        self.try_error(!self.is_file_ok(), SGX_ERROR_FILE_BAD_STATUS)?;
        self.try_error(
            !self.open_mode.write && !self.open_mode.append && !self.open_mode.update,
            libc::EACCES,
        )?;
        if self.open_mode.append {
            self.offset = self.encrypted_part_plain.size; // add at the end of the file
        }

        let mut data_left_to_write = data.len();
        let mut data_offset = 0;

        // the first block of user data is written in the meta-data encrypted part
        if usize!(self.offset) < MD_USER_DATA_SIZE {
            let md_empty = MD_USER_DATA_SIZE - usize!(self.offset);
            let len = if data_left_to_write > md_empty {
                md_empty
            } else {
                data_left_to_write
            };

            self.encrypted_part_plain.data[usize!(self.offset)..usize!(self.offset) + len]
                .copy_from_slice(&data[data_offset..data_offset + len]);
            data_left_to_write -= len;
            data_offset += len;
            self.offset += i64!(len);

            if self.offset > self.encrypted_part_plain.size {
                self.encrypted_part_plain.size = self.offset;
            }
            self.need_writing = true;
        }

        while data_left_to_write > 0 {
            let file_node = self.get_data_node();
            if file_node.is_none() {
                break;
            }
            let file_node = file_node.unwrap();
            let offset_in_node = (usize!(self.offset) - MD_USER_DATA_SIZE) % NODE_SIZE;
            let node_empty_place = NODE_SIZE - offset_in_node;

            let len = if data_left_to_write > node_empty_place {
                node_empty_place
            } else {
                data_left_to_write
            };

            file_node.borrow_mut().plain_mut_slice()[offset_in_node..offset_in_node + len]
                .copy_from_slice(&data[data_offset..data_offset + len]);

            data_left_to_write -= len;
            data_offset += len;
            self.offset += i64!(len);

            if self.offset > self.encrypted_part_plain.size {
                self.encrypted_part_plain.size = self.offset;
            }

            if !file_node.borrow().is_need_writing() {
                file_node.borrow_mut().set_need_writing(true);

                let mut parent = file_node.borrow().parent();
                while let Some(mht) = parent {
                    if mht.borrow().node_number() != 0 {
                        mht.borrow_mut().set_need_writing(true);
                        parent = mht.borrow().parent();
                    } else {
                        break;
                    }
                }

                self.root_mht.borrow_mut().set_need_writing(true);
                self.need_writing = true;
            }
        }
        Ok(data_offset)
    }
}
