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
    pub fn read(&mut self, data: &mut [u8]) -> FsResult<usize> {
        if data.is_empty() {
            return Ok(0);
        }

        #[cfg(feature = "mesalock_sgx")]
        self.try_error(
            rsgx_slice_is_outside_enclave(data),
            SGX_ERROR_INVALID_PARAMETER,
        )?;

        self.try_error(!self.is_file_ok(), SGX_ERROR_FILE_BAD_STATUS)?;
        self.try_error(!self.open_mode.read && !self.open_mode.update, libc::EACCES)?;

        if self.end_of_file {
            return Ok(0);
        }

        // this check is not really needed, can go on with the code and it will do nothing until the end, but it's more 'right' to check it here
        if self.offset == self.encrypted_part_plain.size {
            self.end_of_file = true;
            return Ok(0);
        }

        let mut data_left_to_read = data.len();
        if data_left_to_read > usize!(self.encrypted_part_plain.size - self.offset) {
            data_left_to_read = usize!(self.encrypted_part_plain.size - self.offset);
        }

        let data_attemp_to_read = data_left_to_read;
        let mut data_offset = 0;

        if usize!(self.offset) < MD_USER_DATA_SIZE {
            let md_left = MD_USER_DATA_SIZE - usize!(self.offset);
            let len = if data_left_to_read > md_left {
                md_left
            } else {
                data_left_to_read
            };

            data[data_offset..data_offset + len].copy_from_slice(
                &self.encrypted_part_plain.data[usize!(self.offset)..usize!(self.offset) + len],
            );
            data_offset += len;
            data_left_to_read -= len;
            self.offset += i64!(len);
        }

        while data_left_to_read > 0 {
            let file_node = self.get_data_node();
            if file_node.is_none() {
                break;
            }
            let file_node = file_node.unwrap();

            let offset_in_node = (usize!(self.offset) - MD_USER_DATA_SIZE) % NODE_SIZE;
            let node_left = NODE_SIZE - offset_in_node;

            let len = if data_left_to_read > node_left {
                node_left
            } else {
                data_left_to_read
            };

            data[data_offset..data_offset + len].copy_from_slice(
                &file_node.borrow().plain_slice()[offset_in_node..offset_in_node + len],
            );
            data_offset += len;
            data_left_to_read -= len;
            self.offset += i64!(len);
        }

        // user wanted to read more and we had to shrink the request
        if data_left_to_read == 0 && data_attemp_to_read != data.len() {
            assert!(self.offset == self.encrypted_part_plain.size);
            self.end_of_file = true;
        }
        Ok(data_attemp_to_read - data_left_to_read)
    }
}
