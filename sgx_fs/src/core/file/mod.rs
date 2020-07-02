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

use crate::core::cache::LruCache;
use crate::core::consts::*;
use crate::core::crypto::SessionKey;
use crate::core::meta::*;
use crate::core::nodes::*;
use crate::core::ups::OsFile;
use crate::error::Error;

use std::string::String;
use types::sgx_aes_gcm_128bit_key_t;
use types::sgx_report_t;
use types::sgx_status_t::*;

type sgx_iv_t = [u8; SGX_AESGCM_IV_SIZE];

pub struct ProtectedFile {
    file: OsFile,
    meta_data: MetaData,
    encrypted_part_plain: MetaDataEncrypted, // encrypted part of meta data node, decrypted
    root_mht: NodeRef<FileNode>, // the root of the mht is always needed (for files bigger than 3KB)

    open_mode: OpenMode,
    read_only: bool,
    need_writing: bool,
    end_of_file: bool,
    integrity_only: bool,
    
    real_file_size: i64,
    offset: i64,
    last_error: Error,
    file_status: ProtectedFsStatus,

    user_kdk_key: Option<sgx_aes_gcm_128bit_key_t>,
    cur_key: sgx_aes_gcm_128bit_key_t,
    session_key: SessionKey,

    recovery_filename: String, // might include full path to the file

    cache: LruCache<FileNode>,

    empty_iv: sgx_iv_t,
    report: Option<sgx_report_t>, 
}

impl ProtectedFile {
    pub fn new() -> ProtectedFile {
        ProtectedFile {
            file: OsFile::new_null(),
            meta_data: MetaData::new(),
            encrypted_part_plain: MetaDataEncrypted::new(),
            root_mht: build_filenode_ref(NodeType::Mht, 0, 1, false),

            open_mode: OpenMode::default(),
            read_only: false,
            need_writing: false,
            end_of_file: false,
            integrity_only: false,

            real_file_size: 0,
            offset: 0,
            last_error: Error::from(SGX_SUCCESS),
            file_status: ProtectedFsStatus::SGX_FILE_STATUS_NOT_INITIALIZED,

            user_kdk_key: None,
            cur_key: sgx_aes_gcm_128bit_key_t::default(),
            session_key: SessionKey::default(),

            recovery_filename: String::new(),

            cache: LruCache::with_capacity(MAX_PAGES_IN_CACHE),

            empty_iv: [0; SGX_AESGCM_IV_SIZE],
            report: None, 
        }
    }
}

impl ProtectedFile {
    #[inline]
    pub fn set_last_error(&mut self, error: Error) {
        self.last_error = error;
    }

    #[inline]
    pub fn set_file_status(&mut self, status: ProtectedFsStatus) {
        self.file_status = status;
    }

    #[inline]
    fn last_error(&self) -> Error {
        self.last_error
    }

    #[inline]
    fn raw_last_error(&self) -> i32 {
        self.last_error.raw_error()
    }

    #[inline]
    fn is_last_error_ok(&self) -> bool {
        self.last_error.is_success()
    }

    #[inline]
    fn is_file_ok(&self) -> bool {
        self.file_status == ProtectedFsStatus::SGX_FILE_STATUS_OK
    }

    #[inline]
    fn is_valid_path_length(&self, len: usize) -> bool {
        len < FULLNAME_MAX_LEN - 1
    }

    #[inline]
    fn use_user_kdk_key(&self) -> bool {
        self.user_kdk_key.is_some()
    }

    #[inline]
    fn user_kdk_key(&self) -> Option<sgx_aes_gcm_128bit_key_t> {
        self.user_kdk_key
    }

    #[inline]
    fn set_user_kdk_key(&mut self, key: sgx_aes_gcm_128bit_key_t) {
        self.user_kdk_key = Some(key);
    }

    #[inline]
    fn major_version(&self) -> u8 {
        self.meta_data.meta_node.plain_part.major_version
    }

    #[inline]
    fn file_id(&self) -> u64 {
        self.meta_data.meta_node.plain_part.file_id
    }

    #[inline]
    fn update_flag(&self) -> bool {
        self.meta_data.meta_node.plain_part.update_flag != 0
    }
}

#[repr(u32)]
#[derive(Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Debug)]
pub enum ProtectedFsStatus {
    SGX_FILE_STATUS_OK = 0,
    SGX_FILE_STATUS_NOT_INITIALIZED = 1,
    SGX_FILE_STATUS_FLUSH_ERROR = 2,
    SGX_FILE_STATUS_WRITE_TO_DISK_FAILED = 3,
    SGX_FILE_STATUS_CRYPTO_ERROR = 4,
    SGX_FILE_STATUS_CORRUPTED = 5,
    SGX_FILE_STATUS_MEMORY_CORRUPTED = 6,
    SGX_FILE_STATUS_CLOSED = 7,
}

pub struct OpenMode {
    pub read: bool,
    pub write: bool,
    pub append: bool,
    pub binary: bool,
    pub update: bool,
}

impl OpenMode {
    pub fn new() -> OpenMode {
        OpenMode {
            read: false,
            write: false,
            append: false,
            binary: false,
            update: false,
        }
    }
}

impl Default for OpenMode {
    fn default() -> OpenMode {
        OpenMode::new()
    }
}

mod flush;
mod init;
mod node;
mod other;
mod read;
mod write;
