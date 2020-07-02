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
use crate::core::crypto::*;
use crate::core::nodes::AsSlice;
use crate::deps::ConsttimeMemEq;
use crate::error::{Error, FsError, FsResult};

use std::mem;
use types::marker::ContiguousMemory;
use types::{
    sgx_aes_gcm_128bit_key_t,
    sgx_aes_gcm_128bit_tag_t,
    sgx_attributes_t,
    sgx_cpu_svn_t,
    sgx_isv_svn_t,
    sgx_key_id_t,
    sgx_report_t,
};
use types::sgx_status_t::*;


#[repr(C)]
#[repr(packed)]
#[derive(Copy, Clone, Default)]
pub struct sgx_mc_uuid_t {
    mc_uuid: [u8; 16],
}

pub const USE_USER_KDK_KEY: u8 = 0x01;
pub const INTEGRITY_ONLY: u8 = 0x02;

#[repr(C)]
#[repr(packed)]
pub struct MetaDataPlain {
    pub file_id: u64,
    pub major_version: u8,
    pub minor_version: u8,
    pub meta_data_key_id: sgx_key_id_t,
    pub cpu_svn: sgx_cpu_svn_t,
    pub isv_svn: sgx_isv_svn_t,
    pub flag: u8,
    pub attribute_mask: sgx_attributes_t,
    pub meta_data_gmac: sgx_aes_gcm_128bit_tag_t,
    pub update_flag: u8,
}

impl MetaDataPlain {
    pub fn new() -> MetaDataPlain {
        MetaDataPlain {
            file_id: 0,       // SGX_FILE_ID,
            major_version: 0, // SGX_FILE_MAJOR_VERSION,
            minor_version: 0, // SGX_FILE_MINOR_VERSION,
            meta_data_key_id: sgx_key_id_t::default(),
            cpu_svn: sgx_cpu_svn_t::default(),
            isv_svn: sgx_isv_svn_t::default(),
            flag: 0,
            attribute_mask: sgx_attributes_t::default(),
            meta_data_gmac: sgx_aes_gcm_128bit_tag_t::default(),
            update_flag: 0,
        }
    }
}

#[repr(C)]
#[repr(packed)]
pub struct MetaDataEncrypted {
    pub clean_filename: [u8; FILENAME_MAX_LEN],
    pub size: i64,
    pub mc_uuid: sgx_mc_uuid_t,
    pub mc_value: u32,
    pub mht_key: sgx_aes_gcm_128bit_key_t,
    pub mht_gmac: sgx_aes_gcm_128bit_tag_t,
    pub data: [u8; MD_USER_DATA_SIZE],
}

impl MetaDataEncrypted {
    pub fn new() -> MetaDataEncrypted {
        MetaDataEncrypted {
            clean_filename: [0; FILENAME_MAX_LEN],
            size: 0,
            mc_uuid: sgx_mc_uuid_t::default(),
            mc_value: 0,
            mht_key: sgx_aes_gcm_128bit_key_t::default(),
            mht_gmac: sgx_aes_gcm_128bit_tag_t::default(),
            data: [0; MD_USER_DATA_SIZE],
        }
    }
}

#[repr(C)]
#[repr(packed)]
pub struct MetaData {
    pub node_number: u64,
    pub meta_node: MetaDataNode,
}

impl MetaData {
    pub fn new() -> MetaData {
        MetaData {
            node_number: 0,
            meta_node: MetaDataNode::new(),
        }
    }

    #[inline]
    pub fn integrity_only(&self) -> bool {
        self.meta_node.integrity_only()
    }

    #[inline]
    pub fn set_integrity_only(&mut self, integrity_only: bool) {
        self.meta_node.set_integrity_only(integrity_only)
    }

    #[inline]
    pub fn use_user_kdk_key(&self) -> bool {
        self.meta_node.use_user_kdk_key()
    }

    #[inline]
    pub fn set_use_user_kdk_key(&mut self, use_key: bool) {
        self.meta_node.set_use_user_kdk_key(use_key)
    }

    #[inline]
    pub fn encrypt(
        &mut self,
        key: &sgx_aes_gcm_128bit_key_t,
        plain: &MetaDataEncrypted,
        iv: &[u8],
    ) -> FsError {
        self.meta_node.encrypt(key, plain, iv)
    }

    #[inline]
    pub fn decrypt(
        &self,
        key: &sgx_aes_gcm_128bit_key_t,
        plain: &mut MetaDataEncrypted,
        iv: &[u8],
    ) -> FsError {
        self.meta_node.decrypt(key, plain, iv)
    }

    #[inline]
    pub fn derive_key(
        &mut self,
        user_kdk: Option<&sgx_aes_gcm_128bit_key_t>,
        report: Option<&sgx_report_t>,
    ) -> FsResult<sgx_aes_gcm_128bit_key_t> {
        self.meta_node.derive_key(user_kdk, report)
    }

    #[inline]
    pub fn restore_key(
        &self,
        user_kdk: Option<&sgx_aes_gcm_128bit_key_t>,
    ) -> FsResult<sgx_aes_gcm_128bit_key_t> {
        self.meta_node.restore_key(user_kdk)
    }
}

const META_DATA_PADDING: usize =
    NODE_SIZE - mem::size_of::<MetaDataPlain>() - mem::size_of::<MetaDataEncrypted>();
const META_DATA_ENCRYPTED: usize = mem::size_of::<MetaDataEncrypted>();

#[repr(C)]
#[repr(packed)]
pub struct MetaDataNode {
    pub plain_part: MetaDataPlain,
    pub encrypted_part: [u8; META_DATA_ENCRYPTED],
    pub padding: [u8; META_DATA_PADDING],
}

impl MetaDataNode {
    pub fn new() -> MetaDataNode {
        MetaDataNode {
            plain_part: MetaDataPlain::new(),
            encrypted_part: [0; META_DATA_ENCRYPTED],
            padding: [0; META_DATA_PADDING],
        }
    }

    #[inline]
    pub fn integrity_only(&self) -> bool {
       (self.plain_part.flag & INTEGRITY_ONLY) != 0
    }

    #[inline]
    pub fn set_integrity_only(&mut self, integrity_only: bool) {
        if integrity_only {
            self.plain_part.flag |= INTEGRITY_ONLY;
        } else {
            self.plain_part.flag &= !INTEGRITY_ONLY
        }
    }

    #[inline]
    pub fn use_user_kdk_key(&self) -> bool {
        (self.plain_part.flag & USE_USER_KDK_KEY) != 0
    }

    #[inline]
    pub fn set_use_user_kdk_key(&mut self, use_key: bool) {
        if use_key {
            self.plain_part.flag |= USE_USER_KDK_KEY;
        } else {
            self.plain_part.flag &= !USE_USER_KDK_KEY;
        }
    }

    #[inline]
    pub fn encrypt(
        &mut self,
        key: &sgx_aes_gcm_128bit_key_t,
        plain: &MetaDataEncrypted,
        iv: &[u8],
    ) -> FsError {
        let integrity_only = self.integrity_only();
        encrypt(
            key,
            plain.as_slice(),
            iv,
            &mut self.encrypted_part,
            &mut self.plain_part.meta_data_gmac,
            integrity_only,
        )
    }

    #[inline]
    pub fn decrypt(
        &self,
        key: &sgx_aes_gcm_128bit_key_t,
        plain: &mut MetaDataEncrypted,
        iv: &[u8],
    ) -> FsError {
        let integrity_only = self.integrity_only();
        decrypt(
            key,
            &self.encrypted_part,
            iv,
            &self.plain_part.meta_data_gmac,
            plain.as_mut_slice(),
            integrity_only,
        )
    }

    #[allow(unused_variables)]
    pub fn derive_key(
        &mut self,
        user_kdk: Option<&sgx_aes_gcm_128bit_key_t>,
        report: Option<&sgx_report_t>,
    ) -> FsResult<sgx_aes_gcm_128bit_key_t> {
        if self.integrity_only() {
            return Ok(sgx_aes_gcm_128bit_key_t::default());
        }

        if let Some(user_key) = user_kdk {
            let (key, key_id) = generate_secure_blob_from_key(user_key)?;
            self.plain_part.meta_data_key_id = key_id;
            Ok(key)
        } else {
            #[cfg(feature = "mesalock_sgx")]
            {
                let report = report.ok_or(SGX_ERROR_UNEXPECTED)?;
                let (key, key_id) =
                    generate_secure_blob_from_cpu(&report.body.isv_svn, &report.body.cpu_svn)?;
                self.plain_part.meta_data_key_id = key_id;
                self.plain_part.isv_svn = report.body.isv_svn;
                self.plain_part.cpu_svn = report.body.cpu_svn;
                Ok(key)
            }
            #[cfg(not(feature = "mesalock_sgx"))]
            {
                Err(Error::from(libc::ENOTSUP))
            }
        }
    }

    pub fn restore_key(
        &self,
        user_kdk: Option<&sgx_aes_gcm_128bit_key_t>,
    ) -> FsResult<sgx_aes_gcm_128bit_key_t> {
        if self.integrity_only() {
            return Ok(sgx_aes_gcm_128bit_key_t::default());
        }

        let empty_key_id = sgx_key_id_t::default();
        if empty_key_id.id.consttime_memeq(&self.plain_part.meta_data_key_id.id) {
            return Err(Error::from(SGX_ERROR_FILE_NO_KEY_ID));
        }

        if let Some(user_key) = user_kdk {
            let key_id = self.plain_part.meta_data_key_id;
            let (key, _) = restore_secure_blob_from_key(user_key, &key_id)?;
            Ok(key)
        } else {
            #[cfg(feature = "mesalock_sgx")]
            {
                let isv_svn = self.plain_part.isv_svn;
                let cpu_svn = self.plain_part.cpu_svn;
                let key_id = self.plain_part.meta_data_key_id;
                let (key, _) = restore_secure_blob_from_cpu(&isv_svn, &cpu_svn, &key_id)?;
                Ok(key)
            }
            #[cfg(not(feature = "mesalock_sgx"))]
            {
                Err(Error::from(libc::ENOTSUP))
            }
        }
    }
}

impl_struct_slice!(
    MetaDataEncrypted,
    MetaData,
    MetaDataNode
);

impl_struct_copy_clone!(
    MetaData,
    MetaDataNode,
    MetaDataEncrypted,
    MetaDataPlain
);
