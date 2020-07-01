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
use crate::deps::rsgx_read_rand;
use crate::error::{Error, FsError, FsResult};
use crypto::{
    rsgx_rijndael128GCM_encrypt,
    rsgx_rijndael128GCM_decrypt,
    rsgx_rijndael128_cmac_msg,
};
use libc;
#[cfg(feature = "mesalock_sgx")]
use tse::{
    rsgx_create_report,
    rsgx_get_key,
};
use types::marker::ContiguousMemory;
use types::{
    sgx_aes_gcm_128bit_key_t,
    sgx_aes_gcm_128bit_tag_t,
    sgx_key_id_t,
};
#[cfg(feature = "mesalock_sgx")]
use types::{
    self,
    sgx_report_data_t,
    sgx_key_request_t,
    sgx_config_svn_t,
    sgx_target_info_t,
    sgx_attributes_t,
    sgx_isv_svn_t,
    sgx_cpu_svn_t,
    sgx_report_t,
};

pub fn encrypt(
    key: &sgx_aes_gcm_128bit_key_t,
    src: &[u8],
    iv: &[u8],
    dst: &mut [u8],
    gmac: &mut sgx_aes_gcm_128bit_tag_t,
    integrity_only: bool,
) -> FsError {
    let result = if integrity_only {
        rsgx_rijndael128GCM_encrypt(key, &[0_u8; 0], iv, &src, &mut [0_u8; 0], gmac).map(|_| {
            dst.copy_from_slice(src);
        })
    } else {
        rsgx_rijndael128GCM_encrypt(key, src, iv, &[0_u8; 0], dst, gmac)
    };
    result.map_err(Error::from)
}

pub fn decrypt(
    key: &sgx_aes_gcm_128bit_key_t,
    src: &[u8],
    iv: &[u8],
    gmac: &sgx_aes_gcm_128bit_tag_t,
    dst: &mut [u8],
    integrity_only: bool,
) -> FsError {
    let result = if integrity_only {
        rsgx_rijndael128GCM_decrypt(key, &[0_u8; 0], iv, src, gmac, &mut [0_u8; 0]).map(|_| {
            dst.copy_from_slice(src);
        })
    } else {
        rsgx_rijndael128GCM_decrypt(key, src, iv, &[0_u8; 0], gmac, dst)
    };
    result.map_err(Error::from)
}

#[derive(Copy, Clone, Default, Debug)]
pub struct SessionKey {
    key: sgx_aes_gcm_128bit_key_t,
    count: u32,
}

impl SessionKey {
    pub fn new() -> SessionKey {
        SessionKey::default()
    }

    pub fn init(&mut self) -> FsError {
        self.key = generate_secure_blob(&sgx_aes_gcm_128bit_key_t::default(), MASTER_KEY_NAME, 0)?;
        self.count = 0;
        Ok(())
    }

    pub fn update(&mut self) -> FsResult<sgx_aes_gcm_128bit_key_t> {
        self.count += 1;
        if self.count as usize > MAX_MASTER_KEY_USAGES {
            self.init()?;
        }
        Ok(self.key)
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
struct KdfInput {
    index: u32,
    label: [u8; MAX_LABEL_LEN],
    node_number: u64,    //context 1
    nonce: sgx_key_id_t, // context 2 (nonce16: sgx_cmac_128bit_tag_t)
    output_len: u32,     // in bits
}

unsafe impl ContiguousMemory for KdfInput {}

impl Default for KdfInput {
    fn default() -> KdfInput {
        unsafe { std::mem::zeroed::<KdfInput>() }
    }
}

pub fn generate_secure_blob(
    key: &sgx_aes_gcm_128bit_key_t,
    label: &str,
    physical_node_number: u64,
) -> FsResult<sgx_aes_gcm_128bit_tag_t> {
    if label.len() > MAX_LABEL_LEN {
        return Err(Error::from(libc::EINVAL));
    }

    let mut buf = KdfInput::default();
    buf.index = 0x1;
    buf.node_number = physical_node_number;
    buf.output_len = 0x80;
    buf.label[0..label.len()].copy_from_slice(label.as_bytes());
    rsgx_read_rand(&mut buf.nonce.id[0..16]).map_err(Error::from)?;

    rsgx_rijndael128_cmac_msg(key, &buf).map_err(Error::from)
}

pub fn generate_secure_blob_from_key(
    key: &sgx_aes_gcm_128bit_key_t,
) -> FsResult<(sgx_aes_gcm_128bit_key_t, sgx_key_id_t)> {
    let mut buf = KdfInput::default();
    buf.index = 0x1;
    buf.output_len = 0x80;
    buf.label[0..METADATA_KEY_NAME.len()].copy_from_slice(METADATA_KEY_NAME.as_bytes());
    rsgx_read_rand(&mut buf.nonce.id).map_err(Error::from)?;

    let key = rsgx_rijndael128_cmac_msg(key, &buf).map_err(Error::from)?;

    Ok((key, buf.nonce))
}

pub fn restore_secure_blob_from_key(
    key: &sgx_aes_gcm_128bit_key_t,
    key_id: &sgx_key_id_t,
) -> FsResult<(sgx_aes_gcm_128bit_key_t, sgx_key_id_t)> {
    let mut buf = KdfInput::default();
    buf.index = 0x1;
    buf.output_len = 0x80;
    buf.nonce = *key_id;
    buf.label[0..METADATA_KEY_NAME.len()].copy_from_slice(METADATA_KEY_NAME.as_bytes());

    let key = rsgx_rijndael128_cmac_msg(key, &buf).map_err(Error::from)?;

    Ok((key, buf.nonce))
}

#[cfg(feature = "mesalock_sgx")]
pub fn generate_secure_blob_from_cpu(
    isv_svn: &sgx_isv_svn_t,
    cpu_svn: &sgx_cpu_svn_t,
) -> FsResult<(sgx_aes_gcm_128bit_key_t, sgx_key_id_t)> {
    let mut key_request = sgx_key_request_t {
        key_name: types::SGX_KEYSELECT_SEAL,
        key_policy: types::SGX_KEYPOLICY_MRSIGNER,
        isv_svn: *isv_svn,
        reserved1: 0,
        cpu_svn: *cpu_svn,
        attribute_mask: sgx_attributes_t {
            flags: types::TSEAL_DEFAULT_FLAGSMASK,
            xfrm: 0x0,
        },
        key_id: sgx_key_id_t::default(),
        misc_mask: types::TSEAL_DEFAULT_MISCMASK,
        config_svn: sgx_config_svn_t::default(),
        reserved2: [0; types::SGX_KEY_REQUEST_RESERVED2_BYTES],
    };

    rsgx_read_rand(&mut key_request.key_id.id).map_err(Error::from)?;

    let key = rsgx_get_key(&key_request).map_err(Error::from)?;

    Ok((key, key_request.key_id))
}

#[cfg(feature = "mesalock_sgx")]
pub fn restore_secure_blob_from_cpu(
    isv_svn: &sgx_isv_svn_t,
    cpu_svn: &sgx_cpu_svn_t,
    key_id: &sgx_key_id_t,
) -> FsResult<(sgx_aes_gcm_128bit_key_t, sgx_key_id_t)> {
    let key_request = sgx_key_request_t {
        key_name: types::SGX_KEYSELECT_SEAL,
        key_policy: types::SGX_KEYPOLICY_MRSIGNER,
        isv_svn: *isv_svn,
        reserved1: 0,
        cpu_svn: *cpu_svn,
        attribute_mask: sgx_attributes_t {
            flags: types::TSEAL_DEFAULT_FLAGSMASK,
            xfrm: 0x0,
        },
        key_id: *key_id,
        misc_mask: types::TSEAL_DEFAULT_MISCMASK,
        config_svn: sgx_config_svn_t::default(),
        reserved2: [0; types::SGX_KEY_REQUEST_RESERVED2_BYTES],
    };

    let key = rsgx_get_key(&key_request).map_err(Error::from)?;

    Ok((key, key_request.key_id))
}

#[cfg(feature = "mesalock_sgx")]
pub fn generate_report() -> FsResult<sgx_report_t> {
    let target = sgx_target_info_t::default();
    let report_data = sgx_report_data_t::default();

    rsgx_create_report(&target, &report_data).map_err(Error::from)
}
