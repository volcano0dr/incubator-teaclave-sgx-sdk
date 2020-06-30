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
use crate::deps::ConsttimeMemEq;
use crate::error::{Error, FsError, FsResult};

use std::boxed::Box;
use std::cell::RefCell;
use std::fmt;
use std::mem;
use std::rc::Rc;
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

pub trait AsSlice: ContiguousMemory {
    fn as_slice(&self) -> &[u8];
    fn as_mut_slice(&mut self) -> &mut [u8];
}

#[repr(C)]
#[repr(packed)]
#[derive(Copy, Clone, Default)]
pub struct sgx_mc_uuid_t {
    mc_uuid: [u8; 16],
}

pub type sgx_iv_t = [u8; SGX_AESGCM_IV_SIZE];
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

impl_struct_slice!(MetaDataEncrypted, MetaData, MetaDataNode);

// the key to encrypt the data or mht, and the gmac
#[repr(C)]
#[repr(packed)]
#[derive(Copy, Clone)]
pub struct GcmCryptoData {
    key: sgx_aes_gcm_128bit_key_t,
    gmac: sgx_aes_gcm_128bit_tag_t,
}

impl GcmCryptoData {
    pub fn new() -> GcmCryptoData {
        GcmCryptoData {
            key: sgx_aes_gcm_128bit_key_t::default(),
            gmac: sgx_aes_gcm_128bit_tag_t::default(),
        }
    }

    #[inline]
    pub fn key(&self) -> &sgx_aes_gcm_128bit_key_t {
        &self.key
    }

    #[inline]
    pub fn gmac(&self) -> &sgx_aes_gcm_128bit_tag_t {
        &self.gmac
    }

    #[inline]
    pub fn key_mut(&mut self) -> &mut sgx_aes_gcm_128bit_key_t {
        &mut self.key
    }

    #[inline]
    pub fn gmac_mut(&mut self) -> &mut sgx_aes_gcm_128bit_tag_t {
        &mut self.gmac
    }

    #[inline]
    pub fn set_key(&mut self, key: sgx_aes_gcm_128bit_key_t) {
        self.key = key;
    }

    #[inline]
    pub fn set_gmac(&mut self, gmac: sgx_aes_gcm_128bit_tag_t) {
        self.gmac = gmac;
    }
}

// for NODE_SIZE == 4096, we have 96 attached data nodes and 32 mht child nodes
// 3/4 of the node size is dedicated to data nodes
pub const ATTACHED_DATA_NODES_COUNT: usize = (NODE_SIZE / mem::size_of::<GcmCryptoData>()) * 3 / 4;
// 1/4 of the node size is dedicated to child mht nodes
pub const CHILD_MHT_NODES_COUNT: usize = (NODE_SIZE / mem::size_of::<GcmCryptoData>()) * 1 / 4;
#[repr(C)]
#[repr(packed)]
struct MhtNode {
    data_nodes_crypto: [GcmCryptoData; ATTACHED_DATA_NODES_COUNT],
    mht_nodes_crypto: [GcmCryptoData; CHILD_MHT_NODES_COUNT],
}

impl MhtNode {
    fn new() -> MhtNode {
        MhtNode {
            data_nodes_crypto: [GcmCryptoData::new(); ATTACHED_DATA_NODES_COUNT],
            mht_nodes_crypto: [GcmCryptoData::new(); CHILD_MHT_NODES_COUNT],
        }
    }
}

#[repr(C)]
#[repr(packed)]
struct DataNode {
    data: [u8; NODE_SIZE],
}

impl DataNode {
    fn new() -> DataNode {
        DataNode {
            data: [0; NODE_SIZE],
        }
    }
}

#[repr(C)]
#[repr(packed)]
pub struct EncryptedData {
    data: [u8; NODE_SIZE],
}

impl EncryptedData {
    fn new() -> EncryptedData {
        EncryptedData {
            data: [0; NODE_SIZE],
        }
    }
}

#[repr(C)]
#[repr(packed)]
pub struct EncryptedNode {
    physical_node_number: u64,
    node_data: EncryptedData,
}

impl EncryptedNode {
    fn new() -> EncryptedNode {
        EncryptedNode {
            physical_node_number: 0,
            node_data: EncryptedData::new(),
        }
    }
}

impl_struct_slice!(MhtNode, DataNode, EncryptedData, EncryptedNode);

impl_struct_copy_clone!(
    MetaData,
    MetaDataNode,
    MetaDataEncrypted,
    MetaDataPlain,
    MhtNode,
    DataNode,
    EncryptedNode,
    EncryptedData
);

#[derive(Copy, Clone)]
pub enum NodeType {
    Mht,
    Data,
}

impl fmt::Display for NodeType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            NodeType::Mht => f.debug_tuple("mht").finish(),
            NodeType::Data => f.debug_tuple("data").finish(),
        }
    }
}

#[derive(Copy, Clone)]
enum Node {
    Mht(MhtNode),
    Data(DataNode),
}

impl Node {
    fn new(node_type: NodeType) -> Node {
        match node_type {
            NodeType::Mht => Node::Mht(MhtNode::new()),
            NodeType::Data => Node::Data(DataNode::new()),
        }
    }

    fn clean(&mut self) {
        match self {
            Node::Mht(m) => m
                .as_mut_slice()
                .copy_from_slice(&[0; mem::size_of::<MhtNode>()]),
            Node::Data(d) => d
                .as_mut_slice()
                .copy_from_slice(&[0; mem::size_of::<DataNode>()]),
        }
    }

    fn data_crypto(&self, index: usize) -> Option<GcmCryptoData> {
        match self {
            Node::Mht(m) => Some(m.data_nodes_crypto[index]),
            Node::Data(_) => None,
        }
    }

    fn mht_crypto(&self, index: usize) -> Option<GcmCryptoData> {
        match self {
            Node::Mht(m) => Some(m.mht_nodes_crypto[index]),
            Node::Data(_) => None,
        }
    }

    fn set_data_crypto(&mut self, index: usize, data: GcmCryptoData) {
        match self {
            Node::Mht(m) => m.data_nodes_crypto[index] = data,
            Node::Data(_) => (),
        }
    }

    fn set_mht_crypto(&mut self, index: usize, data: GcmCryptoData) {
        match self {
            Node::Mht(m) => m.mht_nodes_crypto[index] = data,
            Node::Data(_) => (),
        }
    }
}

impl Node {
    pub fn as_slice(&self) -> &[u8] {
        match self {
            Node::Mht(m) => m.as_slice(),
            Node::Data(d) => d.as_slice(),
        }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        match self {
            Node::Mht(m) => m.as_mut_slice(),
            Node::Data(d) => d.as_mut_slice(),
        }
    }
}

pub struct FileNode {
    node_type: NodeType,
    node_number: u64,
    need_writing: bool,
    new_node: bool,
    integrity_only: bool,
    encrypted: EncryptedNode,
    parent: Option<NodeRef<FileNode>>,
    plain: Node,
}

impl FileNode {
    pub fn new(node_type: NodeType) -> FileNode {
        FileNode {
            node_type: node_type,
            node_number: 0,
            need_writing: false,
            integrity_only: false,
            new_node: true,
            encrypted: EncryptedNode::new(),
            parent: None,
            plain: Node::new(node_type),
        }
    }

    pub fn build(
        node_type: NodeType,
        node_number: u64,
        physical_node_number: u64,
        integrity_only: bool,
    ) -> FileNode {
        let mut node = FileNode::new(node_type);
        node.node_number = node_number;
        node.encrypted.physical_node_number = physical_node_number;
        node.integrity_only = integrity_only;
        node
    }

    #[inline]
    pub fn is_new_node(&self) -> bool {
        self.new_node
    }

    #[inline]
    pub fn set_new_node(&mut self, new_node: bool) {
        self.new_node = new_node
    }

    #[inline]
    pub fn integrity_only(&self) -> bool {
        self.integrity_only
    }

    #[inline]
    pub fn set_integrity_only(&mut self, integrity_only: bool) {
        self.integrity_only = integrity_only;
    }

    #[inline]
    pub fn node_number(&self) -> u64 {
        self.node_number
    }

    #[inline]
    pub fn physical_node_number(&self) -> u64 {
        self.encrypted.physical_node_number
    }

    #[inline]
    pub fn is_need_writing(&self) -> bool {
        self.need_writing
    }

    #[inline]
    pub fn set_need_writing(&mut self, need_writing: bool) {
        self.need_writing = need_writing;
    }

    #[inline]
    pub fn is_mht(&self) -> bool {
        match self.node_type {
            NodeType::Mht => true,
            NodeType::Data => false,
        }
    }

    #[inline]
    pub fn is_data(&self) -> bool {
        match self.node_type {
            NodeType::Mht => false,
            NodeType::Data => true,
        }
    }

    #[inline]
    pub fn parent(&self) -> Option<NodeRef<FileNode>> {
        self.parent.clone()
    }

    #[inline]
    pub fn set_parent(&mut self, parent: NodeRef<FileNode>) {
        self.parent = Some(parent);
    }

    #[inline]
    pub fn clean_plain(&mut self) {
        self.plain.clean()
    }

    #[inline]
    pub fn data_nodes_crypto(&self, index: usize) -> Option<GcmCryptoData> {
        self.plain.data_crypto(index)
    }

    #[inline]
    pub fn mht_nodes_crypto(&self, index: usize) -> Option<GcmCryptoData> {
        self.plain.mht_crypto(index)
    }

    #[inline]
    pub fn set_data_nodes_crypto(&mut self, index: usize, data: GcmCryptoData) {
        self.plain.set_data_crypto(index, data)
    }

    #[inline]
    pub fn set_mht_nodes_crypto(&mut self, index: usize, data: GcmCryptoData) {
        self.plain.set_mht_crypto(index, data)
    }

    #[inline]
    pub fn plain_slice(&self) -> &[u8] {
        self.plain.as_slice()
    }

    #[inline]
    pub fn plain_mut_slice(&mut self) -> &mut [u8] {
        self.plain.as_mut_slice()
    }

    #[inline]
    pub fn encrypted_slice(&self) -> &[u8] {
        self.encrypted.node_data.as_slice()
    }

    #[inline]
    pub fn encrypted_mut_slice(&mut self) -> &mut [u8] {
        self.encrypted.node_data.as_mut_slice()
    }

    #[inline]
    pub fn encrypted_data(&self) -> &EncryptedData {
        &self.encrypted.node_data
    }

    #[inline]
    pub fn encrypted_data_mut(&mut self) -> &mut EncryptedData {
        &mut self.encrypted.node_data
    }

    #[inline]
    pub fn encrypted_node(&self) -> &EncryptedNode {
        &self.encrypted
    }

    pub fn encrypt(
        &mut self,
        key: &sgx_aes_gcm_128bit_key_t,
        gmac: &mut sgx_aes_gcm_128bit_tag_t,
        iv: &[u8],
    ) -> FsError {
        encrypt(
            key,
            self.plain.as_slice(),
            iv,
            self.encrypted.node_data.as_mut_slice(),
            gmac,
            self.integrity_only,
        )
    }

    pub fn decrypt(
        &mut self,
        key: &sgx_aes_gcm_128bit_key_t,
        gmac: &sgx_aes_gcm_128bit_tag_t,
        iv: &[u8],
    ) -> FsError {
        decrypt(
            key,
            self.encrypted.node_data.as_slice(),
            iv,
            gmac,
            self.plain.as_mut_slice(),
            self.integrity_only,
        )
    }

    pub fn derive_key(
        &self,
        master_key: &sgx_aes_gcm_128bit_key_t,
    ) -> FsResult<sgx_aes_gcm_128bit_key_t> {
        if self.integrity_only {
            return Ok(sgx_aes_gcm_128bit_key_t::default());
        }
        generate_secure_blob(
            master_key,
            RANDOM_KEY_NAME,
            self.encrypted.physical_node_number,
        )
    }
}

impl fmt::Display for FileNode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "FileNode: node_type:{}, need_write: {}, new_node: {}, node_number: {}, physical_node_number: {}",
            self.node_type,
            self.need_writing,
            self.new_node,
            self.node_number(),
            self.physical_node_number(),
        )
    }
}

pub type NodeRef<T> = Rc<RefCell<Box<T>>>;

pub fn new_filenode_ref(node_type: NodeType) -> NodeRef<FileNode> {
    Rc::new(RefCell::new(Box::new(FileNode::new(node_type))))
}

pub fn build_filenode_ref(
    node_type: NodeType,
    node_number: u64,
    physical_node_number: u64,
    integrity_only: bool,
) -> NodeRef<FileNode> {
    Rc::new(RefCell::new(Box::new(FileNode::build(
        node_type,
        node_number,
        physical_node_number,
        integrity_only,
    ))))
}
