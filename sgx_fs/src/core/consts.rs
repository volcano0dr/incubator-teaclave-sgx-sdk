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

use libc::c_int;

pub const NODE_SIZE: usize = 4096;
pub const SGX_FILE_ID: u64 = 0x5347585F46494C45;
pub const SGX_FILE_MAJOR_VERSION: u8 = 0x01;
pub const SGX_FILE_MINOR_VERSION: u8 = 0x00;

// these are all defined as relative to node size, so we can decrease node size in tests and have deeper tree
pub const MD_USER_DATA_SIZE: usize = NODE_SIZE * 3 / 4; // 3072

pub const FILENAME_MAX_LEN: usize = 260;
pub const PATHNAME_MAX_LEN: usize = 512;
pub const FULLNAME_MAX_LEN: usize = PATHNAME_MAX_LEN + FILENAME_MAX_LEN;

pub const SGX_AESGCM_IV_SIZE: usize = 12;

pub const MASTER_KEY_NAME: &str = "SGX-PROTECTED-FS-MASTER-KEY";
pub const RANDOM_KEY_NAME: &str = "SGX-PROTECTED-FS-RANDOM-KEY";
pub const METADATA_KEY_NAME: &str = "SGX-PROTECTED-FS-METADATA-KEY";

pub const MAX_LABEL_LEN: usize = 64;

pub const MAX_MODE_STRING_LEN: usize = 5;

pub const SEEK_SET: c_int = 0;
pub const SEEK_CUR: c_int = 1;
pub const SEEK_END: c_int = 2;

pub const MAX_PAGES_IN_CACHE: usize = 48;

pub const MAX_MASTER_KEY_USAGES: usize = 65536;

pub const ROOT_MHT_PHY_NUM: u64 = 1;
pub const META_DATA_PHY_NUM: u64 = 0;
