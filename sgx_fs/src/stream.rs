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

use crate::core::ProtectedFile;
use crate::error::{FsError, FsResult};
use libc;
use types::sgx_aes_gcm_128bit_tag_t;
#[cfg(feature = "mesalock_sgx")]
use types::sgx_align_key_128bit_t;
use types::sgx_key_128bit_t;

pub struct SgxFileStream {
    stream: ProtectedFile,
}

impl SgxFileStream {
    #[cfg(feature = "mesalock_sgx")]
    pub fn open(name: &str, mode: &str) -> FsResult<SgxFileStream> {
        ProtectedFile::open(name, mode, None, None, false).map(|f| SgxFileStream { stream: f })
    }

    pub fn open_with_key(name: &str, mode: &str, key: &sgx_key_128bit_t) -> FsResult<SgxFileStream> {
        ProtectedFile::open(name, mode, None, Some(key), false).map(|f| SgxFileStream { stream: f })
    }

    pub fn open_integrity_only(name: &str, mode: &str) -> FsResult<SgxFileStream> {
        ProtectedFile::open(name, mode, None, None, true)
            .map(|f| SgxFileStream { stream: f })
    }

    pub fn read(&self, buf: &mut [u8]) -> FsResult<usize> {
        self.stream.read(buf)
    }

    pub fn write(&self, buf: &[u8]) -> FsResult<usize> {
        self.stream.write(buf)
    }

    pub fn tell(&self) -> FsResult<i64> {
        self.stream.tell()
    }

    pub fn seek(&self, offset: i64, origin: SeekFrom) -> FsError {
        let whence = match origin {
            SeekFrom::Start => libc::SEEK_SET,
            SeekFrom::End => libc::SEEK_END,
            SeekFrom::Current => libc::SEEK_CUR,
        };
        self.stream.seek(offset, whence)
    }

    pub fn flush(&self) -> FsError {
        self.stream.flush()
    }

    pub fn error(&self) -> i32 {
        self.stream.get_error()
    }

    pub fn is_eof(&self) -> bool {
        self.stream.get_eof()
    }

    pub fn clear_error(&self) {
        self.stream.clear_error()
    }

    pub fn clear_cache(&self) -> FsError {
        self.stream.clear_cache()
    }

    pub fn get_meta_mac(&self) -> FsResult<sgx_aes_gcm_128bit_tag_t> {
        self.stream.get_meta_mac()
    }

    pub fn rename_meta(&self, old_name: &str, new_name: &str) -> FsError {
        self.stream.rename_meta(old_name, new_name)
    }
}

pub fn remove(name: &str) -> FsError {
    ProtectedFile::remove(name)
}

#[cfg(feature = "mesalock_sgx")]
pub fn export_auto_key(name: &str) -> FsResult<sgx_key_128bit_t> {
    ProtectedFile::export_auto_key(name)
}

#[cfg(feature = "mesalock_sgx")]
pub fn export_align_auto_key(name: &str) -> FsResult<sgx_align_key_128bit_t> {
    ProtectedFile::export_auto_key(name).map(|f| {
        let mut align_key: sgx_align_key_128bit_t = Default::default();
        align_key.key = f;
        align_key
    })
}

#[cfg(feature = "mesalock_sgx")]
pub fn import_auto_key(name: &str, key: &sgx_key_128bit_t) -> FsError {
    ProtectedFile::import_auto_key(name, key)
}

impl Drop for SgxFileStream {
    fn drop(&mut self) {
        // Note that errors are ignored when closing a file descriptor. The
        // reason for this is that if an error occurs we don't actually know if
        // the file descriptor was closed or not, and if we retried (for
        // something like EINTR), we might close another valid file descriptor
        // (opened after we closed ours.
        self.stream.pre_close(None, false);
    }
}

/// Enumeration of possible methods to seek within an I/O object.
#[derive(Copy, PartialEq, Eq, Clone, Debug)]
pub enum SeekFrom {
    /// Set the offset to the provided number of bytes.
    Start,

    /// Set the offset to the size of this object plus the specified number of
    /// bytes.
    ///
    /// It is possible to seek beyond the end of an object, but it's an error to
    /// seek before byte 0.
    End,

    /// Set the offset to the current position plus the specified number of
    /// bytes.
    ///
    /// It is possible to seek beyond the end of an object, but it's an error to
    /// seek before byte 0.
    Current,
}
