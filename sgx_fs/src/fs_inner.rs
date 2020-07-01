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

use crate::stream::{self, SgxFileStream};
use std::io::{self, Error, SeekFrom};
use std::path::Path;
use std::string::{String, ToString};
#[cfg(feature = "mesalock_sgx")]
use types::sgx_align_key_128bit_t;
use types::{sgx_aes_gcm_128bit_tag_t, sgx_key_128bit_t};

#[derive(Clone, Debug, Default)]
pub struct OpenOptions {
    read: bool,
    write: bool,
    append: bool,
    update: bool,
    binary: bool,
}

impl OpenOptions {
    pub fn new() -> OpenOptions {
        OpenOptions {
            read: false,
            write: false,
            append: false,
            update: false,
            binary: false,
        }
    }

    pub fn read(&mut self, read: bool) {
        self.read = read;
    }
    pub fn write(&mut self, write: bool) {
        self.write = write;
    }
    pub fn append(&mut self, append: bool) {
        self.append = append;
    }
    pub fn update(&mut self, update: bool) {
        self.update = update;
    }
    pub fn binary(&mut self, binary: bool) {
        self.binary = binary;
    }

    fn get_access_mode(&self) -> io::Result<String> {
        let mut mode = match (self.read, self.write, self.append) {
            (true, false, false) => "r".to_string(),
            (false, true, false) => "w".to_string(),
            (false, false, true) => "a".to_string(),
            _ => return Err(Error::from_raw_os_error(libc::EINVAL)),
        };
        if self.update {
            mode += "+";
        }
        if self.binary {
            mode += "b";
        }
        Ok(mode)
    }
}

pub struct SgxFile(SgxFileStream);

impl SgxFile {
    #[cfg(feature = "mesalock_sgx")]
    pub fn open(path: &Path, opts: &OpenOptions) -> io::Result<SgxFile> {
        let path = to_str(path)?;
        let mode = opts.get_access_mode()?;
        SgxFileStream::open(path, &mode)
            .map(SgxFile)
            .map_err(|err| err.to_io_error())
    }

    pub fn open_witch_key(
        path: &Path,
        opts: &OpenOptions,
        key: &sgx_key_128bit_t,
    ) -> io::Result<SgxFile> {
        let path = to_str(path)?;
        let mode = opts.get_access_mode()?;
        SgxFileStream::open_with_key(path, &mode, key)
            .map(SgxFile)
            .map_err(|err| err.to_io_error())
    }

    pub fn open_integrity_only(
        path: &Path,
        opts: &OpenOptions,
    ) -> io::Result<SgxFile> {
        let path = to_str(path)?;
        let mode = opts.get_access_mode()?;
        SgxFileStream::open_integrity_only(path, &mode)
            .map(SgxFile)
            .map_err(|err| err.to_io_error())
    }

    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf).map_err(|err| err.to_io_error())
    }

    pub fn write(&self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf).map_err(|err| err.to_io_error())
    }

    pub fn tell(&self) -> io::Result<u64> {
        self.0
            .tell()
            .map_err(|err| err.to_io_error())
            .map(|offset| offset as u64)
    }

    pub fn seek(&self, pos: SeekFrom) -> io::Result<u64> {
        let (whence, offset) = match pos {
            SeekFrom::Start(off) => (stream::SeekFrom::Start, off as i64),
            SeekFrom::End(off) => (stream::SeekFrom::End, off),
            SeekFrom::Current(off) => (stream::SeekFrom::Current, off),
        };

        self.0
            .seek(offset, whence)
            .map_err(|err| err.to_io_error())?;

        let offset = self.tell()?;
        Ok(offset as u64)
    }

    pub fn flush(&self) -> io::Result<()> {
        self.0.flush().map_err(|err| err.to_io_error())
    }

    pub fn is_eof(&self) -> bool {
        self.0.is_eof()
    }

    pub fn clear_error(&self) {
        self.0.clear_error()
    }

    pub fn clear_cache(&self) -> io::Result<()> {
        self.0.clear_cache().map_err(|err| err.to_io_error())
    }

    pub fn get_meta_mac(&self) -> io::Result<sgx_aes_gcm_128bit_tag_t> {
        self.0
            .get_meta_mac()
            .map_err(|e| Error::from_raw_os_error(e.raw_error()))
    }

    pub fn rename_meta(&self, old_name: &Path, new_name: &Path) -> io::Result<()> {
        let old_name = to_str(old_name)?;
        let new_name = to_str(new_name)?;
        self.0
            .rename_meta(old_name, new_name)
            .map_err(|err| err.to_io_error())
    }
}

pub fn remove(path: &Path) -> io::Result<()> {
    let path = to_str(path)?;
    stream::remove(path).map_err(|err| err.to_io_error())
}

#[cfg(feature = "mesalock_sgx")]
pub fn export_auto_key(path: &Path) -> io::Result<sgx_key_128bit_t> {
    let path = to_str(path)?;
    stream::export_auto_key(path).map_err(|err| err.to_io_error())
}

#[cfg(feature = "mesalock_sgx")]
pub fn export_align_auto_key(path: &Path) -> io::Result<sgx_align_key_128bit_t> {
    let path = to_str(path)?;
    stream::export_align_auto_key(&path).map_err(|err| err.to_io_error())
}

#[cfg(feature = "mesalock_sgx")]
pub fn import_auto_key(path: &Path, key: &sgx_key_128bit_t) -> io::Result<()> {
    let path = to_str(path)?;
    stream::import_auto_key(&path, key).map_err(|err| err.to_io_error())
}

#[cfg(feature = "mesalock_sgx")]
pub fn copy(from: &Path, to: &Path) -> io::Result<u64> {
    use crate::fs::SgxFile;
    use std::io::ErrorKind;
    use std::untrusted::fs;
    use std::untrusted::path::PathEx;

    let metadata = from.metadata()?;
    if !metadata.is_file() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "the source path is not an existing regular file",
        ));
    }

    let mut reader = SgxFile::open(from)?;
    let mut writer = SgxFile::create(to)?;
    let perm = metadata.permissions();

    let ret = io::copy(&mut reader, &mut writer)?;
    fs::set_permissions(to, perm)?;
    Ok(ret)
}

pub fn copy_with_key(
    from: &Path,
    from_key: &sgx_key_128bit_t,
    to: &Path,
    to_key: &sgx_key_128bit_t,
) -> io::Result<u64>  {
    use crate::fs::SgxFile;
    use std::io::ErrorKind;
    cfg_if! {
        if #[cfg(feature = "mesalock_sgx")] {
            use std::untrusted::fs;
            use std::untrusted::path::PathEx;
        } else {
            use std::fs;
        }
    }

    let metadata = from.metadata()?;
    if !metadata.is_file() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "the source path is not an existing regular file",
        ));
    }

    let mut reader = SgxFile::open_with_key(from, from_key)?;
    let mut writer = SgxFile::create_with_key(to, to_key)?;
    let perm = metadata.permissions();

    let ret = io::copy(&mut reader, &mut writer)?;
    fs::set_permissions(to, perm)?;
    Ok(ret)
}

pub fn copy_integrity_only(from: &Path, to: &Path) -> io::Result<u64> {
    use crate::fs::SgxFile;
    use std::io::ErrorKind;
    cfg_if! {
        if #[cfg(feature = "mesalock_sgx")] {
            use std::untrusted::fs;
            use std::untrusted::path::PathEx;
        } else {
            use std::fs;
        }
    }

    let metadata = from.metadata()?;
    if !metadata.is_file() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "the source path is not an existing regular file",
        ));
    }

    let mut reader = SgxFile::open_integrity_only(from)?;
    let mut writer = SgxFile::create_integrity_only(to)?;
    let perm = metadata.permissions();

    let ret = io::copy(&mut reader, &mut writer)?;
    fs::set_permissions(to, perm)?;
    Ok(ret)
}

fn to_str(path: &Path) -> io::Result<&str> {
    path.to_str().ok_or_else(||Error::from_raw_os_error(libc::EINVAL))
}
