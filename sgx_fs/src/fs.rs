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

use crate::fs_inner as fs_imp;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::string::String;
use std::vec::Vec;
use types::sgx_aes_gcm_128bit_tag_t;
#[cfg(feature = "mesalock_sgx")]
use types::sgx_align_key_128bit_t;
use types::sgx_key_128bit_t;

/// Options and flags which can be used to configure how a file is opened.
///
/// This builder exposes the ability to configure how a SgxFile is opened and
/// what operations are permitted on the open file. The SgxFile::open and
/// SgxFile::create methods are aliases for commonly used options using this
/// builder.
///
#[derive(Clone, Debug)]
pub struct OpenOptions(fs_imp::OpenOptions);

/// Read the entire contents of a file into a bytes vector.
///
/// This is a convenience function for using SgxFile::open and read_to_end
/// with fewer imports and without an intermediate variable.
///
/// # Errors
///
/// This function will return an error if `path` does not already exist.
/// Other errors may also be returned according to OpenOptions::open.
///
/// It will also return an error if it encounters while reading an error
/// of a kind other than ErrorKind::Interrupted.
///
#[cfg(feature = "mesalock_sgx")]
pub fn read<P: AsRef<Path>>(path: P) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    SgxFile::open(path)?.read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// Read the entire contents of a file into a string.
///
/// This is a convenience function for using SgxFile::open and read_to_string
/// with fewer imports and without an intermediate variable.
///
/// # Errors
///
/// This function will return an error if `path` does not already exist.
/// Other errors may also be returned according to OpenOptions::open.
///
/// It will also return an error if it encounters while reading an error
/// of a kind other than ErrorKind::Interrupted,
/// or if the contents of the file are not valid UTF-8.
///
#[cfg(feature = "mesalock_sgx")]
pub fn read_to_string<P: AsRef<Path>>(path: P) -> io::Result<String> {
    let mut string = String::new();
    SgxFile::open(path)?.read_to_string(&mut string)?;
    Ok(string)
}

/// Write a slice as the entire contents of a file.
///
/// This function will create a file if it does not exist,
/// and will entirely replace its contents if it does.
///
/// This is a convenience function for using SgxFile::create and write_all
/// with fewer imports.
///
#[cfg(feature = "mesalock_sgx")]
pub fn write<P: AsRef<Path>, C: AsRef<[u8]>>(path: P, contents: C) -> io::Result<()> {
    SgxFile::create(path)?.write_all(contents.as_ref())
}

pub fn read_with_key<P: AsRef<Path>>(path: P, key: &sgx_key_128bit_t) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    SgxFile::open_with_key(path, key)?.read_to_end(&mut bytes)?;
    Ok(bytes)
}

pub fn read_with_key_to_string<P: AsRef<Path>>(
    path: P,
    key: &sgx_key_128bit_t,
) -> io::Result<String> {
    let mut string = String::new();
    SgxFile::open_with_key(path, key)?.read_to_string(&mut string)?;
    Ok(string)
}

pub fn write_with_key<P: AsRef<Path>, C: AsRef<[u8]>>(
    path: P,
    key: &sgx_key_128bit_t,
    contents: C,
) -> io::Result<()> {
    SgxFile::create_with_key(path, key)?.write_all(contents.as_ref())
}

pub fn read_integrity_only<P: AsRef<Path>>(path: P) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    SgxFile::open_integrity_only(path)?.read_to_end(&mut bytes)?;
    Ok(bytes)
}

pub fn read_integrity_only_to_string<P: AsRef<Path>>(path: P) -> io::Result<String> {
    let mut string = String::new();
    SgxFile::open_integrity_only(path)?.read_to_string(&mut string)?;
    Ok(string)
}

pub fn write_integrity_only<P: AsRef<Path>, C: AsRef<[u8]>>(path: P, contents: C) -> io::Result<()> {
    SgxFile::create_integrity_only(path)?.write_all(contents.as_ref())
}

impl OpenOptions {
    /// Creates a blank new set of options ready for configuration.
    ///
    /// All options are initially set to `false`.
    ///
    pub fn new() -> OpenOptions {
        OpenOptions(fs_imp::OpenOptions::new())
    }

    /// Sets the option for read access.
    ///
    /// This option, when true, will indicate that the file should be
    /// `read`-able if opened.
    ///
    pub fn read(&mut self, read: bool) -> &mut OpenOptions {
        self.0.read(read);
        self
    }

    /// Sets the option for write access.
    ///
    /// This option, when true, will indicate that the file should be
    /// `write`-able if opened.
    ///
    pub fn write(&mut self, write: bool) -> &mut OpenOptions {
        self.0.write(write);
        self
    }

    /// Sets the option for the append mode.
    ///
    /// This option, when true, means that writes will append to a file instead
    /// of overwriting previous contents.
    /// Note that setting `.write(true).append(true)` has the same effect as
    /// setting only `.append(true)`.
    ///
    /// For most filesystems, the operating system guarantees that all writes are
    /// atomic: no writes get mangled because another process writes at the same
    /// time.
    ///
    /// One maybe obvious note when using append-mode: make sure that all data
    /// that belongs together is written to the file in one operation. This
    /// can be done by concatenating strings before passing them to `write()`,
    /// or using a buffered writer (with a buffer of adequate size),
    /// and calling `flush()` when the message is complete.
    ///
    /// If a file is opened with both read and append access, beware that after
    /// opening, and after every write, the position for reading may be set at the
    /// end of the file. So, before writing, save the current position (using
    /// `seek(SeekFrom::Current(0))`, and restore it before the next read.
    ///
    pub fn append(&mut self, append: bool) -> &mut OpenOptions {
        self.0.append(append);
        self
    }

    /// Sets the option for update a previous file.
    pub fn update(&mut self, update: bool) -> &mut OpenOptions {
        self.0.update(update);
        self
    }

    /// Sets the option for binary a file.
    pub fn binary(&mut self, binary: bool) -> &mut OpenOptions {
        self.0.binary(binary);
        self
    }

    /// Opens a file at `path` with the options specified by `self`.
    #[cfg(feature = "mesalock_sgx")]
    pub fn open<P: AsRef<Path>>(&self, path: P) -> io::Result<SgxFile> {
        self._open(path.as_ref())
    }

    pub fn open_with_key<P: AsRef<Path>>(
        &self,
        path: P,
        key: &sgx_key_128bit_t,
    ) -> io::Result<SgxFile> {
        self._open_with_key(path.as_ref(), key)
    }

    fn open_integrity_only<P: AsRef<Path>>(&self, path: P) -> io::Result<SgxFile> {
        self._open_integrity_only(path.as_ref())
    }

    #[cfg(feature = "mesalock_sgx")]
    fn _open(&self, path: &Path) -> io::Result<SgxFile> {
        let inner = fs_imp::SgxFile::open(path, &self.0)?;
        Ok(SgxFile { inner })
    }

    fn _open_with_key(&self, path: &Path, key: &sgx_key_128bit_t) -> io::Result<SgxFile> {
        let inner = fs_imp::SgxFile::open_witch_key(path, &self.0, key)?;
        Ok(SgxFile { inner })
    }

    fn _open_integrity_only(&self, path: &Path) -> io::Result<SgxFile> {
        let inner = fs_imp::SgxFile::open_integrity_only(path, &self.0)?;
        Ok(SgxFile { inner })
    }
}

/// A reference to an open file on the filesystem.
///
/// An instance of a `File` can be read and/or written depending on what options
/// it was opened with. Files also implement [`Seek`] to alter the logical cursor
/// that the file contains internally.
///
/// Files are automatically closed when they go out of scope.
pub struct SgxFile {
    inner: fs_imp::SgxFile,
}

impl SgxFile {
    #[cfg(feature = "mesalock_sgx")]
    pub fn open<P: AsRef<Path>>(path: P) -> io::Result<SgxFile> {
        OpenOptions::new().read(true).open(path.as_ref())
    }

    #[cfg(feature = "mesalock_sgx")]
    pub fn create<P: AsRef<Path>>(path: P) -> io::Result<SgxFile> {
        OpenOptions::new().write(true).open(path.as_ref())
    }

    #[cfg(feature = "mesalock_sgx")]
    pub fn append<P: AsRef<Path>>(path: P) -> io::Result<SgxFile> {
        OpenOptions::new().append(true).open(path.as_ref())
    }

    pub fn open_with_key<P: AsRef<Path>>(path: P, key: &sgx_key_128bit_t) -> io::Result<SgxFile> {
        OpenOptions::new()
            .read(true)
            .open_with_key(path.as_ref(), key)
    }

    pub fn create_with_key<P: AsRef<Path>>(path: P, key: &sgx_key_128bit_t) -> io::Result<SgxFile> {
        OpenOptions::new()
            .write(true)
            .open_with_key(path.as_ref(), key)
    }

    pub fn append_with_key<P: AsRef<Path>>(path: P, key: &sgx_key_128bit_t) -> io::Result<SgxFile> {
        OpenOptions::new()
            .append(true)
            .open_with_key(path.as_ref(), key)
    }

    pub fn open_integrity_only<P: AsRef<Path>>(path: P) -> io::Result<SgxFile> {
        OpenOptions::new()
            .read(true)
            .open_integrity_only(path.as_ref())
    }

    pub fn create_integrity_only<P: AsRef<Path>>(path: P) -> io::Result<SgxFile> {
        OpenOptions::new()
            .write(true)
            .open_integrity_only(path.as_ref())
    }

    pub fn append_integrity_only<P: AsRef<Path>>(path: P) -> io::Result<SgxFile> {
        OpenOptions::new()
            .append(true)
            .open_integrity_only(path.as_ref())
    }

    pub fn is_eof(&self) -> bool {
        self.inner.is_eof()
    }

    pub fn clear_error(&self) {
        self.inner.clear_error()
    }

    pub fn clear_cache(&self) -> io::Result<()> {
        self.inner.clear_cache()
    }

    pub fn read_at(&mut self, off: usize, dst: &mut [u8]) -> io::Result<usize> {
        let pre = self.inner.seek(SeekFrom::Current(0))?;
        self.inner.seek(SeekFrom::Start(off as u64))?;

        let size = match self.inner.read(dst) {
            Ok(size) => size,
            Err(e) => {
                self.inner.seek(SeekFrom::Start(pre))?;
                return Err(e);
            }
        };

        self.inner.seek(SeekFrom::Start(pre))?;
        Ok(size)
    }

    pub fn get_meta_mac(&self) -> io::Result<sgx_aes_gcm_128bit_tag_t> {
        self.inner.get_meta_mac()
    }

    pub fn rename_meta<P: AsRef<Path>>(&mut self, old_name: P, new_name: P) -> io::Result<()> {
        self.inner.rename_meta(old_name.as_ref(), new_name.as_ref())
    }
}

impl Read for SgxFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Write for SgxFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl Seek for SgxFile {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }
}

impl<'a> Read for &'a SgxFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl<'a> Write for &'a SgxFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<'a> Seek for &'a SgxFile {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }
}

pub fn remove<P: AsRef<Path>>(path: P) -> io::Result<()> {
    fs_imp::remove(path.as_ref())
}

#[cfg(feature = "mesalock_sgx")]
pub fn export_auto_key<P: AsRef<Path>>(path: P) -> io::Result<sgx_key_128bit_t> {
    fs_imp::export_auto_key(path.as_ref())
}

#[cfg(feature = "mesalock_sgx")]
pub fn export_align_auto_key<P: AsRef<Path>>(path: P) -> io::Result<sgx_align_key_128bit_t> {
    fs_imp::export_align_auto_key(path.as_ref())
}

#[cfg(feature = "mesalock_sgx")]
pub fn import_auto_key<P: AsRef<Path>>(path: P, key: &sgx_key_128bit_t) -> io::Result<()> {
    fs_imp::import_auto_key(path.as_ref(), key)
}

/// Copies the contents of one file to another.
/// This function will **overwrite** the contents of `to`.
///
/// Note that if `from` and `to` both point to the same file, then the file
/// will likely get truncated by this operation.
///
/// On success, the total number of bytes copied is returned.
///
#[cfg(feature = "mesalock_sgx")]
pub fn copy<P: AsRef<Path>, Q: AsRef<Path>>(from: P, to: Q) -> io::Result<u64> {
    fs_imp::copy(from.as_ref(), to.as_ref())
}

pub fn copy_with_key<P: AsRef<Path>, Q: AsRef<Path>>(
    from: P,
    from_key: &sgx_key_128bit_t,
    to: Q,
    to_key: &sgx_key_128bit_t,
) -> io::Result<u64> {
    fs_imp::copy_with_key(from.as_ref(), from_key, to.as_ref(), to_key)
}

pub fn copy_integrity_only<P: AsRef<Path>, Q: AsRef<Path>>(from: P, to: Q) -> io::Result<u64> {
    fs_imp::copy_integrity_only(from.as_ref(), to.as_ref())
}
