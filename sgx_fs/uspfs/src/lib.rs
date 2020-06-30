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

#![allow(non_camel_case_types)]

extern crate libc;
extern crate sgx_types;

use libc::{c_int, c_void};
use sgx_types::{SysError, SysResult};
use std::ffi::CStr;
use std::io::Error;
use std::mem;
use std::mem::ManuallyDrop;
use std::ptr;

const MILISECONDS_SLEEP_FOPEN: u32 = 10;
const MAX_FOPEN_RETRIES: usize = 10;
const O_LARGEFILE: c_int = 0o0100000;
const NODE_SIZE: usize = 4096;
const RECOVERY_NODE_SIZE: usize = mem::size_of::<u64>() + NODE_SIZE;

fn new_stat() -> libc::stat {
    unsafe { mem::zeroed::<libc::stat>() }
}

fn errno() -> i32 {
    Error::last_os_error().raw_os_error().unwrap_or(0)
}

struct FileFd {
    fd: c_int,
}

impl FileFd {
    fn new(fd: c_int) -> FileFd {
        FileFd { fd: fd }
    }

    fn into_raw(self) -> c_int {
        let fd = self.fd;
        mem::forget(self);
        fd
    }

    fn open(name: &CStr, oflag: c_int, mode: libc::mode_t) -> SysResult<FileFd> {
        let fd = unsafe { libc::open(name.as_ptr(), oflag, mode as i32) };
        if fd == -1 {
            Err(errno())
        } else {
            Ok(FileFd { fd: fd })
        }
    }

    fn flock(&self, operation: c_int) -> SysError {
        if unsafe { libc::flock(self.fd, operation) } != 0 {
            Err(errno())
        } else {
            Ok(())
        }
    }

    fn fstat(&self, stat: &mut libc::stat) -> SysError {
        if unsafe { libc::fstat(self.fd, stat) } != 0 {
            Err(errno())
        } else {
            Ok(())
        }
    }
}

impl Drop for FileFd {
    fn drop(&mut self) {
        let _ = unsafe { libc::close(self.fd) };
    }
}

struct FileStream {
    file: *mut libc::FILE,
}

impl FileStream {
    fn new(file: *mut libc::FILE) -> FileStream {
        FileStream { file: file }
    }

    fn raw(&self) -> *mut libc::FILE {
        self.file
    }

    fn fopen(name: &CStr, mode: &CStr) -> SysResult<FileStream> {
        let file = unsafe { libc::fopen(name.as_ptr(), mode.as_ptr()) };
        if file.is_null() {
            Err(errno())
        } else {
            Ok(FileStream { file: file })
        }
    }

    fn from_fd(fd: c_int, mode: &CStr) -> SysResult<FileStream> {
        let file = unsafe { libc::fdopen(fd, mode.as_ptr()) };
        if file.is_null() {
            Err(errno())
        } else {
            Ok(FileStream { file: file })
        }
    }

    fn fseeko(&self, offset: libc::off_t, whence: c_int) -> SysError {
        if unsafe { libc::fseeko(self.file, offset, whence) } != 0 {
            Err(errno())
        } else {
            Ok(())
        }
    }

    fn fread(&self, buf: &mut [u8]) -> SysError {
        let size = unsafe { libc::fread(buf.as_mut_ptr() as *mut c_void, buf.len(), 1, self.file) };
        if size != 1 {
            let err = self.ferror();
            if err != 0 {
                Err(err)
            } else if errno() != 0 {
                Err(errno())
            } else {
                Err(libc::EIO)
            }
        } else {
            Ok(())
        }
    }

    fn fwrite(&self, buf: &[u8]) -> SysError {
        let size = unsafe { libc::fwrite(buf.as_ptr() as *const c_void, 1, buf.len(), self.file) };
        if size != buf.len() {
            let err = self.ferror();
            if err != 0 {
                Err(err)
            } else if errno() != 0 {
                Err(errno())
            } else {
                Err(libc::EIO)
            }
        } else {
            Ok(())
        }
    }

    fn fflush(&self) -> SysError {
        if unsafe { libc::fflush(self.file) } != 0 {
            Err(errno())
        } else {
            Ok(())
        }
    }

    fn ferror(&self) -> i32 {
        unsafe { libc::ferror(self.file) }
    }

    fn fileno(&self) -> SysResult<c_int> {
        let fd = unsafe { libc::fileno(self.file) };
        if fd != -1 {
            Ok(fd)
        } else {
            Err(errno())
        }
    }

    fn ftello(&self) -> SysResult<libc::off_t> {
        let off = unsafe { libc::ftello(self.file) };
        if off != -1 {
            Ok(off)
        } else {
            Err(errno())
        }
    }
}

impl Drop for FileStream {
    fn drop(&mut self) {
        if !self.raw().is_null() {
            let _ = unsafe { libc::fclose(self.file) };
        }
    }
}

pub struct File {
    file: FileStream,
}

impl File {
    pub fn open(name: &CStr, read_only: bool, size: &mut i64) -> SysResult<File> {
        if name.to_bytes().len() <= 0 {
            return Err(libc::EINVAL);
        }

        // open the file with OS API so we can 'lock' the file and get exclusive access to it
        let oflag = if read_only {
            libc::O_RDONLY
        } else {
            libc::O_RDWR
        }; //create the file if it doesn't exists, read-only/read-write
        let oflag = oflag | libc::O_CREAT | O_LARGEFILE;
        let mode = libc::S_IRUSR
            | libc::S_IWUSR
            | libc::S_IRGRP
            | libc::S_IWGRP
            | libc::S_IROTH
            | libc::S_IWOTH;
        let fd = FileFd::open(name, oflag, mode)?;

        // this lock is advisory only and programs with high priviliges can ignore it
        // it is set to help the user avoid mistakes, but it won't prevent intensional DOS attack from priviliged user
        let op = if read_only {
            libc::LOCK_SH
        } else {
            libc::LOCK_EX
        } | libc::LOCK_NB; // NB - non blocking
        fd.flock(op)?;

        let mut stat = new_stat();
        fd.fstat(&mut stat).map_err(|err| {
            let _ = fd.flock(libc::LOCK_UN);
            err
        })?;

        // convert the file handle to standard 'C' API file pointer
        let mode = CStr::from_bytes_with_nul(if read_only { b"rb\0" } else { b"r+b\0" })
            .map_err(|_| libc::EINVAL)?;
        let raw_fd = fd.into_raw();
        let file = FileStream::from_fd(raw_fd, &mode).map_err(|err| {
            let fd = FileFd::new(raw_fd);
            let _ = fd.flock(libc::LOCK_UN);
            err
        })?;

        *size = stat.st_size;
        Ok(File {
            file: FileStream::from(file),
        })
    }

    pub fn read(&mut self, number: u64, node: &mut [u8]) -> SysError {
        if self.file.raw().is_null() {
            return Err(libc::EINVAL);
        }
        if node.len() != NODE_SIZE {
            return Err(libc::EINVAL);
        }
        let offset = number * NODE_SIZE as u64;
        self.file.fseeko(offset as i64, libc::SEEK_SET)?;
        self.file.fread(node)
    }

    pub fn write(&mut self, number: u64, node: &[u8]) -> SysError {
        if self.file.raw().is_null() {
            return Err(libc::EINVAL);
        }
        if node.len() != NODE_SIZE {
            return Err(libc::EINVAL);
        }
        let offset = number * NODE_SIZE as u64;
        self.file.fseeko(offset as i64, libc::SEEK_SET)?;
        self.file.fwrite(node)
    }

    pub fn flush(&mut self) -> SysError {
        if self.file.raw().is_null() {
            return Err(libc::EINVAL);
        }
        self.file.fflush()
    }

    pub fn close(&mut self) -> SysError {
        if self.file.raw().is_null() {
            return Err(libc::EINVAL);
        }
        if let Ok(fd) = self.file.fileno() {
            let file = ManuallyDrop::new(FileFd::new(fd));
            let _ = file.flock(libc::LOCK_UN);
        }
        let ret = unsafe { libc::fclose(self.file.raw()) };
        if ret != 0 {
            Err(errno())
        } else {
            self.file.file = ptr::null_mut();
            Ok(())
        }
    }

    pub fn into_raw(self) -> *mut c_void {
        let file = self.file.raw();
        mem::forget(self);
        file as *mut c_void
    }

    pub fn raw(&self) -> *mut c_void {
        self.file.raw() as *mut c_void
    }

    pub unsafe fn from_raw(file: *mut c_void) -> Option<File> {
        if file.is_null() {
            None
        } else {
            Some(File {
                file: FileStream::new(file as *mut libc::FILE),
            })
        }
    }

    pub unsafe fn from_raw_unchecked(file: *mut c_void) -> File {
        File {
            file: FileStream::new(file as *mut libc::FILE),
        }
    }
}

impl Drop for File {
    fn drop(&mut self) {
        if !self.file.raw().is_null() {
            if let Ok(fd) = self.file.fileno() {
                let file = ManuallyDrop::new(FileFd::new(fd));
                let _ = file.flock(libc::LOCK_UN);
            }
        }
    }
}

pub struct RecoveryFile {
    file: FileStream,
}

impl RecoveryFile {
    pub fn open(name: &CStr) -> SysResult<RecoveryFile> {
        if name.to_bytes().len() <= 0 {
            return Err(libc::EINVAL);
        }

        let mode = CStr::from_bytes_with_nul(b"wb\0").map_err(|_| libc::EINVAL)?;
        for _ in 0..MAX_FOPEN_RETRIES {
            if let Ok(file) = FileStream::fopen(name, &mode) {
                return Ok(RecoveryFile { file: file });
            }
            unsafe { libc::usleep(MILISECONDS_SLEEP_FOPEN) };
        }
        Err(libc::EBUSY)
    }

    pub fn write(&mut self, data: &[u8]) -> SysError {
        if self.file.raw().is_null() {
            return Err(libc::EINVAL);
        }
        if data.len() != RECOVERY_NODE_SIZE {
            return Err(libc::EINVAL);
        }
        self.file.fwrite(data)
    }

    pub fn close(&mut self) -> SysError {
        if self.file.raw().is_null() {
            return Err(libc::EINVAL);
        }
        let ret = unsafe { libc::fclose(self.file.raw()) };
        if ret != 0 {
            Err(errno())
        } else {
            self.file.file = ptr::null_mut();
            Ok(())
        }
    }

    pub fn into_raw(self) -> *mut c_void {
        let file = self.file.raw();
        mem::forget(self);
        file as *mut c_void
    }

    pub fn raw(&self) -> *mut c_void {
        self.file.raw() as *mut c_void
    }

    pub unsafe fn from_raw(file: *mut c_void) -> Option<RecoveryFile> {
        if file.is_null() {
            None
        } else {
            Some(RecoveryFile {
                file: FileStream::new(file as *mut libc::FILE),
            })
        }
    }

    pub unsafe fn from_raw_uncheck(file: *mut c_void) -> RecoveryFile {
        RecoveryFile {
            file: FileStream::new(file as *mut libc::FILE),
        }
    }
}

pub fn remove(name: &CStr) -> SysError {
    if name.to_bytes().len() <= 0 {
        return Err(libc::EINVAL);
    }
    if unsafe { libc::remove(name.as_ptr()) } == 0 {
        Ok(())
    } else {
        Err(errno())
    }
}

pub fn exists(name: &CStr) -> SysResult<bool> {
    if name.to_bytes().len() <= 0 {
        return Err(libc::EINVAL);
    }

    let mut stat = new_stat();
    if unsafe { libc::stat(name.as_ptr(), &mut stat) } == 0 {
        Ok(true)
    } else {
        Ok(false)
    }
}

pub fn recovery(name: &CStr, recovery: &CStr) -> SysError {
    if name.to_bytes().len() <= 0 || recovery.to_bytes().len() <= 0 {
        return Err(libc::EINVAL);
    }

    let mode = CStr::from_bytes_with_nul(b"rb\0").map_err(|_| libc::EINVAL)?;
    let recovery_file = FileStream::fopen(recovery, &mode)?;

    recovery_file.fseeko(0, libc::SEEK_END)?;
    let size = recovery_file.ftello()? as usize;
    recovery_file.fseeko(0, libc::SEEK_SET)?;

    if size % RECOVERY_NODE_SIZE != 0 {
        return Err(libc::ENOTSUP);
    }

    let nodes_count = size / RECOVERY_NODE_SIZE;

    let mode = CStr::from_bytes_with_nul(b"r+b\0").map_err(|_| libc::EINVAL)?;
    let source_file = FileStream::fopen(&name, &mode)?;

    let mut data = vec![0_u8; RECOVERY_NODE_SIZE];
    for _ in 0..nodes_count {
        recovery_file.fread(data.as_mut_slice())?;
        // seek the regular file to the required offset
        let mut number = [0u8; 8];
        number.copy_from_slice(&data[0..8]);
        let physical_node_number = u64::from_ne_bytes(number);

        source_file.fseeko(
            (physical_node_number * NODE_SIZE as u64) as i64,
            libc::SEEK_SET,
        )?;
        source_file.fwrite(&data[8..])?;
    }

    source_file.fflush()?;
    remove(recovery)
}
