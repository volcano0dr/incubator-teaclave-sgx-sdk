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

#![crate_name = "filesampleenclave"]
#![crate_type = "staticlib"]
#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;
extern crate sgx_fs;
extern crate sgx_libc as libc;
extern crate sgx_tprotected_fs as sgxfs;
extern crate sgx_types;

use std::ffi::CString;
use std::prelude::v1::*;
use std::vec;

use sgx_fs::stream as tspfs;
use sgx_fs::{error::Error, error::FsResult};
use sgx_types::*;

fn cstr(name: &str) -> FsResult<CString> {
    CString::new(name.as_bytes()).map_err(|_| Error::from(libc::EINVAL))
}

pub fn test_tspfs_write_with_key(filename: &str, mode: &str, key: &sgx_key_128bit_t) {
    println!("[+] test sgx_fs write with key file");
    let file = tspfs::SgxFileStream::open_with_key(filename, mode, key);
    match file {
        Ok(f) => {
            let mut data = String::from("1234567890");
            for _ in 0..1000 {
                data.push_str("1234567890");
            }
            let ret = f.write(data.as_bytes());
            match ret {
                Ok(n) => {
                    println!("write size: {}", n);
                }
                Err(e) => {
                    println!("write err: {}", e);
                }
            }
            let ret = f.get_meta_mac();
            match ret {
                Ok(mac) => {
                    println!("mac: {:?}", mac);
                }
                Err(e) => {
                    println!("get mac err: {}", e);
                }
            }
        }
        Err(e) => {
            println!("open file err: {}", e);
        }
    }
}

pub fn test_tspfs_write(filename: &str, mode: &str) {
    println!("[+] test sgx_fs write file");
    let file = tspfs::SgxFileStream::open(filename, mode);
    match file {
        Ok(f) => {
            let mut data = String::from("9876543210");
            for _ in 0..1000 {
                data.push_str("9876543210");
            }
            let ret = f.write(data.as_bytes());
            match ret {
                Ok(n) => {
                    println!("write size: {}", n);
                }
                Err(e) => {
                    println!("write err: {}", e);
                }
            }
            let ret = f.get_meta_mac();
            match ret {
                Ok(mac) => {
                    println!("mac: {:?}", mac);
                }
                Err(e) => {
                    println!("get mac err: {}", e);
                }
            }
        }
        Err(e) => {
            println!("open file err: {}", e);
        }
    }
}

pub fn test_tspfs_write_integrity_only(filename: &str, mode: &str) {
    println!("[+] test sgx_fs write integrity only file");
    let file = tspfs::SgxFileStream::open_integrity_only(filename, mode);
    match file {
        Ok(f) => {
            let mut data = String::from("9876543210");
            for _ in 0..1000 {
                data.push_str("9876543210");
            }
            let ret = f.write(data.as_bytes());
            match ret {
                Ok(n) => {
                    println!("write size: {}", n);
                }
                Err(e) => {
                    println!("write err: {}", e);
                }
            }
            let ret = f.get_meta_mac();
            match ret {
                Ok(mac) => {
                    println!("mac: {:?}", mac);
                }
                Err(e) => {
                    println!("get mac err: {}", e);
                }
            }
        }
        Err(e) => {
            println!("open file err: {}", e);
        }
    }
}

fn get_tspfs_file_size(file: &tspfs::SgxFileStream) -> FsResult<usize> {
    if let Err(e) = file.seek(0, tspfs::SeekFrom::End) {
        println!("seek file end error: {}", e);
        return Err(e);
    }

    let file_size = match file.tell() {
        Ok(n) => n as usize,
        Err(e) => {
            println!("get file size error: {}", e);
            return Err(e);
        }
    };

    if let Err(e) = file.seek(0, tspfs::SeekFrom::Start) {
        println!("seek file start error: {}", e);
        return Err(e);
    }

    Ok(file_size)
}

pub fn test_tspfs_read_with_key(filename: &str, mode: &str, key: &sgx_key_128bit_t) {
    println!("[+] test sgx_fs read with key file");
    let file = tspfs::SgxFileStream::open_with_key(filename, mode, key);
    match file {
        Ok(f) => {
            let mut file_size = match get_tspfs_file_size(&f) {
                Ok(n) => n,
                Err(e) => {
                    println!("get file size error: {}", e);
                    return;
                }
            };
            println!("file size = {}", file_size);
            if file_size <= 0 {
                file_size = 1000;
            }

            let mut data: Vec<u8> = vec::from_elem(0_u8, file_size);
            let ret = f.read(data.as_mut_slice());
            match ret {
                Ok(size) => {
                    println!(
                        "read size: {}, read data: {}",
                        size,
                        String::from_utf8(data[0..100].to_vec()).unwrap()
                    );
                }
                Err(e) => {
                    println!("read err: {}", e);
                }
            }
            let ret = f.get_meta_mac();
            match ret {
                Ok(mac) => {
                    println!("mac: {:?}", mac);
                }
                Err(e) => {
                    println!("get mac err: {}", e);
                }
            }
        }
        Err(e) => {
            println!("open file err: {}", e);
        }
    }
}

pub fn test_tspfs_read(filename: &str, mode: &str) {
    println!("[+] test sgx_fs read file");
    let file = tspfs::SgxFileStream::open(filename, mode);
    match file {
        Ok(f) => {
            let mut file_size = match get_tspfs_file_size(&f) {
                Ok(n) => n,
                Err(e) => {
                    println!("get file size error: {}", e);
                    return;
                }
            };
            println!("file size = {}", file_size);
            if file_size <= 0 {
                file_size = 1000;
            }

            let mut data: Vec<u8> = vec::from_elem(0_u8, file_size);
            let ret = f.read(data.as_mut_slice());
            match ret {
                Ok(size) => {
                    println!(
                        "read size: {}, read data: {}",
                        size,
                        String::from_utf8(data[0..100].to_vec()).unwrap()
                    );
                }
                Err(e) => {
                    println!("read err: {}", e);
                }
            }
            let ret = f.get_meta_mac();
            match ret {
                Ok(mac) => {
                    println!("mac: {:?}", mac);
                }
                Err(e) => {
                    println!("get mac err: {}", e);
                }
            }
        }
        Err(e) => {
            println!("open file err: {}", e);
        }
    }
}

pub fn test_tspfs_read_integrity_only(filename: &str, mode: &str) {
    println!("[+] test sgx_fs read integrity only file");
    let file = tspfs::SgxFileStream::open_integrity_only(filename, mode);
    match file {
        Ok(f) => {
            let mut file_size = match get_tspfs_file_size(&f) {
                Ok(n) => n,
                Err(e) => {
                    println!("get file size error: {}", e);
                    return;
                }
            };
            println!("file size = {}", file_size);
            if file_size <= 0 {
                file_size = 1000;
            }

            let mut data: Vec<u8> = vec::from_elem(0_u8, file_size);
            let ret = f.read(data.as_mut_slice());
            match ret {
                Ok(size) => {
                    println!(
                        "read size: {}, read data: {}",
                        size,
                        String::from_utf8(data[0..100].to_vec()).unwrap()
                    );
                }
                Err(e) => {
                    println!("read err: {}", e);
                }
            }
            let ret = f.get_meta_mac();
            match ret {
                Ok(mac) => {
                    println!("mac: {:?}", mac);
                }
                Err(e) => {
                    println!("get mac err: {}", e);
                }
            }
        }
        Err(e) => {
            println!("open file err: {}", e);
        }
    }
}

pub fn test_intel_write_with_key(filename: &str, mode: &str, key: &sgx_key_128bit_t) {
    println!("[+] test intel write with key file");
    let name = cstr(filename).expect("CString::new failed");
    let mode = cstr(mode).expect("CString::new failed");
    let file = sgxfs::SgxFileStream::open(&name, &mode, key);
    match file {
        Ok(f) => {
            let mut data = String::from("1234567890");
            for _ in 0..1000 {
                data.push_str("1234567890");
            }
            let ret = f.write(data.as_bytes());
            match ret {
                Ok(n) => {
                    println!("write size: {}", n);
                }
                Err(e) => {
                    println!("write err: {}", e);
                }
            }
        }
        Err(e) => {
            println!("open file err: {}", e);
        }
    }
}

pub fn test_intel_write(filename: &str, mode: &str) {
    println!("[+] test intel write file");
    let name = cstr(filename).expect("CString::new failed");
    let mode = cstr(mode).expect("CString::new failed");
    let file = sgxfs::SgxFileStream::open_auto_key(&name, &mode);
    match file {
        Ok(f) => {
            let mut data = String::from("9876543210");
            for _ in 0..1000 {
                data.push_str("9876543210");
            }
            let ret = f.write(data.as_bytes());
            match ret {
                Ok(n) => {
                    println!("write size: {}", n);
                }
                Err(e) => {
                    println!("write err: {}", e);
                }
            }
        }
        Err(e) => {
            println!("open file err: {}", e);
        }
    }
}

fn get_intel_file_size(file: &sgxfs::SgxFileStream) -> SysResult<usize> {
    if let Err(e) = file.seek(0, sgxfs::SeekFrom::End) {
        println!("seek file end error: {}", e);
        return Err(e);
    }

    let file_size = match file.tell() {
        Ok(n) => {
            println!("tell file size = {}", n);
            n as usize
        }
        Err(e) => {
            println!("get file size error: {}", e);
            return Err(e);
        }
    };

    if let Err(e) = file.seek(0, sgxfs::SeekFrom::Start) {
        println!("seek file start error: {}", e);
        return Err(e);
    }

    Ok(file_size)
}

pub fn test_intel_read_with_key(filename: &str, mode: &str, key: &sgx_key_128bit_t) {
    println!("[+] test intel read with key file");
    let name = cstr(filename).expect("CString::new failed");
    let mode = cstr(mode).expect("CString::new failed");
    let file = sgxfs::SgxFileStream::open(&name, &mode, key);
    match file {
        Ok(f) => {
            let mut file_size = match get_intel_file_size(&f) {
                Ok(n) => n,
                Err(e) => {
                    println!("get file size error: {}", e);
                    return;
                }
            };
            println!("file size = {}", file_size);
            if file_size <= 0 {
                file_size = 1000;
            }

            let mut data: Vec<u8> = vec::from_elem(0_u8, file_size);
            let ret = f.read(data.as_mut_slice());
            match ret {
                Ok(size) => {
                    println!(
                        "read size: {}, read data: {}",
                        size,
                        String::from_utf8(data[0..100].to_vec()).unwrap()
                    );
                }
                Err(e) => {
                    println!("read err: {}", e);
                }
            }
        }
        Err(e) => {
            println!("open file err: {}", e);
        }
    }
}

pub fn test_intel_read(filename: &str, mode: &str) {
    println!("[+] test intel read file");
    let name = cstr(filename).expect("CString::new failed");
    let mode = cstr(mode).expect("CString::new failed");
    let file = sgxfs::SgxFileStream::open_auto_key(&name, &mode);
    match file {
        Ok(f) => {
            let mut file_size = match get_intel_file_size(&f) {
                Ok(n) => n,
                Err(e) => {
                    println!("get file size error: {}", e);
                    return;
                }
            };
            println!("file size = {}", file_size);
            if file_size <= 0 {
                file_size = 1000;
            }

            let mut data: Vec<u8> = vec::from_elem(0_u8, file_size);
            let ret = f.read(data.as_mut_slice());
            match ret {
                Ok(size) => {
                    println!(
                        "read size: {}, read data: {}",
                        size,
                        String::from_utf8(data[0..100].to_vec()).unwrap()
                    );
                }
                Err(e) => {
                    println!("read err: {}", e);
                }
            }
        }
        Err(e) => {
            println!("open file err: {}", e);
        }
    }
}

fn test_write_bigfile(filename: &str, mode: &str) {
    println!("[+] test write big file");
    let file = tspfs::SgxFileStream::open(filename, mode);
    match file {
        Ok(f) => {
            let data: Vec<u8> = vec![0x41; 4096];
            let mut cnt: i64 = (4*1024*1024*1024) / 4096;
            let mut size: usize = 0;
            let mut count: usize = 0;
            while cnt > 0 {
                let ret = f.write(data.as_slice());
                match ret {
                    Ok(n) => {
                        cnt -= 1;
                        count += 1;
                        size += n;
                    },
                    Err(e) => {
                        println!("write err: {}", e);
                        break;
                    }
                }
            }
            println!("write count: {}, size: {}", count, size);
        }
        Err(e) => {
            println!("open file err: {}", e);
        }
    }
}

fn test_read_bigfile(filename: &str, mode: &str) {
    println!("[+] test read big file");
    let file = tspfs::SgxFileStream::open(filename, mode);
    match file {
        Ok(f) => {
            let mut data = vec![0_u8; 4096];
            let mut size: usize = 0;
            let mut count: usize = 0;
            loop {
                match f.read(&mut data.as_mut_slice()) {
                    Ok(0) => break,
                    Ok(n) => {
                        count += 1;
                        size += n;
                    },
                    Err(e) => {
                        println!("read err: {}", e);
                        break;
                    }
                }
            }
            println!("read count: {}, size: {}", count, size);
        }
        Err(e) => {
            println!("open file err: {}", e);
        }
    }
}

#[no_mangle]
pub extern "C" fn test_file() -> i32 {
    let key = sgx_key_128bit_t::default();
    test_tspfs_write_with_key("sgx_file_1", "w", &key);
    test_tspfs_read_with_key("sgx_file_1", "r", &key);
    test_intel_read_with_key("sgx_file_1", "r", &key);

    println!();

    test_intel_write_with_key("sgx_file_2", "w", &key);
    test_intel_read_with_key("sgx_file_2", "r", &key);
    test_tspfs_read_with_key("sgx_file_2", "r", &key);

    println!();

    test_tspfs_write_with_key("sgx_file_1", "a", &key);
    test_tspfs_read_with_key("sgx_file_1", "r", &key);

    println!();

    test_tspfs_write("sgx_file_3", "w");
    test_tspfs_read("sgx_file_3", "r");
    test_intel_read("sgx_file_3", "r");

    println!();

    test_intel_write("sgx_file_4", "w");
    test_intel_read("sgx_file_4", "r");
    test_tspfs_read("sgx_file_4", "r");

    println!();

    test_tspfs_write_integrity_only("sgx_file_5", "w");
    test_tspfs_read_integrity_only("sgx_file_5", "r");

    println!();

    test_write_bigfile("sgx_file_6", "w");
    test_read_bigfile("sgx_file_6", "r");

    let _ = tspfs::remove("sgx_file_1");
    let _ = tspfs::remove("sgx_file_2");
    let _ = tspfs::remove("sgx_file_3");
    let _ = tspfs::remove("sgx_file_4");
    let _ = tspfs::remove("sgx_file_5");
    let _ = tspfs::remove("sgx_file_6");
    return 0;
}
