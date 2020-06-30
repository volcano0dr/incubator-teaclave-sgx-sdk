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

extern crate sgx_fs;
extern crate libc;
extern crate sgx_types;

use std::vec;
use sgx_fs::error::FsResult;
use sgx_fs::stream::SeekFrom;
use sgx_fs::stream::SgxFileStream;
use sgx_types::*;

fn main() {
    let key = sgx_key_128bit_t::default();
    test_tspfs_write_with_key("sgx_file_1", "w", &key);
    test_tspfs_read_with_key("sgx_file_1", "r", &key);

    println!();

    test_tspfs_write_with_key("sgx_file_1", "a", &key);
    test_tspfs_read_with_key("sgx_file_1", "r", &key);

    println!();

    test_tspfs_write_integrity_only("sgx_file_2", "w");
    test_tspfs_read_integrity_only("sgx_file_2", "r");

    let _ = sgx_fs::stream::remove("sgx_file_1");
    let _ = sgx_fs::stream::remove("sgx_file_2");
}

pub fn test_tspfs_write_with_key(filename: &str, mode: &str, key: &sgx_key_128bit_t) {
    println!("[+] test sgx_fs write with key file");
    let file = SgxFileStream::open_with_key(filename, mode, key);
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

pub fn test_tspfs_write_integrity_only(filename: &str, mode: &str) {
    println!("[+] test sgx_fs write integrity only file");
    let file = SgxFileStream::open_integrity_only(filename, mode);
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

fn get_tspfs_file_size(file: &SgxFileStream) -> FsResult<usize> {
    if let Err(e) = file.seek(0, SeekFrom::End) {
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

    if let Err(e) = file.seek(0, SeekFrom::Start) {
        println!("seek file start error: {}", e);
        return Err(e);
    }

    Ok(file_size)
}

pub fn test_tspfs_read_with_key(filename: &str, mode: &str, key: &sgx_key_128bit_t) {
    println!("[+] test sgx_fs read with key file");
    let file = SgxFileStream::open_with_key(filename, mode, key);
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
    let file = SgxFileStream::open_integrity_only(filename, mode);
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