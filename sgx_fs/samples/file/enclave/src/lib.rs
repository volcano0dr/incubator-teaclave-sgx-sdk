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
extern crate sgx_types;

use std::prelude::v1::*;
use std::io::{self, Read, Seek, Write};
use std::sgxfs;
use sgx_fs::fs as tspfs;
use sgx_types::*;

pub fn test_tspfs_write_with_key(filename: &str, key: &sgx_key_128bit_t) {
    println!("[+] test sgx_fs write with key file");
    let file = tspfs::SgxFile::create_with_key(filename, key);
    match file {
        Ok(mut f) => {
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

pub fn test_tspfs_write(filename: &str) {
    println!("[+] test sgx_fs write file");
    let file = tspfs::SgxFile::create(filename);
    match file {
        Ok(mut f) => {
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

pub fn test_tspfs_write_integrity_only(filename: &str) {
    println!("[+] test sgx_fs write integrity only file");
    let file = tspfs::SgxFile::create_integrity_only(filename);
    match file {
        Ok(mut f) => {
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

fn get_tspfs_file_size(file: &mut tspfs::SgxFile) -> io::Result<usize> {
    file.stream_len().map(|size| size as usize)
}

pub fn test_tspfs_read_with_key(filename: &str, key: &sgx_key_128bit_t) {
    println!("[+] test sgx_fs read with key file");
    let file = tspfs::SgxFile::open_with_key(filename, key);
    match file {
        Ok(mut f) => {
            let file_size = match get_tspfs_file_size(&mut f) {
                Ok(n) => n,
                Err(e) => {
                    println!("get file size error: {}", e);
                    return;
                }
            };
            println!("file size = {}", file_size);

            let mut data = String::new();
            let ret = f.read_to_string(&mut data);
            match ret {
                Ok(size) => {
                    println!(
                        "read size: {}, read data: {}",
                        size,
                        data
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

pub fn test_tspfs_read(filename: &str) {
    println!("[+] test sgx_fs read file");
    let file = tspfs::SgxFile::open(filename);
    match file {
        Ok(mut f) => {
            let file_size = match get_tspfs_file_size(&mut f) {
                Ok(n) => n,
                Err(e) => {
                    println!("get file size error: {}", e);
                    return;
                }
            };
            println!("file size = {}", file_size);

            let mut data = String::new();
            let ret = f.read_to_string(&mut data);
            match ret {
                Ok(size) => {
                    println!(
                        "read size: {}, read data: {}",
                        size,
                        data
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

pub fn test_tspfs_read_integrity_only(filename: &str) {
    println!("[+] test sgx_fs read integrity only file");
    let file = tspfs::SgxFile::open_integrity_only(filename);
    match file {
        Ok(mut f) => {
            let file_size = match get_tspfs_file_size(&mut f) {
                Ok(n) => n,
                Err(e) => {
                    println!("get file size error: {}", e);
                    return;
                }
            };
            println!("file size = {}", file_size);

            let mut data = String::new();
            let ret = f.read_to_string(&mut data);
            match ret {
                Ok(size) => {
                    println!(
                        "read size: {}, read data: {}",
                        size,
                        data
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

pub fn test_intel_write_with_key(filename: &str, key: &sgx_key_128bit_t) {
    println!("[+] test intel write file");
    let file = sgxfs::SgxFile::create_ex(filename, key);
    match file {
        Ok(mut f) => {
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

pub fn test_intel_write(filename: &str) {
    println!("[+] test intel write file");
    let file = sgxfs::SgxFile::create(filename);
    match file {
        Ok(mut f) => {
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

fn get_intel_file_size(file: &mut sgxfs::SgxFile) -> io::Result<usize> {
    file.stream_len().map(|size| size as usize)
}

pub fn test_intel_read_with_key(filename: &str, key: &sgx_key_128bit_t) {
    println!("[+] test intel read file");
    let file = sgxfs::SgxFile::open_ex(filename, key);
    match file {
        Ok(mut f) => {
            let file_size = match get_intel_file_size(&mut f) {
                Ok(n) => n,
                Err(e) => {
                    println!("get file size error: {}", e);
                    return;
                }
            };
            println!("file size = {}", file_size);

            let mut data = String::new();
            let ret = f.read_to_string(&mut data);
            match ret {
                Ok(size) => {
                    println!(
                        "read size: {}, read data: {}",
                        size,
                        data
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

pub fn test_intel_read(filename: &str) {
    println!("[+] test intel read file");
    let file = sgxfs::SgxFile::open(filename);
    match file {
        Ok(mut f) => {
            let file_size = match get_intel_file_size(&mut f) {
                Ok(n) => n,
                Err(e) => {
                    println!("get file size error: {}", e);
                    return;
                }
            };
            println!("file size = {}", file_size);

            let mut data = String::new();
            let ret = f.read_to_string(&mut data);
            match ret {
                Ok(size) => {
                    println!(
                        "read size: {}, read data: {}",
                        size,
                        data
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

fn test_export_import_key(filename: &str) {
    test_tspfs_write(filename);
    let ret = tspfs::export_auto_key(filename);
    let key = match ret {
        Ok(k) => k,
        Err(e) => {
            println!("export key err: {}", e);
            return;
        }
    };

    let ret = tspfs::import_auto_key(filename, &key);
    match ret {
        Ok(_) => (),
        Err(e) => {
            println!("export key err: {}", e);
            return;
        }
    };

    test_tspfs_read(filename);
}

fn test_rename_meta(old_name: &str, new_name: &str) {
    test_tspfs_write(old_name);
    let _ = std::untrusted::fs::rename(old_name, new_name);
    test_tspfs_read(new_name);
    {
        let _ = std::untrusted::fs::rename(new_name, old_name);
        let file = tspfs::SgxFile::create(old_name);
        match file {
            Ok(mut f) => {
                let ret = f.rename_meta(old_name, new_name);
                match ret {
                    Ok(_) => (),
                    Err(e) => {
                        println!("renmae meta err: {}", e);
                        return;
                    }
                }
            }
            Err(e) => {
                println!("open file err: {}", e);
            }
        }
        let _ = std::untrusted::fs::rename(old_name, new_name);
    }
    test_tspfs_read(new_name);
}

fn test_copy(src: &str, dst: &str) {
    test_tspfs_write(src);
    let ret = tspfs::copy(src, dst);
    match ret {
        Ok(n) => println!("copy size {}", n),
        Err(e) => {
            println!("copy err: {}", e);
            return;
        }
    }
    test_tspfs_read(dst);
}

#[no_mangle]
pub extern "C" fn test_file() -> i32 {
    let key = sgx_key_128bit_t::default();
    test_tspfs_write_with_key("sgx_file_1", &key);
    test_tspfs_read_with_key("sgx_file_1", &key);
    test_intel_read_with_key("sgx_file_1", &key);

    println!();

    test_intel_write_with_key("sgx_file_2", &key);
    test_intel_read_with_key("sgx_file_2", &key);
    test_tspfs_read_with_key("sgx_file_2", &key);

    println!();

    test_tspfs_write("sgx_file_3");
    test_tspfs_read("sgx_file_3");
    test_intel_read("sgx_file_3");

    println!();

    test_intel_write("sgx_file_4");
    test_intel_read("sgx_file_4");
    test_tspfs_read("sgx_file_4");

    println!();

    test_tspfs_write_integrity_only("sgx_file_5");
    test_tspfs_read_integrity_only("sgx_file_5");

    println!();

    test_export_import_key("sgx_file_6");

    println!();

    test_rename_meta("sgx_file_7", "sgx_file_8");

    println!();

    test_copy("sgx_file_9", "sgx_file_10");

    let _ = tspfs::remove("sgx_file_1");
    let _ = tspfs::remove("sgx_file_2");
    let _ = tspfs::remove("sgx_file_3");
    let _ = tspfs::remove("sgx_file_4");
    let _ = tspfs::remove("sgx_file_5");
    let _ = tspfs::remove("sgx_file_6");
    let _ = tspfs::remove("sgx_file_7");
    let _ = tspfs::remove("sgx_file_8");
    let _ = tspfs::remove("sgx_file_9");
    let _ = tspfs::remove("sgx_file_10");

    return 0;
}
