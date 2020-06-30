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
#![allow(dead_code)]
#![feature(specialization)]
#![feature(box_into_raw_non_null)]
#![cfg_attr(all(feature = "mesalock_sgx", not(target_env = "sgx")), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

#[cfg(all(feature = "mesalock_sgx", not(target_env = "sgx")))]
#[macro_use]
extern crate sgx_tstd as std;

#[macro_use]
extern crate sgx_types as types;

#[cfg(feature = "mesalock_sgx")]
extern crate sgx_libc as libc;
#[cfg(feature = "mesalock_sgx")]
extern crate sgx_tcrypto as crypto;
#[cfg(feature = "mesalock_sgx")]
extern crate sgx_trts as trts;
#[cfg(feature = "mesalock_sgx")]
extern crate sgx_tse as tse;

#[cfg(not(feature = "mesalock_sgx"))]
extern crate libc;
#[cfg(not(feature = "mesalock_sgx"))]
extern crate sgx_ucrypto as crypto;
#[cfg(not(feature = "mesalock_sgx"))]
extern crate sgx_uspfs as uspfs;

mod core;
mod deps;
mod fs_inner;
pub mod error;
pub mod fs;
pub mod stream;

//pub use fs::*;

