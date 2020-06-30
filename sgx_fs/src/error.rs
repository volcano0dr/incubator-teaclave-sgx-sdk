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

use std::fmt;
use std::io::Error as IoError;
use types::sgx_status_t;

#[derive(Copy, Clone, Debug)]
pub struct Error {
    repr: Repr,
}

#[derive(Copy, Clone, Debug)]
enum Repr {
    Os(i32),
    SgxStatus(sgx_status_t),
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.repr {
            Repr::Os(code) => write!(fmt, "os error {}", code),
            Repr::SgxStatus(status) => write!(fmt, "{}", status.as_str()),
        }
    }
}

impl From<sgx_status_t> for Error {
    #[inline]
    fn from(status: sgx_status_t) -> Error {
        Error::from_sgx_error(status)
    }
}

impl From<i32> for Error {
    #[inline]
    fn from(code: i32) -> Error {
        Error::from_raw_os_error(code)
    }
}

impl Error {
    pub fn from_raw_os_error(code: i32) -> Error {
        Error {
            repr: Repr::Os(code),
        }
    }

    pub fn raw_os_error(&self) -> Option<i32> {
        match self.repr {
            Repr::Os(i) => Some(i),
            Repr::SgxStatus(..) => None,
        }
    }

    pub fn from_sgx_error(status: sgx_status_t) -> Error {
        Error {
            repr: Repr::SgxStatus(status),
        }
    }

    pub fn raw_sgx_error(&self) -> Option<sgx_status_t> {
        match self.repr {
            Repr::Os(..) => None,
            Repr::SgxStatus(status) => Some(status),
        }
    }

    pub fn raw_error(&self) -> i32 {
        match self.repr {
            Repr::Os(code) => code,
            Repr::SgxStatus(status) => status as i32,
        }
    }

    pub fn is_success(&self) -> bool {
        match self.repr {
            Repr::Os(code) => code == 0,
            Repr::SgxStatus(status) => status == sgx_status_t::SGX_SUCCESS,
        }
    }

    #[cfg(feature = "mesalock_sgx")]
    pub fn to_io_error(self) -> IoError {
        match self.repr {
            Repr::Os(code) => IoError::from_raw_os_error(code),
            Repr::SgxStatus(status) => IoError::from_sgx_error(status),
        }
    }

    #[cfg(not(feature = "mesalock_sgx"))]
    pub fn to_io_error(self) -> IoError {
        IoError::from_raw_os_error(self.raw_error())
    }
}

pub type FsResult<T> = std::result::Result<T, Error>;
pub type FsError = std::result::Result<(), Error>;
