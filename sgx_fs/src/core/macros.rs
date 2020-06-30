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

macro_rules! impl_struct_copy_clone {
    ($($i: ident), *) => (
        $(
            impl Copy for $i {}
            impl Clone for $i {
                fn clone(&self) -> $i { *self }
            }

            unsafe impl ContiguousMemory for $i {}
        )*
    )
}

macro_rules! impl_struct_slice {
    ($($i: ident), *) => (
        $(
            impl AsSlice for $i {
                fn as_slice(&self) -> &[u8] {
                    unsafe {
                        std::slice::from_raw_parts(
                            self as * const _ as * const u8,
                            std::mem::size_of::<$i>(),
                    )}
                }

                fn as_mut_slice(&mut self) -> &mut [u8] {
                    unsafe {
                        std::slice::from_raw_parts_mut(
                            self as * mut _ as * mut u8,
                            std::mem::size_of::<$i>(),
                        )
                    }
                }
            }
        )*
    )
}

macro_rules! i64 {
    ($val: expr) => {
        cast_type!($val, i64)
    };
}
macro_rules! u64 {
    ($val: expr) => {
        cast_type!($val, u64)
    };
}
macro_rules! usize {
    ($val: expr) => {
        cast_type!($val, usize)
    };
}
macro_rules! i32 {
    ($val: expr) => {
        cast_type!($val, i32)
    };
}
macro_rules! cast_type {
    ($val: expr, $type: ident) => {
        ($val) as $type
    };
}
