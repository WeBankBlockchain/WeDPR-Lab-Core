// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library of utilities for FFI (adapting Rust to other programming languages).

#[cfg_attr(tarpaulin, skip)]
pub mod utils;

#[allow(unused_imports)]
#[macro_use]
extern crate wedpr_ffi_macros;

#[allow(unused_imports)]
#[macro_use]
extern crate wedpr_macros;
