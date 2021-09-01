// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library of macros and functions for FFI of anonymous bounded voting (ABV) solutions,
//! targeting C/C++ compatible architectures (including iOS).

#[allow(unused_imports)]
#[macro_use]
extern crate wedpr_ffi_macros;

#[macro_use]
extern crate wedpr_l_macros;

pub mod coordinator;
pub mod counter;
pub mod verifier;
pub mod voter;