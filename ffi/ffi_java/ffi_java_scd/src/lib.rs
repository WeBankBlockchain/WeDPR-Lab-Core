// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library of macros and functions for FFI of SCD solution,
//! targeting Java-compatible architectures (including Android).

pub mod issuer;
pub mod user;
pub mod verifier;

#[macro_use]
extern crate wedpr_ffi_macros;
