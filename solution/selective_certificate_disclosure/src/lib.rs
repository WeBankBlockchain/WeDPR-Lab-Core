// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library of selective certificate disclosure (SCD) solution.

#[macro_use]
extern crate wedpr_macros;

pub mod issuer;
pub mod user;
pub mod utils;
pub mod verifier;

// TODO: Add E2E tests for all SCD functions.
// TODO: Add benches for all SCD functions.
