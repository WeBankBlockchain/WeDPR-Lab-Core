// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library of selective_disclosure solution.

#[macro_use]
extern crate wedpr_macros;

pub mod issuer;
pub mod user;
mod utils;
pub mod verifier;
#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
