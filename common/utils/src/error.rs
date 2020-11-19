// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! WeDPR errors definitions.

#[derive(Fail, Clone, Debug, Eq, PartialEq)]
pub enum WedprError {
    #[fail(display = "Verification failed")]
    VerificationError,
    #[fail(display = "Argument is invalid")]
    ArgumentError,
    #[fail(display = "Data cannot be parsed")]
    FormatError,
    #[fail(display = "Data cannot be decoded")]
    DecodeError,
    #[fail(display = "Indy Crypto error.")]
    IndyCryptoError,
}
