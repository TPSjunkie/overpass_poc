// File: overpass_core/src/error/mod.rs

pub mod client_errors;

pub use client_errors::{
    ChannelError, ChannelErrorType, ClientError, ClientErrorType, SystemError, SystemErrorType,
};

