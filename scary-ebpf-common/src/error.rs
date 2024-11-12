//! Error handling for eBPF programs
//!
//! This module provides a zero-cost error handling abstraction
//! optimized for eBPF programs.

use core::fmt;

/// Common error types for eBPF programs
#[derive(Debug, Clone, Copy)]
pub enum Error {
    /// Error reading from kernel memory
    KernelRead(i64),

    /// Error reading from user memory
    UserRead(i64),

    /// Error writing to user memory
    UserWrite(i64),

    /// Error with BPF helper function
    Helper(i64),

    /// Map operation failed
    Map(i64),

    /// Invalid task structure
    InvalidTask,

    /// Missing or invalid field
    Field(&'static str),

    /// Value out of valid range
    OutOfRange(&'static str),

    /// Invalid state transition
    InvalidState(&'static str),

    /// Generic error
    Generic(i64),
}

impl Error {
    /// Convert error to a return code suitable for BPF programs
    #[inline(always)]
    pub const fn to_retval(self) -> u32 {
        match self {
            Self::KernelRead(code)
            | Self::UserRead(code)
            | Self::UserWrite(code)
            | Self::Helper(code)
            | Self::Map(code)
            | Self::Generic(code) => code as u32,
            Self::InvalidTask => 1,
            Self::Field(_) => 2,
            Self::OutOfRange(_) => 3,
            Self::InvalidState(_) => 4,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KernelRead(code) => write!(f, "Kernel read error: {}", code),
            Self::UserRead(code) => write!(f, "User read error: {}", code),
            Self::UserWrite(code) => write!(f, "User write error: {}", code),
            Self::Helper(code) => write!(f, "Helper function error: {}", code),
            Self::Map(code) => write!(f, "Map operation error: {}", code),
            Self::InvalidTask => write!(f, "Invalid task structure"),
            Self::Field(field) => write!(f, "Invalid field: {}", field),
            Self::OutOfRange(value) => write!(f, "Value out of range: {}", value),
            Self::InvalidState(state) => write!(f, "Invalid state: {}", state),
            Self::Generic(code) => write!(f, "Generic error: {}", code),
        }
    }
}

/// Result type specialized for eBPF programs
pub type Result<T> = core::result::Result<T, Error>;

/// Error conversion traits
pub trait IntoError {
    fn into_error(self, context: &'static str) -> Error;
}

impl IntoError for i64 {
    #[inline(always)]
    fn into_error(self, context: &'static str) -> Error {
        Error::Generic(self)
    }
}
