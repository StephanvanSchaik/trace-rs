//! This module implements the error type used throughout this crate.

use crate::Protection;
use thiserror::Error;

/// The error type.
#[derive(Debug, Error)]
pub enum Error {
    /// An invalid protection was specified.
    #[error("invalid protection {0:?}")]
    InvalidProtection(Protection),

    /// Represents [`std::str::Utf8Error`].
    #[error(transparent)]
    Utf8(#[from] std::str::Utf8Error),

    /// Represents [`std::string::FromUtf8Error`].
    #[error(transparent)]
    FromUtf8(#[from] std::string::FromUtf8Error),

    /// Represents [`std::io::Error`].
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[cfg(unix)]
    /// Represents [`nix::Error`].
    #[error(transparent)]
    Nix(#[from] nix::Error),

    #[cfg(target_os = "windows")]
    /// Represents [`windows::core::Error`].
    #[error(transparent)]
    Windows(#[from] windows::core::Error),

    #[cfg(target_os = "windows")]
    /// Represents [`widestring::error::Utf16Error`].
    #[error(transparent)]
    Utf16(#[from] widestring::error::Utf16Error),

    #[cfg(target_os = "macos")]
    /// An error returned by the internal Mach API on MacOS.
    #[error("Mach error {0}")]
    Mach(mach2::kern_return::kern_return_t),
}
