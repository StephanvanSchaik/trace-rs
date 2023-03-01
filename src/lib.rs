pub mod arch;
pub mod error;
pub mod event;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "windows")]
pub mod windows;

pub use error::Error;
pub use event::Event;
pub use mmap_rs::Protection;

#[cfg(target_os = "linux")]
pub use crate::linux::{Tracee, Tracer};

#[cfg(target_os = "windows")]
pub use crate::windows::{Tracee, Tracer};
