pub mod arch;
pub mod error;
pub mod event;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(unix)]
pub mod unix;

#[cfg(target_os = "windows")]
pub mod windows;

pub use error::Error;
pub use event::Event;
pub use mmap_rs::Protection;

#[cfg(unix)]
pub use crate::unix::{Tracee, Tracer};

#[cfg(target_os = "windows")]
pub use crate::windows::{Tracee, Tracer};
