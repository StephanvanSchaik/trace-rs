use nix::{
    sys::signal::Signal,
    unistd::Pid,
};
use std::fs::File;
use super::tracer::ChildState;

/// The tracee is the process that is currently being traced.
#[derive(Debug)]
pub struct Tracee {
    pub(crate) pid: Pid,
    pub(crate) signal: Option<Signal>,
    pub(crate) state: ChildState,
    pub(crate) file: File,
}

impl Tracee {
    /// Returns the process ID.
    pub fn process_id(&self) -> u32 {
        self.pid.as_raw() as _
    }
}
