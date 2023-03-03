use mach2::exception_types::*;
use mach2::mach_types::task_t;
use mach2::port::mach_port_t;
use mach2::thread_status::thread_state_flavor_t;
use nix::unistd::Pid;
use super::exceptions::exception_message_t;

extern "C" {
    pub fn task_set_exception_ports(
        task: task_t,
        exception_types: exception_mask_t,
        exception_port: mach_port_t,
        behavior: exception_behavior_t,
        flavor: thread_state_flavor_t,
    );
}

#[derive(Debug)]
pub struct Tracee {
    pub(crate) task: mach_port_t,
    pub(crate) thread: mach_port_t,
    pub(crate) pid: Pid,
    pub(crate) reply: Option<exception_message_t>,
}

impl Tracee {
    /// Returns the process ID.
    pub fn process_id(&self) -> u32 {
        self.pid.as_raw() as _
    }
}
