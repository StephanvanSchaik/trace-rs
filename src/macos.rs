use crate::Error;
use mach2::boolean::boolean_t;
use mach2::exception_types::{exception_type_t, mach_exception_data_t};
use mach2::kern_return::kern_return_t;
use mach2::message::{mach_msg_header_t, mach_msg_type_number_t, MACH_RCV_INVALID_TYPE};
use mach2::port::mach_port_t;
use mach2::thread_status::thread_state_t;
use nix::unistd::Pid;

extern "C" {
    pub fn mach_exc_server(
        request: *const mach_msg_header_t,
        reply: *mut mach_msg_header_t,
    ) -> boolean_t;
}

#[no_mangle]
extern "C" fn catch_mach_exception_raise(
    exception_port: mach_port_t,
    thread_port: mach_port_t,
    task_port: mach_port_t,
    exception_type: exception_type_t,
    codes: mach_exception_data_t,
    num_codes: mach_msg_type_number_t,
) -> kern_return_t {
    MACH_RCV_INVALID_TYPE
}

#[no_mangle]
extern "C" fn catch_mach_exception_raise_state(
    exception_port: mach_port_t,
    exception: exception_type_t,
    code: mach_exception_data_t,
    code_count: mach_msg_type_number_t,
    flavor: *mut i32,
    old_state: thread_state_t,
    old_state_count: mach_msg_type_number_t,
    new_state: thread_state_t,
    new_state_count: *mut mach_msg_type_number_t,
) -> kern_return_t {
    MACH_RCV_INVALID_TYPE
}

#[no_mangle]
extern "C" fn catch_mach_exception_raise_state_identity(
    exception_port: mach_port_t,
    thread_port: mach_port_t,
    task_port: mach_port_t,
    exception: exception_type_t,
    code: mach_exception_data_t,
    code_count: mach_msg_type_number_t,
    flavor: *mut i32,
    old_state: thread_state_t,
    old_state_count: mach_msg_type_number_t,
    new_state: thread_state_t,
    new_state_count: *mut mach_msg_type_number_t,
) -> kern_return_t {
    MACH_RCV_INVALID_TYPE
}

#[derive(Debug)]
pub struct TraceeData;

impl TraceeData {
    pub fn new(pid: Pid) -> Result<Self, Error> {
        Ok(Self)
    }
}
