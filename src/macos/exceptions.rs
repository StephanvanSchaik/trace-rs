use mach2::boolean::boolean_t;
use mach2::exception_types::{exception_type_t, mach_exception_data_t};
use mach2::kern_return::kern_return_t;
use mach2::message::{mach_msg_header_t, mach_msg_type_number_t, MACH_RCV_INVALID_TYPE};
use mach2::port::mach_port_t;
use mach2::thread_status::thread_state_t;

extern "C" {
    pub fn mach_exc_server(
        request: *const mach_msg_header_t,
        reply: *mut mach_msg_header_t,
    ) -> boolean_t;
}

#[no_mangle]
extern "C" fn catch_mach_exception_raise(
    _exception_port: mach_port_t,
    _thread_port: mach_port_t,
    _task_port: mach_port_t,
    _exception_type: exception_type_t,
    _codes: mach_exception_data_t,
    _num_codes: mach_msg_type_number_t,
) -> kern_return_t {
    MACH_RCV_INVALID_TYPE
}

#[no_mangle]
extern "C" fn catch_mach_exception_raise_state(
    _exception_port: mach_port_t,
    _exception: exception_type_t,
    _code: mach_exception_data_t,
    _code_count: mach_msg_type_number_t,
    _flavor: *mut i32,
    _old_state: thread_state_t,
    _old_state_count: mach_msg_type_number_t,
    _new_state: thread_state_t,
    _new_state_count: *mut mach_msg_type_number_t,
) -> kern_return_t {
    MACH_RCV_INVALID_TYPE
}

#[no_mangle]
extern "C" fn catch_mach_exception_raise_state_identity(
    _exception_port: mach_port_t,
    _thread_port: mach_port_t,
    _task_port: mach_port_t,
    _exception: exception_type_t,
    _code: mach_exception_data_t,
    _code_count: mach_msg_type_number_t,
    _flavor: *mut i32,
    _old_state: thread_state_t,
    _old_state_count: mach_msg_type_number_t,
    _new_state: thread_state_t,
    _new_state_count: *mut mach_msg_type_number_t,
) -> kern_return_t {
    MACH_RCV_INVALID_TYPE
}
