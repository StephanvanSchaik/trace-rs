use crate::{Event, Tracee};
use mach2::boolean::boolean_t;
use mach2::exception_types::*;
use mach2::kern_return::{kern_return_t, KERN_SUCCESS};
use mach2::mach_types::{exception_port_t, task_t};
use mach2::message::{mach_msg, mach_msg_body_t, mach_msg_header_t, mach_msg_port_descriptor_t, mach_msg_type_number_t, MACH_RCV_INVALID_TYPE, MACH_RCV_LARGE, MACH_RCV_MSG, MACH_RCV_TIMEOUT};
use mach2::port::{mach_port_t, MACH_PORT_NULL};
use mach2::task::{task_resume, task_suspend};
use mach2::thread_act::{thread_get_state, thread_set_state, thread_suspend};
use mach2::thread_status::thread_state_t;
use mach2::vm_types::integer_t;
use nix::unistd::Pid;
use std::cell::RefCell;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::SyncSender;
use std::thread_local;

extern "C" {
    pub fn mach_exc_server(
        request: *const mach_msg_header_t,
        reply: *mut mach_msg_header_t,
    ) -> boolean_t;
    pub fn pid_for_task(
        task: task_t,
        pid: *mut libc::c_int,
    );
}

thread_local! {
    static EVENT: RefCell<Option<(Tracee, Event)>> = RefCell::new(None);
}

#[cfg(target_arch = "x86_64")]
pub(crate) fn set_single_step(thread_port: mach_port_t, enabled: bool) {
    use mach2::thread_status::x86_THREAD_STATE64;
    use mach2::structs::x86_thread_state64_t;

    let mut state = x86_thread_state64_t::new();
    let mut state_count = x86_thread_state64_t::count();

    unsafe {
        thread_get_state(
            thread_port,
            x86_THREAD_STATE64,
            std::mem::transmute(&mut state),
            &mut state_count,
        );
    }

    if enabled {
        state.__rflags |= 1 << 8;
    } else {
        state.__rflags &= !(1 << 8);
    }

    unsafe {
        thread_set_state(
            thread_port,
            x86_THREAD_STATE64,
            std::mem::transmute(&state),
            state_count,
        )
    };
}

#[cfg(target_arch = "aarch64")]
pub(crate) fn set_single_step(thread_port: mach_port_t, enabled: bool) {
    use mach2::thread_status::ARM_DEBUG_STATE64;
    use super::structs::arm_debug_state64_t;

    let mut state = arm_debug_state64_t::new();
    let mut state_count = arm_debug_state64_t::count();

    unsafe {
        thread_get_state(
            thread_port,
            ARM_DEBUG_STATE64,
            std::mem::transmute(&mut state),
            &mut state_count,
        );
    }

    if enabled {
        state.__mdscr_el1 |= 1 << 0;
    } else {
        state.__mdscr_el1 &= !(1 << 0);
    }

    unsafe {
        thread_set_state(
            thread_port,
            ARM_DEBUG_STATE64,
            std::mem::transmute(&state),
            state_count,
        )
    };
}

#[no_mangle]
extern "C" fn catch_mach_exception_raise(
    _exception_port: mach_port_t,
    thread_port: mach_port_t,
    task_port: mach_port_t,
    exception_type: exception_type_t,
    codes: mach_exception_data_t,
    num_codes: mach_msg_type_number_t,
) -> kern_return_t {
    let codes = unsafe {
        std::slice::from_raw_parts(codes, num_codes as _)
    };

    // Look up the PID for the task.
    let mut pid: libc::c_int = 0;

    unsafe {
        pid_for_task(task_port, &mut pid)
    };

    // Construct the tracee.
    let tracee = Tracee {
        task: task_port,
        thread: thread_port,
        pid: Pid::from_raw(pid),
        reply: None,
    };

    match exception_type as _ {
        EXC_SOFTWARE => {
            match codes.get(0).map(|v| *v).unwrap_or(0) as _ {
                EXC_SOFT_SIGNAL => {
                    let _signal = codes.get(1).map(|v| *v).unwrap_or(0) as i32;

                    EVENT.with(|e| {
                        *e.borrow_mut() = Some((tracee, Event::CreateProcess));
                    });
                }
                _ => (),
            }
        }
        EXC_BREAKPOINT => {
            let event = if codes[1] == 0 {
                set_single_step(thread_port, false);
                Event::SingleStep
            } else {
                Event::Breakpoint
            };

            EVENT.with(|e| {
                *e.borrow_mut() = Some((tracee, event));
            });
        }
        _ => (),
    }

    KERN_SUCCESS
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

// This is the definition from osfmk/mach/arm/exception.h and osfmk/mach/i386/exception.h.
pub const EXCEPTION_CODE_MAX: usize = 2;

// This is the definition from osfmk/mach/ndr.h.
#[derive(Debug)]
#[repr(C)]
pub struct NDR_record_t {
    pub mig_vers: u8,
    pub if_vers: u8,
    pub _0: u8,
    pub mig_encoding: u8,
    pub int_rep: u8,
    pub char_rep: u8,
    pub float_rep: u8,
    pub _1: u8,
}

#[derive(Debug)]
#[repr(C)]
pub struct exception_message_t {
    pub header: mach_msg_header_t,
    pub body: mach_msg_body_t,
    pub thread: mach_msg_port_descriptor_t,
    pub task: mach_msg_port_descriptor_t,
    pub ndr: NDR_record_t,
    pub exception: exception_type_t,
    pub code_count: mach_msg_type_number_t,
    pub code: [integer_t; EXCEPTION_CODE_MAX],
    pub padding: [u8; 512],
}

pub(crate) fn receive_mach_msgs(
    exception_port: exception_port_t,
    run: Arc<AtomicBool>,
    tx: Arc<SyncSender<(Tracee, Event)>>,
) {
    while run.load(Ordering::Relaxed) {
        let mut msg: exception_message_t = unsafe { std::mem::zeroed() };
        let mut reply: exception_message_t = unsafe { std::mem::zeroed() };

        // Wait for a message on the exception port.
        let result = unsafe {
            mach_msg(
                &mut msg.header,
                MACH_RCV_MSG | MACH_RCV_LARGE | MACH_RCV_TIMEOUT,
                0,
                std::mem::size_of::<exception_message_t>() as _,
                exception_port,
                1,
                MACH_PORT_NULL,
            )
        };

        let task = msg.task.name;

        // Suspend the task.
        unsafe {
            task_suspend(task)
        };

        // Resume the task and try again.
        if result != KERN_SUCCESS {
            unsafe {
                task_resume(task)
            };

            continue;
        }

        // Process the exception.
        unsafe {
            mach_exc_server(&msg.header, &mut reply.header)
        };

        // Take the event from the exception handler.
        let event = EVENT.with(|event| {
            event.borrow_mut().take()
        });

        // Send the event.
        if let Some(mut event) = event {
            // Store the reply for when the thread gets resumed.
            event.0.reply = Some(reply);

            // Suspend the thread so we can resume the task.
            unsafe {
                thread_suspend(event.0.thread);
            }

            tx.send(event).unwrap();
        }

        // Resume the task.
        unsafe {
            task_resume(task);
        }
    }
}
