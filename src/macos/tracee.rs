use crate::{Error, Event};
use mach2::exception_types::*;
use mach2::kern_return::KERN_SUCCESS;
use mach2::mach_port::{mach_port_allocate, mach_port_deallocate, mach_port_insert_right};
use mach2::mach_types::task_t;
use mach2::message::MACH_MSG_TYPE_MAKE_SEND;
use mach2::port::{mach_port_t, mach_port_name_t, MACH_PORT_RIGHT_RECEIVE};
use mach2::thread_status::{thread_state_flavor_t, THREAD_STATE_NONE};
use mach2::traps::{mach_task_self, task_for_pid};
use nix::unistd::Pid;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::SyncSender;
use std::thread::JoinHandle;
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
pub(crate) struct TraceeData {
    pub(crate) task: task_t,
    exception_port: mach_port_t,
    thread: Option<JoinHandle<()>>,
    pub(crate) run: Arc<AtomicBool>,
}

impl TraceeData {
    pub(crate) fn new(
        pid: Pid,
        tx: Arc<SyncSender<(Tracee, Event)>>,
    ) -> Result<Self, Error> {
        // Get the Mach task for the current PID.
        let mut task: mach_port_name_t = 0;

        let result = unsafe {
            task_for_pid(
                mach_task_self() as mach_port_name_t,
                pid.as_raw(),
                &mut task,
            )
        };

        if result != KERN_SUCCESS {
            return Err(Error::Mach(result));
        }

        // Allocate the exception port.
        let mut exception_port: mach_port_t = 0;

        unsafe {
            mach_port_allocate(
                mach_task_self(),
                MACH_PORT_RIGHT_RECEIVE,
                &mut exception_port,
            )
        };

        // Insert the send right.
        unsafe {
            mach_port_insert_right(
                mach_task_self(),
                exception_port,
                exception_port,
                MACH_MSG_TYPE_MAKE_SEND,
            )
        };

        // Set up the exception port for the task.
        unsafe {
            task_set_exception_ports(
                task,
                EXC_MASK_BAD_ACCESS |
                EXC_MASK_BAD_INSTRUCTION |
                EXC_MASK_ARITHMETIC |
                EXC_MASK_EMULATION |
                EXC_MASK_SOFTWARE |
                EXC_MASK_BREAKPOINT |
                EXC_MASK_SYSCALL |
                EXC_MASK_MACH_SYSCALL,
                exception_port,
                (EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES) as _,
                THREAD_STATE_NONE,
            );
        }

        let run = Arc::new(AtomicBool::new(true));

        let moved_run = run.clone();
        let thread = std::thread::spawn(move || {
            super::exceptions::receive_mach_msgs(exception_port, moved_run, tx);
        });

        Ok(Self {
            task,
            exception_port,
            thread: Some(thread),
            run,
        })
    }
}

impl Drop for TraceeData {
    fn drop(&mut self) {
        self.run.store(false, Ordering::Relaxed);

        if let Some(thread) = self.thread.take() {
            let _ = thread.join().unwrap();
        }

        unsafe {
            mach_port_deallocate(
                mach_task_self(),
                self.exception_port,
            );
        }

        unsafe {
            mach_port_deallocate(
                mach_task_self(),
                self.task,
            );
        }
    }
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
