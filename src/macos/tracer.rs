use crate::{Error, Event, Tracee};
use nix::{
    sys::ptrace,
    unistd::{getpid, Pid, pipe, read, write},
};
use std::collections::HashMap;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command};
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, SyncSender};
use super::tracee::TraceeData;

#[derive(Debug)]
pub struct Tracer {
    children: HashMap<Pid, Child>,
    data: HashMap<Pid, TraceeData>,
    rx: Receiver<(Tracee, Event)>,
    tx: Arc<SyncSender<(Tracee, Event)>>,
}

impl Tracer {
    /// Construct a new tracer.
    pub fn new() -> Self {
        let (tx, rx) = mpsc::sync_channel(1);

        Self {
            children: HashMap::new(),
            data: HashMap::new(),
            rx,
            tx: Arc::new(tx),
        }
    }

    /// Returns true if the tracer is tracing any processes.
    pub fn is_tracing(&self) -> bool {
        !self.children.is_empty()
    }

    /// Spawns and traces the process using the provided [`std::process::Command`].
    pub fn spawn(&mut self, mut command: Command) -> Result<(), Error> {
        let (pid_rx, pid_tx) = pipe()?;
        let (rx, tx) = pipe()?;

        unsafe {
            command.pre_exec(move || {
                // Send the PID.
                write(pid_tx, &i32::to_ne_bytes(getpid().as_raw()))?;

                // Wait until the exception port is set up properly.
                let mut bytes = [0u8; 1];
                read(rx, &mut bytes)?;

                // Set up ptrace.
                ptrace::traceme()?;

                #[cfg(target_os = "macos")]
                libc::ptrace(libc::PT_SIGEXC, 0, std::ptr::null_mut(), 0);

                Ok(())
            });
        }

        // Spawn a thread to handle the process forking, since we need to synchronize the ptrace
        // calls.
        let thread = std::thread::spawn(move || -> Result<Child, Error> {
            let child = command.spawn()?;
            Ok(child)
        });

        // Receive the PID.
        let mut bytes = [0u8; 4];
        read(pid_rx, &mut bytes)?;
        let pid = Pid::from_raw(i32::from_ne_bytes(bytes));

        // Set up the exception port.
        let data = TraceeData::new(pid, self.tx.clone())?;
        self.data.insert(pid, data);

        // Signal that the exception port is set up.
        write(tx, &[0])?;

        // Wait for the thread to finish and keep track of the spawned child.
        let child = thread.join().unwrap()?;
        self.children.insert(pid, child);

        Ok(())
    }

    /// Waits for an event from any of the processes that are currently being traced.
    pub fn wait(&mut self) -> Result<(Tracee, Event), Error> {
        let (tracee, event) = self.rx.recv().unwrap();
        Ok((tracee, event))
    }

    /// Resumes the execution of the traced process.
    pub fn resume(&mut self, tracee: Tracee) -> Result<(), Error> {
        unsafe {
            libc::ptrace(
                libc::PT_THUPDATE,
                tracee.pid.into(),
                tracee.thread as _,
                0,
            );
        }

        if let Some(data) = self.data.get(&tracee.pid) {
            data.tx.send(()).unwrap();
        }

        Ok(())
    }
}
