use crate::{Error, Event, Tracee};
use nix::{
    sys::event::*,
    sys::ptrace,
    unistd::{getpid, Pid, pipe, read, write},
};
use std::collections::{HashMap, HashSet};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command};
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, Sender, SyncSender};
use std::thread::JoinHandle;
use super::tracee::TraceeData;

fn poll_events(
    tx: Arc<SyncSender<(Tracee, Event)>>,
    wakeup_rx: RawFd,
    event_rx: Receiver<Pid>,
) -> Result<(), Error> {
    let kq = kqueue()?;
    let mut pids: HashSet<Pid> = HashSet::new();

    loop {
        let mut events = vec![];
        let mut new_events = vec![];

        let event = KEvent::new(
            wakeup_rx.as_raw_fd() as _,
            EventFilter::EVFILT_READ,
            EventFlag::EV_ADD | EventFlag::EV_ONESHOT,
            FilterFlag::empty(),
            0,
            0,
        );

        events.push(event.clone());
        new_events.push(event);

        for pid in &pids {
            let event = KEvent::new(
                pid.as_raw() as _,
                EventFilter::EVFILT_PROC,
                EventFlag::EV_ADD | EventFlag::EV_ONESHOT,
                FilterFlag::NOTE_EXIT,
                0,
                0,
            );

            events.push(event.clone());
            new_events.push(event);
        }

        let count = kevent(kq, &events, &mut new_events, 0)?;

        for event in &new_events[..count] {
            match event.filter()? {
                EventFilter::EVFILT_READ => {
                    let mut bytes = [0u8; 1];
                    read(wakeup_rx, &mut bytes)?;

                    while let Ok(pid) = event_rx.try_recv() {
                        pids.insert(pid);
                    }
                },
                EventFilter::EVFILT_PROC => {
                    let pid = Pid::from_raw(event.ident() as _);
                    pids.remove(&pid);

                    let tracee = Tracee {
                        thread: 0,
                        pid,
                    };

                    tx.send((tracee, Event::ExitProcess {
                        child: None,
                        status: event.data() as _,
                    })).unwrap();
                }
                _ => (),
            }
        }
    }
}

#[derive(Debug)]
pub struct Tracer {
    children: HashMap<Pid, Child>,
    data: HashMap<Pid, TraceeData>,
    rx: Receiver<(Tracee, Event)>,
    tx: Arc<SyncSender<(Tracee, Event)>>,
    _thread: JoinHandle<Result<(), Error>>,
    wakeup_tx: RawFd,
    event_tx: Sender<Pid>,
}

impl Tracer {
    /// Construct a new tracer.
    pub fn new() -> Self {
        let (tx, rx) = mpsc::sync_channel(1);
        let tx = Arc::new(tx);
        let (wakeup_rx, wakeup_tx) = pipe().unwrap();
        let (event_tx, event_rx) = mpsc::channel();

        // Set up the kqueue thread.
        let moved_tx = tx.clone();
        let thread = std::thread::spawn(move || poll_events(moved_tx, wakeup_rx, event_rx));

        Self {
            children: HashMap::new(),
            data: HashMap::new(),
            rx,
            tx,
            _thread: thread,
            wakeup_tx,
            event_tx,
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

        // Send the PID to monitor using kqueue.
        self.event_tx.send(pid).unwrap();
        write(self.wakeup_tx, &[0])?;

        // Signal that the exception port is set up.
        write(tx, &[0])?;

        // Wait for the thread to finish and keep track of the spawned child.
        let child = thread.join().unwrap()?;
        self.children.insert(pid, child);

        Ok(())
    }

    /// Attaches the tracer to the process with the given process ID.
    pub fn attach(&mut self, process_id: u32) -> Result<(), Error> {
        let pid = Pid::from_raw(process_id as _);

        // Set up the exception port.
        let data = TraceeData::new(pid, self.tx.clone())?;
        self.data.insert(pid, data);

        let result = unsafe {
            libc::ptrace(
                libc::PT_ATTACHEXC,
                process_id as _,
                std::ptr::null_mut(),
                0,
            )
        };

        if result != 0 {
            Err(nix::Error::from_i32(result))?;
        }

        Ok(())
    }

    /// Waits for an event from any of the processes that are currently being traced.
    pub fn wait(&mut self) -> Result<(Tracee, Event), Error> {
        let (tracee, event) = self.rx.recv().unwrap();

        let event = match event {
            Event::ExitProcess { status, .. } => {
                let child = self.children.remove(&tracee.pid);

                Event::ExitProcess { child, status }
            },
            _ => event,
        };

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

    /// Step through the traced process.
    pub fn step(&mut self, tracee: Tracee) -> Result<(), Error> {
        unsafe {
            libc::ptrace(
                libc::PT_THUPDATE,
                tracee.pid.into(),
                tracee.thread as _,
                0,
            );
        }

        super::exceptions::set_single_step(tracee.thread, true);

        if let Some(data) = self.data.get(&tracee.pid) {
            data.tx.send(()).unwrap();
        }

        Ok(())
    }
}
