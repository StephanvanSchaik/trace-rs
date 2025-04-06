use crate::{Error, Event, Tracee};
use crate::breakpoint::Breakpoint;
use nix::{
    sys::{
        ptrace::{self, Event as PtraceEvent},
        signal::Signal,
        wait::{waitpid, WaitStatus},
    },
    unistd::Pid,
};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ChildState {
    Create,
    Resume,
    Step,
    BeforeSystemCall,
    AfterSystemCall,
}

#[derive(Debug)]
pub(crate) struct ChildInfo {
    pub(crate) child: Option<Child>,
    pub(crate) state: ChildState,
}

/// The tracer is a collection of processes that are currently being traced.
#[derive(Debug)]
pub struct Tracer {
    pub(crate) children: HashMap<Pid, ChildInfo>,
    pub(crate) files: HashMap<Pid, File>,
    pub(crate) breakpoints: HashMap<u32, HashMap<usize, Breakpoint>>,
}

impl Tracer {
    /// Construct a new tracer.
    pub fn new() -> Self {
        Self {
            children: HashMap::new(),
            files: HashMap::new(),
            breakpoints: HashMap::new(),
        }
    }

    /// Returns true if the tracer is tracing any processes.
    pub fn is_tracing(&self) -> bool {
        !self.children.is_empty()
    }

    /// Spawns and traces the process using the provided [`std::process::Command`].
    pub fn spawn(&mut self, mut command: Command) -> Result<(), Error> {
        unsafe {
            command.pre_exec(|| {
                ptrace::traceme()?;

                Ok(())
            });
        }

        let child = command.spawn()?;
        let pid = Pid::from_raw(child.id() as i32);

        self.children.insert(pid, ChildInfo {
            child: Some(child),
            state: ChildState::Create,
        });

        Ok(())
    }

    /// Attaches the tracer to the process with the given process ID.
    pub fn attach(&mut self, process_id: u32) -> Result<(), Error> {
        ptrace::attach(Pid::from_raw(process_id as i32))?;

        Ok(())
    }

    /// Waits for an event from any of the processes that are currently being traced.
    pub fn wait(&mut self) -> Result<(Tracee, Event), Error> {
        let status = waitpid(None, None)?;

        let (pid, signal) = match status {
            WaitStatus::Stopped(pid, signal) => {
                let signal = match signal {
                    Signal::SIGTRAP => None,
                    signal => Some(signal),
                };

                (pid, signal)
            }
            WaitStatus::Exited(pid, _) => {
                (pid, None)
            }
            #[cfg(target_os = "linux")]
            WaitStatus::PtraceSyscall(pid) => {
                (pid, None)
            }
            #[cfg(target_os = "linux")]
            WaitStatus::PtraceEvent(pid, signal, event) => {
                (pid, None)
            }
            _ => panic!("should not happen yet {status:?}"),
        };

        let file = match self.files.remove(&pid) {
            Some(file) => file,
            _ => {
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(false)
                    .open(format!("/proc/{pid}/mem"))?
            }
        };

        let tracee = Tracee {
            pid,
            state: self.children.get(&pid).map(|child| child.state).unwrap_or(ChildState::Create),
            signal,
            file,
        };

        match status {
            WaitStatus::Stopped(pid, _) => {
                let event = match self.children.get(&pid) {
                    Some(child) => match child.state {
                        ChildState::Create => {
                            #[cfg(target_os = "linux")]
                            ptrace::setoptions(pid, ptrace::Options::PTRACE_O_TRACESYSGOOD | ptrace::Options::PTRACE_O_TRACECLONE)?;

                            Event::CreateProcess
                        },
                        ChildState::Step => Event::SingleStep,
                        _ => if signal.is_none() {
                            Event::Breakpoint(0)
                        } else {
                            // FIXME: sigstop?
                            Event::CreateProcess
                        },
                    }
                    None => {
                        self.children.insert(pid, ChildInfo {
                            child: None,
                            state: ChildState::Create,
                        });

                        #[cfg(target_os = "linux")]
                        ptrace::setoptions(pid, ptrace::Options::PTRACE_O_TRACESYSGOOD | ptrace::Options::PTRACE_O_TRACECLONE)?;

                        Event::CreateProcess
                    }
                };

                Ok((tracee, event))
            }
            WaitStatus::Exited(pid, exit_code) => {
                let child = self.children.remove(&pid)
                    .map(|info| info.child)
                    .flatten();

                let event = Event::ExitProcess {
                    child: child,
                    status: exit_code,
                };

                Ok((tracee, event))
            }
            #[cfg(target_os = "linux")]
            WaitStatus::PtraceSyscall(pid) => {
                #[cfg(target_arch = "x86_64")]
                let sysno = {
                    let context = ptrace::getregs(tracee.pid)?;
                    context.orig_rax
                };

                let event = match self.children.get(&pid) {
                    Some(child) => match child.state {
                        ChildState::BeforeSystemCall => Event::BeforeSystemCall(sysno as _),
                        ChildState::AfterSystemCall => Event::AfterSystemCall(sysno as _),
                        _ => unreachable!(),
                    }
                    _ => unreachable!(),
                };

                Ok((tracee, event))
            }
            #[cfg(target_os = "linux")]
            WaitStatus::PtraceEvent(pid, signal, _) => {
                let event = Event::CreateProcess;

                Ok((tracee, event))
            }
            status => panic!("{:?}", status),
        }
    }

    /// Resumes the execution of the traced process.
    pub fn resume(&mut self, tracee: Tracee) -> Result<(), Error> {
        if let Some(info) = self.children.get_mut(&tracee.pid) {
            info.state = ChildState::Resume;
        }

        self.files.insert(tracee.pid, tracee.file);
        ptrace::cont(tracee.pid, tracee.signal)?;

        Ok(())
    }

    /// Step through the traced process.
    pub fn step(&mut self, tracee: Tracee) -> Result<(), Error> {
        if let Some(info) = self.children.get_mut(&tracee.pid) {
            info.state = ChildState::Step;
        }

        self.files.insert(tracee.pid, tracee.file);
        ptrace::step(tracee.pid, tracee.signal)?;

        Ok(())
    }

    /// Detach the tracer from the process.
    pub fn detach(&mut self, tracee: Tracee) -> Result<Option<Child>, Error> {
        let child = match self.children.remove(&tracee.pid) {
            Some(info) => info.child,
            _ => None,
        };

        self.files.remove(&tracee.pid);
        ptrace::detach(tracee.pid, None)?;

        Ok(child)
    }
}
