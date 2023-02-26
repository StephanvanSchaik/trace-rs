use crate::{Error, Event, Protection};
use nix::sys::ptrace;
use nix::sys::mman::{MapFlags, ProtFlags};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::sys::signal::Signal;
use nix::unistd::Pid;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::ops::Range;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command};

/// The tracee is the process that is currently being traced.
#[derive(Debug)]
pub struct Tracee {
    pub(crate) pid: Pid,
    signal: Option<Signal>,
    #[cfg(target_os = "linux")]
    pub(crate) file: File,
}

impl Tracee {
    /// Returns the process ID.
    pub fn process_id(&self) -> u32 {
        self.pid.as_raw() as _
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ChildState {
    Create,
    Resume,
    Step,
    BeforeSystemCall,
    AfterSystemCall,
}

#[derive(Debug)]
struct ChildInfo {
    child: Option<Child>,
    state: ChildState,
}

/// The tracer is a collection of processes that are currently being traced.
#[derive(Debug)]
pub struct Tracer {
    children: HashMap<Pid, ChildInfo>,
    #[cfg(target_os = "linux")]
    files: HashMap<Pid, File>,
}

impl Tracer {
    /// Construct a new tracer.
    pub fn new() -> Self {
        Self {
            children: HashMap::new(),
            #[cfg(target_os = "linux")]
            files: HashMap::new(),
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
            _ => panic!("should not happen yet"),
        };

        #[cfg(target_os = "linux")]
        let file = match self.files.remove(&pid) {
            Some(file) => file,
            None => OpenOptions::new()
                .read(true)
                .write(true)
                .create(false)
                .open(format!("/proc/{pid}/mem"))?,
        };

        let tracee = Tracee {
            pid,
            signal,
            file,
        };

        match status {
            WaitStatus::Stopped(pid, _) => {
                let event = match self.children.get(&pid) {
                    Some(child) => match child.state {
                        ChildState::Create => {
                            #[cfg(target_os = "linux")]
                            ptrace::setoptions(pid, ptrace::Options::PTRACE_O_TRACESYSGOOD)?;

                            Event::CreateProcess
                        },
                        ChildState::Step => Event::SingleStep,
                        _ => Event::Breakpoint,
                    }
                    None => {
                        self.children.insert(pid, ChildInfo {
                            child: None,
                            state: ChildState::Create,
                        });

                        #[cfg(target_os = "linux")]
                        ptrace::setoptions(pid, ptrace::Options::PTRACE_O_TRACESYSGOOD)?;

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
            status => panic!("{:?}", status),
        }
    }

    /// Resumes the execution of the traced process.
    pub fn resume(&mut self, tracee: Tracee) -> Result<(), Error> {
        if let Some(info) = self.children.get_mut(&tracee.pid) {
            info.state = ChildState::Resume;
        }

        #[cfg(target_os = "linux")]
        self.files.insert(tracee.pid, tracee.file);

        ptrace::cont(tracee.pid, tracee.signal)?;

        Ok(())
    }

    /// Step through the traced process.
    pub fn step(&mut self, tracee: Tracee) -> Result<(), Error> {
        if let Some(info) = self.children.get_mut(&tracee.pid) {
            info.state = ChildState::Step;
        }

        #[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
impl Tracer {
    /// Maps memory in the virtual address space of the traced process. Returns the virtual address
    /// of the new memory range that was allocated.
    pub fn map_memory(
        &mut self,
        tracee: Tracee,
        size: usize,
        protection: Protection,
    ) -> Result<(Tracee, usize), Error> {
        use syscalls::Sysno;

        let mut flags = ProtFlags::empty();

        if protection.contains(Protection::READ) {
            flags |= ProtFlags::PROT_READ;
        }

        if protection.contains(Protection::WRITE) {
            flags |= ProtFlags::PROT_WRITE;
        }

        if protection.contains(Protection::EXECUTE) {
            flags |= ProtFlags::PROT_EXEC;
        }

        let (tracee, result) = self.syscall(
            tracee,
            Sysno::mmap as _,
            &[0, size as _, flags.bits() as _, (MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS).bits() as _, std::usize::MAX, 0],
        )?;

        Ok((tracee, result))
    }

    /// Unmaps the specified range from the virtual address space of the traced process.
    pub fn unmap_range(
        &mut self,
        tracee: Tracee,
        range: Range<usize>,
    ) -> Result<Tracee, Error> {
        use syscalls::Sysno;

        let (tracee, result) = self.syscall(
            tracee,
            Sysno::munmap as _,
            &[range.start as _, range.len() as _],
        )?;

        if result != 0 {
            let errno = nix::errno::Errno::from_i32(result as i32);

            return Err(Error::from(errno));
        }

        Ok(tracee)
    }

    /// Changes the protection of the specified range in the virtual address space of the traced
    /// process.
    pub fn protect_range(
        &mut self,
        tracee: Tracee,
        range: Range<usize>,
        protection: Protection,
    ) -> Result<Tracee, Error> {
        use syscalls::Sysno;

        let mut flags = ProtFlags::empty();

        if protection.contains(Protection::READ) {
            flags |= ProtFlags::PROT_READ;
        }

        if protection.contains(Protection::WRITE) {
            flags |= ProtFlags::PROT_WRITE;
        }

        if protection.contains(Protection::EXECUTE) {
            flags |= ProtFlags::PROT_EXEC;
        }

        let (tracee, result) = self.syscall(
            tracee,
            Sysno::mprotect as _,
            &[range.start as _, range.len() as _, flags.bits() as _],
        )?;

        if result != 0 {
            let errno = nix::errno::Errno::from_i32(result as i32);

            return Err(Error::from(errno));
        }

        Ok(tracee)
    }
}

/// Unix-specific extensions to [`Tracer`].
pub trait TracerExt {
    /// Run the traced process until the next system call.
    fn until_syscall(&mut self, tracee: Tracee) -> Result<(), Error>;

    /// Issue a system call from the traced process.
    fn syscall(&mut self, tracee: Tracee, num: usize, args: &[usize]) -> Result<(Tracee, usize), Error>;
}

#[cfg(target_os = "linux")]
impl TracerExt for Tracer {
    fn until_syscall(&mut self, tracee: Tracee) -> Result<(), Error> {
        if let Some(info) = self.children.get_mut(&tracee.pid) {
            info.state = match info.state {
                ChildState::BeforeSystemCall => ChildState::AfterSystemCall,
                _ => ChildState::BeforeSystemCall,
            };
        }

        #[cfg(target_os = "linux")]
        self.files.insert(tracee.pid, tracee.file);

        ptrace::syscall(tracee.pid, tracee.signal)?;

        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    fn syscall(&mut self, mut tracee: Tracee, num: usize, args: &[usize]) -> Result<(Tracee, usize), Error> {
        use crate::arch::x86_64::{CpuRegs, Register};

        // Store a checkpoint.
        let regs = ptrace::getregs(tracee.pid)?;

        // Write the system call instruction.
        let rip = tracee.get_registers(&[Register::Rip])?[0];
        let mut bytes = [0u8; 3];
        tracee.read_memory(rip as _, &mut bytes)?;
        tracee.write_memory(rip as _, &[0x0f, 0x05, 0xcc])?;

        // Prepare the system call number and argument registers.
        let mut registers = vec![Register::Rax];
        let mut values = vec![num as _];

        for (register, value) in [Register::Rdi, Register::Rsi, Register::Rdx, Register::Rcx, Register::R8, Register::R9].into_iter().zip(args.into_iter()) {
            registers.push(register);
            values.push(*value as _);
        }

        tracee.set_registers(&registers, &values)?;

        // Issue the system call.
        self.resume(tracee)?;
        tracee = self.wait()?.0;

        // Get the result.
        let result = tracee.get_registers(&[Register::Rax])?[0];

        // Restore the original instruction.
        tracee.write_memory(rip as _, &bytes)?;

        // Restore the checkpoint.
        ptrace::setregs(tracee.pid, regs)?;

        Ok((tracee, result as usize))
    }
}
