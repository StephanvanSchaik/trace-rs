use crate::{Error, Event, Protection};
use std::collections::HashMap;
use std::ops::Range;
use std::os::windows::process::CommandExt;
use std::process::{Child, Command};
use widestring::Utf16String;
use windows::Win32::Foundation::*;
use windows::Win32::System::Diagnostics::Debug::*;
use windows::Win32::System::Memory::*;
use windows::Win32::System::Threading::DEBUG_ONLY_THIS_PROCESS;
use windows::Win32::System::WindowsProgramming::INFINITE;

fn bytes_to_string(is_unicode: bool, bytes: &[u8]) -> Result<String, Error> {
    let mut bytes = bytes.to_vec();

    let s = if is_unicode {
        let mut codepoints = vec![];

        for chunk in bytes.chunks(2) {
            let slice = [chunk[0], chunk[1]];
            codepoints.push(u16::from_ne_bytes(slice));
        }

        if let Some(index) = codepoints.iter().position(|c| *c == 0) {
            codepoints.truncate(index); 
        }

        Utf16String::from_vec(codepoints)?.to_string()
    } else {
        if let Some(index) = bytes.iter().position(|c| *c == 0) {
            bytes.truncate(index); 
        }

        String::from_utf8(bytes)?
    };

    Ok(s)
}

/// The tracee is the process that is currently being traced.
#[derive(Debug)]
pub struct Tracee {
    process_id: u32,
    thread_id: u32,
    process: Option<HANDLE>,
    thread: Option<HANDLE>,
}

impl Tracee {
    /// Reads the data at the virtual address from the traced process.
    pub fn read_memory(&self, address: usize, data: &mut [u8]) -> Result<usize, Error> {
        let handle = match self.process {
            Some(handle) => handle,
            _ => return Ok(0),
        };

        let mut bytes_read = 0;

        let status = unsafe {
            ReadProcessMemory(
                handle,
                address as *mut _,
                data.as_mut_ptr() as _,
                data.len(),
                Some(&mut bytes_read),
            )
        }.as_bool();

        if !status {
            return Err(std::io::Error::last_os_error())?;
        }

        Ok(bytes_read)
    }

    /// Writes data at the virtual address to the traced process.
    pub fn write_memory(&self, address: usize, data: &[u8]) -> Result<usize, Error> {
        let handle = match self.process {
            Some(handle) => handle,
            _ => return Ok(0),
        };

        let mut bytes_written = 0;

        let status = unsafe {
            WriteProcessMemory(
                handle,
                address as *mut _,
                data.as_ptr() as _,
                data.len(),
                Some(&mut bytes_written),
            )
        }.as_bool();

        if !status {
            return Err(std::io::Error::last_os_error())?;
        }

        Ok(bytes_written)
    }
}

const CONTEXT_INTEGER: u32 = 1 << 1;

#[cfg(target_arch = "x86_64")]
use windows::Win32::System::SystemServices::CONTEXT_AMD64;

#[cfg(target_arch = "x86_64")]
use crate::arch::x86_64::{CpuRegs, Register};

#[cfg(target_arch = "x86_64")]
impl CpuRegs for Tracee {
    fn get_registers(
        &self,
        registers: &[Register],
    ) -> Result<Vec<u64>, Error> {
        let mut context = CONTEXT::default();

        context.ContextFlags = CONTEXT_AMD64 as u32 | CONTEXT_INTEGER;

        let status = unsafe {
            GetThreadContext(
                self.thread,
                &mut context,
            )
        }.as_bool();

        if !status {
            return Err(std::io::Error::last_os_error())?;
        }

        Ok(registers
            .into_iter()
            .map(|register| match register {
                Register::Rax => context.Rax,
                Register::Rcx => context.Rcx,
                Register::Rdx => context.Rdx,
                Register::Rbx => context.Rbx,
                Register::Rsp => context.Rsp,
                Register::Rbp => context.Rbp,
                Register::Rsi => context.Rsi,
                Register::Rdi => context.Rdi,
                Register::R8 => context.R8,
                Register::R9 => context.R9,
                Register::R10 => context.R10,
                Register::R11 => context.R11,
                Register::R12 => context.R12,
                Register::R13 => context.R13,
                Register::R14 => context.R14,
                Register::R15 => context.R15,
                Register::Rip => context.Rip,
                Register::Rflags => context.EFlags as u64,
            })
            .collect())
    }

    fn set_registers(
        &mut self,
        registers: &[Register],
        values: &[u64],
    ) -> Result<(), Error> {
        let mut context = CONTEXT::default();

        context.ContextFlags = CONTEXT_AMD64 as u32 | CONTEXT_INTEGER;

        let status = unsafe {
            GetThreadContext(
                self.thread,
                &mut context,
            )
        }.as_bool();

        if !status {
            return Err(std::io::Error::last_os_error())?;
        }

        for (register, value) in registers.into_iter().zip(values.into_iter()) {
            match register {
                Register::Rax => context.Rax = *value,
                Register::Rcx => context.Rcx = *value,
                Register::Rdx => context.Rdx = *value,
                Register::Rbx => context.Rbx = *value,
                Register::Rsp => context.Rsp = *value,
                Register::Rbp => context.Rbp = *value,
                Register::Rsi => context.Rsi = *value,
                Register::Rdi => context.Rdi = *value,
                Register::R8 => context.R8 = *value,
                Register::R9 => context.R9 = *value,
                Register::R10 => context.R10 = *value,
                Register::R11 => context.R11 = *value,
                Register::R12 => context.R12 = *value,
                Register::R13 => context.R13 = *value,
                Register::R14 => context.R14 = *value,
                Register::R15 => context.R15 = *value,
                Register::Rip => context.Rip = *value,
                Register::Rflags => context.EFlags = *value as u32,
            }
        }

        let status = unsafe {
            SetThreadContext(
                self.thread,
                &context,
            )
        }.as_bool();

        if !status {
            return Err(std::io::Error::last_os_error())?;
        }

        Ok(())
    }
}

/// The tracer is a collection of processes that are currently being traced.
#[derive(Debug)]
pub struct Tracer {
    children: HashMap<u32, Child>,
    processes: HashMap<u32, HANDLE>,
    threads: HashMap<u32, HANDLE>,
}

impl Tracer {
    /// Construct a new tracer.
    pub fn new() -> Self {
        Self {
            children: HashMap::new(),
            processes: HashMap::new(),
            threads: HashMap::new(),
        }
    }

    /// Returns true if the tracer is tracing any processes.
    pub fn is_tracing(&self) -> bool {
        !self.children.is_empty()
    }

    /// Spawns and traces the process using the provided [`std::process::Command`].
    pub fn spawn(&mut self, mut command: Command) -> Result<(), Error> {
        let child = command
            .creation_flags(DEBUG_ONLY_THIS_PROCESS.0)
            .spawn()?;

        self.children.insert(child.id(), child);

        Ok(())
    }

    /// Attaches the tracer to the process with the given process ID.
    pub fn attach(&mut self, process_id: u32) -> Result<(), Error> {
        let status = unsafe {
            DebugActiveProcess(process_id)
        }.as_bool();

        if !status {
            return Err(std::io::Error::last_os_error())?;
        }

        Ok(())
    }

    /// Waits for an event from any of the processes that are currently being traced.
    pub fn wait(&mut self) -> Result<(Tracee, Event), Error> {
        let mut event = DEBUG_EVENT::default();

        let status = unsafe {
            WaitForDebugEventEx(&mut event, INFINITE)
        }.as_bool();

        if !status {
            return Err(std::io::Error::last_os_error())?;
        }

        match event.dwDebugEventCode {
            CREATE_PROCESS_DEBUG_EVENT => {
                let info = unsafe { event.u.CreateProcessInfo };

                self.processes.insert(event.dwProcessId, info.hProcess);
                self.threads.insert(event.dwThreadId, info.hThread);
            }
            CREATE_THREAD_DEBUG_EVENT => {
                let info = unsafe { event.u.CreateThread };

                self.threads.insert(event.dwThreadId, info.hThread);
            }
            _ => (),
        }

        let tracee = Tracee {
            process_id: event.dwProcessId,
            thread_id: event.dwThreadId,
            process: self.processes.get(&event.dwProcessId).map(|handle| *handle),
            thread: self.threads.get(&event.dwThreadId).map(|handle| *handle),
        };

        let result = match event.dwDebugEventCode {
            CREATE_PROCESS_DEBUG_EVENT => {
                Event::CreateProcess
            }
            EXIT_PROCESS_DEBUG_EVENT => {
                let info = unsafe { event.u.ExitProcess };
                let child = self.children.remove(&event.dwProcessId);

                self.processes.remove(&event.dwProcessId);
                self.threads.remove(&event.dwThreadId);

                unsafe {
                    DebugActiveProcessStop(event.dwProcessId);
                }

                Event::ExitProcess {
                    child,
                    status: info.dwExitCode as _,
                }
            }
            CREATE_THREAD_DEBUG_EVENT => {
                Event::CreateThread
            }
            EXIT_THREAD_DEBUG_EVENT => {
                self.threads.remove(&event.dwThreadId);

                Event::ExitThread
            }
            LOAD_DLL_DEBUG_EVENT => {
                let info = unsafe { event.u.LoadDll };

                Event::LoadLibrary {
                    base: info.lpBaseOfDll as usize,
                }
            }
            UNLOAD_DLL_DEBUG_EVENT => {
                let info = unsafe { event.u.UnloadDll };

                Event::UnloadLibrary {
                    base: info.lpBaseOfDll as usize,
                }
            }
            EXCEPTION_DEBUG_EVENT => {
                let info = unsafe { event.u.Exception };

                match info.ExceptionRecord.ExceptionCode {
                    EXCEPTION_BREAKPOINT => Event::Breakpoint,
                    EXCEPTION_SINGLE_STEP => Event::SingleStep,
                    code => Event::Exception(code.0 as u32),
                }
            }
            OUTPUT_DEBUG_STRING_EVENT => {
                let info = unsafe { event.u.DebugString };

                let size = if info.fUnicode != 0 {
                    2 * info.nDebugStringLength as usize
                } else {
                    info.nDebugStringLength as usize
                };

                let mut bytes = vec![0u8; size];
                tracee.read_memory(info.lpDebugStringData.0 as *mut core::ffi::c_void as usize, &mut bytes)?;
                let s = bytes_to_string(info.fUnicode != 0, &bytes)?;

                Event::Output(s)
            }
            _ => unreachable!(),
        };

        Ok((tracee, result))
    }

    /// Resumes the execution of the traced process.
    pub fn resume(&self, tracee: Tracee) -> Result<(), Error> {
        unsafe {
            ContinueDebugEvent(tracee.process_id, tracee.thread_id, DBG_CONTINUE);
        }

        Ok(())
    }

    /// Step through the traced process.
    pub fn step(&self, mut tracee: Tracee) -> Result<(), Error> {
        #[cfg(target_arch = "x86_64")]
        {
            let mut values = tracee.get_registers(&[Register::Rflags])?;
            values[0] |= 0x100;
            tracee.set_registers(&[Register::Rflags], &values)?;
        }

        self.resume(tracee)?;

        Ok(())
    }

    /// Detach the tracer from the process.
    pub fn detach(&mut self, tracee: Tracee) -> Result<Option<Child>, Error> {
        let child = self.children.remove(&tracee.process_id);
        self.processes.remove(&tracee.process_id);
        self.threads.remove(&tracee.thread_id);

        unsafe {
            DebugActiveProcessStop(tracee.process_id);
        }

        Ok(child)
    }

    /// Maps memory in the virtual address space of the traced process. Returns the virtual address
    /// of the new memory range that was allocated.
    pub fn map_memory(
        &mut self,
        tracee: Tracee,
        size: usize,
        protection: Protection,
    ) -> Result<(Tracee, usize), Error> {
        let protect = if protection.contains(Protection::READ | Protection::WRITE | Protection::EXECUTE) {
            PAGE_EXECUTE_READWRITE
        } else if protection.contains(Protection::READ | Protection::WRITE) {
            PAGE_READWRITE
        } else if protection.contains(Protection::READ | Protection::EXECUTE) {
            PAGE_EXECUTE_READ
        } else if protection.contains(Protection::READ) {
            PAGE_READONLY
        } else if protection.contains(Protection::EXECUTE) {
            PAGE_EXECUTE
        } else {
            return Err(Error::InvalidProtection(protection))
        };

        let result = unsafe {
            VirtualAllocEx(
                tracee.process,
                None,
                size,
                MEM_COMMIT | MEM_RESERVE,
                protect,
            )
        };

        if result.is_null() {
            return Err(std::io::Error::last_os_error())?;
        }

        Ok((tracee, result as usize))
    }

    /// Unmaps the specified range from the virtual address space of the traced process.
    pub fn unmap_range(
        &mut self,
        tracee: Tracee,
        range: Range<usize>,
    ) -> Result<Tracee, Error> {
        let status = unsafe {
            VirtualFreeEx(
                tracee.process,
                range.start as *mut core::ffi::c_void,
                range.len(),
                VIRTUAL_FREE_TYPE(MEM_DECOMMIT.0 | MEM_RELEASE.0),
            )
        }.as_bool();

        if !status {
            return Err(std::io::Error::last_os_error())?;
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
        let mut old_protect = PAGE_PROTECTION_FLAGS::default();
        let protect = if protection.contains(Protection::READ | Protection::WRITE | Protection::EXECUTE) {
            PAGE_EXECUTE_READWRITE
        } else if protection.contains(Protection::READ | Protection::WRITE) {
            PAGE_READWRITE
        } else if protection.contains(Protection::READ | Protection::EXECUTE) {
            PAGE_EXECUTE_READ
        } else if protection.contains(Protection::READ) {
            PAGE_READONLY
        } else if protection.contains(Protection::EXECUTE) {
            PAGE_EXECUTE
        } else {
            return Err(Error::InvalidProtection(protection))
        };

        let status = unsafe {
            VirtualProtectEx(
                tracee.process,
                range.start as *mut core::ffi::c_void,
                range.len(),
                protect,
                &mut old_protect,
            )
        }.as_bool();

        if !status {
            return Err(std::io::Error::last_os_error())?;
        }

        Ok(tracee)
    }
}
