use crate::{Error, Tracee, Tracer};
use nix::sys::ptrace;
use super::tracer::ChildState;

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
        let mut bytes = [0u8; 2];
        tracee.read_memory(rip as _, &mut bytes)?;
        tracee.write_memory(rip as _, &[0x0f, 0x05])?;

        // Prepare the system call number and argument registers.
        let mut registers = vec![Register::Rax];
        let mut values = vec![num as _];

        for (register, value) in [Register::Rdi, Register::Rsi, Register::Rdx, Register::Rcx, Register::R8, Register::R9].into_iter().zip(args.into_iter()) {
            registers.push(register);
            values.push(*value as _);
        }

        tracee.set_registers(&registers, &values)?;

        // Issue the system call.
        self.until_syscall(tracee)?;
        tracee = self.wait()?.0;

        let (tracee, result) = match tracee.state {
            // If we get the syscall-exit-stop event after issuing the system call twice, it means
            // we were already processing a syscall-enter-stop event. In this case, we capture the
            // system call result, restore the original instruction and checkpoint state and issue
            // the system call again to ensure we are back in the syscall-enter-stop event 
            ChildState::AfterSystemCall => {
                // Get the result.
                let result = tracee.get_registers(&[Register::Rax])?[0];

                // Restore the original instruction.
                tracee.write_memory(rip as _, &bytes)?;

                // Restore the checkpoint.
                ptrace::setregs(tracee.pid, regs)?;

                // Issue the system call.
                self.until_syscall(tracee)?;
                tracee = self.wait()?.0;

                (tracee, result)
            }
            // Otherwise, we should be in the syscall-enter-stop event for sure. In this case, we
            // complete the system call to reach the syscall-exit-stop state, capture the system
            // call result and restore the original instruction and checkpoint state.
            _ => {
                // Issue the system call.
                self.until_syscall(tracee)?;
                tracee = self.wait()?.0;

                // Get the result.
                let result = tracee.get_registers(&[Register::Rax])?[0];

                // Restore the original instruction.
                tracee.write_memory(rip as _, &bytes)?;

                // Restore the checkpoint.
                ptrace::setregs(tracee.pid, regs)?;

                (tracee, result)
            }
        };

        Ok((tracee, result as usize))
    }
}
