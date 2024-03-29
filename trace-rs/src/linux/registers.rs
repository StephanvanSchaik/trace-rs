use crate::{Error, Tracee};
use nix::sys::ptrace;
use super::tracer::ChildState;

#[cfg(target_arch = "x86_64")]
use crate::arch::x86_64::{CpuRegs, Register};

#[cfg(target_arch = "x86_64")]
impl CpuRegs for Tracee {
    fn get_registers(
        &self,
        registers: &[Register],
    ) -> Result<Vec<u64>, Error> {
        let context = ptrace::getregs(self.pid)?;

        Ok(registers
            .into_iter()
            .map(|register| match register {
                Register::Rax => if self.state == ChildState::BeforeSystemCall {
                    context.orig_rax
                } else {
                    context.rax
                }
                Register::Rcx => context.rcx,
                Register::Rdx => context.rdx,
                Register::Rbx => context.rbx,
                Register::Rsp => context.rsp,
                Register::Rbp => context.rbp,
                Register::Rsi => context.rsi,
                Register::Rdi => context.rdi,
                Register::R8 => context.r8,
                Register::R9 => context.r9,
                Register::R10 => context.r10,
                Register::R11 => context.r11,
                Register::R12 => context.r12,
                Register::R13 => context.r13,
                Register::R14 => context.r14,
                Register::R15 => context.r15,
                Register::Rip => context.rip,
                Register::Rflags => context.eflags,
            })
            .collect())
    }

    fn set_registers(
        &mut self,
        registers: &[Register],
        values: &[u64],
    ) -> Result<(), Error> {
        let mut context = ptrace::getregs(self.pid)?;

        for (register, value) in registers.into_iter().zip(values.into_iter()) {
            match register {
                Register::Rax => if self.state == ChildState::BeforeSystemCall {
                    context.orig_rax = *value;
                } else {
                    context.rax = *value;
                },
                Register::Rcx => context.rcx = *value,
                Register::Rdx => context.rdx = *value,
                Register::Rbx => context.rbx = *value,
                Register::Rsp => context.rsp = *value,
                Register::Rbp => context.rbp = *value,
                Register::Rsi => context.rsi = *value,
                Register::Rdi => context.rdi = *value,
                Register::R8 => context.r8 = *value,
                Register::R9 => context.r9 = *value,
                Register::R10 => context.r10 = *value,
                Register::R11 => context.r11 = *value,
                Register::R12 => context.r12 = *value,
                Register::R13 => context.r13 = *value,
                Register::R14 => context.r14 = *value,
                Register::R15 => context.r15 = *value,
                Register::Rip => context.rip = *value,
                Register::Rflags => context.eflags = *value,
            }
        }

        ptrace::setregs(self.pid, context)?;

        Ok(())
    }
}
