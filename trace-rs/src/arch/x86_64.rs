//! This module provides code specific to the x86-64 architecture.

use crate::error::Error;

/// Represents the general-purpose registers of the x86-64 architecture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Register {
    /// The accumulator register.
    Rax,
    /// The counter register.
    Rcx,
    /// The data register.
    Rdx,
    /// The base register.
    Rbx,
    /// The stack pointer register.
    Rsp,
    /// The base pointer register.
    Rbp,
    /// The source index register.
    Rsi,
    /// The destination index register.
    Rdi,
    /// The R8 register.
    R8,
    /// The R9 register.
    R9,
    /// The R10 register.
    R10,
    /// The R11 register.
    R11,
    /// The R12 register.
    R12,
    /// The R13 register.
    R13,
    /// The R14 register.
    R14,
    /// The R15 register.
    R15,
    /// The instruction pointer register.
    Rip,
    /// The status register.
    Rflags,
}

/// Extends [`crate::Tracee`] with functions to access architecture-specific registers.
pub trait CpuRegs {
    /// Gets the general-purpose registers specified by the array of [`Register`]s.
    fn get_registers(
        &self,
        registers: &[Register],
    ) -> Result<Vec<u64>, Error>;

    /// Sets the general-purpose registers specified by the array of [`Register`]s to the
    /// corresponding values.
    fn set_registers(
        &mut self,
        register: &[Register],
        values: &[u64],
    ) -> Result<(), Error>;
}
