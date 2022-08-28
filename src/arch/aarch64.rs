//! This module provides code specific to the AArch64 architecture.

use crate::error::Error;

/// Represents the general-purpose registers of the AArch64 architecture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Register {
    /// A general-purpose register.
    X(usize),
    /// The program counter register.
    Pc,
    /// The stack pointer register.
    Sp,
    /// The processor state register.
    Pstate,
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
