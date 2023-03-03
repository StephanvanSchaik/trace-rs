use crate::{Error, Tracee};
use mach2::thread_act::{thread_get_state, thread_set_state};

#[cfg(target_arch = "x86_64")]
use crate::arch::x86_64::{CpuRegs, Register};

#[cfg(target_arch = "x86_64")]
impl CpuRegs for Tracee {
    fn get_registers(
        &self,
        registers: &[Register],
    ) -> Result<Vec<u64>, Error> {
        use mach2::thread_status::x86_THREAD_STATE64;
        use mach2::structs::x86_thread_state64_t;

        let mut state = x86_thread_state64_t::new();
        let mut state_count = x86_thread_state64_t::count();

        unsafe {
            thread_get_state(
                self.thread,
                x86_THREAD_STATE64,
                std::mem::transmute(&mut state),
                &mut state_count,
            )
        };

        let mut values = vec![];

        for register in registers {
            let value = match register {
                Register::Rax => state.__rax,
                Register::Rcx => state.__rcx,
                Register::Rdx => state.__rdx,
                Register::Rbx => state.__rbx,
                Register::Rsp => state.__rsp,
                Register::Rbp => state.__rbp,
                Register::Rsi => state.__rsi,
                Register::Rdi => state.__rdi,
                Register::R8 => state.__r8,
                Register::R9 => state.__r9,
                Register::R10 => state.__r10,
                Register::R11 => state.__r11,
                Register::R12 => state.__r12,
                Register::R13 => state.__r13,
                Register::R14 => state.__r14,
                Register::R15 => state.__r15,
                Register::Rip => state.__rip,
                Register::Rflags => state.__rflags,
            };
            values.push(value);
        }

        Ok(values)
    }

    fn set_registers(
        &mut self,
        registers: &[Register],
        values: &[u64],
    ) -> Result<(), Error> {
        use mach2::thread_status::x86_THREAD_STATE64;
        use mach2::structs::x86_thread_state64_t;

        let mut state = x86_thread_state64_t::new();
        let mut state_count = x86_thread_state64_t::count();

        unsafe {
            thread_get_state(
                self.thread,
                x86_THREAD_STATE64,
                std::mem::transmute(&mut state),
                &mut state_count,
            )
        };

        for (register, value) in registers.iter().zip(values) {
            match register {
                Register::Rax => state.__rax = *value,
                Register::Rcx => state.__rcx = *value,
                Register::Rdx => state.__rdx = *value,
                Register::Rbx => state.__rbx = *value,
                Register::Rsp => state.__rsp = *value,
                Register::Rbp => state.__rbp = *value,
                Register::Rsi => state.__rsi = *value,
                Register::Rdi => state.__rdi = *value,
                Register::R8 => state.__r8 = *value,
                Register::R9 => state.__r9 = *value,
                Register::R10 => state.__r10 = *value,
                Register::R11 => state.__r11 = *value,
                Register::R12 => state.__r12 = *value,
                Register::R13 => state.__r13 = *value,
                Register::R14 => state.__r14 = *value,
                Register::R15 => state.__r15 = *value,
                Register::Rip => state.__rip = *value,
                Register::Rflags => state.__rflags = *value,
            };
        }

        unsafe {
            thread_set_state(
                self.thread,
                x86_THREAD_STATE64,
                std::mem::transmute(&state),
                state_count,
            )
        };

        Ok(())
    }
}

#[cfg(target_arch = "aarch64")]
use crate::arch::aarch64::{CpuRegs, Register};

#[cfg(target_arch = "aarch64")]
impl CpuRegs for Tracee {
    fn get_registers(
        &self,
        registers: &[Register],
    ) -> Result<Vec<u64>, Error> {
        use mach2::thread_status::ARM_THREAD_STATE64;
        use mach2::structs::arm_thread_state64_t;

        let mut state = arm_thread_state64_t::new();
        let mut state_count = arm_thread_state64_t::count();

        unsafe {
            thread_get_state(
                self.thread,
                ARM_THREAD_STATE64,
                std::mem::transmute(&mut state),
                &mut state_count,
            )
        };

        let mut values = vec![];

        for register in registers {
            let value = match register {
                Register::X(index) => state.__x[*index],
                Register::Fp => state.__fp,
                Register::Lr => state.__lr,
                Register::Sp => state.__sp,
                Register::Pc => state.__pc,
                Register::Pstate => state.__cpsr as u64,
            };
            values.push(value);
        }

        Ok(values)
    }

    fn set_registers(
        &mut self,
        registers: &[Register],
        values: &[u64],
    ) -> Result<(), Error> {
        use mach2::thread_status::ARM_THREAD_STATE64;
        use mach2::structs::arm_thread_state64_t;

        let mut state = arm_thread_state64_t::new();
        let mut state_count = arm_thread_state64_t::count();

        unsafe {
            thread_get_state(
                self.thread,
                ARM_THREAD_STATE64,
                std::mem::transmute(&mut state),
                &mut state_count,
            )
        };

        for (register, value) in registers.iter().zip(values) {
            match register {
                Register::X(index) => state.__x[*index] = *value,
                Register::Fp => state.__fp = *value,
                Register::Lr => state.__lr = *value,
                Register::Sp => state.__sp = *value,
                Register::Pc => state.__pc = *value,
                Register::Pstate => state.__cpsr = *value as u32,
            };
        }

        unsafe {
            thread_set_state(
                self.thread,
                ARM_THREAD_STATE64,
                std::mem::transmute(&state),
                state_count,
            )
        };

        Ok(())
    }
}
