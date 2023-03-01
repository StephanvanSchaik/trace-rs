use crate::{Error, Protection, Tracee, Tracer};
use nix::sys::{
    mman::{MapFlags, ProtFlags},
    uio::{pread, pwrite},
};
use std::ops::Range;
use std::os::unix::io::AsRawFd;
use super::syscall::TracerExt;

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

impl Tracee {
    /// Reads the data at the virtual address from the traced process.
    pub fn read_memory(&self, address: usize, data: &mut [u8]) -> Result<usize, Error> {
        let size = pread(self.file.as_raw_fd(), data, address as _)?;

        Ok(size)
    }

    /// Writes the data to the virtual address of the traced process.
    pub fn write_memory(&mut self, address: usize, data: &[u8]) -> Result<usize, Error> {
        let size = pwrite(self.file.as_raw_fd(), data, address as _)?;

        Ok(size)
    }
}


