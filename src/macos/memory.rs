use crate::{Error, Protection, Tracee, Tracer};
use mach2::kern_return::KERN_SUCCESS;
use mach2::vm::{mach_vm_allocate, mach_vm_deallocate, mach_vm_protect, mach_vm_read_overwrite, mach_vm_region, mach_vm_write};
use mach2::vm_prot::{VM_PROT_COPY, VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE};
use mach2::vm_region::VM_REGION_BASIC_INFO_64;
use mach2::vm_region::{vm_region_info_t, vm_region_basic_info_64};
use mach2::vm_types::mach_vm_address_t;
use std::ops::Range;

impl Tracer {
    /// Maps memory in the virtual address space of the traced process. Returns the virtual address
    /// of the new memory range that was allocated.
    pub fn map_memory(
        &mut self,
        tracee: Tracee,
        size: usize,
        protection: Protection,
    ) -> Result<(Tracee, usize), Error> {
        let mut flags = 0;

        if protection.contains(Protection::READ) {
            flags |= VM_PROT_READ;
        }

        if protection.contains(Protection::WRITE) {
            flags |= VM_PROT_WRITE;
        }

        if protection.contains(Protection::EXECUTE) {
            flags |= VM_PROT_EXECUTE;
        }

        let mut address = 0;

        let result = unsafe {
            mach_vm_allocate(
                tracee.task,
                &mut address,
                size as _,
                flags,
            )
        };

        if result != KERN_SUCCESS {
            return Err(Error::Mach(result));
        }

        Ok((tracee, address as _))
    }

    /// Unmaps the specified range from the virtual address space of the traced process.
    pub fn unmap_range(
        &mut self,
        tracee: Tracee,
        range: Range<usize>,
    ) -> Result<Tracee, Error> {
        let result = unsafe {
            mach_vm_deallocate(
                tracee.task,
                range.start as _,
                range.len() as _,
            )
        };

        if result != KERN_SUCCESS {
            return Err(Error::Mach(result));
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
        let mut flags = 0;

        if protection.contains(Protection::READ) {
            flags |= VM_PROT_READ;
        }

        if protection.contains(Protection::WRITE) {
            flags |= VM_PROT_WRITE;
        }

        if protection.contains(Protection::EXECUTE) {
            flags |= VM_PROT_EXECUTE;
        }

        let result = unsafe {
            mach_vm_protect(
                tracee.task,
                range.start as _,
                range.len() as _,
                false as _,
                flags,
            )
        };

        if result != KERN_SUCCESS {
            return Err(Error::Mach(result));
        }

        Ok(tracee)
    }
}

impl Tracee {
    /// Reads the data at the virtual address from the traced process.
    pub fn read_memory(&self, address: usize, data: &mut [u8]) -> Result<usize, Error> {
        let mut size = 0;

        let result = unsafe {
            mach_vm_read_overwrite(
                self.task,
                address as _,
                data.len() as _,
                data.as_mut_ptr() as _,
                &mut size,
            )
        };

        if result != KERN_SUCCESS {
            return Err(Error::Mach(result));
        }

        Ok(size as _)
    }

    /// Writes the data to the virtual address of the traced process.
    pub fn write_memory(&mut self, address: usize, data: &[u8]) -> Result<usize, Error> {
        let mut start = address as mach_vm_address_t;
        let mut count = 0;
        let mut size = 0;
        let mut info: vm_region_basic_info_64 = unsafe { std::mem::zeroed() };

        while count < data.len() {
            // Query the region to get the region address, size and protection flags.
            let result = unsafe {
                mach_vm_region(
                    self.task,
                    &mut start,
                    &mut size,
                    VM_REGION_BASIC_INFO_64,
                    (&mut info as *mut _) as vm_region_info_t,
                    &mut vm_region_basic_info_64::count(),
                    &mut 0,
                )
            };

            if result != KERN_SUCCESS {
                break;
            }

            // Temporarily elevate the permissions such that we can write to the region.
            let result = unsafe {
                mach_vm_protect(
                    self.task,
                    start,
                    size,
                    false as _,
                    VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY,
                )
            };

            if result != KERN_SUCCESS {
                break;
            }

            // Determine the slice to write.
            let actual_start = start.max(address as _);
            let actual_size = size.saturating_sub(actual_start - start);

            let slice = &data[count..];
            let left = slice.len().min(actual_size as _);
            let slice = &data[..left];

            // Write the data into the traced process.
            let write_result = unsafe {
                mach_vm_write(
                    self.task,
                    actual_start,
                    slice.as_ptr() as _,
                    slice.len() as _,
                )
            };

            // Restore the original permissions of the region.
            let result = unsafe {
                mach_vm_protect(
                    self.task,
                    start,
                    size,
                    false as _,
                    info.protection,
                )
            };

            if result != KERN_SUCCESS {
                return Err(Error::Mach(result));
            }

            if write_result != KERN_SUCCESS {
                break;
            }

            start = start.saturating_add(size as _);
            count += size as usize;
        }

        Ok(count as _)
    }
}
