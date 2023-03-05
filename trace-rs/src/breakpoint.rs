use crate::{Error, Tracee, Tracer};
use std::collections::HashMap;

#[cfg(target_arch = "aarch64")]
pub const BREAKPOINT: &[u8] = &[0x00, 0x00, 0x20, 0xd4];

#[cfg(target_arch = "x86_64")]
pub const BREAKPOINT: &[u8] = &[0xcc];

#[derive(Clone, Copy, Debug, Default)]
pub struct Breakpoint {
    original: [u8; BREAKPOINT.len()],
}

impl Tracer {
    pub fn add_breakpoint(
        &mut self,
        tracee: &mut Tracee,
        address: usize,
    ) -> Result<(), Error> {
        let mut breakpoint = Breakpoint::default();

        tracee.read_memory(address, &mut breakpoint.original)?;
        tracee.write_memory(address, BREAKPOINT)?;

        self.breakpoints.entry(tracee.process_id())
            .and_modify(|breakpoints| {
                breakpoints.insert(address, breakpoint.clone());
            })
            .or_insert(HashMap::from([(address, breakpoint)]));

        Ok(())
    }

    pub fn remove_breakpoint(
        &mut self,
        tracee: &mut Tracee,
        address: usize,
    ) -> Result<(), Error> {
        let breakpoints = match self.breakpoints.get_mut(&tracee.process_id()) {
            Some(breakpoints) => breakpoints,
            _ => return Ok(()),
        };

        let breakpoint = match breakpoints.remove(&address) {
            Some(breakpoint) => breakpoint,
            _ => return Ok(()),
        };

        tracee.write_memory(address, &breakpoint.original)?;

        if breakpoints.is_empty() {
            self.breakpoints.remove(&tracee.process_id());
        }

        Ok(())
    }
}
