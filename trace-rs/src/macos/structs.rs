use mach2::message::mach_msg_type_number_t;

#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Hash, PartialOrd, PartialEq, Eq, Ord)]
pub struct x86_debug_state64_t {
    pub __dr0: u64,
    pub __dr1: u64,
    pub __dr2: u64,
    pub __dr3: u64,
    pub __dr4: u64,
    pub __dr5: u64,
    pub __dr6: u64,
    pub __dr7: u64,
}

#[cfg(target_arch = "x86_64")]
impl x86_debug_state64_t {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn count() -> mach_msg_type_number_t {
        (std::mem::size_of::<Self>() / std::mem::size_of::<libc::c_int>()) as mach_msg_type_number_t
    }
}

#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Hash, PartialOrd, PartialEq, Eq, Ord)]
pub struct arm_debug_state64_t {
    pub __bvr: [u64; 16],
    pub __bcr: [u64; 16],
    pub __wvr: [u64; 16],
    pub __wcr: [u64; 16],
    pub __mdscr_el1: u64,
}

#[cfg(target_arch = "aarch64")]
impl arm_debug_state64_t {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn count() -> mach_msg_type_number_t {
        (std::mem::size_of::<Self>() / std::mem::size_of::<libc::c_int>()) as mach_msg_type_number_t
    }
}
