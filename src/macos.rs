use crate::Error;
use nix::unistd::Pid;

#[derive(Debug)]
pub struct TraceeData;

impl TraceeData {
    pub fn new(pid: Pid) -> Result<Self, Error> {
        Ok(Self)
    }
}
