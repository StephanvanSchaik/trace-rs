use std::path::PathBuf;
use std::process::Child;

/// The debug event triggered by the traced process.
#[derive(Debug)]
pub enum Event {
    /// A new process was created.
    CreateProcess,
    /// The process has exited.
    ExitProcess {
        child: Option<Child>,
        status: i32,
    },
    /// A new thread was created.
    CreateThread,
    /// The thread has exited.
    ExitThread,
    /// The process loaded a different executable.
    Execute {
        path: PathBuf,
    },
    /// A shared library was loaded.
    LoadLibrary {
        base: usize,
    },
    /// A shared library was unloaded.
    UnloadLibrary {
        base: usize,
    },
    /// The process yielded debug output.
    Output(String),
    /// A breakpoint was triggered.
    Breakpoint(usize),
    /// The traced process has performed a single step.
    SingleStep,
    /// The traced process is about to invoke a system call.
    BeforeSystemCall(usize),
    /// The traced process invoked a system call.
    AfterSystemCall(usize),
    /// The process triggered an exception.
    Exception(u32),
}
