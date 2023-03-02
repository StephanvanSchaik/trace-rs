# trace-rs

[![CI](https://github.com/StephanvanSchaik/trace-rs/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/StephanvanSchaik/trace-rs/actions/workflows/ci.yml)

A cross-platform and safe Rust API to trace other processes using [`ptrace`](https://man7.org/linux/man-pages/man2/ptrace.2.html) and [the Windows debugging API](https://docs.microsoft.com/en-us/windows/win32/debug/debugging-functions).
More specifically, with trace-rs you can spawn a process and immediately trace and debug it, or attach to an already running process.
You can then follow and control the execution of the process as well as examine and change its memory and registers similar to debugging tools like gdb, lldb and the Windows Debugger, except by programming it in Rust.

## Supported Platforms

 * `x86_64-pc-windows-msvc`
 * `x86_64-unknown-linux-gnu`
 * `x86_64-apple-darwin`
 * `aarch64-apple-darwin`
