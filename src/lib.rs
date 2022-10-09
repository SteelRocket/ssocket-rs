#![no_std]

mod public;
pub use public::*;

#[cfg(windows)]
#[path = "sys/windows.rs"]
mod sys;

#[cfg(unix)]
#[path = "sys/unix.rs"]
mod sys;

pub use sys::*;
