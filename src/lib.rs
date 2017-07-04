extern crate libc;
extern crate sodiumoxide;

use std::io;
use std::io::Write;

pub mod crypto;
pub mod boxer;
pub mod unboxer;

pub use boxer::*;
pub use unboxer::*;

#[cfg(test)]
mod test;

/// Common interface for writable streams which encrypt all bytes using box-stream.
pub trait BoxWriter: Write {
    /// Tries to write a final header, indicating the end of the connection.
    /// This will flush all internally buffered data before writing the header.
    /// After this has returned `Ok(())`, no further methods of the `BoxWriter`
    /// may be called.
    fn shutdown(&mut self) -> io::Result<()>;
}
