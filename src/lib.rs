extern crate libc;
extern crate sodiumoxide;

pub mod crypto;
pub mod box_writer;
pub mod box_reader;

pub use box_writer::*;
pub use box_reader::*;

#[cfg(test)]
mod test;

// TODO add duplex stream
// TODO add async wrappers
