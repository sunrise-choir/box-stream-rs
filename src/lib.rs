extern crate libc;
extern crate sodiumoxide;

pub mod crypto;
mod impl_writing;
mod impl_reading;
pub mod box_writer;
pub mod box_reader;
pub mod box_duplex;

pub use box_writer::*;
pub use box_reader::*;

#[cfg(test)]
mod test;

// TODO add async wrappers
