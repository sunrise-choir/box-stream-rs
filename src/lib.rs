//! Implementation of the [box-stream](https://github.com/dominictarr/pull-box-stream)
//! encryption protocol. This crate provides structs which wrap readers and/or
//! writers, decrypting all reads and encrypting all writes. Also provides
//! wrappers for [tokio](https://tokio.rs/)'s asynchronous readers and writers.

extern crate libc;
extern crate sodiumoxide;

pub mod crypto;
mod impl_writing;
mod impl_reading;
mod box_writer;
mod box_reader;
mod box_duplex;

pub use impl_reading::{FINAL_ERROR, INVALID_LENGTH, UNAUTHENTICATED_HEADER, UNAUTHENTICATED_PACKET};

pub use box_writer::*;
pub use box_reader::*;
pub use box_duplex::*;

#[cfg(test)]
mod test;

// TODO add async wrappers
