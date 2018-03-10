//! Implementation of the [box-stream](https://github.com/dominictarr/pull-box-stream)
//! encryption protocol. This crate provides structs which wrap (async) readers and/or
//! writers, decrypting all reads and encrypting all writes.

#![deny(missing_docs)]

extern crate libc;
extern crate sodiumoxide;
#[macro_use]
extern crate futures_core;
extern crate futures_io;

pub mod crypto;
mod box_writer;
mod box_reader;
mod box_duplex;
mod decryptor;
mod encryptor;

pub use decryptor::{UNAUTHENTICATED_EOF, INVALID_LENGTH, UNAUTHENTICATED_HEADER,
                    UNAUTHENTICATED_PACKET};

pub use box_writer::*;
pub use box_reader::*;
pub use box_duplex::*;

#[cfg(test)]
extern crate async_ringbuffer;
#[cfg(test)]
extern crate atm_io_utils;
#[cfg(test)]
extern crate futures;

#[cfg(test)]
mod test;
