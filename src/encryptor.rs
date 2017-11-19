use std::io::{Error, Write, ErrorKind};
use std::cmp::min;

use sodiumoxide::crypto::secretbox;
use sodiumoxide::utils::memzero;

use crypto::{CYPHER_HEADER_SIZE, MAX_PACKET_SIZE, MAX_PACKET_USIZE, encrypt_packet, final_header};

const BUFFER_SIZE: usize = CYPHER_HEADER_SIZE + MAX_PACKET_USIZE;

// Implements the base functionality for creating encrypting wrappers around `io::Write`s.
pub struct Encryptor {
    // Bytes are written into this buffer and get encrypted in-place
    buffer: [u8; BUFFER_SIZE],
    state: State,
}

impl Encryptor {
    pub fn new() -> Encryptor {
        Encryptor {
            buffer: [0; BUFFER_SIZE],
            state: Writable,
        }
    }

    // A Write wrapper using the encryptor should delegate to this method in its `write` implementation.
    pub fn write<W: Write>(&mut self,
                           buf: &[u8],
                           writer: &mut W,
                           key: &secretbox::Key,
                           nonce: &mut secretbox::Nonce)
                           -> Result<usize, Error> {
        match self.state {
            Writable => {
                let written = min(buf.len() as u16, MAX_PACKET_SIZE);

                unsafe {
                    encrypt_packet(self.buffer.as_mut_ptr(),
                                   buf.as_ptr(),
                                   written,
                                   &key.0,
                                   &mut nonce.0);
                }

                self.state = WriteInner {
                    offset: 0,
                    length: written,
                };

                return Ok(written as usize);
            }

            WriteInner { offset, length } => {
                debug_assert!(offset < length);
                debug_assert!(length <= BUFFER_SIZE as u16);

                let written = writer.write(&self.buffer[offset as usize..CYPHER_HEADER_SIZE + length as usize])?;

                if written == 0 {
                    return Ok(0);
                } else {
                    if offset + (written as u16) < length {
                        self.state = WriteInner {
                            offset: offset + (written as u16),
                            length: length,
                        };
                    } else {
                        self.state = Writable;
                    }
                }

                return self.write(buf, writer, key, nonce);
            }

            Shutdown { offset } => {
                debug_assert!(offset < CYPHER_HEADER_SIZE as u16);

                let written = writer
                    .write(&self.buffer[offset as usize..CYPHER_HEADER_SIZE])?;

                if written == 0 {
                    return Ok(0);
                } else {
                    if offset + (written as u16) < CYPHER_HEADER_SIZE as u16 {
                        self.state = Shutdown { offset: offset + (written as u16) };
                    } else {
                        self.state = Writable;
                    }
                }

                return self.write(buf, writer, key, nonce);
            }
        }
    }

    pub fn flush<W: Write>(&mut self,
                           writer: &mut W,
                           key: &secretbox::Key,
                           nonce: &mut secretbox::Nonce)
                           -> Result<(), Error> {
        match self.state {
            Writable => return writer.flush(),

            WriteInner { offset, length } => {
                let written = self.write(&[0] /* so that written != 0*/, writer, key, nonce)?;
                if written == 0 {
                    debug_assert!(self.state == WriteInner { offset, length });
                    return Err(Error::new(ErrorKind::WriteZero,
                                          "failed to write the buffered data"));
                } else {
                    debug_assert!(self.state == Writable);
                    return self.flush(writer, key, nonce);
                }
            }

            Shutdown { offset } => {
                let written = self.write(&[0] /* so that written != 0*/, writer, key, nonce)?;
                if written == 0 {
                    debug_assert!(self.state == Shutdown { offset });
                    return Err(Error::new(ErrorKind::WriteZero,
                                          "failed to write the buffered final packet"));
                } else {
                    debug_assert!(self.state == Writable);
                    return self.flush(writer, key, nonce);
                }
            }
        }
    }

    // This does not call writer.shutdown(), since it should also work on Write
    // rather than only AsyncWrite. An AsyncWrite wrapper should call this in
    // its shutdown method and then delegate to the inner shutdown method.
    pub fn shutdown<W: Write>(&mut self,
                              writer: &mut W,
                              key: &secretbox::Key,
                              nonce: &mut secretbox::Nonce)
                              -> Result<(), Error> {
        match self.state {
            Writable => {
                unsafe {
                    final_header(&mut *(self.buffer.as_mut_ptr() as *mut [u8; CYPHER_HEADER_SIZE]),
                                 &key.0,
                                 &nonce.0);
                }
                self.state = Shutdown { offset: 0 };
                return self.flush(writer, key, nonce);
            }

            WriteInner {
                offset: _,
                length: _,
            } => {
                self.flush(writer, key, nonce)?;
                debug_assert!(self.state == Writable);
                return self.shutdown(writer, key, nonce);
            }

            Shutdown { offset: _ } => panic!("multiple shutdowns"),
        }
    }
}

/// Zero buffered data on dropping.
impl Drop for Encryptor {
    fn drop(&mut self) {
        memzero(&mut self.buffer);
    }
}

// State of the encryptor state machine. When `write` is called on the Encryptor, it advances
// through the state machine.
//
// Initial state is Writable.
#[derive(PartialEq)]
enum State {
    // On `write`, encrypt up to BUFFER_SIZE bytes into the buffer at offset 0.
    // Then, the state machine advances to WriteInner {offset: 0, length: written_bytes} and
    // `write` returns Ok(written_bytes).
    Writable,
    // On `write`, buffer[offset..CYPHER_HEADER_SIZE + length] to the given Write, then offset += writter_bytes.
    // Repeat until offset == CYPHER_HEADER_SIZE + length, then the state machine advance to Writable (and read is
    // called again).
    //
    // Invariants: offset < length, length <= BUFFER_SIZE
    WriteInner { offset: u16, length: u16 },
    // This state signals that the buffer contains a valid final header, ready
    // to get flushed to the given Write.
    //
    // Invariants: offset < CYPHER_HEADER_SIZE
    Shutdown { offset: u16 },
}
use encryptor::State::*;
