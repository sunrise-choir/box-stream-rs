use std::cmp::min;

use futures_core::Poll;
use futures_core::Async::Ready;
use futures_core::task::Context;
use futures_io::{Error, AsyncWrite, ErrorKind};
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
    pub fn poll_write<W: AsyncWrite>(&mut self,
                                     cx: &mut Context,
                                     buf: &[u8],
                                     writer: &mut W,
                                     key: &secretbox::Key,
                                     nonce: &mut secretbox::Nonce)
                                     -> Poll<usize, Error> {
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

                return Ok(Ready(written as usize));
            }

            WriteInner { offset, length } => {
                debug_assert!(offset < length + CYPHER_HEADER_SIZE as u16);
                debug_assert!(length + CYPHER_HEADER_SIZE as u16 <= BUFFER_SIZE as u16);

                let written = try_ready!(writer.poll_write(cx,
                                                           &self.buffer[offset as usize..
                                                            CYPHER_HEADER_SIZE +
                                                            length as usize]));

                if written == 0 {
                    return Err(Error::new(ErrorKind::WriteZero, "failed to write data"));
                } else {
                    if offset + (written as u16) < length + CYPHER_HEADER_SIZE as u16 {
                        self.state = WriteInner {
                            offset: offset + (written as u16),
                            length: length,
                        };
                    } else {
                        self.state = Writable;
                    }
                }

                return self.poll_write(cx, buf, writer, key, nonce);
            }

            Shutdown { offset: _ } => {
                panic!("write during shutdown");
            }
        }
    }

    pub fn poll_flush<W: AsyncWrite>(&mut self,
                                     cx: &mut Context,
                                     writer: &mut W,
                                     key: &secretbox::Key,
                                     nonce: &mut secretbox::Nonce)
                                     -> Poll<(), Error> {
        match self.state {
            Writable => {
                return writer.poll_flush(cx);
            }

            WriteInner { offset, length } => {
                debug_assert!(offset < length + CYPHER_HEADER_SIZE as u16);
                debug_assert!(length + CYPHER_HEADER_SIZE as u16 <= BUFFER_SIZE as u16);

                let written = try_ready!(writer.poll_write(cx,
                                                           &self.buffer[offset as usize..
                                                            CYPHER_HEADER_SIZE +
                                                            length as usize]));

                if written == 0 {
                    return Err(Error::new(ErrorKind::WriteZero, "failed to write buffered data"));
                } else {
                    if offset + (written as u16) < length + CYPHER_HEADER_SIZE as u16 {
                        self.state = WriteInner {
                            offset: offset + (written as u16),
                            length: length,
                        };
                    } else {
                        self.state = Writable;
                    }
                }

                return self.poll_flush(cx, writer, key, nonce);
            }

            Shutdown { offset } => {
                debug_assert!(offset < CYPHER_HEADER_SIZE as u16);
                let written = try_ready!(writer.poll_write(cx,
                                                           &self.buffer[offset as usize..
                                                            CYPHER_HEADER_SIZE]));

                if written == 0 {
                    return Err(Error::new(ErrorKind::WriteZero, "failed to write final packet"));
                } else {
                    if offset + (written as u16) < CYPHER_HEADER_SIZE as u16 {
                        self.state = Shutdown { offset: offset + (written as u16) };
                    } else {
                        self.state = Writable;
                    }
                }

                return self.poll_flush(cx, writer, key, nonce);
            }
        }
    }

    pub fn poll_close<W: AsyncWrite>(&mut self,
                                     cx: &mut Context,
                                     writer: &mut W,
                                     key: &secretbox::Key,
                                     nonce: &mut secretbox::Nonce)
                                     -> Poll<(), Error> {
        match self.state {
            Writable => {
                unsafe {
                    final_header(&mut *(self.buffer.as_mut_ptr() as *mut [u8; CYPHER_HEADER_SIZE]),
                                 &key.0,
                                 &nonce.0);
                }
                self.state = Shutdown { offset: 0 };
                return self.poll_flush(cx, writer, key, nonce);
            }

            WriteInner {
                offset: _,
                length: _,
            } => {
                let _ = try_ready!(self.poll_flush(cx, writer, key, nonce));
                debug_assert!(self.state == Writable);
                return self.poll_close(cx, writer, key, nonce);
            }

            Shutdown { offset: _ } => return self.poll_flush(cx, writer, key, nonce),
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
#[derive(PartialEq, Debug)]
enum State {
    // On `write`, encrypt up to BUFFER_SIZE bytes into the buffer at offset 0.
    // Then, the state machine advances to WriteInner {offset: 0, length: written_bytes} and
    // `write` returns Ok(written_bytes).
    Writable,
    // On `write`, write buffer[offset..CYPHER_HEADER_SIZE + length] to the given Write, then offset += written_bytes.
    // Repeat until offset == CYPHER_HEADER_SIZE + length, then the state machine advance to Writable (and write is
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
