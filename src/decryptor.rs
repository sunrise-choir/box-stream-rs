use std::io::{Error, Read, ErrorKind};
use std::mem::transmute;
use std::cmp::min;
use std::ptr::copy_nonoverlapping;

use sodiumoxide::crypto::secretbox;
use sodiumoxide::utils::memzero;

use crypto::{CYPHER_HEADER_SIZE, CYPHER_HEADER_SIZE_U16, MAX_PACKET_SIZE, MAX_PACKET_USIZE,
             PlainHeader, decrypt_header_inplace, decrypt_packet_inplace};

const BUFFER_SIZE: usize = CYPHER_HEADER_SIZE + MAX_PACKET_USIZE;

/// The error value signaling that a header is not correctly authenticated.
pub const UNAUTHENTICATED_HEADER: &'static str = "read unauthenticated header";

/// The error value signaling that a header claims an invalid packet length.
pub const INVALID_LENGTH: &'static str = "read header containing invalid length";

/// The error value used signaling that a packet is not correctly authenticated.
pub const UNAUTHENTICATED_PACKET: &'static str = "read unauthenticated packet";

/// The error value signaling that the box stream reached an unauthenticated eof.
pub const UNAUTHENTICATED_EOF: &'static str = "reached unauthenticated eof";

// TODO move to utils
macro_rules! retry {
    ($e:expr) => (
        loop {
            match $e {
                Ok(t) => break t,
                Err(ref e) if e.kind() == ::std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e.into()),
            }
        }
    )
}

// Implements the base functionality for creating decrypting wrappers around `io::Read`s.
pub struct Decryptor {
    // Bytes are read into this buffer and get decrypted in-place
    buffer: [u8; BUFFER_SIZE],
    state: State,
}

impl Decryptor {
    pub fn new() -> Decryptor {
        Decryptor {
            buffer: [0; BUFFER_SIZE],
            state: ReadCypherHeader { offset: 0 },
        }
    }

    // A Read wrapper using the decryptor should delegate to this method in its `read` implementation.
    //
    // If this returns Ok(0) and the provided buffer was not 0 bytes in length, a final header was read
    // and no more data will be emitted. If the underlying Read emitted 0 bytes although it was not
    // given a 0 length buffer, this results in an io::Error of kind `UnexpectedEof` (since EOF
    // must be signaled by the final header).
    pub fn read<R: Read>(&mut self,
                         buf: &mut [u8],
                         reader: &mut R,
                         key: &secretbox::Key,
                         nonce: &mut secretbox::Nonce)
                         -> Result<usize, Error> {
        match self.state {
            ReadCypherHeader { offset } => {
                debug_assert!(offset < CYPHER_HEADER_SIZE_U16);

                let new_offset = offset +
                                 (read_nonzero(reader,
                                               &mut self.buffer[(offset as usize)..
                                                    CYPHER_HEADER_SIZE])? as
                                  u16);

                if new_offset < CYPHER_HEADER_SIZE_U16 {
                    self.state = ReadCypherHeader { offset: new_offset };
                    return self.read(buf, reader, key, nonce);
                } else {
                    let is_header_valid =
                        unsafe {
                            decrypt_header_inplace(&mut *(self.buffer.as_mut_ptr() as
                                                          *mut [u8; CYPHER_HEADER_SIZE]),
                                                   &key.0,
                                                   &mut nonce.0)
                        };

                    if is_header_valid {
                        let plain_header = unsafe { self.plain_header() };

                        println!("about to check whether header is final");
                        if plain_header.is_final_header() {
                            println!("header is final");
                            return Ok(0);
                        } else {
                            let len = plain_header.get_packet_len();
                            if len > MAX_PACKET_SIZE || len == 0 {
                                return Err(Error::new(ErrorKind::InvalidData, INVALID_LENGTH));
                            } else {
                                self.state = ReadCypherPacket {
                                    offset: 0,
                                    length: len,
                                };
                                return self.read(buf, reader, key, nonce);
                            }
                        }
                    } else {
                        return Err(Error::new(ErrorKind::InvalidData, UNAUTHENTICATED_HEADER));
                    }
                }
            }

            ReadCypherPacket { offset, length } => {
                debug_assert!(offset < length);
                debug_assert!(length <= MAX_PACKET_SIZE);
                println!("read ReadCypherPacket at offset {}", offset);

                let new_offset = offset +
                                 (read_nonzero(reader,
                                               &mut self.buffer[CYPHER_HEADER_SIZE + (offset as usize)..
                                                    CYPHER_HEADER_SIZE +
                                                    (length as usize)])? as
                                  u16);
                println!("new offset {}", new_offset);
                if new_offset < length {
                    self.state = ReadCypherPacket {
                        offset: new_offset,
                        length: length,
                    };
                    return self.read(buf, reader, key, nonce);
                } else {
                    let plain_header = unsafe { self.plain_header() };

                    let is_packet_valid = unsafe {
                        decrypt_packet_inplace(self.buffer
                                                   .as_mut_ptr()
                                                   .offset(CYPHER_HEADER_SIZE as isize),
                                               &plain_header,
                                               &key.0,
                                               &mut nonce.0)
                    };

                    if is_packet_valid {
                        self.state = Readable {
                            offset: 0,
                            length: length,
                        };
                        return self.read(buf, reader, key, nonce);
                    } else {
                        return Err(Error::new(ErrorKind::InvalidData, UNAUTHENTICATED_PACKET));
                    }
                }
            }

            Readable { offset, length } => {
                debug_assert!(offset < length);
                debug_assert!(length <= MAX_PACKET_SIZE);

                let read = min(buf.len(), (length - offset) as usize);

                unsafe {
                    copy_nonoverlapping(self.buffer
                                            .as_ptr()
                                            .offset(CYPHER_HEADER_SIZE as isize +
                                                    offset as isize),
                                        buf.as_mut_ptr(),
                                        read);
                }

                if offset + (read as u16) < length {
                    self.state = Readable {
                        offset: offset + (read as u16),
                        length: length,
                    };
                } else {
                    self.state = ReadCypherHeader { offset: 0 }
                }

                return Ok(read);
            }
        }
    }

    // This unsafely casts the first 2 + secretbox::MACBYTES bytes of the buffer as a PlainHeader.
    // Everything goes horribly wrong if these bytes don't actually contain a decrypted header.
    unsafe fn plain_header(&self) -> PlainHeader {
        transmute::<[u8; secretbox::MACBYTES + 2], PlainHeader>(*(self.buffer.as_ptr() as
                                                                  *const [u8;
                                                                          secretbox::MACBYTES + 2]))
    }
}

/// Zero buffered data on dropping.
impl Drop for Decryptor {
    fn drop(&mut self) {
        memzero(&mut self.buffer);
    }
}

// State of the decryptor state machine. When `read` is called on the Decryptor, it advances
// through the state machine, providing as many bytes as possible until either the given buffer is
// full, or the underlying AsyncRead blocks.
//
// Initial state is ReadCypherHeader{offset: 0}.
enum State {
    // Read (CYPHER_HEADER_SIZE - offset) bytes from the given Readable to buffer[offset], then
    // offset += read_bytes.
    // Once offset == CYPHER_HEADER_SIZE, the CypherHeader is verified, decrypted in place, and the
    //  state machine advances to ReadCypherPacket {offset: 0, length: length_from_header}.
    //
    // Invariants: offset < CYPHER_HEADER_SIZE (since the state changes once it reaches CYPHER_HEADER_SIZE)
    ReadCypherHeader { offset: u16 },
    // Read (length - offset) bytes from the given Readable to buffer[CYPHER_HEADER_SIZE + offset],
    // then offset += read_bytes.
    // Once offset == length, the CypherPacket is verified, decrypted in place, and the state
    // machine advances to Readable {offset: 0, length: length}.
    //
    // Invariants: offset < length, length <= MAX_PACKET_SIZE
    ReadCypherPacket { offset: u16, length: u16 },
    // `read` should read (length - offset) bytes from buffer[CYPHER_HEADER_SIZE + offset], then
    // offset += written_bytes.
    // Once offset == length, the state machine advances to WriteCypherHeader { offset: 0}.
    //
    // Invariants: offset < length, length <= MAX_PACKET_SIZE
    Readable { offset: u16, length: u16 },
}
use decryptor::State::*;

// Helper function which delegates to `Reader::read`, but returns an Error of kind UnexpectedEof
// if zero bytes were read although `buf` had length greater than 0.
fn read_nonzero<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<usize, Error> {
    let read = retry!(r.read(buf));
    if read == 0 && buf.len() > 0 {
        return Err(Error::new(ErrorKind::UnexpectedEof, UNAUTHENTICATED_EOF));
    } else {
        return Ok(read);
    }
}
