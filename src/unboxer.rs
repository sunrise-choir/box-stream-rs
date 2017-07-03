// Implementation of Unboxer, a wrapper for readers that dencrypts all writes and handles buffering.

use std::io::Read;
use std::{io, cmp, mem, u16, ptr};
use sodiumoxide::crypto::secretbox;

use crypto::{CYPHER_HEADER_SIZE, MAX_PACKET_SIZE, MAX_PACKET_USIZE, PlainHeader,
             decrypt_header_inplace, decrypt_packet_inplace};

/// Wraps a reader, decrypting all reads.
pub struct Unboxer<R: Read> {
    inner: R,
    key: secretbox::Key,
    nonce: secretbox::Nonce,
    buffer: ReaderBuffer,
}

impl<R: Read> Unboxer<R> {
    pub fn new(inner: R, key: secretbox::Key, nonce: secretbox::Nonce) -> Unboxer<R> {
        Unboxer {
            inner,
            key,
            nonce,
            buffer: ReaderBuffer::new(),
        }
    }

    /// Gets a reference to the underlying reader.
    pub fn get_ref(&self) -> &R {
        &self.inner
    }

    /// Gets a mutable reference to the underlying reader.
    ///
    /// It is inadvisable to directly write to the underlying reader.
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    /// Unwraps this `Unboxer`, returning the underlying reader.
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read> Read for Unboxer<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        do_read(buf,
                &mut self.inner,
                &self.key,
                &mut self.nonce,
                &mut self.buffer)
    }
}

//////////////////////////////////
// Begin implementation details //
//////////////////////////////////

const READ_BUFFER_SIZE: usize = CYPHER_HEADER_SIZE + MAX_PACKET_USIZE;

// A buffer for both read data and decrypted data
struct ReaderBuffer {
    buffer: [u8; READ_BUFFER_SIZE],
    last: u16, // the last element in the buffer that contains up-to-date data
    mode: ReaderBufferMode,
}

#[derive(PartialEq, Debug)]
enum ReaderBufferMode {
    WaitingForHeader,
    WaitingForPacket,
    ReadyToDecryptPacket,
    HoldsPlaintextPacket { offset: u16, packet_len: u16 },
}
use self::ReaderBufferMode::*;

// TODO malicious peer could send headers with a length greater than MAX_PACKET_SIZE
// how should that be handled?
impl ReaderBuffer {
    fn new() -> ReaderBuffer {
        ReaderBuffer {
            buffer: [0; CYPHER_HEADER_SIZE + MAX_PACKET_USIZE],
            last: 0,
            mode: WaitingForHeader,
        }
    }

    // Decrypts the cypher_header at the given offset in the buffer.
    fn decrypt_header_at(&mut self,
                         key: &secretbox::Key,
                         nonce: &mut secretbox::Nonce,
                         header_index: u16)
                         -> bool {
        unsafe {
            decrypt_header_inplace(&mut *(self.buffer.as_mut_ptr().offset(header_index as isize) as
                                          *mut [u8; CYPHER_HEADER_SIZE]),
                                   &key.0,
                                   &mut nonce.0)
        }
    }

    fn decrypt_packet_at(&mut self,
                         key: &secretbox::Key,
                         nonce: &mut secretbox::Nonce,
                         header_index: u16)
                         -> bool {
        let plain_header = self.plain_header_at(header_index);
        unsafe {
            decrypt_packet_inplace(self.buffer
                                       .as_mut_ptr()
                                       .offset(header_index as isize +
                                               CYPHER_HEADER_SIZE as isize),
                                   &plain_header,
                                   &key.0,
                                   &mut nonce.0)
        }
    }

    // Casts the buffer content at the given index to a PlainHeader.
    fn plain_header_at(&self, header_index: u16) -> PlainHeader {
        unsafe {
            // header is already decrypted, this is just a cast
            mem::transmute::<[u8;
                              secretbox::MACBYTES + 2],
                             PlainHeader>(*(self.buffer.as_ptr().offset(header_index as isize) as
                                            *const [u8; secretbox::MACBYTES + 2]))
        }
    }

    // Returns the length property of a decrypted header at the given offset in the buffer.
    fn cypher_packet_len_at(&mut self, header_index: u16) -> u16 {
        self.plain_header_at(header_index).get_packet_len()
    }

    // Shifts all relevant data from offset to the beginning of the buffer
    fn shift_left(&mut self, offset: u16) {
        unsafe {
            ptr::copy(self.buffer.as_ptr().offset(offset as isize),
                      self.buffer.as_mut_ptr(),
                      (self.last - offset) as usize);
        }
        self.last -= offset;
    }

    fn read_to(&mut self,
               out: &mut [u8],
               key: &secretbox::Key,
               nonce: &mut secretbox::Nonce)
               -> usize {
        match self.mode {
            HoldsPlaintextPacket { offset, packet_len } => {
                let max_readable = cmp::min(out.len() as u16, packet_len);

                unsafe {
                    ptr::copy_nonoverlapping(self.buffer.as_ptr().offset(offset as isize),
                                             out.as_mut_ptr(),
                                             max_readable as usize);
                }
                let offset = offset + max_readable;

                // done reading, now update mode

                if max_readable < packet_len {
                    // we have more plaintext, but the `out` buffer is full
                    debug_assert!(self.mode == HoldsPlaintextPacket { offset, packet_len });
                    return max_readable as usize;
                } else {
                    // we don't have more plaintext to fill the outbuffer

                    if self.last < offset + CYPHER_HEADER_SIZE as u16 {
                        self.mode = WaitingForHeader;
                    } else {
                        // decrypt header to see whether we have a full packet buffered
                        // TODO check return value of decrypt_header_at and handle failure
                        assert!(self.decrypt_header_at(key, nonce, offset));

                        let cypher_packet_len = self.cypher_packet_len_at(offset);
                        if cypher_packet_len + offset + (CYPHER_HEADER_SIZE as u16) > self.last {
                            self.mode = WaitingForPacket;
                        } else {
                            self.mode = ReadyToDecryptPacket;
                        }
                    }

                    self.shift_left(offset);

                    return max_readable as usize;
                }

            }
            _ => unreachable!(),
        }
    }

    fn fill<R: Read>(&mut self,
                     reader: &mut R,
                     key: &secretbox::Key,
                     nonce: &mut secretbox::Nonce)
                     -> io::Result<()> {
        debug_assert!(self.mode == WaitingForHeader || self.mode == WaitingForPacket);

        let read = reader.read(&mut self.buffer[self.last as usize..])?;
        self.last += read as u16;

        if self.last < CYPHER_HEADER_SIZE as u16 {
            // this is only reached in mode == WaitingForHeader, so no need to set that again
            debug_assert!(self.mode == WaitingForHeader);
            return Ok(());
        } else {
            if self.mode == WaitingForHeader {
                // TODO check return value of decrypt_header_at and handle failure
                assert!(self.decrypt_header_at(key, nonce, 0));
            }
            let cypher_packet_len = self.cypher_packet_len_at(0);

            if self.last < CYPHER_HEADER_SIZE as u16 + cypher_packet_len {
                self.mode = WaitingForPacket;
                return Ok(());
            } else {
                self.mode = ReadyToDecryptPacket;
                return Ok(());
            }
        }
    }

    fn decrypt_packet(&mut self, key: &secretbox::Key, nonce: &mut secretbox::Nonce) {
        debug_assert!(self.mode == ReadyToDecryptPacket);

        let packet_len = self.cypher_packet_len_at(0);
        assert!(packet_len <= MAX_PACKET_SIZE); // TODO correct handling of this

        assert!(self.decrypt_packet_at(key, nonce, 0)); // TODO correct handling of this

        self.mode = HoldsPlaintextPacket {
            offset: CYPHER_HEADER_SIZE as u16,
            packet_len,
        };
    }
}

// Implements box reading. The different streams delegate to this in `read`.
fn do_read<R: Read>(out: &mut [u8],
                    reader: &mut R,
                    key: &secretbox::Key,
                    nonce: &mut secretbox::Nonce,
                    buffer: &mut ReaderBuffer)
                    -> io::Result<usize> {
    let ret;

    match buffer.mode {
        WaitingForHeader => {
            buffer.fill(reader, key, nonce)?;
            ret = 0;
        }
        WaitingForPacket => {
            buffer.fill(reader, key, nonce)?;
            ret = 0;
        }
        ReadyToDecryptPacket => {
            buffer.decrypt_packet(key, nonce);
            ret = 0;
        }
        HoldsPlaintextPacket {
            offset: _,
            packet_len: _,
        } => ret = buffer.read_to(out, key, nonce),
    }
    return Ok(ret);
}
