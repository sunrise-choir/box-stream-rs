// Implementation of BoxReader, a wrapper for readers that decrypts all writes and handles buffering.

use std::io::{Read, ErrorKind};
use std::{io, cmp, mem, u16, ptr};
use sodiumoxide::crypto::secretbox;

use crypto::{CYPHER_HEADER_SIZE, MAX_PACKET_SIZE, MAX_PACKET_USIZE, PlainHeader,
             decrypt_header_inplace, decrypt_packet_inplace};

/// The error value used by `read` to signal that a final header has been read.
///
/// See `BoxReader::read` for more details.
pub const FINAL_ERROR: &'static str = "final";

/// The error value used by `read` to signal that a header claims an invalid length.
///
/// See `BoxReader::read` for more details.
pub const INVALID_LENGTH: &'static str = "length";

/// The error value used by `read` to signal that a header is not correctly authenticated.
///
/// See `BoxReader::read` for more details.
pub const UNAUTHENTICATED_HEADER: &'static str = "header_auth";

/// The error value used by `read` to signal that a packet is not correctly authenticated.
///
/// See `BoxReader::read` for more details.
pub const UNAUTHENTICATED_PACKET: &'static str = "packet_auth";

/// Wraps a reader, decrypting all reads.
pub struct BoxReader<R: Read> {
    inner: R,
    key: secretbox::Key,
    nonce: secretbox::Nonce,
    buffer: ReaderBuffer,
}

impl<R: Read> BoxReader<R> {
    pub fn new(inner: R, key: secretbox::Key, nonce: secretbox::Nonce) -> BoxReader<R> {
        BoxReader {
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

    /// Unwraps this `BoxReader`, returning the underlying reader.
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read> Read for BoxReader<R> {
    /// Read bytes from the wrapped reader and decrypt them.
    ///
    /// # Errors
    /// In addition to propagating all errors from the wrapped reader, a
    /// `BoxReader` produces the following error kinds:
    ///
    /// - `ErrorKind::InvalidData`: If data could not be decrypted, or if a
    /// header declares an invalid length. Possible error values are
    /// `INVALID_LENGTH`, `UNAUTHENTICATED_HEADER`, `UNAUTHENTICATED_PACKET`.
    /// - `ErrorKind::Other`: This is used to signal that a final header has
    /// been read. In this case, the error value is `FINAL_ERROR`.
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
    offset: u16, // where in the buffer to read from next (only relevant in Readable)
    header_index: u16, // points to the plain header of the currently read package (only relevant in Readable)
    mode: ReaderBufferMode,
    err: BufErr,
}

#[derive(PartialEq, Debug)]
enum ReaderBufferMode {
    WaitingForHeader,
    WaitingForPacket,
    Readable,
}
use self::ReaderBufferMode::*;

#[derive(PartialEq)]
enum BufErr {
    None,
    InvalidLength,
    FinalHeader,
    UnauthenticatedHeader,
    UnauthenticatedPacket,
}

impl ReaderBufferMode {
    fn is_waiting(&self) -> bool {
        match *self {
            Readable => false,
            _ => true,
        }
    }
}

impl ReaderBuffer {
    fn new() -> ReaderBuffer {
        ReaderBuffer {
            buffer: [0; CYPHER_HEADER_SIZE + MAX_PACKET_USIZE],
            last: 0,
            offset: 0,
            header_index: 0,
            mode: WaitingForHeader,
            err: BufErr::None,
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
        self.offset = CYPHER_HEADER_SIZE as u16;
        self.header_index = 0;
    }

    fn decrypt_packet_at(&mut self,
                         key: &secretbox::Key,
                         nonce: &mut secretbox::Nonce,
                         header_index: u16)
                         -> bool {
        let plain_header = self.plain_header_at(header_index);
        let packet_len = plain_header.get_packet_len();

        debug_assert!(packet_len <= MAX_PACKET_SIZE);

        unsafe {
            if !decrypt_packet_inplace(self.buffer
                                           .as_mut_ptr()
                                           .offset(header_index as isize +
                                                   CYPHER_HEADER_SIZE as isize),
                                       &plain_header,
                                       &key.0,
                                       &mut nonce.0) {
                return false;
            }
        }
        self.offset = CYPHER_HEADER_SIZE as u16;
        self.header_index = header_index;
        self.mode = Readable;
        true
    }

    fn set_err(&mut self, e: BufErr) -> io::Error {
        let ret = make_io_error(&e);
        self.err = e;
        ret
    }

    fn read_to(&mut self,
               out: &mut [u8],
               key: &secretbox::Key,
               nonce: &mut secretbox::Nonce)
               -> usize {
        debug_assert!(self.mode == Readable);

        let tmp = self.header_index;
        let packet_len = self.cypher_packet_len_at(tmp);
        let remaining_plaintext = self.header_index + CYPHER_HEADER_SIZE as u16 + packet_len -
                                  self.offset;

        // let max_readable = cmp::min(cmp::min(out.len() as u16, packet_len), remaining_plaintext);
        let max_readable = cmp::min(out.len() as u16, remaining_plaintext);

        unsafe {
            ptr::copy_nonoverlapping(self.buffer.as_ptr().offset(self.offset as isize),
                                     out.as_mut_ptr(),
                                     max_readable as usize);
        }
        let offset = self.offset + max_readable;

        // done reading, now update mode

        // if (remaining_plaintext != 0) && (out.len() as u16) < packet_len {
        if (out.len() as u16) < remaining_plaintext {
            // we have more plaintext, but the `out` buffer is full
            self.offset = offset;
            return max_readable as usize;
        } else {
            // we don't have more plaintext to fill the outbuffer

            if self.last < offset + CYPHER_HEADER_SIZE as u16 {
                self.mode = WaitingForHeader;
            } else {
                // decrypt header to see whether we have a full packet buffered
                if !self.decrypt_header_at(key, nonce, offset) {
                    self.set_err(BufErr::UnauthenticatedHeader);
                    return max_readable as usize;
                }

                let plain_header = self.plain_header_at(offset);
                if plain_header.is_final_header() {
                    self.set_err(BufErr::FinalHeader);
                    return max_readable as usize;
                }

                let cypher_packet_len = self.cypher_packet_len_at(offset);

                if cypher_packet_len > MAX_PACKET_SIZE {
                    self.set_err(BufErr::InvalidLength);
                    return max_readable as usize;
                }

                if cypher_packet_len + offset + (CYPHER_HEADER_SIZE as u16) > self.last {
                    self.mode = WaitingForPacket;
                } else {
                    if !self.decrypt_packet_at(key, nonce, offset) {
                        self.set_err(BufErr::UnauthenticatedPacket);
                        return max_readable as usize;
                    }
                }
            }

            self.shift_left(offset);

            return max_readable as usize;
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
                if !self.decrypt_header_at(key, nonce, 0) {
                    return Err(self.set_err(BufErr::UnauthenticatedHeader));
                }
            }
            let plain_header = self.plain_header_at(0);
            if plain_header.is_final_header() {
                return Err(self.set_err(BufErr::FinalHeader));
            }

            let cypher_packet_len = self.cypher_packet_len_at(0);

            if cypher_packet_len > MAX_PACKET_SIZE {
                return Err(self.set_err(BufErr::InvalidLength));
            }

            if self.last < CYPHER_HEADER_SIZE as u16 + cypher_packet_len {
                self.mode = WaitingForPacket;
                return Ok(());
            } else {
                if !self.decrypt_packet_at(key, nonce, 0) {
                    return Err(self.set_err(BufErr::UnauthenticatedPacket));
                }
                return Ok(());
            }
        }
    }
}

// Implements box reading. The different streams delegate to this in `read`.
fn do_read<R: Read>(out: &mut [u8],
                    reader: &mut R,
                    key: &secretbox::Key,
                    nonce: &mut secretbox::Nonce,
                    buffer: &mut ReaderBuffer)
                    -> io::Result<usize> {
    match buffer.err {
        BufErr::None => {
            let mut total_read = 0;
            if buffer.mode.is_waiting() {
                buffer.fill(reader, key, nonce)?;
            }

            while let Readable = buffer.mode {
                if buffer.err != BufErr::None {
                    break;
                }
                if total_read >= out.len() {
                    break;
                }
                total_read += buffer.read_to(&mut out[total_read..], key, nonce);
            }

            Ok(total_read)
        }
        _ => Err(make_io_error(&buffer.err)),
    }
}

fn make_io_error(e: &BufErr) -> io::Error {
    match e {
        &BufErr::FinalHeader => io::Error::new(ErrorKind::Other, FINAL_ERROR),
        &BufErr::InvalidLength => io::Error::new(ErrorKind::InvalidData, INVALID_LENGTH),
        &BufErr::UnauthenticatedHeader => {
            io::Error::new(ErrorKind::InvalidData, UNAUTHENTICATED_HEADER)
        }
        &BufErr::UnauthenticatedPacket => {
            io::Error::new(ErrorKind::InvalidData, UNAUTHENTICATED_PACKET)
        }
        &BufErr::None => {
            unreachable!();
        }
    }
}
