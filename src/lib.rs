extern crate libc;
extern crate sodiumoxide;

use std::io;
use std::io::{Write, Read};
use std::cmp;
use std::slice;
use std::mem;
use std::u16;
use std::ptr;
use sodiumoxide::crypto::secretbox;

use crypto::{CYPHER_HEADER_SIZE, MAX_PACKET_SIZE, MAX_PACKET_USIZE, PlainHeader};

pub mod crypto;

// Buffers encrypted bytes, so that the stream can correctly resume even if the
// underlying stream is unable to write a whole header + packet combination at
// once.
struct WriterBuffer {
    // Stores the result of a call to `encrypt_packet`.
    buffer: [u8; CYPHER_HEADER_SIZE + MAX_PACKET_USIZE],
    // Indicates where to resume writing, or whether to encrypt the next packet (if greater than the size of `buffer`).
    offset: u16,
    // Length of the data that is actually relevant, buffer[length] is useless data from a previous packet.
    length: u16,
}

impl WriterBuffer {
    fn new() -> WriterBuffer {
        WriterBuffer {
            buffer: unsafe { mem::uninitialized() },
            offset: CYPHER_HEADER_SIZE as u16 + MAX_PACKET_SIZE,
            length: 0,
        }
    }

    // Adds more data to the buffer. After this, `has_unwritten_data` returns
    // true until at least the next `write_to`. This guarantee does not hold if
    // this is given an empty buffer, so don't do that...
    //
    // Don't call this if `has_unwritten_data` returns true.
    fn insert(&mut self,
              data: &[u8],
              encryption_key: &secretbox::Key,
              encryption_nonce: &mut secretbox::Nonce) {
        let packet_length = cmp::max(data.len(), MAX_PACKET_USIZE) as u16;
        self.length = packet_length + CYPHER_HEADER_SIZE as u16;
        self.offset = 0;

        unsafe {
            crypto::encrypt_packet(self.buffer.as_mut_ptr(),
                                   data.as_ptr(),
                                   packet_length,
                                   &encryption_key.0,
                                   &mut encryption_nonce.0);
        }
    }

    // Returns true if this still contains data, false if new data should be inserted.
    // Calling `insert` after this returns `true` overwrites unwritten data. Calling
    // `write_to` when this returns `false` is undefined behaviour.
    fn has_unwritten_data(&self) -> bool {
        self.offset >= self.length
    }

    // Writes buffered data into the given writer, returning how much data was written.
    fn write_to<W: Write>(&mut self, writer: &mut W) -> io::Result<usize> {

        let written = writer
            .write(unsafe {
                       slice::from_raw_parts(self.buffer.as_ptr().offset(self.offset as isize),
                                             (self.length - self.offset) as usize)
                   })?;

        self.offset += written as u16;
        Ok(written)
    }

    // Tries to flush the buffer to a given writer. Does not call flush on the writer.
    fn flush_to<W: Write>(&mut self, writer: &mut W) -> io::Result<()> {
        while self.has_unwritten_data() {
            self.write_to(writer)?;
        }
        Ok(())
    }
}

/// Common interface for writable streams that encrypts all bytes using box-stream.
pub trait BoxWriter: Write {
    /// Tries to write a final header, indicating the end of the connection.
    /// This will flush all internally buffered data before writing the header.
    /// After this has returned `Ok(())`, no further methods of the `BoxWriter`
    /// may be called.
    fn shutdown(&mut self) -> io::Result<()>;
}

/// Wraps a writer, encrypting all writes.
pub struct Boxer<W: Write> {
    inner: W,
    encryption_key: secretbox::Key,
    encryption_nonce: secretbox::Nonce,
    buffer: WriterBuffer,
}

impl<W: Write> Boxer<W> {
    /// Creates a new Encrypter, using the supplied key and nonce.
    pub fn new(inner: W,
               encryption_key: secretbox::Key,
               encryption_nonce: secretbox::Nonce)
               -> Boxer<W> {
        Boxer {
            inner,
            encryption_key,
            encryption_nonce,
            buffer: WriterBuffer::new(),
        }
    }

    /// Gets a reference to the underlying writer.
    pub fn get_ref(&self) -> &W {
        &self.inner
    }

    /// Gets a mutable reference to the underlying writer.
    ///
    /// It is inadvisable to directly write to the underlying writer.
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.inner
    }

    /// Unwraps this `Encrypter`, returning the underlying writer.
    pub fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: Write> Write for Boxer<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.len() == 0 {
            return Ok(0);
        }

        if !self.buffer.has_unwritten_data() {
            self.buffer
                .insert(buf, &self.encryption_key, &mut self.encryption_nonce);
        }

        self.buffer.write_to(&mut self.inner)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.buffer.flush_to(&mut self.inner)?;

        self.inner.flush()
    }
}

impl<W: Write> BoxWriter for Boxer<W> {
    fn shutdown(&mut self) -> io::Result<()> {
        self.buffer.flush_to(&mut self.inner)?;

        unsafe {
            crypto::final_header(&mut *(self.buffer.buffer.as_mut_ptr() as
                                        *mut [u8; CYPHER_HEADER_SIZE]),
                                 &self.encryption_key.0,
                                 &mut self.encryption_nonce.0);
        }
        self.buffer.offset = 0;
        self.buffer.length = CYPHER_HEADER_SIZE as u16;

        self.buffer.flush_to(&mut self.inner)
    }
}

// Buffers cyphertext. This is a state machine with two states:
//   - NeedsHeader: Waiting to accumulate a full cypher_header
//   - NeedsPacket: Waiting to accumulate a full cypher_packet
// In NeedsHeader, only read as much data as needed to store the full header. Then,
// decrypt it and transition to NeedsPacket.
// In NeedsPacket, only read as much data as needed to store the full packet. Then,
// decrypt it, return it to the reader, and transition to NeedsHeader.
//
// In NeedsHeader, store an offset into the currently accumulated header, to
// compute where to put further bytes, and how many bytes to read.
//
// In NeedsPacket, store the mac for decryption, the packet's length, and an
// offset into the currently accumulated packet bytes, to compute where to put
// further bytes, and how many bytes to read (together with the length).
struct ReaderBuffer {
    // Stores encrypted data, at most a header and a packet.
    buffer: [u8; CYPHER_HEADER_SIZE + MAX_PACKET_USIZE],
    // Where in the buffer to write the next data, or where to read it from.
    offset: u16,
    mode: ReaderBufferMode,
}

#[derive(PartialEq)]
enum ReaderBufferMode {
    Buffering,
    Readable,
}
use ReaderBufferMode::{Buffering, Readable};

impl ReaderBuffer {
    fn new() -> ReaderBuffer {
        ReaderBuffer {
            buffer: [0; CYPHER_HEADER_SIZE + MAX_PACKET_USIZE],
            offset: 0,
            mode: Buffering,
        }
    }

    fn get_packet_len(&self) -> u16 {
        let plain_header = unsafe {
            mem::transmute::<[u8;
                              secretbox::MACBYTES + 2],
                             PlainHeader>(*(self.buffer.as_ptr() as
                                            *const [u8; secretbox::MACBYTES + 2]))
        };

        plain_header.get_packet_len()
    }

    // fn get_packet_mac(&self) -> [u8; secretbox::MACBYTES] {
    //     let plain_header = unsafe {
    //         mem::transmute::<[u8;
    //                           secretbox::MACBYTES + 2],
    //                          PlainHeader>(*(self.buffer.as_ptr() as
    //                                         *const [u8; secretbox::MACBYTES + 2]))
    //     };
    //
    //     plain_header.get_packet_mac()
    // }

    // Reads data from a reader into the buffer and returns `true` if the next
    // `is_readable` call would return `true`. Calling this when `is_readable`
    // returns true is unspecified behaviour.
    fn insert<R: Read>(&mut self,
                       reader: &mut R,
                       encryption_key: &secretbox::Key,
                       encryption_nonce: &mut secretbox::Nonce)
                       -> io::Result<bool> {
        debug_assert!(self.mode == Buffering);

        // have not yet read a full header, so optimistically read as much data as possible
        if self.offset < CYPHER_HEADER_SIZE as u16 {
            let mut buffer_as_slice = unsafe {
                slice::from_raw_parts_mut(self.buffer.as_mut_ptr().offset(self.offset as isize),
                                          CYPHER_HEADER_SIZE + MAX_PACKET_USIZE -
                                          self.offset as usize)
            };

            let read = reader.read(buffer_as_slice)?;
            self.offset += read as u16;
            debug_assert!(self.offset as usize <= CYPHER_HEADER_SIZE + MAX_PACKET_USIZE);

            if self.offset < CYPHER_HEADER_SIZE as u16 {
                return Ok(false);
            }
            // else, we have a full encrypted header

            unsafe {
                crypto::decrypt_header_inplace(&mut *(self.buffer.as_mut_ptr() as
                                                      *mut [u8; CYPHER_HEADER_SIZE]),
                                               &encryption_key.0,
                                               &mut encryption_nonce.0);
            }

            if self.get_packet_len() >= self.offset - CYPHER_HEADER_SIZE as u16 {
                self.mode = Readable;
                return Ok(true);
            } else {
                return Ok(false);
            }
        } else {
            // try to read the remainder of the currently read packet
            let mut buffer_as_slice = unsafe {
                slice::from_raw_parts_mut(self.buffer.as_mut_ptr().offset(self.offset as isize),
                                          CYPHER_HEADER_SIZE + self.get_packet_len() as usize)
            };

            let read = reader.read(buffer_as_slice)?;
            self.offset += read as u16;
            debug_assert!(self.offset as usize <= CYPHER_HEADER_SIZE + MAX_PACKET_USIZE);

            if self.get_packet_len() >= self.offset - CYPHER_HEADER_SIZE as u16 {
                self.mode = Readable;
                return Ok(true);
            } else {
                return Ok(false);
            }
        }
    }

    // Pulls some bytes from this into the given output
    // Returns how many bytes were read into out.
    fn read_to(&mut self,
               out: &mut [u8],
               encryption_key: &secretbox::Key,
               encryption_nonce: &mut secretbox::Nonce)
               -> usize {
        debug_assert!(self.offset <= CYPHER_HEADER_SIZE as u16 + self.get_packet_len());

        // full packet was just read, decrypt it and reset offset to the first byte of the packet
        if self.offset == CYPHER_HEADER_SIZE as u16 + self.get_packet_len() {
            let plain_header = unsafe {
                &mem::transmute::<[u8;
                                   secretbox::MACBYTES +
                                   2],
                                  PlainHeader>(*(self.buffer.as_ptr() as
                                                 *const [u8; secretbox::MACBYTES + 2]))
            };

            unsafe {
                crypto::decrypt_packet_inplace(self.buffer
                                                   .as_mut_ptr()
                                                   .offset(CYPHER_HEADER_SIZE as isize),
                                               plain_header,
                                               &encryption_key.0,
                                               &mut encryption_nonce.0);
            }
            self.offset = CYPHER_HEADER_SIZE as u16;
        }

        // write to out
        if out.len() >= self.get_packet_len() as usize {
            unsafe {
                ptr::copy_nonoverlapping(self.buffer.as_mut_ptr().offset(self.offset as isize),
                                         out.as_mut_ptr(),
                                         self.get_packet_len() as usize);
            }
            self.mode = Buffering;
            return self.get_packet_len() as usize;
        } else {
            unsafe {
                ptr::copy_nonoverlapping(self.buffer.as_mut_ptr().offset(self.offset as isize),
                                         out.as_mut_ptr(),
                                         out.len());
            }
            return out.len();
        }
    }
}

/// Wraps a reader, decrypting all reads.
pub struct Unboxer<R: Read> {
    inner: R,
    encryption_key: secretbox::Key,
    encryption_nonce: secretbox::Nonce,
    buffer: ReaderBuffer,
}

impl<R: Read> Unboxer<R> {
    pub fn new(inner: R,
               encryption_key: secretbox::Key,
               encryption_nonce: secretbox::Nonce)
               -> Unboxer<R> {
        Unboxer {
            inner,
            encryption_key,
            encryption_nonce,
            buffer: ReaderBuffer::new(),
        }
    }
}

impl<R: Read> Read for Unboxer<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.buffer.mode {
            Buffering => {
                self.buffer
                    .insert(&mut self.inner,
                            &self.encryption_key,
                            &mut self.encryption_nonce)?;
                Ok(0)
            }
            Readable => {
                Ok(self.buffer
                       .read_to(buf, &self.encryption_key, &mut self.encryption_nonce))
            }
        }
    }
}
