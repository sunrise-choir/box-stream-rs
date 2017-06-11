extern crate libc;
extern crate sodiumoxide;

use std::io;
use std::io::{Write, Read};
use std::cmp;
use std::slice;
use std::mem;
use sodiumoxide::crypto::secretbox;

use crypto::{CYPHER_HEADER_SIZE, MAX_PACKET_SIZE, MAX_PACKET_USIZE};

pub mod crypto;

// Buffer encrypted bytes, so that the stream can correctly resume even if the
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

    // Adds more data to the buffer. Returns how much data was added, at most `MAX_PACKET_SIZE`.
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
