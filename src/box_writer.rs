// Implementation of BoxWriter, a wrapper for writers that encrypts all writes and handles buffering, flushing etc.

use std::io::Write;
use std::{io, cmp, mem, u16};
use sodiumoxide::crypto::secretbox;

use crypto::{CYPHER_HEADER_SIZE, MAX_PACKET_SIZE, MAX_PACKET_USIZE, encrypt_packet, final_header};

/// Wraps a writer, encrypting all writes.
pub struct BoxWriter<W: Write> {
    inner: W,
    key: secretbox::Key,
    nonce: secretbox::Nonce,
    buffer: WriterBuffer,
}

impl<W: Write> BoxWriter<W> {
    /// Creates a new BoxWriter, using the supplied key and nonce.
    pub fn new(inner: W, key: secretbox::Key, nonce: secretbox::Nonce) -> BoxWriter<W> {
        BoxWriter {
            inner,
            key,
            nonce,
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

    /// Unwraps this `BoxWriter`, returning the underlying writer.
    pub fn into_inner(self) -> W {
        self.inner
    }

    /// Tries to write a final header, indicating the end of the connection.
    /// This will flush all internally buffered data before writing the header.
    /// After this has returned `Ok(())`, no further methods of the `BoxWriter`
    /// may be called.
    pub fn shutdown(&mut self) -> io::Result<()> {
        do_shutdown(&mut self.inner,
                    &self.key,
                    &mut self.nonce,
                    &mut self.buffer)
    }
}

impl<W: Write> Write for BoxWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        do_write(buf,
                 &mut self.inner,
                 &self.key,
                 &mut self.nonce,
                 &mut self.buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        do_flush(&mut self.inner, &mut self.buffer)
    }
}

//////////////////////////////////
// Begin implementation details //
//////////////////////////////////

const WRITE_BUFFER_SIZE: usize = CYPHER_HEADER_SIZE + MAX_PACKET_USIZE;

// Buffers encrypted bytes, so that the stream can correctly resume even if the
// underlying stream is unable to write a whole header + packet combination at
// once.
struct WriterBuffer {
    // Stores the result of a call to `encrypt_packet`.
    buffer: [u8; WRITE_BUFFER_SIZE],
    // Indicates where to resume writing, or whether to encrypt the next packet (if greater than the size of `buffer`).
    offset: u16,
    // Length of the data that is actually relevant, everything from buffer[length] is useless data from a previous packet.
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

    fn is_empty(&self) -> bool {
        self.offset >= self.length
    }

    // Adds data to this buffer and returns how many bytes of the data source were added.
    fn fill(&mut self, data: &[u8], key: &secretbox::Key, nonce: &mut secretbox::Nonce) -> u16 {
        let packet_length = cmp::min(data.len() as u16, MAX_PACKET_SIZE);
        self.length = packet_length + CYPHER_HEADER_SIZE as u16;
        self.offset = 0;

        unsafe {
            encrypt_packet(self.buffer.as_mut_ptr(),
                           data.as_ptr(),
                           packet_length,
                           &key.0,
                           &mut nonce.0);
        }

        packet_length
    }

    // Writes data from the buffer and updates the buffer's data offset.
    fn write_buffered_data<W: Write>(&mut self, writer: &mut W) -> io::Result<usize> {
        let written = writer
            .write(&self.buffer[self.offset as usize..self.length as usize])?;
        self.offset += written as u16;
        Ok(written)
    }

    // Flushes the buffer to a writer, propagating the first encountered error.
    // Does not call flush on the writer.
    fn flush_to<W: Write>(&mut self, writer: &mut W) -> io::Result<()> {
        while !self.is_empty() {
            self.write_buffered_data(writer)?;
        }
        Ok(())
    }
}

// Implements box writing. The different streams delegate to this in `write`.
fn do_write<W: Write>(data: &[u8],
                      writer: &mut W,
                      key: &secretbox::Key,
                      nonce: &mut secretbox::Nonce,
                      buffer: &mut WriterBuffer)
                      -> io::Result<usize> {

    let buffered: u16;

    if buffer.is_empty() {
        buffered = buffer.fill(data, key, nonce);
    } else {
        buffered = 0;
    }

    buffer.write_buffered_data(writer)?;
    Ok(buffered as usize)
}

// Implements box flushing. The different streams delegate to this in `flush`.
fn do_flush<W: Write>(writer: &mut W, buffer: &mut WriterBuffer) -> io::Result<()> {
    buffer.flush_to(writer)?;

    writer.flush()
}

// Implements box shutdown. The different streams delegate to this in `shutdown`.
fn do_shutdown<W: Write>(writer: &mut W,
                         key: &secretbox::Key,
                         nonce: &secretbox::Nonce,
                         buffer: &mut WriterBuffer)
                         -> io::Result<()> {
    buffer.flush_to(writer)?;

    unsafe {
        final_header(&mut *(buffer.buffer.as_mut_ptr() as *mut [u8; CYPHER_HEADER_SIZE]),
                     &key.0,
                     &nonce.0);
    }
    buffer.offset = 0;
    buffer.length = CYPHER_HEADER_SIZE as u16;

    buffer.flush_to(writer)?;
    writer.flush()
}
