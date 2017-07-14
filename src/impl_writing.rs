// Implementation details for box writing

use std::io::Write;
use std::{io, cmp, mem, u16};
use sodiumoxide::crypto::secretbox;

use crypto::{CYPHER_HEADER_SIZE, MAX_PACKET_SIZE, MAX_PACKET_USIZE, encrypt_packet, final_header};

const WRITE_BUFFER_SIZE: usize = CYPHER_HEADER_SIZE + MAX_PACKET_USIZE;

// Buffers encrypted bytes, so that the stream can correctly resume even if the
// underlying stream is unable to write a whole header + packet combination at
// once.
pub struct WriterBuffer {
    // Stores the result of a call to `encrypt_packet`.
    buffer: [u8; WRITE_BUFFER_SIZE],
    // Indicates where to resume writing, or whether to encrypt the next packet (if greater than the size of `buffer`).
    offset: u16,
    // Length of the data that is actually relevant, everything from buffer[length] is useless data from a previous packet.
    length: u16,
}

impl WriterBuffer {
    pub fn new() -> WriterBuffer {
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
pub fn do_write<W: Write>(data: &[u8],
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
pub fn do_flush<W: Write>(writer: &mut W, buffer: &mut WriterBuffer) -> io::Result<()> {
    buffer.flush_to(writer)?;

    writer.flush()
}

// Implements box shutdown. The different streams delegate to this in `shutdown`.
// TODO make sure to only write one final header until this returns a ok
pub fn do_shutdown<W: Write>(writer: &mut W,
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
