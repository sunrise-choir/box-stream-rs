// Implementation of BoxWriter, a wrapper for writers that encrypts all writes and handles buffering, flushing etc.

use std::io::Write;
use std::io;
use sodiumoxide::crypto::secretbox;
use futures::Poll;
use tokio_io::AsyncWrite;

use impl_writing::*;

/// Wraps a writer, encrypting all writes.
pub struct BoxWriter<W: Write> {
    inner: W,
    key: secretbox::Key,
    nonce: secretbox::Nonce,
    buffer: WriterBuffer,
}

impl<W: Write> BoxWriter<W> {
    /// Create a new writer, wrapping `inner` and using `key` and `nonce` for
    /// encryption.
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
    ///
    /// After this has returned `Ok(())`, no further methods of the `BoxWriter`
    /// may be called.
    /// If this returns an error, it may be safely called again. Only once this
    /// returns `Ok(())` the final header is guaranteed to have been written.
    pub fn write_final_header(&mut self) -> io::Result<()> {
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

impl<AW: AsyncWrite> AsyncWrite for BoxWriter<AW> {
    fn shutdown(&mut self) -> Poll<(), io::Error> {
        try_nb!(self.write_final_header());
        self.inner.shutdown()
    }
}
