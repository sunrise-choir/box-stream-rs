use std::io::{Read, Write};
use std::io;
use sodiumoxide::crypto::secretbox;
use futures::Poll;
use tokio_io::{AsyncRead, AsyncWrite};

use impl_reading::*;
use impl_writing::*;

/// Wraps a duplex stream, encrypting all writes and decrypting all reads.
pub struct BoxDuplex<S: Write + Read> {
    inner: S,
    encryption_key: secretbox::Key,
    decryption_key: secretbox::Key,
    decryption_nonce: secretbox::Nonce,
    encryption_nonce: secretbox::Nonce,
    reader_buffer: ReaderBuffer,
    writer_buffer: WriterBuffer,
}

impl<S: Write + Read> BoxDuplex<S> {
    /// Create a new duplex stream, wrapping `inner` and the supplied keys and
    /// nonces for encryption and decryption.
    pub fn new(inner: S,
               encryption_key: secretbox::Key,
               decryption_key: secretbox::Key,
               encryption_nonce: secretbox::Nonce,
               decryption_nonce: secretbox::Nonce)
               -> BoxDuplex<S> {
        BoxDuplex {
            inner,
            encryption_key,
            decryption_key,
            encryption_nonce,
            decryption_nonce,
            reader_buffer: ReaderBuffer::new(),
            writer_buffer: WriterBuffer::new(),
        }
    }

    /// Gets a reference to the underlying stream.
    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    /// Gets a mutable reference to the underlying stream.
    ///
    /// It is inadvisable to directly write to or read from the underlying
    /// stream.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    /// Unwraps this `BoxDuplex`, returning the underlying stream.
    pub fn into_inner(self) -> S {
        self.inner
    }

    /// Tries to write a final header, indicating the end of the connection.
    /// This will flush all internally buffered data before writing the header.
    ///
    /// After this has returned `Ok(())`, no further `write` or `flush` methods
    /// of the `BoxDuplex` may be called.
    /// If this returns an error, it may be safely called again. Only once this
    /// returns `Ok(())` the final header is guaranteed to have been written.
    pub fn write_final_header(&mut self) -> io::Result<()> {
        do_shutdown(&mut self.inner,
                    &self.encryption_key,
                    &mut self.encryption_nonce,
                    &mut self.writer_buffer)
    }
}

impl<S: Read + Write> Read for BoxDuplex<S> {
    /// Read bytes from the wrapped stream and decrypt them.
    ///
    /// # Errors
    /// In addition to propagating all errors from the wrapped stream, a
    /// `BoxDuplex` produces the following error kinds:
    ///
    /// - `ErrorKind::InvalidData`: If data could not be decrypted, or if a
    /// header declares an invalid length. Possible error values are
    /// `INVALID_LENGTH`, `UNAUTHENTICATED_HEADER`, `UNAUTHENTICATED_PACKET`.
    /// - `ErrorKind::Other`: This is used to signal that a final header has
    /// been read. In this case, the error value is `FINAL_ERROR`.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        do_read(buf,
                &mut self.inner,
                &self.decryption_key,
                &mut self.decryption_nonce,
                &mut self.reader_buffer)
    }
}

impl<S: Read + Write> Write for BoxDuplex<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        do_write(buf,
                 &mut self.inner,
                 &self.encryption_key,
                 &mut self.encryption_nonce,
                 &mut self.writer_buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        do_flush(&mut self.inner, &mut self.writer_buffer)
    }
}

impl<AS: AsyncRead + AsyncWrite> AsyncRead for BoxDuplex<AS> {}

impl<AS: AsyncRead + AsyncWrite> AsyncWrite for BoxDuplex<AS> {
    fn shutdown(&mut self) -> Poll<(), io::Error> {
        try_nb!(self.write_final_header());
        self.inner.shutdown()
    }
}
