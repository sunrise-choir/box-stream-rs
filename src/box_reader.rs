// Implementation of BoxReader, a wrapper for readers that decrypts all writes and handles buffering.

use std::io::Read;
use std::io;
use sodiumoxide::crypto::secretbox;

use impl_reading::*;

/// Wraps a reader, decrypting all reads.
pub struct BoxReader<R: Read> {
    inner: R,
    key: secretbox::Key,
    nonce: secretbox::Nonce,
    buffer: ReaderBuffer,
}

impl<R: Read> BoxReader<R> {
    /// Create a new reader, wrapping `inner` and using `key` and `nonce` for
    /// decryption.
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
