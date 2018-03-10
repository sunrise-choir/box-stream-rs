use futures_core::Poll;
use futures_core::task::Context;
use futures_io::{Error, AsyncRead, AsyncWrite};
use sodiumoxide::crypto::secretbox;

use encryptor::*;
use decryptor::*;

/// Wraps a duplex stream, encrypting all writes and decrypting all reads.
pub struct BoxDuplex<S> {
    inner: S,
    encryption_key: secretbox::Key,
    decryption_key: secretbox::Key,
    decryption_nonce: secretbox::Nonce,
    encryption_nonce: secretbox::Nonce,
    encryptor: Encryptor,
    decryptor: Decryptor,
}

impl<S> BoxDuplex<S> {
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
            encryptor: Encryptor::new(),
            decryptor: Decryptor::new(),
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
}

impl<R: AsyncRead> AsyncRead for BoxDuplex<R> {
    /// Read bytes from the wrapped reader and decrypt them. End of stream is signalled by
    /// returning `Ok(0)` even though this function was passed a buffer of nonzero length.
    ///
    /// # Errors
    /// In addition to propagating all errors from the wrapped reader, a
    /// `BoxReader` produces the following error kinds:
    ///
    /// - `ErrorKind::InvalidData`: If data could not be decrypted, or if a
    /// header declares an invalid length. Possible error values are
    /// `INVALID_LENGTH`, `UNAUTHENTICATED_HEADER`, `UNAUTHENTICATED_PACKET`.
    /// `ErrorKind::UnexpectedEof`: If a call to the inner reader returned `Ok(0)` although it was
    /// given a buffer of nonzero length. This is an error since end of file must be signalled via
    /// a special header in a box stream. The error value for this is `UNAUTHENTICATED_EOF`.
    fn poll_read(&mut self, cx: &mut Context, buf: &mut [u8]) -> Poll<usize, Error> {
        self.decryptor
            .poll_read(cx,
                       buf,
                       &mut self.inner,
                       &self.decryption_key,
                       &mut self.decryption_nonce)
    }
}

impl<W: AsyncWrite> AsyncWrite for BoxDuplex<W> {
    fn poll_write(&mut self, cx: &mut Context, buf: &[u8]) -> Poll<usize, Error> {
        self.encryptor
            .poll_write(cx,
                        buf,
                        &mut self.inner,
                        &self.encryption_key,
                        &mut self.encryption_nonce)
    }

    fn poll_flush(&mut self, cx: &mut Context) -> Poll<(), Error> {
        self.encryptor
            .poll_flush(cx,
                        &mut self.inner,
                        &self.encryption_key,
                        &mut self.encryption_nonce)
    }

    fn poll_close(&mut self, cx: &mut Context) -> Poll<(), Error> {
        self.encryptor
            .poll_close(cx,
                        &mut self.inner,
                        &self.encryption_key,
                        &mut self.encryption_nonce)
    }
}
