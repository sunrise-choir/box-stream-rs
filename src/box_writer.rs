// Implementation of BoxWriter, a wrapper for writers that encrypts all writes.

use futures_core::Poll;
use futures_core::task::Context;
use futures_io::{Error, AsyncWrite};
use sodiumoxide::crypto::secretbox;

use encryptor::*;

/// Wraps a writer, encrypting all writes.
pub struct BoxWriter<W> {
    inner: W,
    key: secretbox::Key,
    nonce: secretbox::Nonce,
    encryptor: Encryptor,
}

impl<W> BoxWriter<W> {
    /// Create a new writer, wrapping `inner` and using `key` and `nonce` for
    /// encryption.
    pub fn new(inner: W, key: secretbox::Key, nonce: secretbox::Nonce) -> BoxWriter<W> {
        BoxWriter {
            inner,
            key,
            nonce,
            encryptor: Encryptor::new(),
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
}

impl<W: AsyncWrite> AsyncWrite for BoxWriter<W> {
    fn poll_write(&mut self, cx: &mut Context, buf: &[u8]) -> Poll<usize, Error> {
        self.encryptor
            .poll_write(cx, buf, &mut self.inner, &self.key, &mut self.nonce)
    }

    fn poll_flush(&mut self, cx: &mut Context) -> Poll<(), Error> {
        self.encryptor
            .poll_flush(cx, &mut self.inner, &self.key, &mut self.nonce)
    }

    fn poll_close(&mut self, cx: &mut Context) -> Poll<(), Error> {
        self.encryptor
            .poll_close(cx, &mut self.inner, &self.key, &mut self.nonce)
    }
}
