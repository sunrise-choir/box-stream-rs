use super::*;

use std::cmp;
use std::io::{Write, Read};
use std::io::{Error, ErrorKind};

use crypto::{CYPHER_HEADER_SIZE, MAX_PACKET_USIZE};
use tokio_io::{AsyncRead, AsyncWrite};
use atm_io_utils::MockDuplex;
use futures::{Poll, Async, Future};

use partial_io::{PartialOp, PartialAsyncRead, PartialAsyncWrite, PartialWithErrors};
use partial_io::quickcheck_types::GenInterruptedWouldBlock;
use quickcheck::{QuickCheck, StdGen};
use async_ringbuffer::*;
use rand;

#[test]
// A reader propagates io errors.
fn test_reader_io_error() {
    let key = sodiumoxide::crypto::secretbox::gen_key();
    let nonce = sodiumoxide::crypto::secretbox::gen_nonce();

    let r = MockDuplex::new();
    let r = PartialAsyncRead::new(r,
                                  vec![PartialOp::Err(ErrorKind::NotFound),
                                       PartialOp::Err(ErrorKind::UnexpectedEof)]);

    let mut b = BoxReader::new(r, key, nonce);

    assert_eq!(b.read(&mut []).unwrap_err().kind(), ErrorKind::NotFound);
    assert_eq!(b.read(&mut []).unwrap_err().kind(),
               ErrorKind::UnexpectedEof);
}

#[test]
// A reader that reads 0 bytes errors with UnexpectedEof.
fn test_reader_read0() {
    let key = sodiumoxide::crypto::secretbox::gen_key();
    let nonce = sodiumoxide::crypto::secretbox::gen_nonce();

    let r = MockDuplex::new();
    let r = PartialAsyncRead::new(r, vec![PartialOp::Limited(0)]);

    let mut b = BoxReader::new(r, key, nonce);

    assert_eq!(b.read(&mut []).unwrap_err().kind(),
               ErrorKind::UnexpectedEof);
}

#[test]
// A reader that reads a final header signals it via read returning Ok(0).
fn test_reader_final_header() {
    let key = sodiumoxide::crypto::secretbox::gen_key();
    let nonce = sodiumoxide::crypto::secretbox::gen_nonce();

    let inner = MockDuplex::new();
    let mut b = BoxWriter::new(inner, key.clone(), nonce.clone());
    assert_eq!(b.write(&[0, 1, 2, 3]).unwrap(), 4);
    assert_eq!(b.write_final_header().unwrap(), ());
    let (_, writes_deque) = b.into_inner().into_inner();
    let (data, _) = writes_deque.as_slices();

    let mut r = MockDuplex::new();
    r.add_read_data(data);

    let mut b = BoxReader::new(r, key, nonce);

    assert_eq!(b.read(&mut [10, 20, 30, 40]).unwrap(), 4);
    assert_eq!(b.read(&mut []).unwrap(), 0);
}

#[test]
// A writer propagates io errors.
fn test_writer_io_error() {
    let key = sodiumoxide::crypto::secretbox::gen_key();
    let nonce = sodiumoxide::crypto::secretbox::gen_nonce();

    let w = MockDuplex::new();
    let w = PartialAsyncWrite::new(w,
                                   vec![PartialOp::Err(ErrorKind::NotFound),
                                        PartialOp::Err(ErrorKind::UnexpectedEof)]);

    let mut b = BoxWriter::new(w, key, nonce);

    assert_eq!(b.flush().unwrap_err().kind(), ErrorKind::NotFound);
    assert_eq!(b.flush().unwrap_err().kind(), ErrorKind::UnexpectedEof);
}

#[test]
// A writer errors WriteZero if writing to the underlying Write during flushing returns Ok(0).
fn test_writer_write0_flush() {
    {
        let key = sodiumoxide::crypto::secretbox::gen_key();
        let nonce = sodiumoxide::crypto::secretbox::gen_nonce();

        let w = MockDuplex::new();
        let w = PartialAsyncWrite::new(w, vec![PartialOp::Limited(0)]);

        let mut b = BoxWriter::new(w, key, nonce);

        assert_eq!(b.write(&[0, 1, 2, 3]).unwrap(), 4);
        assert_eq!(b.flush().unwrap_err().kind(), ErrorKind::WriteZero);
    }

    {
        let key = sodiumoxide::crypto::secretbox::gen_key();
        let nonce = sodiumoxide::crypto::secretbox::gen_nonce();

        let w = MockDuplex::new();
        let w = PartialAsyncWrite::new(w, vec![PartialOp::Limited(2), PartialOp::Limited(0)]);

        let mut b = BoxWriter::new(w, key, nonce);

        assert_eq!(b.write(&[0, 1, 2, 3]).unwrap(), 4);
        assert_eq!(b.flush().unwrap_err().kind(), ErrorKind::WriteZero);
    }
}

#[test]
// A writer errors WriteZero if writing to the underlying Write during shutdown returns Ok(0).
fn test_writer_write0_shutdown() {
    {
        let key = sodiumoxide::crypto::secretbox::gen_key();
        let nonce = sodiumoxide::crypto::secretbox::gen_nonce();

        let w = MockDuplex::new();
        let w = PartialAsyncWrite::new(w, vec![PartialOp::Limited(0)]);

        let mut b = BoxWriter::new(w, key, nonce);

        assert_eq!(b.shutdown().unwrap_err().kind(), ErrorKind::WriteZero);
    }

    {
        let key = sodiumoxide::crypto::secretbox::gen_key();
        let nonce = sodiumoxide::crypto::secretbox::gen_nonce();

        let w = MockDuplex::new();
        let w = PartialAsyncWrite::new(w, vec![PartialOp::Limited(2), PartialOp::Limited(0)]);

        let mut b = BoxWriter::new(w, key, nonce);

        assert_eq!(b.shutdown().unwrap_err().kind(), ErrorKind::WriteZero);
    }
}

struct TestSender<W> {
    w: W,
    counter: usize,
    buffer: [u8; (CYPHER_HEADER_SIZE + MAX_PACKET_USIZE + 210) * 2],
}

impl<W> TestSender<W> {
    fn new(w: W, counter: usize) -> TestSender<W> {
        TestSender {
            w,
            counter,
            buffer: [42; (CYPHER_HEADER_SIZE + MAX_PACKET_USIZE + 210) * 2],
        }
    }
}

impl<W: AsyncWrite> Future for TestSender<W> {
    type Item = ();
    type Error = Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        if self.counter > 0 {
            let written = try_nb!(self.w
                                      .write(&self.buffer[0..
                                              cmp::min(self.counter,
                                                       (CYPHER_HEADER_SIZE + MAX_PACKET_USIZE +
                                                        210) *
                                                       2)]));

            assert!(written != 0);
            self.counter -= written;

            let should_flush = rand::random::<f64>();
            if should_flush < 0.2 {
                try_nb!(self.w.flush());
            }

            return self.poll();
        } else {
            return self.w.shutdown();
        }
    }
}

struct TestReceiver<R> {
    r: R,
    counter: usize,
    expected: usize,
    buffer: [u8; (CYPHER_HEADER_SIZE + MAX_PACKET_USIZE + 210) * 2],
}

impl<R> TestReceiver<R> {
    fn new(r: R, expected: usize) -> TestReceiver<R> {
        TestReceiver {
            r,
            counter: 0,
            expected,
            buffer: [0; (CYPHER_HEADER_SIZE + MAX_PACKET_USIZE + 210) * 2],
        }
    }
}

impl<R: AsyncRead> Future for TestReceiver<R> {
    type Item = ();
    type Error = Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let read = try_nb!(self.r.read(&mut self.buffer[0..]));

        if read == 0 {
            assert_eq!(self.counter, self.expected);
            return Ok(Async::Ready(()));
        }

        self.counter += read;

        for byte in self.buffer[0..read].iter() {
            assert_eq!(*byte, 42u8);
        }
        for i in 0..read {
            self.buffer[i] = 0;
        }

        return self.poll();
    }
}

#[test]
fn test_success() {
    let rng = StdGen::new(rand::thread_rng(),
                          (CYPHER_HEADER_SIZE + MAX_PACKET_USIZE + 200) * 2);
    let mut quickcheck = QuickCheck::new().gen(rng).tests(500);
    quickcheck.quickcheck(success as
                          fn(usize,
                             PartialWithErrors<GenInterruptedWouldBlock>,
                             PartialWithErrors<GenInterruptedWouldBlock>)
                             -> bool);
}

fn success(buf_size: usize,
           write_ops: PartialWithErrors<GenInterruptedWouldBlock>,
           read_ops: PartialWithErrors<GenInterruptedWouldBlock>)
           -> bool {
    let key = sodiumoxide::crypto::secretbox::gen_key();
    let nonce = sodiumoxide::crypto::secretbox::gen_nonce();

    let (writer, reader) = ring_buffer(buf_size);
    let w = BoxWriter::new(PartialAsyncWrite::new(writer, write_ops),
                           key.clone(),
                           nonce.clone());
    let r = BoxReader::new(PartialAsyncRead::new(reader, read_ops),
                           key.clone(),
                           nonce.clone());

    let test_sender = TestSender::new(w, 4096 * 32);
    let test_receiver = TestReceiver::new(r, 4096 * 32);

    let (_, _) = test_sender.join(test_receiver).wait().unwrap();
    return true;
}
