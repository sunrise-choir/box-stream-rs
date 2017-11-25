use super::*;

use std::cmp;
use std::io;
use std::io::{Write, Read};
use std::io::{Error, ErrorKind};

use crypto::{CYPHER_HEADER_SIZE, MAX_PACKET_USIZE};
use tokio_io::{AsyncRead, AsyncWrite};
use futures::{Poll, Async, Future};

use partial_io::{PartialOp, PartialAsyncRead, PartialAsyncWrite, PartialWithErrors};
use partial_io::quickcheck_types::GenInterruptedWouldBlock;
use quickcheck::{QuickCheck, StdGen};
use async_ringbuffer::*;
use rand;

// TODO utils
/// A duplex stream for testing: it records all writes to it, and reads return predefined data
#[derive(Debug)]
struct TestDuplex<'a> {
    writes: Vec<u8>,
    read_data: &'a [u8],
}

impl<'a> TestDuplex<'a> {
    fn new(read_data: &'a [u8]) -> TestDuplex {
        TestDuplex {
            writes: Vec::new(),
            read_data,
        }
    }
}

impl<'a> Write for TestDuplex<'a> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        self.writes.write(buf)
    }

    fn flush(&mut self) -> Result<(), io::Error> {
        self.writes.flush()
    }
}

impl<'a> AsyncWrite for TestDuplex<'a> {
    fn shutdown(&mut self) -> Poll<(), io::Error> {
        Ok(Async::Ready(()))
    }
}

impl<'a> Read for TestDuplex<'a> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        self.read_data.read(buf)
    }
}

impl<'a> AsyncRead for TestDuplex<'a> {}

const NO_DATA: [u8; 0] = [];

#[test]
// A reader propagates io errors.
fn test_reader_io_error() {
    let key = sodiumoxide::crypto::secretbox::gen_key();
    let nonce = sodiumoxide::crypto::secretbox::gen_nonce();

    let r = TestDuplex::new(&NO_DATA);
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

    let r = TestDuplex::new(&NO_DATA);
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

    let inner = Vec::new();
    let mut b = BoxWriter::new(inner, key.clone(), nonce.clone());
    assert_eq!(b.write(&[0, 1, 2, 3]).unwrap(), 4);
    assert_eq!(b.write_final_header().unwrap(), ());
    let data = b.into_inner();

    let r = TestDuplex::new(&data);

    let mut b = BoxReader::new(r, key, nonce);

    assert_eq!(b.read(&mut [10, 20, 30, 40]).unwrap(), 4);
    assert_eq!(b.read(&mut []).unwrap(), 0);
}

#[test]
// A writer propagates io errors.
fn test_writer_io_error() {
    let key = sodiumoxide::crypto::secretbox::gen_key();
    let nonce = sodiumoxide::crypto::secretbox::gen_nonce();

    let w = TestDuplex::new(&NO_DATA);
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

        let w = TestDuplex::new(&NO_DATA);
        let w = PartialAsyncWrite::new(w, vec![PartialOp::Limited(0)]);

        let mut b = BoxWriter::new(w, key, nonce);

        assert_eq!(b.write(&[0, 1, 2, 3]).unwrap(), 4);
        assert_eq!(b.flush().unwrap_err().kind(), ErrorKind::WriteZero);
    }

    {
        let key = sodiumoxide::crypto::secretbox::gen_key();
        let nonce = sodiumoxide::crypto::secretbox::gen_nonce();

        let w = TestDuplex::new(&NO_DATA);
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

        let w = TestDuplex::new(&NO_DATA);
        let w = PartialAsyncWrite::new(w, vec![PartialOp::Limited(0)]);

        let mut b = BoxWriter::new(w, key, nonce);

        assert_eq!(b.shutdown().unwrap_err().kind(), ErrorKind::WriteZero);
    }

    {
        let key = sodiumoxide::crypto::secretbox::gen_key();
        let nonce = sodiumoxide::crypto::secretbox::gen_nonce();

        let w = TestDuplex::new(&NO_DATA);
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
        println!("");
        println!("sender counter: {}", self.counter);
        if self.counter > 0 {
            println!("sender write with buffer {}",
                     cmp::min(self.counter,
                              (CYPHER_HEADER_SIZE + MAX_PACKET_USIZE + 210) * 2));
            match self.w
                      .write(&self.buffer[0..
                              cmp::min(self.counter,
                                       (CYPHER_HEADER_SIZE + MAX_PACKET_USIZE + 210) *
                                       2)]) {
                Ok(written) => {
                    assert!(written != 0);
                    self.counter -= written;

                    let should_flush = rand::random::<f64>();
                    if should_flush < 0.2 {
                        match self.w.flush() {
                            Ok(_) => {
                                println!("flushed in sender");
                            }
                            Err(e) => {
                                if e.kind() == ErrorKind::WouldBlock {
                                    return Ok(Async::NotReady);
                                } else {
                                    println!("SenderFlushError: {:?}", e);
                                    return Err(e);
                                }
                            }
                        }
                    }

                    return self.poll();
                }
                Err(e) => {
                    if e.kind() == ErrorKind::WouldBlock {
                        return Ok(Async::NotReady);
                    } else {
                        println!("SenderWriteError: {:?}", e);
                        return Err(e);
                    }
                }
            }
        } else {
            println!("begin shutdown in sender");
            match self.w.shutdown() {
                Ok(Async::Ready(_)) => {
                    println!("sender shutdown");
                    return Ok(Async::Ready(()));
                }
                Ok(Async::NotReady) => return Ok(Async::NotReady),
                Err(e) => {
                    if e.kind() == ErrorKind::WouldBlock {
                        println!("WouldBlock in test_sender_shutdown");
                        return Ok(Async::NotReady);
                    } else {
                        println!("SenderShutdownError: {:?}", e);
                        return Err(e);
                    }
                }
            }
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
        match self.r.read(&mut self.buffer[0..]) {
            Ok(read) => {
                println!("receiver: read {} at counter {}", read, self.counter);
                if read == 0 {
                    assert_eq!(self.counter, self.expected);
                    return Ok(Async::Ready(()));
                }

                self.counter += read;
                println!("new receiver counter: {}", self.counter);

                for byte in self.buffer[0..read].iter() {
                    assert_eq!(*byte, 42u8);
                }
                for i in 0..read {
                    self.buffer[i] = 0;
                }

                return self.poll();
            }
            Err(e) => {
                if e.kind() == ErrorKind::WouldBlock {
                    println!("receiver wouldblock");
                    return Ok(Async::NotReady);
                } else {
                    println!("ReceiverError: {:?}", e);
                    println!("");
                    println!("");
                    return Err(e);
                }
            }
        }
    }
}

#[test]
fn test_success() {
    let rng = StdGen::new(rand::thread_rng(),
                          (CYPHER_HEADER_SIZE + MAX_PACKET_USIZE + 200) * 2);
    let mut quickcheck = QuickCheck::new().gen(rng).tests(500); // TODO more runs
    quickcheck.quickcheck(success as
                          fn(PartialWithErrors<GenInterruptedWouldBlock>,
                             PartialWithErrors<GenInterruptedWouldBlock>)
                             -> bool);
}

fn success(write_ops: PartialWithErrors<GenInterruptedWouldBlock>,
           read_ops: PartialWithErrors<GenInterruptedWouldBlock>)
           -> bool {
    let key = sodiumoxide::crypto::secretbox::gen_key();
    let nonce = sodiumoxide::crypto::secretbox::gen_nonce();

    let (writer, reader) = ring_buffer((CYPHER_HEADER_SIZE + MAX_PACKET_USIZE + 50) * 2);
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
