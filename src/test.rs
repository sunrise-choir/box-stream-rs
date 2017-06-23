extern crate rand;

use super::*;

use std::io::Write; // , Read
use std::io::{Error, ErrorKind};
use std::collections::VecDeque;

use crypto::{CYPHER_HEADER_SIZE, MAX_PACKET_SIZE, MAX_PACKET_USIZE, PlainHeader};
use sodiumoxide::crypto::secretbox;

// use test::rand::Rand;
// use test::rand::distributions::{IndependentSample, Range};

// #[derive(Clone)]
// struct TestStream(VecDeque<u8>);
//
// impl Write for TestStream {
//     fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
//         // randomly choose whether to work perfectly, not write at all, error etc.
//         let rnd = f32::rand(&mut rand::thread_rng());
//         if rnd <= 0.1 {
//             return Err(Error::new(ErrorKind::Interrupted, "simulating Interrupted error"));
//         } else if rnd <= 0.2 {
//             return Err(Error::new(ErrorKind::WouldBlock, "simulating WouldBlock error"));
//         } else if rnd <= 0.4 && buf.len() >= 1 {
//             for byte in buf.iter().take(1) {
//                 self.0.push_back(*byte);
//             }
//
//             return Ok(1);
//         } else if rnd <= 0.6 && buf.len() >= 2 {
//             for byte in buf.iter().take(2) {
//                 self.0.push_back(*byte);
//             }
//
//             return Ok(2);
//         } else if rnd <= 0.8 {
//             let num = Range::new(0, buf.len()).ind_sample(&mut rand::thread_rng());
//
//             for byte in buf.iter().take(num) {
//                 self.0.push_back(*byte);
//             }
//
//             return Ok(num);
//         } else if rnd <= 0.9 {
//             for byte in buf {
//                 self.0.push_back(*byte)
//             }
//             return Ok(buf.len());
//         } else {
//             return Ok(0);
//         }
//     }
//
//     fn flush(&mut self) -> io::Result<()> {
//         Ok(())
//     }
// }
//
// impl Read for TestStream {
//     fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
//         // randomly choose whether to work perfectly, not read at all, error etc.
//         let rnd = f32::rand(&mut rand::thread_rng());
//         if rnd <= 0.1 {
//             return Err(Error::new(ErrorKind::Interrupted, "simulating Interrupted error"));
//         } else if rnd <= 0.2 {
//             return Err(Error::new(ErrorKind::WouldBlock, "simulating WouldBlock error"));
//         } else if rnd <= 0.4 && buf.len() >= 1 {
//             for i in 0..1 {
//                 buf[i] = self.0.pop_front().unwrap();
//             }
//             return Ok(1);
//         } else if rnd <= 0.6 && buf.len() >= 2 {
//             for i in 0..2 {
//                 buf[i] = self.0.pop_front().unwrap();
//             }
//             return Ok(2);
//         } else if rnd <= 0.8 && buf.len() > 0 {
//             let num: usize = Range::new(0, buf.len()).ind_sample(&mut rand::thread_rng());
//
//             for i in 0..num {
//                 buf[i] = self.0.pop_front().unwrap();
//             }
//
//             return Ok(num);
//         } else if rnd <= 0.9 {
//             for i in 0..buf.len() {
//                 buf[i] = self.0.pop_front().unwrap();
//             }
//             return Ok(buf.len());
//         } else {
//             return Ok(0);
//         }
//     }
// }
//
// // Check that the test streams themselves work correctly.
// // #[test]
// fn the_test_streams_work() {
//     sodiumoxide::init();
//
//     let length = 99;
//
//     let data = sodiumoxide::randombytes::randombytes(length);
//     let mut writer = TestStream(VecDeque::new());
//     let mut reader = TestStream(VecDeque::new());
//     let mut data_out: Vec<u8> = vec![0; length];
//
//     // TODO don't write everthing, write a random amount between 0 and 3 * MAX_PACKET_USIZE
//     let mut total_written = 0;
//     while total_written < length {
//         match writer.write(&data[total_written..]) {
//             Ok(written) => total_written += written,
//             Err(_) => {}
//         }
//     }
//
//     reader = writer.clone();
//
//     // TODO interleave reading and writing: For each write, perform two reads, then repeat until done
//     let mut total_read = 0;
//     while total_read < length {
//         match reader.read(&mut data_out[total_read..]) {
//             Ok(read) => {
//                 total_read += read;
//             }
//             Err(_) => {}
//         }
//     }
//
//     for (i, byte) in data_out.iter().enumerate() {
//         assert_eq!(*byte, data[i]);
//     }
// }
//
// // Encrypt and decrypt data across test readers and writers, resulting in the identity function.
// // #[test]
// fn encrypt_decrypt() {
//     sodiumoxide::init();
//
//     let length = 99999;
//
//     let data = sodiumoxide::randombytes::randombytes(length);
//     let mut inner_writer = TestStream(VecDeque::new());
//     let mut inner_reader = TestStream(VecDeque::new());
//     let mut data_out: Vec<u8> = vec![0; length];
//
//     let key1 = sodiumoxide::crypto::secretbox::gen_key();
//     let key2 = key1.clone();
//     let mut nonce1 = sodiumoxide::crypto::secretbox::gen_nonce();
//     let mut nonce2 = nonce1.clone();
//
//     let mut writer = Boxer::new(inner_writer, key1, nonce1);
//
//     let mut total_written = 0;
//     while total_written < length {
//         match writer.write(&data[total_written..]) {
//             Ok(written) => total_written += written,
//             Err(_) => {}
//         }
//     }
//
//     inner_reader = writer.into_inner().clone();
//
//     let mut reader = Unboxer::new(inner_reader, key2, nonce2);
//
//     let mut total_read = 0;
//     while total_read < length {
//         match reader.read(&mut data_out[total_read..]) {
//             Ok(read) => {
//                 total_read += read;
//             }
//             Err(_) => {}
//         }
//     }
//
//     for (i, byte) in data_out.iter().enumerate() {
//         assert_eq!(*byte, data[i]);
//     }
// }

struct TestWriter {
    data: Vec<u8>,
    mode_queue: VecDeque<TestWriterMode>,
    flush_count: usize,
}

// Determines how a test writer should react to a write call
enum TestWriterMode {
    Error(io::Error),
    Write(usize),
}

impl TestWriter {
    fn new() -> TestWriter {
        TestWriter {
            data: Vec::new(),
            mode_queue: VecDeque::new(),
            flush_count: 0,
        }
    }

    fn push(&mut self, mode: TestWriterMode) {
        self.mode_queue.push_front(mode)
    }

    fn inner(&self) -> &Vec<u8> {
        &self.data
    }

    fn get_flush_count(&self) -> usize {
        self.flush_count
    }
}

impl Write for TestWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.mode_queue.pop_back().unwrap() {
            TestWriterMode::Error(e) => return Err(e),
            TestWriterMode::Write(length) => {
                for byte in buf.iter().take(length) {
                    self.data.push(*byte);
                }
                return Ok(cmp::min(length, buf.len()));
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_count += 1;
        Ok(())
    }
}

// underlying writer errors => Boxer propagates the error
#[test]
fn test_writer_error() {
    let key = sodiumoxide::crypto::secretbox::gen_key();
    let nonce = sodiumoxide::crypto::secretbox::gen_nonce();

    let mut w = TestWriter::new();
    w.push(TestWriterMode::Error(Error::new(ErrorKind::Interrupted,
                                            "simulating Interrupted error")));
    w.push(TestWriterMode::Error(Error::new(ErrorKind::WouldBlock, "simulating WouldBlock error")));
    w.push(TestWriterMode::Error(Error::new(ErrorKind::NotFound, "simulating NotFound error")));

    let mut b = Boxer::new(w, key, nonce);

    assert_eq!(b.write(&[0; 8]).unwrap_err().kind(), ErrorKind::Interrupted);
    assert_eq!(b.write(&[0; 8]).unwrap_err().kind(), ErrorKind::WouldBlock);
    assert_eq!(b.write(&[0; 8]).unwrap_err().kind(), ErrorKind::NotFound);
}

// write more than underlying writer can accept but less than MAX_PACKET_USIZE => writer buffers encrypted data and on subsequent writes ignores its input and writes from the buffer instead (returning 0)
#[test]
fn test_writer_slow() {
    let key = sodiumoxide::crypto::secretbox::gen_key();
    let nonce = sodiumoxide::crypto::secretbox::gen_nonce();

    let mut w = TestWriter::new();
    for write_size in &[8 + CYPHER_HEADER_SIZE,
                        0,
                        4,
                        0,
                        4,
                        0,
                        8 + CYPHER_HEADER_SIZE,
                        8 + CYPHER_HEADER_SIZE,
                        8 + CYPHER_HEADER_SIZE,
                        CYPHER_HEADER_SIZE - 8,
                        12,
                        CYPHER_HEADER_SIZE + 1] {
        w.push(TestWriterMode::Write(*write_size));
    }

    let mut b = Boxer::new(w, key, nonce);

    // push 16 <= MAX_PACKET_USIZE bytes, but w only writes 8, remaining 8 bytes are buffered
    assert_eq!(b.write(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
                   .unwrap(),
               16);
    // w does not write anything, still buffering 8 bytes and not consuming more input
    assert_eq!(b.write(&[16, 17, 18, 19]).unwrap(), 0);
    // w writes 4, still buffering 4 bytes and not consuming more input
    assert_eq!(b.write(&[16, 17, 18, 19]).unwrap(), 0);
    // w does not write anything, still buffering 4 bytes and not consuming more input
    assert_eq!(b.write(&[16, 17, 18, 19]).unwrap(), 0);
    // w writes 4, buffer becomes empty but does not yet consume more input
    assert_eq!(b.write(&[16, 17, 18, 19]).unwrap(), 0);
    // w writes 0, remaining 4 bytes are buffered
    assert_eq!(b.write(&[16, 17, 18, 19]).unwrap(), 4);
    // w is able to write 8, but is only given the 4 buffered bytes
    assert_eq!(b.write(&[20, 21, 22, 23]).unwrap(), 0);
    // w is able to write 8 and buffer is empty, so write all 4 <= 8 given bytes
    assert_eq!(b.write(&[24, 25, 26, 27]).unwrap(), 4);
    // w is able to write 8 and buffer is empty, so write all 4 <= 8 given bytes
    assert_eq!(b.write(&[28, 29, 30, 31]).unwrap(), 4);
    // w can not write the full header, buffers partial header and the payload
    assert_eq!(b.write(&[32, 33, 34, 35]).unwrap(), 4);
    // write the remaining header and the payload, buffer becomes empty
    assert_eq!(b.write(&[36]).unwrap(), 0);
    // buffer was emptied, now write the last byte
    assert_eq!(b.write(&[36]).unwrap(), 1);
}

// error propagation does not interfer with buffering
#[test]
fn test_writer_error_while_buffering() {
    let key = sodiumoxide::crypto::secretbox::gen_key();
    let nonce = sodiumoxide::crypto::secretbox::gen_nonce();

    let mut w = TestWriter::new();
    w.push(TestWriterMode::Write(0));
    w.push(TestWriterMode::Error(Error::new(ErrorKind::WouldBlock, "simulating WouldBlock error")));
    w.push(TestWriterMode::Write(4 + CYPHER_HEADER_SIZE));
    w.push(TestWriterMode::Write(0));

    let mut b = Boxer::new(w, key, nonce);

    // push 4 <= MAX_PACKET_USIZE bytes, but w only writes 0, remaining 4 bytes are buffered
    assert_eq!(b.write(&[0, 1, 2, 3]).unwrap(), 4);
    // w errors, but the buffer will be preserved for the next write
    assert_eq!(b.write(&[4, 5, 6, 7]).unwrap_err().kind(),
               ErrorKind::WouldBlock);
    // w writes 4, buffer is fully written
    assert_eq!(b.write(&[4, 5, 6, 7]).unwrap(), 0);
    // w writes 4 without a buffer, so consume all input
    assert_eq!(b.write(&[4, 5, 6, 7]).unwrap(), 4);
}

// write more than MAX_PACKET_USIZE => only buffer up to MAX_PACKET_USIZE, even if underlying writer could write more then MAX_PACKET_USIZE
#[test]
fn test_writer_larger_then_buffer() {
    let key = sodiumoxide::crypto::secretbox::gen_key();
    let nonce = sodiumoxide::crypto::secretbox::gen_nonce();

    let mut w = TestWriter::new();
    for write_size in &[4,
                        CYPHER_HEADER_SIZE + MAX_PACKET_USIZE,
                        CYPHER_HEADER_SIZE + MAX_PACKET_USIZE + 42,
                        CYPHER_HEADER_SIZE + 84] {
        w.push(TestWriterMode::Write(*write_size));
    }

    let mut b = Boxer::new(w, key, nonce);

    // write more than MAX_PACKET_USIZE => buffer MAX_PACKET_USIZE bytes, of which 4 get written to w
    assert_eq!(b.write(&[0; MAX_PACKET_USIZE + 1]).unwrap(),
               MAX_PACKET_USIZE);
    // buffered data is written to w
    assert_eq!(b.write(&[123, 456]).unwrap(), 0);
    // write more than MAX_PACKET_USIZE => Only MAX_PACKET_USIZE are consumed, even though w could write more
    assert_eq!(b.write(&[1; MAX_PACKET_USIZE + 42]).unwrap(),
               MAX_PACKET_USIZE);
    // buffer is empty now, so the next write can succeed immediately
    assert_eq!(b.write(&[2; 63]).unwrap(), 63);
}

#[test]
fn test_writer_flush() {
    let key = sodiumoxide::crypto::secretbox::gen_key();
    let nonce = sodiumoxide::crypto::secretbox::gen_nonce();

    let mut w = TestWriter::new();
    w.push(TestWriterMode::Write(0));
    w.push(TestWriterMode::Error(Error::new(ErrorKind::WouldBlock, "simulating WouldBlock error")));
    w.push(TestWriterMode::Write(2 + CYPHER_HEADER_SIZE));
    w.push(TestWriterMode::Write(2));

    let mut b = Boxer::new(w, key, nonce);

    // push 4 <= MAX_PACKET_USIZE bytes, but w only writes 0, remaining 4 + CYPHER_HEADER_SIZE bytes are buffered
    assert_eq!(b.write(&[0, 1, 2, 3]).unwrap(), 4);

    // call flush with buffered data
    // the next inner write errors, flush should propagate the error and not call inner.flush()
    assert_eq!(b.flush().unwrap_err().kind(), ErrorKind::WouldBlock);
    assert_eq!(b.get_ref().get_flush_count(), 0);
    // the next flush flushes the buffer (needing two reads) and then calls inner.flush()
    assert_eq!(b.flush().unwrap(), ());
    assert_eq!(b.get_ref().get_flush_count(), 1);
}

#[test]
fn test_writer_shutdown() {
    let key = sodiumoxide::crypto::secretbox::gen_key();
    let nonce = sodiumoxide::crypto::secretbox::gen_nonce();

    let mut w = TestWriter::new();
    w.push(TestWriterMode::Write(0));
    w.push(TestWriterMode::Error(Error::new(ErrorKind::WouldBlock, "simulating WouldBlock error")));
    w.push(TestWriterMode::Write(2 + CYPHER_HEADER_SIZE));
    w.push(TestWriterMode::Write(2));
    w.push(TestWriterMode::Write(CYPHER_HEADER_SIZE - 2));
    w.push(TestWriterMode::Write(1));
    w.push(TestWriterMode::Write(9999));

    let mut b = Boxer::new(w, key, nonce);

    // push 4 <= MAX_PACKET_USIZE bytes, but w only writes 0, remaining 4 + CYPHER_HEADER_SIZE bytes are buffered
    assert_eq!(b.write(&[0, 1, 2, 3]).unwrap(), 4);

    // call shutdown with buffered data
    // the next inner write errors, shutdown should propagate the error and not call inner.flush()
    assert_eq!(b.shutdown().unwrap_err().kind(), ErrorKind::WouldBlock);
    assert_eq!(b.get_ref().get_flush_count(), 0);
    // the next shutdown flushes the buffer (needing two reads) and then calls inner.flush()
    assert_eq!(b.shutdown().unwrap(), ());
    assert_eq!(b.get_ref().get_flush_count(), 1);
    assert_eq!(b.get_ref().inner().len(), 4 + 2 * CYPHER_HEADER_SIZE);
}

struct TestReader<'a> {
    data: Vec<u8>,
    mode_queue: VecDeque<TestReaderMode<'a>>,
}

// Determines how a test reader should react to a read call
enum TestReaderMode<'a> {
    Error(io::Error),
    Read(&'a [u8]),
}

impl<'a> TestReader<'a> {
    fn new() -> TestReader<'a> {
        TestReader {
            data: Vec::new(),
            mode_queue: VecDeque::new(),
        }
    }

    fn push(&mut self, mode: TestReaderMode<'a>) {
        self.mode_queue.push_front(mode)
    }

    fn inner(&self) -> &Vec<u8> {
        &self.data
    }
}

impl<'a> Read for TestReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.mode_queue.pop_back().unwrap() {
            TestReaderMode::Error(e) => return Err(e),
            TestReaderMode::Read(data) => {
                let mut count = 0;
                for (i, byte) in data.iter().take(buf.len()).enumerate() {
                    buf[i] = *byte;
                    count += 1;
                }
                println!("TestReader: Read {:?}", count);
                return Ok(cmp::min(data.len(), buf.len()));
            }
        }
    }
}

// Some test data TODO remove this when not needed anymore
// let header1 = [181u8, 28, 106, 117, 226, 186, 113, 206, 135, 153, 250, 54, 221, 225, 178, 211,
//                144, 190, 14, 102, 102, 246, 118, 54, 195, 34, 174, 182, 190, 45, 129, 48, 96,
//                193];
// let data1 = [231u8, 234, 80, 195, 113, 173, 5, 158];
// let header2 = [227u8, 230, 249, 230, 176, 170, 49, 34, 220, 29, 156, 118, 225, 243, 7, 3, 163,
//                197, 125, 225, 240, 111, 195, 126, 240, 148, 201, 237, 158, 158, 134, 224, 246,
//                137];
// let data2 = [22u8, 134, 141, 191, 19, 113, 211, 114];

// underlying writer errors => Boxer propagates the error
#[test]
fn test_reader_error() {
    let key = sodiumoxide::crypto::secretbox::gen_key();
    let nonce = sodiumoxide::crypto::secretbox::gen_nonce();

    let mut r = TestReader::new();
    r.push(TestReaderMode::Error(Error::new(ErrorKind::Interrupted,
                                            "simulating Interrupted error")));
    r.push(TestReaderMode::Error(Error::new(ErrorKind::WouldBlock, "simulating WouldBlock error")));
    r.push(TestReaderMode::Error(Error::new(ErrorKind::NotFound, "simulating NotFound error")));

    let mut u = Unboxer::new(r, key, nonce);

    assert_eq!(u.read(&mut [0; 8]).unwrap_err().kind(),
               ErrorKind::Interrupted);
    assert_eq!(u.read(&mut [0; 8]).unwrap_err().kind(),
               ErrorKind::WouldBlock);
    assert_eq!(u.read(&mut [0; 8]).unwrap_err().kind(), ErrorKind::NotFound);
}

// read slower than the underlying reader => encrypted data is buffered
#[test]
fn test_reader_slow_consumer() {
    let data = [
        181u8, 28, 106, 117, 226, 186, 113, 206, 135, 153, 250, 54, 221, 225, 178, 211,
        144, 190, 14, 102, 102, 246, 118, 54, 195, 34, 174, 182, 190, 45, 129, 48, 96,
        193, // end header 1, index: 34
        231, 234, 80, 195, 113, 173, 5, 158, // end data 1, index: 42
        227, 230, 249, 230, 176, 170, 49, 34, 220, 29, 156, 118, 225, 243, 7, 3, 163,
        197, 125, 225, 240, 111, 195, 126, 240, 148, 201, 237, 158, 158, 134, 224, 246,
        137, // end header 2, index: 76
        22u8, 134, 141, 191, 19, 113, 211, 114 // end data 2, index: 84
    ];

    let key = secretbox::Key([162u8, 29, 153, 150, 123, 225, 10, 173, 175, 201, 160, 34, 190,
                              179, 158, 14, 176, 105, 232, 238, 97, 66, 133, 194, 250, 148, 199,
                              7, 34, 157, 174, 24]);
    let nonce = secretbox::Nonce([44, 140, 79, 227, 23, 153, 202, 203, 81, 40, 114, 59, 56, 167,
                                  63, 166, 201, 9, 50, 152, 0, 255, 226, 147]);

    let mut r = TestReader::new();
    r.push(TestReaderMode::Read(&data[..])); // only one read is needed since both packets fit into the internal buffer

    let mut u = Unboxer::new(r, key, nonce);
    let mut buf = [0u8; 6];

    // read 6 bytes: internally, read all data
    assert_eq!(u.read(&mut buf).unwrap(), 6);
    assert_eq!(buf, [0, 1, 2, 3, 4, 5]);
    // read the next 6 bytes (across packet boundaries)
    assert_eq!(u.read(&mut buf).unwrap(), 6);
    assert_eq!(buf, [6, 7, 7, 6, 5, 4]);
    // try to read 6 more bytes, but only 4 are available
    assert_eq!(u.read(&mut buf).unwrap(), 4);
    assert_eq!(buf[..4], [3, 2, 1, 0]);
}

// read slower than the underlying reader => encrypted data is buffered
#[test]
fn test_reader_slow_inner() {
    let data = [
        181u8, 28, 106, 117, 226, 186, 113, 206, 135, 153, 250, 54, 221, 225, 178, 211,
        144, 190, 14, 102, 102, 246, 118, 54, 195, 34, 174, 182, 190, 45, 129, 48, 96,
        193, // end header 1, index: 34
        231, 234, 80, 195, 113, 173, 5, 158, // end data 1, index: 42
        227, 230, 249, 230, 176, 170, 49, 34, 220, 29, 156, 118, 225, 243, 7, 3, 163,
        197, 125, 225, 240, 111, 195, 126, 240, 148, 201, 237, 158, 158, 134, 224, 246,
        137, // end header 2, index: 76
        22u8, 134, 141, 191, 19, 113, 211, 114 // end data 2, index: 84
    ];

    let key = secretbox::Key([162u8, 29, 153, 150, 123, 225, 10, 173, 175, 201, 160, 34, 190,
                              179, 158, 14, 176, 105, 232, 238, 97, 66, 133, 194, 250, 148, 199,
                              7, 34, 157, 174, 24]);
    let nonce = secretbox::Nonce([44, 140, 79, 227, 23, 153, 202, 203, 81, 40, 114, 59, 56, 167,
                                  63, 166, 201, 9, 50, 152, 0, 255, 226, 147]);

    let mut r = TestReader::new();
    r.push(TestReaderMode::Read(&data[0..16]));
    r.push(TestReaderMode::Read(&data[16..32]));
    r.push(TestReaderMode::Error(Error::new(ErrorKind::WouldBlock, "simulating WouldBlock error")));
    r.push(TestReaderMode::Read(&data[32..48]));
    r.push(TestReaderMode::Read(&data[48..64]));
    r.push(TestReaderMode::Read(&data[64..80]));
    r.push(TestReaderMode::Read(&data[80..84]));

    let mut u = Unboxer::new(r, key, nonce);
    let mut buf = [0u8; 6];

    // Read, but inner reader is too slow
    assert_eq!(u.read(&mut buf).unwrap(), 0);
    assert_eq!(u.read(&mut buf).unwrap(), 0);
    assert_eq!(u.read(&mut buf).unwrap_err().kind(), ErrorKind::WouldBlock);
    assert_eq!(u.read(&mut buf).unwrap(), 6);
    assert_eq!(buf, [0, 1, 2, 3, 4, 5]);
    // read the next 6 bytes, but only two are available
    assert_eq!(u.read(&mut buf).unwrap(), 2);
    assert_eq!(buf[..2], [6, 7]);
    // next inner call to read should happen here
    // read the next 6 bytes
    assert_eq!(u.read(&mut buf).unwrap(), 0);
    assert_eq!(u.read(&mut buf).unwrap(), 0);
    assert_eq!(u.read(&mut buf).unwrap(), 6);
    assert_eq!(buf, [7, 6, 5, 4, 3, 2]);
    // read the last 2 bytes, which are buffered already
    assert_eq!(u.read(&mut buf).unwrap(), 2);
    assert_eq!(buf[..2], [1, 0]);
}

// - slow consumer: read slower than inner, the last read could then read more than available
// - slow inner: read calls return 0 until buffer could read enough

// ## Unboxer TODO write these tests
// - underlying reader errors -> Unboxer propagates the error
// - read more than underlying reader offers -> only read as much as possible, across packat boundaries
// - read more than MAX_PACKET_USIZE -> only fill and return MAX_PACKET_USIZE
// - read not enough to decrypt -> buffer read bytes and return/fill 0
//   - when the buffer contains a fully decryptable message, return it (on the same read)

// How Boxer and Unboxer work
//
// ## Boxer
// - encrypt given data (at max MAX_PACKET_USIZE bytes) and put the encrypted data into a buffer
// - then ignore all further input until the buffer has been fully written to the underlying writer
//
// ## Unboxer
// - read the encrypted data into a buffer (at most CYPHER_HEADER_SIZE + MAX_PACKET_USIZE)
// - when the buffer contains a full header, decrypt the header in-place
// - then, read further data (if needed) until a full encrypted message is in the buffer
// - decrypt the message in-place and return it on reads
// - when the buffered message has been fully read, pull more data from the underlying reader

// TODO test that composing boxer and unboxer yields the identity stream, use randomly behaving underlying writer and reader
