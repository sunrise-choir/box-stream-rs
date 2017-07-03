extern crate rand;

use super::*;

use std::io::Write; // , Read
use std::io::{Error, ErrorKind};
use std::collections::VecDeque;

use crypto::{CYPHER_HEADER_SIZE, MAX_PACKET_SIZE, MAX_PACKET_USIZE, PlainHeader, decrypt_header,
             decrypt_packet};
use sodiumoxide::crypto::secretbox;

use test::rand::Rand;
use test::rand::distributions::{IndependentSample, Range};

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

    fn remaining_writes(&self) -> usize {
        self.mode_queue.len()
    }
}

impl Write for TestWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.mode_queue.pop_back() {
            Some(mode) => {
                match mode {
                    TestWriterMode::Error(e) => return Err(e),
                    TestWriterMode::Write(length) => {
                        for byte in buf.iter().take(length) {
                            self.data.push(*byte);
                        }
                        return Ok(cmp::min(length, buf.len()));
                    }
                }
            }
            None => self.data.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_count += 1;
        Ok(())
    }
}

// underlying writer errors => Boxer propagates the error
// #[test]
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
// #[test]
fn test_writer_slow() {
    let key = secretbox::Key([162u8, 29, 153, 150, 123, 225, 10, 173, 175, 201, 160, 34, 190,
                              179, 158, 14, 176, 105, 232, 238, 97, 66, 133, 194, 250, 148, 199,
                              7, 34, 157, 174, 24]);
    let nonce = secretbox::Nonce([44, 140, 79, 227, 23, 153, 202, 203, 81, 40, 114, 59, 56, 167,
                                  63, 166, 201, 9, 50, 152, 0, 255, 226, 147]);

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
    assert_eq!(b.write(&[20, 21, 22, 23]).unwrap(), 0); // 20..23 is never written
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

    let expected_cyphertext = [61u8, 15, 75, 215, 49, 221, 145, 94, 210, 86, 132, 5, 19, 245, 207,
                                163, 144, 166, 202, 157, 144, 125, 36, 237, 220, 243, 133, 48, 64,
                                121, 61, 129, 78, 169, // end of first cypher_header
                                231, 234, 80, 195, 113, 173, 5, 158, 68, 87,
                                13, 241, 200, 89, 252, 34, // end of first packet
                                95, 207, 184, 63, 123, 43, 109, 237, 152, 124, 246, 140, 225, 220, 127, 245, 163, 201, 42, 164, 121, 84, 82, 21, 210, 18, 28, 193, 112, 92, 94, 16, 51, 30, // end of 2nd header
                                1, 145, 154, 168, // end of 2nd packet
                                228, 160, 88, 229, 5, 90, 216, 89, 132, 168, 50, 140, 198, 168, 75, 23, 194, 193, 144, 27, 38, 172, 205, 94, 88, 246, 108, 158, 14, 236, 33, 181, 17, 105, // end of 3rd header
                                101, 0, 171, 8, // end of 3rd packet
                                226, 89, 192, 220, 247, 198, 210, 14, 22, 248, 202, 211, 215, 16, 105, 81, 72, 143, 123, 179, 193, 142, 129, 69, 190, 21, 6, 181, 143, 117, 52, 64, 189, 43, // end of 4th header
                                211, 129, 89, 114, // end of 4th packet
                                39, 213, 72, 104, 107, 122, 225, 122, 88, 83, 134, 58, 108, 252, 169, 238, 21, 59, 181, 139, 104, 159, 159, 28, 24, 133, 238, 208, 201, 76, 18, 109, 222, 228, // end of 5th header
                                200, 107, 197, 134, // end of 5th packet
                                146, 221, 154, 151, 159, 226, 234, 187, 46, 165, 165, 221, 14, 13, 154, 8, 61, 45, 28, 29, 45, 15, 121, 27, 89, 254, 131, 70, 68, 127, 117, 220, 145, 118, // end of 6th header
                                229, // end of 6th packet
                              ];

    // check the produced cyphertext
    assert_eq!(b.into_inner().data[..], expected_cyphertext[..]);
}

// error propagation does not interfer with buffering
// #[test]
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
// #[test]
fn test_writer_larger_then_buffer() {
    let key = secretbox::Key([162u8, 29, 153, 150, 123, 225, 10, 173, 175, 201, 160, 34, 190,
                              179, 158, 14, 176, 105, 232, 238, 97, 66, 133, 194, 250, 148, 199,
                              7, 34, 157, 174, 24]);
    let nonce = secretbox::Nonce([44, 140, 79, 227, 23, 153, 202, 203, 81, 40, 114, 59, 56, 167,
                                  63, 166, 201, 9, 50, 152, 0, 255, 226, 147]);

    let mut w = TestWriter::new();
    for write_size in &[CYPHER_HEADER_SIZE + MAX_PACKET_USIZE,
                        CYPHER_HEADER_SIZE + MAX_PACKET_USIZE] {
        w.push(TestWriterMode::Write(*write_size));
    }

    let mut b = Boxer::new(w, key, nonce);

    let plain_data = [0u8; MAX_PACKET_USIZE + 42];

    // write more than MAX_PACKET_USIZE => CYPHER_HEADER_SIZE + MAX_PACKET_USIZE get written to w
    assert_eq!(b.write(&plain_data[..]).unwrap(), MAX_PACKET_USIZE);
    assert_eq!(b.write(&plain_data[MAX_PACKET_USIZE..]).unwrap(), 42);

    let expected_cyphertext =
        [19, 249, 30, 100, 146, 232, 74, 49, 176, 123, 152, 216, 219, 226, 92, 225, 163, 231, 125,
         1, 136, 38, 195, 181, 101, 192, 136, 180, 67, 159, 242, 67, 211, 5, 17, 128, 136, 187,
         16, 115, 210, 114, 135, 93, 112, 234, 37, 90, 179, 149, 175, 241, 3, 40, 2, 154, 233,
         180, 200, 45, 28, 5, 17, 83, 19, 144, 47, 158, 212, 86, 132, 18, 230, 200, 28, 238];

    assert_eq!(b.into_inner().data[CYPHER_HEADER_SIZE + MAX_PACKET_USIZE..],
               expected_cyphertext[..]);
}

// write more than MAX_PACKET_USIZE => only buffer up to MAX_PACKET_USIZE, even if underlying writer could write more then MAX_PACKET_USIZE
// #[test]
fn test_writer_larger_then_buffer_fancy() {
    let key = secretbox::Key([162u8, 29, 153, 150, 123, 225, 10, 173, 175, 201, 160, 34, 190,
                              179, 158, 14, 176, 105, 232, 238, 97, 66, 133, 194, 250, 148, 199,
                              7, 34, 157, 174, 24]);
    let nonce = secretbox::Nonce([44, 140, 79, 227, 23, 153, 202, 203, 81, 40, 114, 59, 56, 167,
                                  63, 166, 201, 9, 50, 152, 0, 255, 226, 147]);

    let mut w = TestWriter::new();
    for write_size in &[4,
                        CYPHER_HEADER_SIZE + MAX_PACKET_USIZE,
                        CYPHER_HEADER_SIZE + MAX_PACKET_USIZE + 42,
                        CYPHER_HEADER_SIZE + 200] {
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
    assert_eq!(b.write(&[2; 64]).unwrap(), 64);

    let expected_cyphertext = [220u8, 125, 131, 229, 3, 70, 236, 229, 35, 197, 228, 69, 47, 71,
                               141, 69, 194, 133, 204, 239, 127, 152, 1, 59, 108, 140, 163, 94,
                               199, 10, 229, 200, 237, 154, 127, 27, 179, 17, 125, 177, 213, 115,
                               203, 34, 79, 137, 110, 213, 167, 152, 177, 7, 133, 62, 110, 151,
                               231, 255, 65, 204, 40, 72, 139, 241, 195, 143, 61, 233, 106, 118,
                               143, 166, 252, 37, 235, 178, 211, 240, 46, 5, 213, 213, 75, 161,
                               72, 135, 215, 229, 186, 103, 62, 254, 137, 168, 243, 221, 225, 83];

    assert_eq!(b.into_inner().data[(CYPHER_HEADER_SIZE + MAX_PACKET_USIZE) * 2..],
               expected_cyphertext[..]);
}

// #[test]
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

// #[test]
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
    // data: Vec<u8>,
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
            // data: Vec::new(),
            mode_queue: VecDeque::new(),
        }
    }

    fn push(&mut self, mode: TestReaderMode<'a>) {
        self.mode_queue.push_front(mode)
    }
    //
    // fn inner(&self) -> &Vec<u8> {
    //     &self.data
    // }
    //
    // fn inner_mut(&mut self) -> &mut Vec<u8> {
    //     &mut self.data
    // }
}

impl<'a> Read for TestReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.mode_queue.pop_back() {
            None => Err(Error::new(ErrorKind::UnexpectedEof, "reached end of TestReader")),
            Some(mode) => {
                match mode {
                    TestReaderMode::Error(e) => return Err(e),
                    TestReaderMode::Read(data) => {
                        let mut count = 0;
                        for (i, byte) in data.iter().take(buf.len()).enumerate() {
                            buf[i] = *byte;
                            count += 1;
                        }
                        return Ok(cmp::min(data.len(), buf.len()));
                    }
                }
            }
        }
    }
}

// underlying writer errors => Boxer propagates the error
// #[test]
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
// #[test]
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
// #[test]
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

// read more than one packet in one go
// #[test]
fn test_reader_fast() {
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
    r.push(TestReaderMode::Read(&data));

    let mut u = Unboxer::new(r, key, nonce);
    let mut buf = [0u8; 32];

    assert_eq!(u.read(&mut buf).unwrap(), 16);
    assert_eq!(buf[..16],
               [0u8, 1, 2, 3, 4, 5, 6, 7, 7, 6, 5, 4, 3, 2, 1, 0]);
}

// read more than one packet, landing in the middle of a header
// #[test]
fn test_reader_fast2() {
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
    r.push(TestReaderMode::Read(&data[..70]));
    r.push(TestReaderMode::Read(&data[70..72]));
    r.push(TestReaderMode::Error(Error::new(ErrorKind::WouldBlock, "simulating WouldBlock error")));
    r.push(TestReaderMode::Read(&data[72..]));

    let mut u = Unboxer::new(r, key, nonce);
    let mut buf = [0u8; 16];

    assert_eq!(u.read(&mut buf).unwrap(), 8);
    assert_eq!(buf[..8], [0, 1, 2, 3, 4, 5, 6, 7]);
    assert_eq!(u.read(&mut buf).unwrap(), 0);
    assert_eq!(u.read(&mut buf).unwrap_err().kind(), ErrorKind::WouldBlock);
    assert_eq!(u.read(&mut buf).unwrap(), 8);
    assert_eq!(buf[..8], [7, 6, 5, 4, 3, 2, 1, 0]);
}

// read more than MAX_PACKET_SIZE -> only read MAX_PACKET_SIZE
// #[test]
fn test_reader_max_size() {
    let plain_data = [0u8; MAX_PACKET_USIZE + 42];

    let key = secretbox::Key([162u8, 29, 153, 150, 123, 225, 10, 173, 175, 201, 160, 34, 190,
                              179, 158, 14, 176, 105, 232, 238, 97, 66, 133, 194, 250, 148, 199,
                              7, 34, 157, 174, 24]);
    let nonce = secretbox::Nonce([44, 140, 79, 227, 23, 153, 202, 203, 81, 40, 114, 59, 56, 167,
                                  63, 166, 201, 9, 50, 152, 0, 255, 226, 147]);

    let mut inner = Vec::new();
    let mut b = Boxer::new(inner, key.clone(), nonce.clone());

    assert!(b.write_all(&plain_data).is_ok());
    let data = b.into_inner();

    let mut r = TestReader::new();
    r.push(TestReaderMode::Read(&data[..]));
    r.push(TestReaderMode::Read(&data[CYPHER_HEADER_SIZE + MAX_PACKET_USIZE..]));

    let mut u = Unboxer::new(r, key, nonce);
    let mut buf = [0u8; MAX_PACKET_USIZE + 42];

    assert_eq!(u.read(&mut buf).unwrap(), MAX_PACKET_USIZE);
    assert_eq!(buf[..MAX_PACKET_USIZE], plain_data[..MAX_PACKET_USIZE]);
    assert_eq!(u.read(&mut buf).unwrap(), 42);
    assert_eq!(buf[..42], plain_data[MAX_PACKET_USIZE..]);
}

// unboxer reads two packets, second one does not fit into buffer, then call read with large out buffer
// #[test]
fn test_reader_partially_buffered_packet() {
    let plain_data = [0u8; 3000];

    let key = secretbox::Key([162u8, 29, 153, 150, 123, 225, 10, 173, 175, 201, 160, 34, 190,
                              179, 158, 14, 176, 105, 232, 238, 97, 66, 133, 194, 250, 148, 199,
                              7, 34, 157, 174, 24]);
    let nonce = secretbox::Nonce([44, 140, 79, 227, 23, 153, 202, 203, 81, 40, 114, 59, 56, 167,
                                  63, 166, 201, 9, 50, 152, 0, 255, 226, 147]);

    let mut inner = Vec::new();
    let mut b = Boxer::new(inner, key.clone(), nonce.clone());

    assert!(b.write(&plain_data).is_ok());
    assert!(b.write(&plain_data).is_ok());
    let data = b.into_inner();

    let mut r = TestReader::new();
    r.push(TestReaderMode::Read(&data[..]));
    r.push(TestReaderMode::Read(&data[CYPHER_HEADER_SIZE + MAX_PACKET_USIZE..]));

    let mut u = Unboxer::new(r, key, nonce);
    let mut buf = [0u8; MAX_PACKET_USIZE + 42];

    assert_eq!(u.read(&mut buf).unwrap(), 3000);
    assert_eq!(buf[..3000], plain_data[..3000]);
    assert_eq!(u.read(&mut buf).unwrap(), 3000);
    assert_eq!(buf[..3000], plain_data[..3000]);
}

// ## Unboxer TODO write these tests
// - handle end of stream
// - handling malicious peers (packets > MAX_PACKET_SIZE, packets with too long packet length)

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

// struct OwningTestReader {
//     mode_queue: VecDeque<OwningTestReaderMode>,
// }
//
// // Determines how a test reader should react to a read call
// enum OwningTestReaderMode {
//     Error(io::Error),
//     Read(Vec<u8>),
// }
//
// impl OwningTestReader {
//     fn new() -> OwningTestReader {
//         OwningTestReader { mode_queue: VecDeque::new() }
//     }
//
//     fn push(&mut self, mode: OwningTestReaderMode) {
//         self.mode_queue.push_front(mode)
//     }
// }
//
// impl Read for OwningTestReader {
//     fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
//         match self.mode_queue.pop_back() {
//             None => Err(Error::new(ErrorKind::UnexpectedEof, "reached end of OwningTestReader")),
//             Some(mode) => {
//                 match mode {
//                     OwningTestReaderMode::Error(e) => return Err(e),
//                     OwningTestReaderMode::Read(data) => {
//                         let mut count = 0;
//                         for (i, byte) in data.iter().take(buf.len()).enumerate() {
//                             buf[i] = *byte;
//                             count += 1;
//                         }
//                         println!("OwnedTestReader: Read {:?}", count);
//                         return Ok(cmp::min(data.len(), buf.len()));
//                     }
//                 }
//             }
//         }
//     }
// }

// write data with a randomly behaving inner writer, and ensure it writes correctly
// #[test]
fn test_writer_random() {
    // number of writes to test
    let writes = 1000;

    let plain_data = [42u8; MAX_PACKET_USIZE + 500];
    let mut cypher_text: Vec<u8> = Vec::new();

    let key = secretbox::Key([162u8, 29, 153, 150, 123, 225, 10, 173, 175, 201, 160, 34, 190,
                              179, 158, 14, 176, 105, 232, 238, 97, 66, 133, 194, 250, 148, 199,
                              7, 34, 157, 174, 24]);
    let nonce = secretbox::Nonce([44, 140, 79, 227, 23, 153, 202, 203, 81, 40, 114, 59, 56, 167,
                                  63, 166, 201, 9, 50, 152, 0, 255, 226, 147]);

    let mut w = TestWriter::new();
    for i in 0..writes {
        let rnd = f32::rand(&mut rand::thread_rng());

        if rnd < 0.1 {
            w.push(TestWriterMode::Error(Error::new(ErrorKind::Interrupted,
                                                    "simulating Interrupted error")));
        } else if rnd < 0.2 {
            w.push(TestWriterMode::Error(Error::new(ErrorKind::WouldBlock,
                                                    "simulating WouldBlock error")));
        } else if rnd < 0.3 {
            w.push(TestWriterMode::Write(MAX_PACKET_USIZE));
        } else if rnd < 0.4 {
            w.push(TestWriterMode::Write(MAX_PACKET_USIZE + 200));
        } else if rnd < 0.5 {
            w.push(TestWriterMode::Write(0));
        } else if rnd < 0.6 {
            w.push(TestWriterMode::Write(3));
        } else {
            let rnd2 = f32::rand(&mut rand::thread_rng());
            w.push(TestWriterMode::Write((rnd2 * (MAX_PACKET_USIZE + 42) as f32) as usize));
        }
    }

    let mut b = Boxer::new(w, key.clone(), nonce.clone());

    // perform the encryption
    while b.get_ref().remaining_writes() > 0 {
        let rnd = f32::rand(&mut rand::thread_rng());
        // some of these get ignored because the TestWrite might be too slow
        b.write(&plain_data[..(rnd * (MAX_PACKET_USIZE + 42) as f32) as usize]);
    }
    b.flush();
    cypher_text.extend(b.get_ref().inner());

    // decrypt everything
    let mut decryption_key = key.clone();
    let mut decryption_nonce = nonce.clone();
    let mut offset = 0usize;
    let mut decrypted_header = PlainHeader::new();
    let mut decrypted_packet = [0u8; MAX_PACKET_USIZE];

    while offset < cypher_text.len() {
        unsafe {
            assert!(decrypt_header(&mut decrypted_header,
                                   &*(cypher_text.as_ptr().offset(offset as isize) as
                                      *const [u8; CYPHER_HEADER_SIZE]),
                                   &decryption_key.0,
                                   &mut decryption_nonce.0));
        }
        offset += CYPHER_HEADER_SIZE;

        unsafe {
            assert!(decrypt_packet(&mut decrypted_packet as *mut [u8; MAX_PACKET_USIZE] as
                                   *mut u8,
                                   cypher_text.as_ptr().offset(offset as isize),
                                   &decrypted_header,
                                   &decryption_key.0,
                                   &mut decryption_nonce.0));
        }

        offset += decrypted_header.get_packet_len() as usize;

        for byte in &decrypted_packet[..decrypted_header.get_packet_len() as usize] {
            assert_eq!(*byte, 42u8);
        }
        decrypted_packet = [0u8; MAX_PACKET_USIZE];
    }
}

// read data with a randomly behaving inner reader, and ensure it reads correctly
#[test]
fn test_reader_random() {
    // number of writes to test
    let writes = 1000;

    let plain_data = [42u8; MAX_PACKET_USIZE + 500];
    let mut cypher_text: Vec<u8> = Vec::new();

    let key = secretbox::Key([162u8, 29, 153, 150, 123, 225, 10, 173, 175, 201, 160, 34, 190,
                              179, 158, 14, 176, 105, 232, 238, 97, 66, 133, 194, 250, 148, 199,
                              7, 34, 157, 174, 24]);
    let nonce = secretbox::Nonce([44, 140, 79, 227, 23, 153, 202, 203, 81, 40, 114, 59, 56, 167,
                                  63, 166, 201, 9, 50, 152, 0, 255, 226, 147]);

    let mut w = TestWriter::new();
    for i in 0..writes {
        let rnd = f32::rand(&mut rand::thread_rng());

        if rnd < 0.1 {
            w.push(TestWriterMode::Error(Error::new(ErrorKind::Interrupted,
                                                    "simulating Interrupted error")));
        } else if rnd < 0.2 {
            w.push(TestWriterMode::Error(Error::new(ErrorKind::WouldBlock,
                                                    "simulating WouldBlock error")));
        } else if rnd < 0.3 {
            w.push(TestWriterMode::Write(MAX_PACKET_USIZE));
        } else if rnd < 0.4 {
            w.push(TestWriterMode::Write(MAX_PACKET_USIZE + 200));
        } else if rnd < 0.5 {
            w.push(TestWriterMode::Write(0));
        } else if rnd < 0.6 {
            w.push(TestWriterMode::Write(3));
        } else {
            let rnd2 = f32::rand(&mut rand::thread_rng());
            w.push(TestWriterMode::Write((rnd2 * (MAX_PACKET_USIZE + 42) as f32) as usize));
        }
    }

    let mut b = Boxer::new(w, key.clone(), nonce.clone());

    let mut total_written = 0usize;
    // perform the encryption
    while b.get_ref().remaining_writes() > 0 {
        let rnd = f32::rand(&mut rand::thread_rng());
        // some of these get ignored because the TestWrite might be too slow
        match b.write(&plain_data[..(rnd * (MAX_PACKET_USIZE + 42) as f32) as usize]) {
            Ok(amount) => total_written += amount,
            Err(_) => {}
        }
    }
    b.flush();
    cypher_text.extend(b.get_ref().inner());

    // decrypt everything
    let mut r = RandomReader::new(cypher_text);
    let mut u = Unboxer::new(r, key.clone(), nonce.clone());

    let mut total_read = 0usize;
    while total_read < total_written {
        let mut decrypted = [0u8; MAX_PACKET_USIZE];
        match u.read(&mut decrypted) {
            Err(_) => {}
            Ok(amount) => {
                total_read += amount;
                assert_eq!(decrypted[..amount], plain_data[..amount]);
            }
        }
    }
}

// sequentially reads from an owned buffer, reads random amounts (and sometimes errors)
struct RandomReader {
    data: Vec<u8>,
    offset: usize,
}

impl RandomReader {
    fn new(data: Vec<u8>) -> RandomReader {
        RandomReader { data, offset: 0 }
    }

    fn has_data(&self) -> bool {
        self.offset < self.data.len()
    }
}

impl Read for RandomReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if !self.has_data() {
            panic!("Check `has_data` before calling read...");
        }

        let rnd = f32::rand(&mut rand::thread_rng());
        if rnd < 0.1 {
            return Err(Error::new(ErrorKind::Interrupted, "simulating Interrupted error"));
        } else if rnd < 0.2 {
            return Err(Error::new(ErrorKind::WouldBlock, "simulating WouldBlock error"));
        } else if rnd < 0.3 {
            let amount = cmp::min(cmp::min(buf.len(), MAX_PACKET_USIZE), self.data.len());
            for (i, byte) in self.data[self.offset..
                cmp::min(self.offset + amount, self.data.len())]
                        .iter()
                        .enumerate() {
                buf[i] = *byte;
            }
            self.offset += amount;
            return Ok(amount);
        } else if rnd < 0.4 {
            let amount = cmp::min(cmp::min(buf.len(), MAX_PACKET_USIZE + 200), self.data.len());
            for (i, byte) in self.data[self.offset..
                cmp::min(self.offset + amount, self.data.len())]
                        .iter()
                        .enumerate() {
                buf[i] = *byte;
            }
            self.offset += amount;
            return Ok(amount);
        } else if rnd < 0.5 {
            return Ok(0);
        } else if rnd < 0.6 {
            let amount = cmp::min(cmp::min(buf.len(), 3), self.data.len());
            for (i, byte) in self.data[self.offset..
                cmp::min(self.offset + amount, self.data.len())]
                        .iter()
                        .enumerate() {
                buf[i] = *byte;
            }
            self.offset += amount;
            return Ok(amount);
        } else {
            let rnd2 = f32::rand(&mut rand::thread_rng());
            let amount = cmp::min(cmp::min(buf.len(),
                                           (rnd2 * (MAX_PACKET_USIZE + 42) as f32) as usize),
                                  self.data.len());
            for (i, byte) in self.data[self.offset..
                cmp::min(self.offset + amount, self.data.len())]
                        .iter()
                        .enumerate() {
                buf[i] = *byte;
            }
            self.offset += amount;
            return Ok(amount);
        }
    }
}
