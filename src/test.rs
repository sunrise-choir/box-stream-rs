extern crate rand;

use super::*;

use std::io::{Write, Read};
use std::io::{Error, ErrorKind};
use std::collections::VecDeque;
use test::rand::Rand;
use test::rand::distributions::{IndependentSample, Range};

#[derive(Clone)]
struct TestStream(VecDeque<u8>);

impl Write for TestStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // randomly choose whether to work perfectly, not write at all, error etc.
        let rnd = f32::rand(&mut rand::thread_rng());
        if rnd <= 0.1 {
            return Err(Error::new(ErrorKind::Interrupted, "simulating Interrupted error"));
        } else if rnd <= 0.2 {
            return Err(Error::new(ErrorKind::WouldBlock, "simulating WouldBlock error"));
        } else if rnd <= 0.4 && buf.len() >= 1 {
            for byte in buf.iter().take(1) {
                self.0.push_back(*byte);
            }

            return Ok(1);
        } else if rnd <= 0.6 && buf.len() >= 2 {
            for byte in buf.iter().take(2) {
                self.0.push_back(*byte);
            }

            return Ok(2);
        } else if rnd <= 0.8 {
            let num = Range::new(0, buf.len()).ind_sample(&mut rand::thread_rng());

            for byte in buf.iter().take(num) {
                self.0.push_back(*byte);
            }

            return Ok(num);
        } else if rnd <= 0.9 {
            for byte in buf {
                self.0.push_back(*byte)
            }
            return Ok(buf.len());
        } else {
            return Ok(0);
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Read for TestStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // randomly choose whether to work perfectly, not read at all, error etc.
        let rnd = f32::rand(&mut rand::thread_rng());
        if rnd <= 0.1 {
            return Err(Error::new(ErrorKind::Interrupted, "simulating Interrupted error"));
        } else if rnd <= 0.2 {
            return Err(Error::new(ErrorKind::WouldBlock, "simulating WouldBlock error"));
        } else if rnd <= 0.4 && buf.len() >= 1 {
            for i in 0..1 {
                buf[i] = self.0.pop_front().unwrap();
            }
            return Ok(1);
        } else if rnd <= 0.6 && buf.len() >= 2 {
            for i in 0..2 {
                buf[i] = self.0.pop_front().unwrap();
            }
            return Ok(2);
        } else if rnd <= 0.8 && buf.len() > 0 {
            let num: usize = Range::new(0, buf.len()).ind_sample(&mut rand::thread_rng());

            for i in 0..num {
                buf[i] = self.0.pop_front().unwrap();
            }

            return Ok(num);
        } else if rnd <= 0.9 {
            for i in 0..buf.len() {
                buf[i] = self.0.pop_front().unwrap();
            }
            return Ok(buf.len());
        } else {
            return Ok(0);
        }
    }
}

// Check that the test streams themselves work correctly.
#[test]
fn the_test_streams_work() {
    sodiumoxide::init();

    let length = 99;

    let data = sodiumoxide::randombytes::randombytes(length);
    let mut writer = TestStream(VecDeque::new());
    let mut reader = TestStream(VecDeque::new());
    let mut data_out: Vec<u8> = vec![0; length];

    let mut total_written = 0;
    while total_written < length {
        match writer.write(&data[total_written..]) {
            Ok(written) => total_written += written,
            Err(_) => {}
        }
    }

    reader = writer.clone();

    let mut total_read = 0;
    while total_read < length {
        match reader.read(&mut data_out[total_read..]) {
            Ok(read) => {
                total_read += read;
            }
            Err(_) => {}
        }
    }

    for (i, byte) in data_out.iter().enumerate() {
        assert_eq!(*byte, data[i]);
    }
}

// Encrypt and decrypt data across test readers and writers, resulting in the identity function.
#[test]
fn encrypt_decrypt() {
    sodiumoxide::init();

    let length = 99999;

    let data = sodiumoxide::randombytes::randombytes(length);
    let mut inner_writer = TestStream(VecDeque::new());
    let mut inner_reader = TestStream(VecDeque::new());
    let mut data_out: Vec<u8> = vec![0; length];

    let key1 = sodiumoxide::crypto::secretbox::gen_key();
    let key2 = key1.clone();
    let mut nonce1 = sodiumoxide::crypto::secretbox::gen_nonce();
    let mut nonce2 = nonce1.clone();

    let mut writer = Boxer::new(inner_writer, key1, nonce1);

    let mut total_written = 0;
    while total_written < length {
        match writer.write(&data[total_written..]) {
            Ok(written) => total_written += written,
            Err(_) => {}
        }
    }

    inner_reader = writer.into_inner().clone();

    let mut reader = Unboxer::new(inner_reader, key2, nonce2);

    let mut total_read = 0;
    while total_read < length {
        match reader.read(&mut data_out[total_read..]) {
            Ok(read) => {
                total_read += read;
            }
            Err(_) => {}
        }
    }

    for (i, byte) in data_out.iter().enumerate() {
        assert_eq!(*byte, data[i]);
    }
}
