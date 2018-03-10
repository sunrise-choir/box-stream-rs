use super::*;

use futures::FutureExt;
use futures::executor::block_on;
use futures::io::{AsyncReadExt, AsyncWriteExt};
use sodiumoxide;

use async_ringbuffer::*;

#[test]
fn success() {
    let key = sodiumoxide::crypto::secretbox::gen_key();
    let nonce = sodiumoxide::crypto::secretbox::gen_nonce();

    let data: Vec<u8> = (0..255).collect();

    let (writer, reader) = ring_buffer(2);

    let writer = BoxWriter::new(writer, key.clone(), nonce.clone());
    let reader = BoxReader::new(reader, key.clone(), nonce.clone());

    let write_all = writer
        .write_all(data.clone())
        .and_then(|(writer, _)| writer.close());
    let read_all = reader
        .read_to_end(Vec::with_capacity(256))
        .map(|(_, read_data)| for (i, byte) in read_data.iter().enumerate() {
                 assert_eq!(*byte, i as u8);
             });

    assert!(block_on(write_all.join(read_all)).is_ok());
}

// #[test]
// // A reader propagates io errors.
// fn test_reader_io_error() {
//     let key = sodiumoxide::crypto::secretbox::gen_key();
//     let nonce = sodiumoxide::crypto::secretbox::gen_nonce();
//
//     let r = MockDuplex::new();
//     let r = PartialAsyncRead::new(r,
//                                   vec![PartialOp::Err(ErrorKind::NotFound),
//                                        PartialOp::Err(ErrorKind::UnexpectedEof)]);
//
//     let mut b = BoxReader::new(r, key, nonce);
//
//     assert_eq!(b.read(&mut []).unwrap_err().kind(), ErrorKind::NotFound);
//     assert_eq!(b.read(&mut []).unwrap_err().kind(),
//                ErrorKind::UnexpectedEof);
// }
//
// #[test]
// // A reader that reads 0 bytes errors with UnexpectedEof.
// fn test_reader_read0() {
//     let key = sodiumoxide::crypto::secretbox::gen_key();
//     let nonce = sodiumoxide::crypto::secretbox::gen_nonce();
//
//     let r = MockDuplex::new();
//     let r = PartialAsyncRead::new(r, vec![PartialOp::Limited(0)]);
//
//     let mut b = BoxReader::new(r, key, nonce);
//
//     assert_eq!(b.read(&mut []).unwrap_err().kind(),
//                ErrorKind::UnexpectedEof);
// }
//
// #[test]
// // A reader that reads a final header signals it via read returning Ok(0).
// fn test_reader_final_header() {
//     let key = sodiumoxide::crypto::secretbox::gen_key();
//     let nonce = sodiumoxide::crypto::secretbox::gen_nonce();
//
//     let inner = MockDuplex::new();
//     let mut b = BoxWriter::new(inner, key.clone(), nonce.clone());
//     assert_eq!(b.write(&[0, 1, 2, 3]).unwrap(), 4);
//     assert_eq!(b.write_final_header().unwrap(), ());
//     let (_, writes_deque) = b.into_inner().into_inner();
//     let (data, _) = writes_deque.as_slices();
//
//     let mut r = MockDuplex::new();
//     r.add_read_data(data);
//
//     let mut b = BoxReader::new(r, key, nonce);
//
//     assert_eq!(b.read(&mut [10, 20, 30, 40]).unwrap(), 4);
//     assert_eq!(b.read(&mut []).unwrap(), 0);
// }
//
// #[test]
// // A writer propagates io errors.
// fn test_writer_io_error() {
//     let key = sodiumoxide::crypto::secretbox::gen_key();
//     let nonce = sodiumoxide::crypto::secretbox::gen_nonce();
//
//     let w = MockDuplex::new();
//     let w = PartialAsyncWrite::new(w,
//                                    vec![PartialOp::Err(ErrorKind::NotFound),
//                                         PartialOp::Err(ErrorKind::UnexpectedEof)]);
//
//     let mut b = BoxWriter::new(w, key, nonce);
//
//     assert_eq!(b.flush().unwrap_err().kind(), ErrorKind::NotFound);
//     assert_eq!(b.flush().unwrap_err().kind(), ErrorKind::UnexpectedEof);
// }
//
// #[test]
// // A writer errors WriteZero if writing to the underlying Write during flushing returns Ok(0).
// fn test_writer_write0_flush() {
//     {
//         let key = sodiumoxide::crypto::secretbox::gen_key();
//         let nonce = sodiumoxide::crypto::secretbox::gen_nonce();
//
//         let w = MockDuplex::new();
//         let w = PartialAsyncWrite::new(w, vec![PartialOp::Limited(0)]);
//
//         let mut b = BoxWriter::new(w, key, nonce);
//
//         assert_eq!(b.write(&[0, 1, 2, 3]).unwrap(), 4);
//         assert_eq!(b.flush().unwrap_err().kind(), ErrorKind::WriteZero);
//     }
//
//     {
//         let key = sodiumoxide::crypto::secretbox::gen_key();
//         let nonce = sodiumoxide::crypto::secretbox::gen_nonce();
//
//         let w = MockDuplex::new();
//         let w = PartialAsyncWrite::new(w, vec![PartialOp::Limited(2), PartialOp::Limited(0)]);
//
//         let mut b = BoxWriter::new(w, key, nonce);
//
//         assert_eq!(b.write(&[0, 1, 2, 3]).unwrap(), 4);
//         assert_eq!(b.flush().unwrap_err().kind(), ErrorKind::WriteZero);
//     }
// }
//
// #[test]
// // A writer errors WriteZero if writing to the underlying Write during shutdown returns Ok(0).
// fn test_writer_write0_shutdown() {
//     {
//         let key = sodiumoxide::crypto::secretbox::gen_key();
//         let nonce = sodiumoxide::crypto::secretbox::gen_nonce();
//
//         let w = MockDuplex::new();
//         let w = PartialAsyncWrite::new(w, vec![PartialOp::Limited(0)]);
//
//         let mut b = BoxWriter::new(w, key, nonce);
//
//         assert_eq!(b.shutdown().unwrap_err().kind(), ErrorKind::WriteZero);
//     }
//
//     {
//         let key = sodiumoxide::crypto::secretbox::gen_key();
//         let nonce = sodiumoxide::crypto::secretbox::gen_nonce();
//
//         let w = MockDuplex::new();
//         let w = PartialAsyncWrite::new(w, vec![PartialOp::Limited(2), PartialOp::Limited(0)]);
//
//         let mut b = BoxWriter::new(w, key, nonce);
//
//         assert_eq!(b.shutdown().unwrap_err().kind(), ErrorKind::WriteZero);
//     }
// }
