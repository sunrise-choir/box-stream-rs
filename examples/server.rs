extern crate box_stream;
extern crate sodiumoxide;

use box_stream::*;
use sodiumoxide::crypto::secretbox;

use std::io::prelude::*;
use std::io::ErrorKind;
use std::net::TcpListener;

fn main() {
    let encryption_key = secretbox::Key([162u8, 29, 153, 150, 123, 225, 10, 173, 175, 201, 160,
                                         34, 190, 179, 158, 14, 176, 105, 232, 238, 97, 66, 133,
                                         194, 250, 148, 199, 7, 34, 157, 174, 24]);
    let decryption_key = secretbox::Key([162u8, 29, 153, 150, 123, 225, 10, 173, 175, 201, 160,
                                         34, 190, 179, 158, 14, 176, 105, 232, 238, 97, 66, 133,
                                         194, 250, 148, 199, 7, 34, 157, 174, 24]);
    let encryption_nonce = secretbox::Nonce([44, 140, 79, 227, 23, 153, 202, 203, 81, 40, 114,
                                             59, 56, 167, 63, 166, 201, 9, 50, 152, 0, 255, 226,
                                             147]);

    let decryption_nonce = secretbox::Nonce([44, 140, 79, 227, 23, 153, 202, 203, 81, 40, 114,
                                             59, 56, 167, 63, 166, 201, 9, 50, 152, 0, 255, 226,
                                             147]);

    let listener = TcpListener::bind("127.0.0.1:34254").unwrap();
    let (stream, _) = listener.accept().unwrap();
    let mut stream = BoxDuplex::new(stream,
                                    encryption_key,
                                    decryption_key,
                                    encryption_nonce,
                                    decryption_nonce);

    let mut received = [0u8; 8];
    stream.read_exact(&mut received).unwrap();
    assert_eq!(received, [0u8, 1, 2, 3, 4, 5, 6, 7]);

    stream
        .write_all(&[8u8, 9, 10, 11, 12, 13, 14, 15])
        .unwrap();

    let end_of_stream = stream.read(&mut received).unwrap_err();
    assert_eq!(end_of_stream.kind(), ErrorKind::Other);
    assert_eq!(end_of_stream.get_ref().unwrap().description(), FINAL_ERROR);
}
