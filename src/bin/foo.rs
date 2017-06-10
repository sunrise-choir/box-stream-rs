extern crate box_stream;

use box_stream::crypto;

fn main() {
    let mut out = [0u8; 42];
    let plain_packet = [0u8, 1, 2, 3, 4, 5, 6, 7];
    let packet_len = 8u16;
    let encryption_key = [162, 29, 153, 150, 123, 225, 10, 173, 175, 201, 160, 34, 190, 179, 158,
                          14, 176, 105, 232, 238, 97, 66, 133, 194, 250, 148, 199, 7, 34, 157,
                          174, 24];
    let mut encryption_nonce = [44, 140, 79, 227, 23, 153, 202, 203, 81, 40, 114, 59, 56, 167, 63,
                                166, 201, 9, 50, 152, 0, 255, 226, 147];

    unsafe {
        crypto::bs_encrypt_packet(&mut out as *mut [u8; 42] as *mut u8,
                                  &plain_packet as *const [u8; 8] as *const u8,
                                  packet_len,
                                  &encryption_key,
                                  &mut encryption_nonce);
    }

    for byte in &out[..] {
        print!("{:?} ", byte);
    }
}
