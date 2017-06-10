use sodiumoxide::crypto::secretbox;

extern "C" {
    // TODO doc
    pub fn bs_encrypt_packet(out: *mut u8,
                             plain_packet: *const u8,
                             packet_len: u16,
                             encryption_key: *const [u8; secretbox::KEYBYTES],
                             nonce: *mut [u8; secretbox::NONCEBYTES]);
}

// // panics if the slice is longer than MAXBYTEs TODO
// pub fn encrypt_packet(plain_packet: &[u8],
//                       encryption_key: &secretbox::Key,
//                       nonce: &mut secretbox::Nonce)
//                       -> &[u8] {
//
// }

// pub fn ed25519_pk_to_curve25519(ed25519_pub: &sign::PublicKey) -> box_::PublicKey {
//     let mut curve = [0u8; box_::PUBLICKEYBYTES];
//     unsafe {
//         crypto_sign_ed25519_pk_to_curve25519(&mut curve, &ed25519_pub.0);
//     }
//     box_::PublicKey(curve)
// }
//
// pub fn ed25519_sk_to_curve25519(ed25519_sec: &sign::SecretKey) -> box_::SecretKey {
//     let mut curve = [0u8; box_::SECRETKEYBYTES];
//     unsafe {
//         crypto_sign_ed25519_sk_to_curve25519(&mut curve, &ed25519_sec.0);
//     }
//     box_::SecretKey(curve)
// }
