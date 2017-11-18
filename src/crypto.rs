//! Low-level bindings to box-stream-c. You probably don't need to use this
//! module directly.

use sodiumoxide::crypto::secretbox;

/// The size of an encrypted header: The header's mac, the length of the
/// following packet, and the mac of the following packet.
pub const CYPHER_HEADER_SIZE: usize = secretbox::MACBYTES + 2 + secretbox::MACBYTES;
/// CYPHER_HEADER_SIZE as a u16
pub const CYPHER_HEADER_SIZE_U16: u16 = CYPHER_HEADER_SIZE as u16;
/// The maximum allowed size of a single packet passed to `encrypt_packet`.
pub const MAX_PACKET_SIZE: u16 = 4096;
/// Same as `MAX_PACKET_SIZE`, but as a `usize`.
pub const MAX_PACKET_USIZE: usize = MAX_PACKET_SIZE as usize;

/// The result of decrypting a cypher_header. This is
/// `sodiumoxide::crypto::secretbox::MACBYTES` smaller than the encrypted header
/// since the leading mac is not needed anymore.
#[repr(C)]
#[derive(Debug)]
pub struct PlainHeader {
    packet_len: u16,
    packet_mac: [u8; secretbox::MACBYTES],
}

impl PlainHeader {
    /// Create a new PlainHeader, initially zeroed out.
    pub fn new() -> PlainHeader {
        PlainHeader {
            packet_len: 0,
            packet_mac: [0u8; secretbox::MACBYTES],
        }
    }

    /// Returns the length of the packet this header describes.
    pub fn get_packet_len(&self) -> u16 {
        self.packet_len
    }

    /// Returns the mac of the packet this header describes.
    pub fn get_packet_mac(&self) -> [u8; secretbox::MACBYTES] {
        self.packet_mac
    }

    /// Returns whether this header signals the end of the stream.
    pub fn is_final_header(&self) -> bool {
        unsafe { bs_is_final_header(self) }
    }
}

extern "C" {
    fn bs_encrypt_packet(out: *mut u8,
                         plain_packet: *const u8,
                         packet_len: u16,
                         encryption_key: *const [u8; secretbox::KEYBYTES],
                         nonce: *mut [u8; secretbox::NONCEBYTES]);

    fn bs_final_header(out: *mut [u8; CYPHER_HEADER_SIZE],
                       encryption_key: *const [u8; secretbox::KEYBYTES],
                       nonce: *const [u8; secretbox::NONCEBYTES]);


    fn bs_is_final_header(plain_header: *const PlainHeader) -> bool;

    fn bs_decrypt_header(out: *mut PlainHeader,
                         cypher_header: *const [u8; CYPHER_HEADER_SIZE],
                         decryption_key: *const [u8; secretbox::KEYBYTES],
                         nonce: *mut [u8; secretbox::NONCEBYTES])
                         -> bool;

    fn bs_decrypt_header_inplace(cypher_header: *mut [u8; CYPHER_HEADER_SIZE],
                                 decryption_key: *const [u8; secretbox::KEYBYTES],
                                 nonce: *mut [u8; secretbox::NONCEBYTES])
                                 -> bool;

    fn bs_decrypt_packet(out: *mut u8,
                         cypher_packet: *const u8,
                         plain_header: *const PlainHeader,
                         decryption_key: *const [u8; secretbox::KEYBYTES],
                         nonce: *mut [u8; secretbox::NONCEBYTES])
                         -> bool;

    fn bs_decrypt_packet_inplace(cypher_packet: *mut u8,
                                 plain_header: *const PlainHeader,
                                 decryption_key: *const [u8; secretbox::KEYBYTES],
                                 nonce: *mut [u8; secretbox::NONCEBYTES])
                                 -> bool;
}

/// Writes the encrypted header and payload for a given plaintext packet into `out`.
///
/// `out` must be a pointer to at least `CYPHER_HEADER_SIZE + packet_len` bytes.
///
/// `packet_len` must be at most MAX_PACKET_SIZE
pub unsafe fn encrypt_packet(out: *mut u8,
                             plain_packet: *const u8,
                             packet_len: u16,
                             encryption_key: &[u8; secretbox::KEYBYTES],
                             nonce: &mut [u8; secretbox::NONCEBYTES]) {
    debug_assert!(packet_len <= MAX_PACKET_SIZE);
    bs_encrypt_packet(out, plain_packet, packet_len, encryption_key, nonce);
}

/// Writes the final header that signals the end of the box stream into `out`.
pub unsafe fn final_header(out: &mut [u8; CYPHER_HEADER_SIZE],
                           encryption_key: &[u8; secretbox::KEYBYTES],
                           nonce: &[u8; secretbox::NONCEBYTES]) {
    bs_final_header(out, encryption_key, nonce);
}

/// If this returns true, it decrypts a received header into `out`. Returns false
/// if the cyper_header was invalid.
#[must_use]
pub unsafe fn decrypt_header(out: &mut PlainHeader,
                             cypher_header: &[u8; CYPHER_HEADER_SIZE],
                             decryption_key: &[u8; secretbox::KEYBYTES],
                             nonce: &mut [u8; secretbox::NONCEBYTES])
                             -> bool {
    bs_decrypt_header(out, cypher_header, decryption_key, nonce)
}

/// Same as `decrypt_header`, but writes the result into `cypher_header`. If this
/// returns true, `cypher_header` can be safely cast to a `PlainHeader`.
#[must_use]
pub unsafe fn decrypt_header_inplace(cypher_header: &mut [u8; CYPHER_HEADER_SIZE],
                                     decryption_key: &[u8; secretbox::KEYBYTES],
                                     nonce: &mut [u8; secretbox::NONCEBYTES])
                                     -> bool {
    bs_decrypt_header_inplace(cypher_header, decryption_key, nonce)
}

/// Decrypts a received packet, given a pointer to the corresponding
/// plain_header, and writes the result into `out`. Returns false on invalid
/// input, in which case the content of `out` is unspecified.
#[must_use]
pub unsafe fn decrypt_packet(out: *mut u8,
                             cypher_packet: *const u8,
                             plain_header: &PlainHeader,
                             decryption_key: &[u8; secretbox::KEYBYTES],
                             nonce: &mut [u8; secretbox::NONCEBYTES])
                             -> bool {
    bs_decrypt_packet(out, cypher_packet, plain_header, decryption_key, nonce)
}

/// Same as `decrypt_packet`, but writes the result into `cypher_packet`.
#[must_use]
pub unsafe fn decrypt_packet_inplace(cypher_packet: *mut u8,
                                     plain_header: &PlainHeader,
                                     decryption_key: &[u8; secretbox::KEYBYTES],
                                     nonce: &mut [u8; secretbox::NONCEBYTES])
                                     -> bool {
    bs_decrypt_packet_inplace(cypher_packet, plain_header, decryption_key, nonce)
}
