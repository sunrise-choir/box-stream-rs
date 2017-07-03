// Implementation of Unboxer, a wrapper for readers that dencrypts all writes and handles buffering.

use std::io::Read;
use std::{io, cmp, mem, u16, ptr};
use sodiumoxide::crypto::secretbox;

use crypto::{CYPHER_HEADER_SIZE, MAX_PACKET_SIZE, MAX_PACKET_USIZE, PlainHeader,
             decrypt_header_inplace, decrypt_packet_inplace};

/// Wraps a reader, decrypting all reads.
pub struct Unboxer<R: Read> {
    inner: R,
    key: secretbox::Key,
    nonce: secretbox::Nonce,
    buffer: ReaderBuffer,
}

impl<R: Read> Unboxer<R> {
    pub fn new(inner: R, key: secretbox::Key, nonce: secretbox::Nonce) -> Unboxer<R> {
        Unboxer {
            inner,
            key,
            nonce,
            buffer: ReaderBuffer::new(),
        }
    }

    /// Gets a reference to the underlying reader.
    pub fn get_ref(&self) -> &R {
        &self.inner
    }

    /// Gets a mutable reference to the underlying reader.
    ///
    /// It is inadvisable to directly write to the underlying reader.
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    /// Unwraps this `Unboxer`, returning the underlying reader.
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read> Read for Unboxer<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        do_read(buf,
                &mut self.inner,
                &self.key,
                &mut self.nonce,
                &mut self.buffer)
    }
}

//////////////////////////////////
// Begin implementation details //
//////////////////////////////////

const READ_BUFFER_SIZE: usize = CYPHER_HEADER_SIZE + MAX_PACKET_USIZE;

// A buffer for both read data and decrypted data
struct ReaderBuffer {
    buffer: [u8; READ_BUFFER_SIZE],
    last: u16, // the last element in the buffer that contains up-to-date data
    mode: ReaderBufferMode,
}

#[derive(PartialEq, Debug)]
enum ReaderBufferMode {
    WaitingForHeader,
    WaitingForPacket,
    HoldsPlaintextPacket { offset: u16, packet_len: u16 },
}
use self::ReaderBufferMode::*;

impl ReaderBufferMode {
    fn is_waiting(&self) -> bool {
        match *self {
            HoldsPlaintextPacket { offset, packet_len } => false,
            _ => true,
        }
    }
}

// TODO malicious peer could send headers with a length greater than MAX_PACKET_SIZE
// how should that be handled?
impl ReaderBuffer {
    fn new() -> ReaderBuffer {
        ReaderBuffer {
            buffer: [0; CYPHER_HEADER_SIZE + MAX_PACKET_USIZE],
            last: 0,
            mode: WaitingForHeader,
        }
    }

    // Decrypts the cypher_header at the given offset in the buffer.
    fn decrypt_header_at(&mut self,
                         key: &secretbox::Key,
                         nonce: &mut secretbox::Nonce,
                         header_index: u16)
                         -> bool {
        unsafe {
            decrypt_header_inplace(&mut *(self.buffer.as_mut_ptr().offset(header_index as isize) as
                                          *mut [u8; CYPHER_HEADER_SIZE]),
                                   &key.0,
                                   &mut nonce.0)
        }
    }

    // Casts the buffer content at the given index to a PlainHeader.
    fn plain_header_at(&self, header_index: u16) -> PlainHeader {
        unsafe {
            // header is already decrypted, this is just a cast
            mem::transmute::<[u8;
                              secretbox::MACBYTES + 2],
                             PlainHeader>(*(self.buffer.as_ptr().offset(header_index as isize) as
                                            *const [u8; secretbox::MACBYTES + 2]))
        }
    }

    // Returns the length property of a decrypted header at the given offset in the buffer.
    fn cypher_packet_len_at(&mut self, header_index: u16) -> u16 {
        self.plain_header_at(header_index).get_packet_len()
    }

    // Shifts all relevant data from offset to the beginning of the buffer
    fn shift_left(&mut self, offset: u16) {
        unsafe {
            ptr::copy(self.buffer.as_ptr().offset(offset as isize),
                      self.buffer.as_mut_ptr(),
                      (self.last - offset) as usize);
        }
        self.last -= offset;
    }

    fn decrypt_packet_at(&mut self,
                         key: &secretbox::Key,
                         nonce: &mut secretbox::Nonce,
                         header_index: u16) {
        let plain_header = self.plain_header_at(header_index);
        let packet_len = plain_header.get_packet_len();

        debug_assert!(packet_len <= MAX_PACKET_SIZE); // TODO correct handling of this

        unsafe {
            assert!(decrypt_packet_inplace(self.buffer
                                               .as_mut_ptr()
                                               .offset(header_index as isize +
                                                       CYPHER_HEADER_SIZE as isize),
                                           &plain_header,
                                           &key.0,
                                           &mut nonce.0)); // TODO handle this
        }

        self.mode = HoldsPlaintextPacket {
            offset: CYPHER_HEADER_SIZE as u16,
            packet_len,
        };
    }

    fn read_to(&mut self,
               out: &mut [u8],
               key: &secretbox::Key,
               nonce: &mut secretbox::Nonce)
               -> usize {

        // while let HoldsPlaintextPacket { offset, packet_len } = self.mode {
        //     let max_readable = cmp::min(out.len() as u16, packet_len);
        //
        //     unsafe {
        //         ptr::copy_nonoverlapping(self.buffer.as_ptr().offset(offset as isize),
        //                                  out.as_mut_ptr(),
        //                                  max_readable as usize);
        //     }
        //     let offset = offset + max_readable;
        //
        //     // done reading, now update mode
        //
        //     if max_readable < packet_len {
        //         // we have more plaintext, but the `out` buffer is full
        //         debug_assert!(self.mode == HoldsPlaintextPacket { offset, packet_len });
        //         return max_readable as usize;
        //     } else {
        //         // we don't have more plaintext to fill the outbuffer
        //
        //         if self.last < offset + CYPHER_HEADER_SIZE as u16 {
        //             self.mode = WaitingForHeader;
        //         } else {
        //             // decrypt header to see whether we have a full packet buffered
        //             // TODO check return value of decrypt_header_at and handle failure
        //             assert!(self.decrypt_header_at(key, nonce, offset));
        //
        //             let cypher_packet_len = self.cypher_packet_len_at(offset);
        //             if cypher_packet_len + offset + (CYPHER_HEADER_SIZE as u16) > self.last {
        //                 self.mode = WaitingForPacket;
        //             } else {
        //                 self.decrypt_packet_at(key, nonce, offset);
        //             }
        //         }
        //
        //         self.shift_left(offset);
        //
        //         return max_readable as usize;
        //     }
        // }
        //
        // unreachable!();

        match self.mode {
            HoldsPlaintextPacket { offset, packet_len } => {
                let max_readable = cmp::min(out.len() as u16, packet_len);

                unsafe {
                    ptr::copy_nonoverlapping(self.buffer.as_ptr().offset(offset as isize),
                                             out.as_mut_ptr(),
                                             max_readable as usize);
                }
                let offset = offset + max_readable;

                // done reading, now update mode

                if max_readable < packet_len {
                    // we have more plaintext, but the `out` buffer is full
                    println!("offset: {:?}", offset);
                    println!("packet_len: {:?}", packet_len);
                    println!("self.mode: {:?}", self.mode);
                    self.mode = HoldsPlaintextPacket { offset, packet_len };
                    debug_assert!(self.mode == HoldsPlaintextPacket { offset, packet_len });
                    return max_readable as usize;
                } else {
                    // we don't have more plaintext to fill the outbuffer

                    if self.last < offset + CYPHER_HEADER_SIZE as u16 {
                        self.mode = WaitingForHeader;
                    } else {
                        // decrypt header to see whether we have a full packet buffered
                        // TODO check return value of decrypt_header_at and handle failure
                        assert!(self.decrypt_header_at(key, nonce, offset));

                        let cypher_packet_len = self.cypher_packet_len_at(offset);
                        if cypher_packet_len + offset + (CYPHER_HEADER_SIZE as u16) > self.last {
                            self.mode = WaitingForPacket;
                        } else {
                            self.decrypt_packet_at(key, nonce, offset);
                        }
                    }

                    self.shift_left(offset);

                    return max_readable as usize;
                }

            }
            _ => unreachable!(),
        }
    }

    fn fill<R: Read>(&mut self,
                     reader: &mut R,
                     key: &secretbox::Key,
                     nonce: &mut secretbox::Nonce)
                     -> io::Result<()> {
        debug_assert!(self.mode == WaitingForHeader || self.mode == WaitingForPacket);

        let read = reader.read(&mut self.buffer[self.last as usize..])?;
        self.last += read as u16;

        if self.last < CYPHER_HEADER_SIZE as u16 {
            // this is only reached in mode == WaitingForHeader, so no need to set that again
            debug_assert!(self.mode == WaitingForHeader);
            return Ok(());
        } else {
            if self.mode == WaitingForHeader {
                // TODO check return value of decrypt_header_at and handle failure
                assert!(self.decrypt_header_at(key, nonce, 0));
            }
            let cypher_packet_len = self.cypher_packet_len_at(0);

            if self.last < CYPHER_HEADER_SIZE as u16 + cypher_packet_len {
                self.mode = WaitingForPacket;
                return Ok(());
            } else {
                self.decrypt_packet_at(key, nonce, 0);
                return Ok(());
            }
        }
    }
}

// Implements box reading. The different streams delegate to this in `read`.
fn do_read<R: Read>(out: &mut [u8],
                    reader: &mut R,
                    key: &secretbox::Key,
                    nonce: &mut secretbox::Nonce,
                    buffer: &mut ReaderBuffer)
                    -> io::Result<usize> {

    let mut total_read = 0;
    if buffer.mode.is_waiting() {
        buffer.fill(reader, key, nonce)?;
    }

    while let HoldsPlaintextPacket { offset, packet_len } = buffer.mode {
        println!("total_read: {:?}", total_read);
        println!("out.len(): {:?}", out.len());
        if total_read >= out.len() {
            break;
        }
        total_read += buffer.read_to(&mut out[total_read..], key, nonce);
    }

    return Ok(total_read);
}
