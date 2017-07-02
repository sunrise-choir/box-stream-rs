// Implementation of Unboxer, a wrapper for readers that dencrypts all writes and handles buffering.

use std::io::Read;
use std::{io, cmp, slice, mem, u16, ptr};
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

// // A buffer for both read data and decrypted data
// struct ReaderBuffer {
//     buffer: [u8; READ_BUFFER_SIZE],
//     // Indicates where to add more data or where to output from.
//     // If this is smaller than CYPHER_HEADER_SIZE, the buffer is currently waiting to complete an encrypted header.
//     // If this is greater than CYPHER_HEADER_SIZE, the `readable` flag indicates whether the offset points into a complete, decrypted packet (true), or into an incomplete, encrypted packet (false).
//     offset: u16,
//     // Length of the data that is actually relevant, everything from buffer[length] is useless data from previous packets.
//     length: u16,
//     header_start: u16,
//     mode: ReaderBufferMode,
// }

// #[derive(PartialEq, Debug)]
// enum ReaderBufferMode {
//     WaitingForHeader,
//     WaitingForPacket,
//     ReadyToDecryptPacket,
//     HoldsPlaintextPacket,
// }
// use self::ReaderBufferMode::*;
//
// // TODO malicious peer could send headers with a length greater than MAX_PACKET_SIZE
// // how should that be handled?
// impl ReaderBuffer {
//     fn new() -> ReaderBuffer {
//         ReaderBuffer {
//             buffer: [0; CYPHER_HEADER_SIZE + MAX_PACKET_USIZE],
//             offset: 0,
//             length: 0,
//             header_start: 0,
//             mode: WaitingForHeader,
//         }
//     }
//
//     fn is_readable(&self) -> bool {
//         self.mode == ReadyToDecryptPacket || self.mode == HoldsPlaintextPacket
//     }
//
//     // Puts plaintext data from the buffer into out, returns how many bytes were put.
//     // Only called when self.holds_plaintext() returns true, i.e. there is a decrypted header at offset secretbox::MACBYTES and enough data to decrypt a full packet
//     fn read_to(&mut self,
//                out: &mut [u8],
//                key: &secretbox::Key,
//                nonce: &mut secretbox::Nonce)
//                -> usize {
//         println!("entered read_to in mode: {:?}", self.mode);
//         debug_assert!(self.is_readable());
//
//         let mut out_offset = 0u16;
//         let mut total_written = 0u16;
//
//         // as long as possible, decrypt cypher_packets and put them into `out`
//         loop {
//             println!("self.header_start: {:?}", self.header_start);
//             let plain_header = unsafe {
//                 // header is already decrypted, this is just a cast
//                 &mem::transmute::<[u8;
//                                    secretbox::MACBYTES +
//                                    2],
//                                   PlainHeader>(*(self.buffer.as_ptr().offset(self.header_start as
//                                                                              isize) as
//                                                  *const [u8; secretbox::MACBYTES + 2]))
//             };
//             debug_assert!(plain_header.get_packet_len() <= MAX_PACKET_SIZE);
//             println!("packet len: {:?}", plain_header.get_packet_len());
//             println!("self.length: {:?}", self.length);
//             println!("self.offset: {:?}", self.offset);
//
//             if self.mode == ReadyToDecryptPacket {
//                 println!("{:?}", "decrypting the following packet:");
//                 for byte in &self.buffer[self.offset as usize..
//                              self.offset as usize +
//                              plain_header.get_packet_len() as usize] {
//                     print!("{:?}, ", *byte);
//                 }
//                 println!("{}", "");
//                 unsafe {
//                     debug_assert!(decrypt_packet_inplace(self.buffer
//                                                              .as_mut_ptr()
//                                                              .offset(self.offset as isize),
//                                                          plain_header,
//                                                          &key.0,
//                                                          &mut nonce.0));
//                 }
//             } // else `self.offset` already points into the plaintext where output should resume
//
//             println!("{:?}", "entered loop");
//             println!("self.offset: {:?}", self.offset);
//             println!("self.length: {:?}", self.length);
//             println!("plain_header.length {:?}", plain_header.get_packet_len());
//             println!("self.mode: {:?}", self.mode);
//             println!("out.len(): {:?}", out.len());
//             println!("out_offset: {:?}", out_offset);
//             println!("self.header_start: {:?}", self.header_start);
//             println!("{:?}", "");
//
//             let available_decrypted_packet = plain_header.get_packet_len() -
//                                              (self.offset -
//                                               (self.header_start + CYPHER_HEADER_SIZE as u16));
//             println!("available_decrypted_packet: {:?}",
//                      available_decrypted_packet);
//             let len = cmp::min(out.len() as u16 - out_offset, available_decrypted_packet);
//
//             unsafe {
//                 ptr::copy_nonoverlapping(self.buffer.as_ptr().offset(self.offset as isize),
//                                          out.as_mut_ptr().offset(out_offset as isize),
//                                          len as usize);
//             }
//             self.offset += len;
//             out_offset += len;
//             total_written += len;
//             println!("len: {:?}", len);
//
//             if (out.len() as u16 - (out_offset - len)) < available_decrypted_packet {
//                 // if out.len() as u16 - out_offset == 0 {
//                 println!("{:?}", "hi!");
//                 println!("out_offset: {:?}", out_offset);
//                 println!("out.len(): {:?}", out.len() as u16);
//                 println!("plain_header.get_packet_len(): {:?}",
//                          plain_header.get_packet_len());
//                 // we have more plaintext, but the `out` buffer is full
//                 self.mode = HoldsPlaintextPacket;
//                 return total_written as usize;
//             } else {
//                 println!("{:?}", "yayyyyyyyyyyyyyyyyyyyyyy");
//                 // we don't have more plaintext to fill the outbuffer
//                 // `self.offset + len` thus points to the beginning of the next cypher_header
//                 self.header_start = self.offset;
//                 println!("self.header_start: {:?}", self.header_start);
//
//                 println!("self.header_start + CYPHER_HEADER_SIZE: {:?}",
//                          self.header_start + CYPHER_HEADER_SIZE as u16);
//
//                 // check whether our buffered data contains another cypherheader
//                 if self.length >= self.header_start + CYPHER_HEADER_SIZE as u16 {
//                     // we have a full cypher_header, so decrypt it
//                     // TODO check return value of decrypt_header_inplace and handle failure
//                     unsafe {
//                         debug_assert!(decrypt_header_inplace(&mut *(self.buffer
//                                                                         .as_mut_ptr()
//                                                                         .offset(self.header_start as
//                                                                                 isize) as
//                                                                     *mut [u8; CYPHER_HEADER_SIZE]),
//                                                              &key.0,
//                                                              &mut nonce.0));
//                     }
//
//                     println!("{:?}", "decrypted a cypher_header");
//                     self.offset += CYPHER_HEADER_SIZE as u16;
//                     println!("offset: {:?}", self.offset);
//
//                     // next check whether the buffer holds a full cypher_packet
//                     if self.length <
//                        unsafe {
//                            *(self.buffer.as_ptr().offset(self.header_start as isize) as *const u16)
//                            //  } {
//                        } + self.offset {
//                         // XXX
//                         // not enough data to decrypt packet
//                         self.mode = WaitingForPacket;
//                         // copy all available data to the beginning of the buffer, so that `fill` works correctly
//                         unsafe {
//                             ptr::copy(self.buffer.as_ptr().offset(self.header_start as isize),
//                                       self.buffer.as_mut_ptr(),
//                                       (self.length - self.header_start) as usize);
//                         }
//                         self.length -= self.header_start;
//                         println!("self.header_start: {:?}", self.header_start);
//                         self.header_start = 0;
//                         self.offset = self.length;
//                         println!("back to WaitingForPacket{}", "");
//                         println!("self.length: {:?}", self.length);
//                         println!("self.offset: {:?}", self.offset);
//                         println!("returning {:?}", total_written);
//                         return total_written as usize;
//                     } else {
//                         // we have a full cypher_packet, so we can decrypt it and continue the same loop
//                         println!("{:?}", "continue with the next cypher_packet decryption");
//                         self.mode = ReadyToDecryptPacket;
//                         continue;
//                     }
//                 } else {
//                     println!("no full cypher_header: length: {:?}, offset: {:?}",
//                              self.length,
//                              self.offset);
//                     // we don't have a full cypher_header
//                     // copy all available data to the beginning of the buffer, so that `fill` works correctly
//                     unsafe {
//                         ptr::copy(self.buffer.as_ptr().offset(self.header_start as isize),
//                                   self.buffer.as_mut_ptr(),
//                                   (self.length - self.header_start) as usize);
//                     }
//                     self.length -= self.header_start;
//                     println!("new length: {:?}", self.length);
//                     self.header_start = 0;
//                     self.offset = self.length;
//                     self.mode = WaitingForHeader;
//                     return total_written as usize;
//                 }
//             }
//         } // end loop
//     }
//
//     // This is called when there is no readable plaintext data in the buffer.
//     // Returns whether there is a complete cypher_packet buffered after reading in some bytes.
//     // TODO don't return, use self.mode instead (same in implementation of writer)
//     fn fill<R: Read>(&mut self,
//                      reader: &mut R,
//                      key: &secretbox::Key,
//                      nonce: &mut secretbox::Nonce)
//                      -> io::Result<bool> {
//         debug_assert!(self.mode == WaitingForHeader || self.mode == WaitingForPacket);
//         println!("{:?}", "entered fill");
//         println!("self.offset: {:?}", self.offset);
//         println!("self.length: {:?}", self.length);
//
//         let read = reader.read(&mut self.buffer[self.offset as usize..])?;
//         // for byte in &self.buffer[self.offset as usize..self.offset as usize + read] {
//         //     print!("{:?}, ", *byte);
//         // }
//         self.offset += read as u16;
//         self.length += read as u16;
//         println!("read: {:?}", read);
//         println!("self.offset: {:?}", self.offset);
//         println!("self.length: {:?}", self.length);
//         println!("self.mode: {:?}", self.mode);
//
//         if self.length < CYPHER_HEADER_SIZE as u16 {
//             // this is only reached in mode == WaitingForHeader, so no need to set that again
//             debug_assert!(self.mode == WaitingForHeader);
//             return Ok(false);
//         } else {
//             println!("\n{:?}", "header:");
//             for byte in &self.buffer[..CYPHER_HEADER_SIZE] {
//                 print!("{:?}, ", *byte);
//             }
//             println!("{}", "\n");
//             println!("nonce: {:?}", nonce);
//
//             if self.mode == WaitingForHeader {
//                 // TODO check return value of decrypt_header_inplace and handle failure
//                 unsafe {
//                     assert!(decrypt_header_inplace(&mut *(self.buffer.as_mut_ptr() as
//                                                           *mut [u8; CYPHER_HEADER_SIZE]),
//                                                    &key.0,
//                                                    &mut nonce.0));
//                 }
//                 println!("{:?}", "decrypted in fill");
//
//                 println!("self.length: {:?}", self.length);
//                 println!("len of cypherpacket: {:?}",
//                          unsafe { *(self.buffer.as_ptr() as *const u16) });
//             }
//             // true if a full encrypted packet is available
//             if self.length >=
//                CYPHER_HEADER_SIZE as u16 + unsafe { *(self.buffer.as_ptr() as *const u16) } {
//                 self.mode = ReadyToDecryptPacket;
//                 self.offset = CYPHER_HEADER_SIZE as u16;
//                 return Ok(true);
//             } else {
//                 println!("{:?}", "continue waiting for packet?");
//                 self.mode = WaitingForPacket;
//                 return Ok(false);
//             }
//         }
//
//         // when this returns, self.offset == self.length, which is used by `read_to` to detect that the available packet needs to be decrypted
//     }
// }
//
// // Implements box reading. The different streams delegate to this in `read`.
// fn do_read<R: Read>(out: &mut [u8],
//                     reader: &mut R,
//                     key: &secretbox::Key,
//                     nonce: &mut secretbox::Nonce,
//                     buffer: &mut ReaderBuffer)
//                     -> io::Result<usize> {
//     if buffer.is_readable() {
//         let tmp = buffer.read_to(out, key, nonce);
//         println!("READ1: {:?}", tmp);
//         println!("{}", "");
//         return Ok(tmp); // TODO error handling
//     }
//
//     buffer.fill(reader, key, nonce)?;
//
//     if buffer.is_readable() {
//         let tmp = buffer.read_to(out, key, nonce);
//         println!("READ2: {:?}", tmp);
//         println!("{}", "");
//         return Ok(tmp);
//     } else {
//         println!("{:?}", "no inner read");
//         return Ok(0);
//     }
// }

// XXX XXX XXX XXX XXX XXX XXX
// XXX XXX XXX XXX XXX XXX XXX
// XXX XXX XXX XXX XXX XXX XXX

// A buffer for both read data and decrypted data
struct ReaderBuffer {
    buffer: [u8; READ_BUFFER_SIZE],
    // Indicates where to add more data or where to output from.
    // If this is smaller than CYPHER_HEADER_SIZE, the buffer is currently waiting to complete an encrypted header.
    // If this is greater than CYPHER_HEADER_SIZE, the `readable` flag indicates whether the offset points into a complete, decrypted packet (true), or into an incomplete, encrypted packet (false).
    // offset: u16,
    // Length of the data that is actually relevant, everything from buffer[length] is useless data from previous packets.
    // length: u16,
    // header_start: u16,
    last: u16, // the last element in the buffer that contains up-to-date data
    mode: ReaderBufferMode,
}

#[derive(PartialEq, Debug)]
enum ReaderBufferMode {
    WaitingForHeader,
    WaitingForPacket,
    ReadyToDecryptPacket,
    HoldsPlaintextPacket { offset: u16, packet_len: u16 },
}
use self::ReaderBufferMode::*;

// TODO malicious peer could send headers with a length greater than MAX_PACKET_SIZE
// how should that be handled?
impl ReaderBuffer {
    fn new() -> ReaderBuffer {
        ReaderBuffer {
            buffer: [0; CYPHER_HEADER_SIZE + MAX_PACKET_USIZE],
            // offset: 0,
            // length: 0,
            // header_start: 0,
            last: 0,
            mode: WaitingForHeader,
        }
    }

    // Puts plaintext data from the buffer into out, returns how many bytes were put.
    // Only called when self.holds_plaintext() returns true, i.e. there is a decrypted header at offset secretbox::MACBYTES and enough data to decrypt a full packet
    fn read_to(&mut self,
               out: &mut [u8],
               key: &secretbox::Key,
               nonce: &mut secretbox::Nonce)
               -> usize {
        println!("  entered read_to{}", "");
        match self.mode {
            HoldsPlaintextPacket { offset, packet_len } => {
                println!("  self.last: {:?}", self.last);
                println!("  offset: {:?}", offset);
                println!("  packet_length: {:?}", packet_len);
                println!("  out.len(): {:?}", out.len());

                let max_readable = cmp::min(out.len() as u16, packet_len);
                println!("  max_readable: {:?}", max_readable);

                unsafe {
                    ptr::copy_nonoverlapping(self.buffer.as_ptr().offset(offset as isize),
                                             out.as_mut_ptr(),
                                             max_readable as usize);
                }
                let offset = offset + max_readable;

                // done reading, now update mode

                if max_readable < packet_len {
                    // we have more plaintext, but the `out` buffer is full
                    debug_assert!(self.mode == HoldsPlaintextPacket { offset, packet_len });
                    println!("  leaving read_to with more plaintext avaiable{}", "");
                    return max_readable as usize;
                } else {
                    // we don't have more plaintext to fill the outbuffer

                    if self.last < offset + CYPHER_HEADER_SIZE as u16 {
                        println!("  no full cypher_header buffered{}", "");
                        self.mode = WaitingForHeader;
                    } else {
                        println!("  full cypher_header buffered{}", "");
                        // decrypt header to see whether we have a full packet buffered
                        println!("  decrypting header {}", "");
                        // TODO check return value of decrypt_header_inplace and handle failure
                        unsafe {
                            println!("offset: {:?}", offset);
                            println!("buffer_ptr: {:?}", self.buffer.as_mut_ptr());
                            println!("buffer_ptr.offset(): {:?}",
                                     self.buffer.as_mut_ptr().offset(offset as isize));
                            println!("buffer_ptr.offset.cast: {:?}",
                                     self.buffer.as_mut_ptr().offset(offset as isize) as
                                     *mut [u8; CYPHER_HEADER_SIZE]);
                            assert!(decrypt_header_inplace(&mut *(self.buffer
                                                                      .as_mut_ptr()
                                                                      .offset(offset as
                                                                              isize) as
                                                                  *mut [u8; CYPHER_HEADER_SIZE]),
                                                           &key.0,
                                                           &mut nonce.0));
                        }
                        let cypher_packet_len = unsafe {
                            *(self.buffer.as_ptr().offset(offset as isize) as *const u16)
                        };
                        println!("  cypher_packet_len: {:?}", cypher_packet_len);
                        if cypher_packet_len + offset + (CYPHER_HEADER_SIZE as u16) > self.last {
                            println!("  no full cypher_packet buffered{}", "");
                            self.mode = WaitingForPacket;
                        } else {
                            println!("  full cypher_packet buffered{}", "");
                            self.mode = ReadyToDecryptPacket;
                        }
                    }

                    // shift buffered data to the left
                    unsafe {
                        ptr::copy(self.buffer.as_ptr().offset(offset as isize),
                                  self.buffer.as_mut_ptr(),
                                  (self.last - offset) as usize);
                    }
                    self.last -= offset;

                    println!("  leaving read_to in mode {:?}", self.mode);
                    return max_readable as usize;
                }

            }
            _ => unreachable!(),
        }


    }

    // This is called when there is no readable plaintext data in the buffer.
    // Returns whether there is a complete cypher_packet buffered after reading in some bytes.
    // TODO don't return, use self.mode instead (same in implementation of writer)
    fn fill<R: Read>(&mut self,
                     reader: &mut R,
                     key: &secretbox::Key,
                     nonce: &mut secretbox::Nonce)
                     -> io::Result<()> {
        debug_assert!(self.mode == WaitingForHeader || self.mode == WaitingForPacket);
        println!("  entered fill in mode {:?}", self.mode);
        println!("  self.last: {:?}", self.last);

        let read = reader.read(&mut self.buffer[self.last as usize..])?;
        // for byte in &self.buffer[self.offset as usize..self.offset as usize + read] {
        //     print!("{:?}, ", *byte);
        // }
        self.last += read as u16;
        println!("  read: {:?}", read);
        println!("  new self.last: {:?}", self.last);

        if self.last < CYPHER_HEADER_SIZE as u16 {
            // this is only reached in mode == WaitingForHeader, so no need to set that again
            debug_assert!(self.mode == WaitingForHeader);
            println!("  leaving fill in mode {:?}", self.mode);
            return Ok(());
        } else {
            println!("\nheader at {:?}", 0);
            for byte in &self.buffer[..CYPHER_HEADER_SIZE] {
                print!("{:?}, ", *byte);
            }
            println!("{}", "\n");
            println!("nonce: {:?}", nonce);

            if self.mode == WaitingForHeader {
                println!("  decrypting header at offset {}", 0);
                // TODO check return value of decrypt_header_inplace and handle failure
                unsafe {
                    assert!(decrypt_header_inplace(&mut *(self.buffer.as_mut_ptr().offset(0 as
                                                                                          isize) as
                                                          *mut [u8; CYPHER_HEADER_SIZE]),
                                                   &key.0,
                                                   &mut nonce.0));
                }
            }
            let cypher_packet_len = unsafe { *(self.buffer.as_ptr() as *const u16) };
            println!("  cypher_packet_len: {:?}", cypher_packet_len);

            if self.last < CYPHER_HEADER_SIZE as u16 + cypher_packet_len {
                self.mode = WaitingForPacket;
                println!("  leaving fill in mode {:?}", self.mode);
                return Ok(());
            } else {
                self.mode = ReadyToDecryptPacket;
                println!("  leaving fill in mode {:?}", self.mode);
                return Ok(());
            }
        }
    }

    // TODO handle failures
    // Decrypts a packet, assuming that `self.buffer[self.header_start]`  contains a decrypted header and that the buffer contains the full cypher_packet
    fn decrypt_packet(&mut self, key: &secretbox::Key, nonce: &mut secretbox::Nonce) {
        debug_assert!(self.mode == ReadyToDecryptPacket);
        println!("  entered decrypt_packet{}", "");

        let plain_header = unsafe {
            // header is already decrypted, this is just a cast
            &mem::transmute::<[u8;
                               secretbox::MACBYTES +
                               2],
                              PlainHeader>(*(self.buffer.as_ptr().offset(0 as isize) as
                                             *const [u8; secretbox::MACBYTES + 2]))
        };
        debug_assert!(plain_header.get_packet_len() <= MAX_PACKET_SIZE); // TODO correct handling of this

        println!("  packet len: {:?}", plain_header.get_packet_len());
        println!("  self.last: {:?}", self.last);

        unsafe {
            debug_assert!(decrypt_packet_inplace(self.buffer
                                                     .as_mut_ptr()
                                                     .offset(CYPHER_HEADER_SIZE as isize),
                                                 plain_header,
                                                 &key.0,
                                                 &mut nonce.0));
        }

        self.mode = HoldsPlaintextPacket {
            offset: CYPHER_HEADER_SIZE as u16,
            packet_len: plain_header.get_packet_len(),
        };

        println!("  leaving decrypt_packet{}", "");
    }
}

// Implements box reading. The different streams delegate to this in `read`.
fn do_read<R: Read>(out: &mut [u8],
                    reader: &mut R,
                    key: &secretbox::Key,
                    nonce: &mut secretbox::Nonce,
                    buffer: &mut ReaderBuffer)
                    -> io::Result<usize> {
    println!("entered do_read in mode {:?}", buffer.mode);
    let ret;

    match buffer.mode {
        WaitingForHeader => {
            buffer.fill(reader, key, nonce)?;
            ret = 0;;
        }
        WaitingForPacket => {
            buffer.fill(reader, key, nonce)?;
            ret = 0;
        }
        ReadyToDecryptPacket => {
            buffer.decrypt_packet(key, nonce);
            ret = 0;
        }
        HoldsPlaintextPacket {
            offset: _,
            packet_len: _,
        } => ret = buffer.read_to(out, key, nonce),
    }
    println!("do_read returned Ok({})\n", ret);
    return Ok(ret);
}
