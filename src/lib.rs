//! **stream** implements OAE2 STREAM.
//!
//! OAE stands for Online Authenticated Encryption. Here, the term
//! "online" means plaintext and ciphertext can be encrypted and
//! decrypted, respectively, with one left-to-right pass [stream].
//! In other words, it supports streaming.
//!
//! OAE2 is a simple construction: the plaintext is broken into
//! chunks and each chunk is encrypted separately. A counter nonce
//! is used to ensure unique nonces and to provider ordering.
//!
//! Eaech plaintext chunk_n in {0, 1, ..., N-2} is exactly 64 KiB
//! with the final plaintext chunk_{N-1} being an arbitrary size
//! less than or equal to 64 KiB. In other words, every chunk is
//! the same size, except the final chunk may be a smaller.
//!
//! Borrowing from Hoang and Shen [tink], this package adds
//! a random prefix to the nonces, increasing the concrete
//! security bound. More specifically, given a hypothetical
//! 192-bit nonce:
//!
//!    prefix counter eof
//!      152    32     8  bits
//!
//! The EOF byte signals the end of the stream. Without an
//! explicit EOF signal the stream could be susceptible to
//! truncation attacks.
//!
//! As always, it is not a good idea to act on a plaintext until
//! the entire message has been verified.
//!
//! [stream]: https://eprint.iacr.org/2015/189.pdf
//! [tink]: https://eprint.iacr.org/2020/1019.pdf
//! [hkdf]: https://tools.ietf.org/html/rfc5869

#![deny(unsafe_code)]
#![feature(inherent_associated_types)]
#![allow(incomplete_features)]
#![feature(generic_const_exprs)]
#![warn(missing_docs, rust_2018_idioms)]

use aead::{
    generic_array::{ArrayLength, GenericArray},
    AeadCore, AeadInPlace, Key, KeyInit, Nonce, Tag,
};
use byteorder::{BigEndian, ByteOrder};
use core::{convert::From, result};
use hkdf::Hkdf;
use sha2::Sha256;
use std::{
    cmp::min,
    io::{ErrorKind, Read, Write},
    ops::{Add, Drop},
};
use typenum::{Sum, Unsigned, U65536};

/// Error is the error type returned by this module.
#[derive(Debug)]
pub enum Error {
    /// InvalidVersion is returned when the version in the
    /// stream's header is invalid.
    InvalidVersion([u8; 4]),
    /// InvalidKeySize is returned when the key size is larger
    /// than HKDF's upper bound of 255*D.
    InvalidKeySize(hkdf::InvalidLength),
    /// IoError is returned when an I/O error occurs while
    /// reading the stream.
    IoError(std::io::Error),
    /// AuthError is returned when the ciphertext cannot be
    /// decrypted.
    AuthError(),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidVersion(v) => {
                write!(f, "invalid version: {:?}", &v[..])
            }
            Error::InvalidKeySize(err) => {
                write!(f, "invalid key size: {}", err)
            }
            Error::IoError(err) => write!(f, "I/O error: {}", err),
            Error::AuthError() => write!(f, "authentication error"),
        }
    }
}
impl std::error::Error for Error {}

impl From<hkdf::InvalidLength> for Error {
    fn from(value: hkdf::InvalidLength) -> Self {
        Error::InvalidKeySize(value)
    }
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Error::IoError(value)
    }
}

/// Result is a specialized [`Result`] for this module.
pub type Result<T> = result::Result<T, Error>;

const VERSION: [u8; 4] = [0, 0, 0, 1];

/// Reader decrypts a stream.
pub struct Reader<'a, R, A, C = U65536>
where
    A: AeadCore,
    A::TagSize: Add<C>,
    <A::TagSize as Add<C>>::Output: ArrayLength<u8>,
    C: ArrayLength<u8>,
{
    /// The underlying ciphertext stream.
    stream: &'a mut R,
    /// Decrypts individual chunks.
    aead: A,
    /// Incrementing nonce.
    nonce: Nonce<A>,
    /// Decryption buffer.
    buf: Buf<Self::BufSize>,
    /// True if we've reached the end of the stream.
    eof: bool,
    /// Additional authenticated data.
    associated_data: Vec<u8>,
}

impl<'a, R, A, C> Reader<'a, R, A, C>
where
    R: 'a,
    A: AeadCore,
    A::TagSize: Add<C>,
    <A::TagSize as Add<C>>::Output: ArrayLength<u8>,
    C: ArrayLength<u8>,
{
    const NONCE_SIZE: usize = <A as AeadCore>::NonceSize::USIZE;
    const PREFIX_SIZE: usize = Self::NONCE_SIZE - 5;
    const EOF_IDX: usize = Self::NONCE_SIZE - 1;
    const CTR_IDX: usize = Self::NONCE_SIZE - 5;

    // Size of each ciphertext chunk.
    type TagSize = A::TagSize;
    type BufSize = Sum<Self::TagSize, C>;
}

impl<'a, R, A, C> Reader<'a, R, A, C>
where
    R: Read + 'a,
    A: AeadCore + KeyInit,
    A::TagSize: Add<C>,
    <A::TagSize as Add<C>>::Output: ArrayLength<u8>,
    C: ArrayLength<u8>,
{
    /// Creates a Reader that reads plaintext from the stream.
    pub fn new(stream: &'a mut R, ikm: &Key<A>) -> Result<Self> {
        let mut vers = [0u8; 4];
        stream.read_exact(&mut vers)?;
        match vers {
            VERSION => (),
            v => return Err(Error::InvalidVersion(v)),
        }

        let mut salt = [0u8; 32];
        stream.read_exact(&mut salt)?;

        let mut nonce = Nonce::<A>::default();
        stream.read_exact(&mut nonce[..Self::PREFIX_SIZE])?;

        let key = Self::derive(ikm, Some(&salt), &[0u8; 0])?;

        Ok(Reader {
            stream,
            nonce,
            aead: A::new(&key),
            buf: Buf::new(),
            eof: false,
            associated_data: Vec::new(),
        })
    }

    fn derive(
        ikm: &Key<A>,
        salt: Option<&[u8]>,
        info: &[u8],
    ) -> Result<Key<A>> {
        let kdf = Hkdf::<Sha256>::new(salt, ikm);
        let mut key = Key::<A>::default();
        kdf.expand(info, &mut key)?;
        Ok(key)
    }
}

impl<'a, R, A, C> Reader<'a, R, A, C>
where
    R: Read,
    A: AeadInPlace,
    A::TagSize: Add<C>,
    <A::TagSize as Add<C>>::Output: ArrayLength<u8>,
    C: ArrayLength<u8>,
{
    /// Writes plaintext data, if any.
    fn try_emit(&mut self, buf: &mut [u8]) -> Option<usize> {
        if self.buf.is_empty() {
            None
        } else {
            // buf.read never returns an error.
            Some(self.buf.read(buf).unwrap())
        }
    }

    /// Reads the next ciphertext chunk from the stream.
    fn absorb(&mut self) -> std::io::Result<usize> {
        // We do not process more than one chunk at a time.
        assert!(self.buf.is_empty());

        self.buf.reset();
        let mut src = self.stream.take(Self::BufSize::U64);
        let n = std::io::copy(&mut src, &mut self.buf)?;
        assert_eq!(n, self.buf.len() as u64);
        Ok(n as usize)
    }
}

impl<'a, R, A, C> Read for Reader<'a, R, A, C>
where
    R: Read,
    A: AeadInPlace,
    A::TagSize: Add<C>,
    <A::TagSize as Add<C>>::Output: ArrayLength<u8>,
    C: ArrayLength<u8>,
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            // Nothing to do here.
            return Ok(0);
        }

        match self.try_emit(buf) {
            Some(n) => return Ok(n),
            None => (),
        }

        if self.eof {
            return Ok(0);
        }

        let n = self.absorb()?;
        if n < Self::TagSize::USIZE {
            return Err(std::io::Error::new(
                ErrorKind::Other,
                Error::AuthError(),
            ));
        }
        self.eof = n < Self::BufSize::USIZE;
        if self.eof {
            self.nonce[Self::EOF_IDX] = 1;
        }

        let (ciphertext, tag) = self.buf.split_at_mut(n - Self::TagSize::USIZE);
        let mut ok = self
            .aead
            .decrypt_in_place_detached(
                &self.nonce,
                &self.associated_data,
                ciphertext,
                Tag::<A>::from_slice(tag),
            )
            .is_ok();
        if !ok && !self.eof {
            self.nonce[Self::EOF_IDX] = 1;
            self.eof = true;
            ok = self
                .aead
                .decrypt_in_place_detached(
                    &self.nonce,
                    &self.associated_data,
                    ciphertext,
                    Tag::<A>::from_slice(tag),
                )
                .is_ok();
        }
        if !ok {
            return Err(std::io::Error::new(
                ErrorKind::Other,
                Error::AuthError(),
            ));
        }

        if !self.eof {
            let ctr =
                BigEndian::read_u32(&self.nonce[Self::CTR_IDX..Self::EOF_IDX]);
            BigEndian::write_u32(
                &mut self.nonce[Self::CTR_IDX..Self::EOF_IDX],
                ctr + 1,
            );
        }

        self.buf.truncate(n - Self::TagSize::USIZE);

        // Ok(0) unfortunately indicates EOF for Read, so we
        // have to try emit plaintext here.
        Ok(match self.try_emit(buf) {
            Some(n) => n,
            // This case can only happen for the terminal chunk
            // since emit only returns None if there aren't any
            // bytes to read.
            None => 0,
        })
    }
}

/// A fixed-length buffer.
struct Buf<N>
where
    N: ArrayLength<u8>,
{
    /// Contents are data[read..write].
    /// Read at data[read], write at data[write].
    data: GenericArray<u8, N>,
    /// Read offset.
    read: usize,
    /// Write offset.
    write: usize,
}

impl<N> Buf<N>
where
    N: ArrayLength<u8>,
{
    #[must_use]
    fn new() -> Self {
        Self {
            data: GenericArray::default(),
            read: 0,
            write: 0,
        }
    }

    /// Reports whether all bytes have been read.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the number of unread bytes in the buffer.
    fn len(&self) -> usize {
        self.write - self.read
    }

    /// Resets the buffer to empty.
    fn reset(&mut self) {
        self.read = 0;
        self.write = 0;
    }

    /// Discards all but the first n unread bytes in the buffer.
    fn truncate(&mut self, n: usize) {
        if n == 0 {
            self.reset();
            return;
        }
        self.write = self.read + n;
    }

    /// Returns the unread portion of the buffer.
    fn remaining_slice(&self) -> &[u8] {
        &self.data[self.read..self.write]
    }

    fn split_at_mut(&mut self, mid: usize) -> (&mut [u8], &mut [u8]) {
        let slice = &mut self.data[self.read..self.write];
        slice.split_at_mut(mid)
    }
}

impl<N> Drop for Buf<N>
where
    N: ArrayLength<u8>,
{
    fn drop(&mut self) {
        self.data.fill(0);
    }
}

impl<N> Write for Buf<N>
where
    N: ArrayLength<u8>,
{
    #[inline]
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let i = min(self.write, N::USIZE);
        let n = (&mut self.data[i..]).write(buf)?;
        self.write += n;
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<N> Read for Buf<N>
where
    N: ArrayLength<u8>,
{
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = Read::read(&mut self.remaining_slice(), buf)?;
        self.read += n;
        Ok(n)
    }
}
