//! **stream** implements OAE2 STREAM.
//!
//! OAE stands for Online Authenticated Encryption. Here, the
//! term "online" means plaintext and ciphertext can be encrypted
//! and decrypted, respectively, with one left-to-right pass
//! ([stream]). In other words, it supports streaming.
//!
//! OAE2 is a simple construction: the plaintext is broken into
//! chunks and each chunk is encrypted separately. A counter
//! nonce is used to ensure unique nonces and to provider
//! ordering.
//!
//! Each plaintext chunk_n in `{0, 1, ..., N-2}` is, by default,
//! exactly 65 KiB with the final plaintext `chunk_{N-1}` being
//! an arbitrary size less than or equal to 65 KiB. In other
//! words, every chunk is the same size, except that the final
//! chunk may be smaller.
//!
//! Borrowing from Hoang and Shen ([tink]), this package adds
//! a random prefix to the nonces, increasing the concrete
//! security bound. More specifically, given a hypothetical
//! 192-bit nonce:
//!
//! ```text
//!    prefix counter eof
//!      152    32     8  bits
//! ```
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
#![allow(incomplete_features)]
#![feature(allocator_api)]
#![feature(doc_cfg)]
#![feature(error_in_core)]
#![feature(generic_const_exprs)]
#![feature(inherent_associated_types)]
#![warn(missing_docs, rust_2018_idioms)]
#![cfg_attr(not(any(feature = "std", test)), no_std)]

mod buf;
mod error;
mod io;
mod reader;
mod version;
mod writer;

pub use error::*;
pub use io::*;
pub use reader::*;
pub use version::*;
pub use writer::*;

use {
    aead::{AeadCore, Key, KeyInit},
    hkdf::Hkdf,
    sha2::Sha256,
};

/// The default chunk size used by [`Reader`] and [`Writer`].
pub const DEFAULT_CHUNK_SIZE: usize = 1 << 16;

fn hkdf<A>(ikm: &Key<A>, salt: Option<&[u8]>, info: &[u8]) -> Result<Key<A>>
where
    A: AeadCore + KeyInit,
{
    let kdf = Hkdf::<Sha256>::new(salt, ikm);
    let mut key = Key::<A>::default();
    kdf.expand(info, &mut key)?;
    Ok(key)
}
