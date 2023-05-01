use {
    crate::{
        buf::Buf,
        error::{Error, Result},
        hkdf,
        io::Write,
        version::Version,
    },
    aead::{AeadCore, AeadInPlace, Key, KeyInit, Nonce},
    byteorder::{BigEndian, ByteOrder},
    core::mem,
    rand_core::{CryptoRng, RngCore},
    typenum::Unsigned,
};

/// Options for configuring a [`Writer`].
#[derive(Clone, Copy, Debug)]
pub struct WriterOpts<'a> {
    version: Version,
    ad: &'a [u8],
    info: &'a [u8],
}

impl Default for WriterOpts<'_> {
    fn default() -> Self {
        WriterOpts::new()
    }
}

impl<'a> WriterOpts<'a> {
    /// Create the default set of options.
    pub const fn new() -> Self {
        Self {
            version: Version::Two,
            ad: &[0u8; 0],
            info: &[0u8; 0],
        }
    }

    /// Set the version.
    ///
    /// By defualt, [`Version::Two`] is used.
    pub fn with_version(&mut self, v: Version) -> &mut Self {
        self.version = v;
        self
    }

    /// Set the additional authenticated data used per-chunk.
    ///
    /// Additional authenticated data is typically used to bind
    /// the ciphertext to a particular context.
    ///
    /// By default, no additional authenticated data is used.
    pub fn with_additional_data(&mut self, ad: &'a [u8]) -> &mut Self {
        self.ad = ad;
        self
    }

    /// Set the HKDF 'info' paramete used when deriving the
    /// encryption key
    ///
    /// The info parameter is typically used to bind the key to
    /// a particular context.
    ///
    /// By default, the info parameter is not used.
    pub fn with_info(&mut self, info: &'a [u8]) -> &mut Self {
        self.info = info;
        self
    }

    /// Build the options.
    pub fn build(self) -> Self {
        self
    }
}

/// Encrypts a stream.
pub struct Writer<'a, W, A, const C: usize = 65536>
where
    A: AeadCore,
{
    /// The underlying ciphertext stream.
    stream: &'a mut W,
    /// Decrypts individual chunks.
    aead: A,
    /// Incrementing nonce.
    nonce: Nonce<A>,
    /// Decryption buffer.
    buf: Buf<C>,
    /// Additional authenticated data.
    associated_data: &'a [u8],
    /// Which version are we reading?
    version: Version,
}

impl<'a, W, A, const C: usize> Writer<'a, W, A, C>
where
    W: 'a,
    A: AeadCore,
{
    const SALT_SIZE: usize = 32;
    const PREFIX_SIZE: usize = Self::NONCE_SIZE - 5;
    const NONCE_SIZE: usize = <A as AeadCore>::NonceSize::USIZE;
    const EOF_IDX: usize = Self::NONCE_SIZE - 1;
    const CTR_IDX: usize = Self::NONCE_SIZE - 5;
    const TAG_SIZE: usize = A::TagSize::USIZE;

    /// Returns the size in bytes of a hypothetical stream with
    /// the size `n`.
    pub const fn size(n: usize, opts: WriterOpts<'_>) -> usize {
        let mut nchunks = (n + C - 1) / C;
        match opts.version {
            Version::Two if n % C == 0 => nchunks += 1,
            _ => (),
        }
        mem::size_of::<Version>()
            + Self::SALT_SIZE
            + Self::PREFIX_SIZE
            + n
            + (nchunks * Self::TAG_SIZE)
    }
}

impl<'a, W, A, const C: usize> Writer<'a, W, A, C>
where
    W: Write + 'a,
    A: AeadCore + KeyInit,
    [(); Self::SALT_SIZE]:,
{
    /// Creates a [`Writer`] that writes ciphertext to `stream`.
    pub fn new<R: RngCore + CryptoRng>(
        stream: &'a mut W,
        rng: &mut R,
        ikm: &Key<A>,
    ) -> Result<Self> {
        Self::new_with(stream, rng, ikm, WriterOpts::default())
    }

    /// Creates a [`Writer`] that writes ciphertext to `stream`
    /// with the provided options.
    pub fn new_with<R: RngCore + CryptoRng>(
        stream: &'a mut W,
        rng: &mut R,
        ikm: &Key<A>,
        opts: WriterOpts<'a>,
    ) -> Result<Self> {
        let version = opts.version;
        stream.write(&version.to_bytes())?;

        let mut salt = [0u8; Self::SALT_SIZE];
        rng.try_fill_bytes(&mut salt)?;
        stream.write(&salt)?;

        let mut nonce = Nonce::<A>::default();
        rng.try_fill_bytes(&mut nonce[..Self::PREFIX_SIZE])?;
        stream.write(&nonce[..Self::PREFIX_SIZE])?;

        let key = hkdf::<A>(ikm, Some(&salt), &opts.info)?;

        Ok(Writer {
            stream,
            nonce,
            aead: A::new(&key),
            buf: Buf::new(),
            associated_data: opts.ad,
            version,
        })
    }
}

impl<W, A, const C: usize> Writer<'_, W, A, C>
where
    W: Write,
    A: AeadInPlace,
{
    fn flush_internal(&mut self, eof: bool) -> Result<usize> {
        if eof {
            self.nonce[Self::EOF_IDX] = 1;
        }
        let tag = self
            .aead
            .encrypt_in_place_detached(
                &self.nonce,
                self.associated_data,
                self.buf.as_mut_slice(),
            )
            .map_err(Error::Encryption)?;
        let n = self.buf.write_to(self.stream)? + self.stream.write(&tag)?;
        if !eof {
            let ctr =
                BigEndian::read_u32(&self.nonce[Self::CTR_IDX..Self::EOF_IDX])
                    .checked_add(1)
                    .ok_or(Error::CounterOverflow)?;
            BigEndian::write_u32(
                &mut self.nonce[Self::CTR_IDX..Self::EOF_IDX],
                ctr,
            );
        }
        self.buf.reset();
        Ok(n)
    }

    fn do_write(&mut self, buf: &[u8]) -> Result<usize> {
        let mut n = 0;
        while n < buf.len() {
            match self.version {
                Version::One => {
                    if self.buf.is_full() {
                        self.flush_internal(false)?;
                    }
                    n += self.buf.write(&buf[n..])?;
                }
                Version::Two => {
                    n += self.buf.write(&buf[n..])?;
                    if self.buf.is_full() {
                        self.flush_internal(false)?;
                    }
                }
            }
        }
        Ok(n)
    }

    fn do_flush(&mut self) -> Result<()> {
        self.flush_internal(true)?;
        Ok(())
    }
}

#[cfg(not(feature = "std"))]
#[cfg_attr(docsrs, doc(cfg(not(feature = "std"))))]
impl<W, A, const C: usize> Write for Writer<'_, W, A, C>
where
    W: Write,
    A: AeadInPlace,
{
    #[inline]
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.do_write(buf)
    }

    fn flush(&mut self) -> Result<()> {
        self.do_flush()
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl<W, A, const C: usize> std::io::Write for Writer<'_, W, A, C>
where
    W: Write,
    A: AeadInPlace,
{
    #[inline]
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        crate::error::map_res(self.do_write(buf))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        crate::error::map_res(self.do_flush())
    }
}
