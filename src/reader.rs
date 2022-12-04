use {
    crate::{
        buf::Buf,
        error::{Error, Result},
        hkdf,
        io::Read,
        version::Version,
    },
    aead::{AeadCore, AeadInPlace, Key, KeyInit, Nonce, Tag},
    byteorder::{BigEndian, ByteOrder},
    typenum::Unsigned,
};

/// Options for configuring a [`Reader`].
#[derive(Clone, Copy, Debug)]
pub struct ReaderOpts<'a> {
    ad: &'a [u8],
    info: &'a [u8],
}

impl Default for ReaderOpts<'_> {
    fn default() -> Self {
        ReaderOpts::new()
    }
}

impl<'a> ReaderOpts<'a> {
    /// Create the default set of options.
    pub const fn new() -> Self {
        Self {
            ad: &[0u8; 0],
            info: &[0u8; 0],
        }
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

/// Decrypts a stream.
pub struct Reader<'a, R, A, const C: usize = 65536>
where
    R: Read,
    A: AeadCore,
    [(); C + A::TagSize::USIZE]:,
{
    /// The underlying ciphertext stream.
    stream: &'a mut R,
    /// Decrypts individual chunks.
    aead: A,
    /// Incrementing nonce.
    nonce: Nonce<A>,
    /// Decryption buffer.
    buf: Buf<{ C + A::TagSize::USIZE }>,
    /// True if we've reached the end of the stream.
    eof: bool,
    /// Additional authenticated data.
    associated_data: &'a [u8],
    /// Which version are we reading?
    version: Version,
}

impl<'a, R, A, const C: usize> Reader<'a, R, A, C>
where
    R: Read + 'a,
    A: AeadCore,
    [(); C + A::TagSize::USIZE]:,
{
    const NONCE_SIZE: usize = A::NonceSize::USIZE;
    const TAG_SIZE: usize = A::TagSize::USIZE;
    const PREFIX_SIZE: usize = Self::NONCE_SIZE - 5;
    const EOF_IDX: usize = Self::NONCE_SIZE - 1;
    const CTR_IDX: usize = Self::NONCE_SIZE - 5;
    const BUF_SIZE: usize = Self::TAG_SIZE + C;
}

impl<'a, R, A, const C: usize> Reader<'a, R, A, C>
where
    R: Read + 'a,
    A: AeadCore + KeyInit,
    [(); C + A::TagSize::USIZE]:,
{
    /// Creates a [`Reader`] that reads plaintext from `stream`.
    pub fn new(stream: &'a mut R, ikm: &Key<A>) -> Result<Self> {
        Self::new_with(stream, ikm, ReaderOpts::default())
    }

    /// Creates a [`Reader`] that reads plaintext from `stream`
    /// with the provided options.
    pub fn new_with(
        stream: &'a mut R,
        ikm: &Key<A>,
        opts: ReaderOpts<'a>,
    ) -> Result<Self> {
        let version: Version = {
            let mut b = [0u8; 4];
            stream.read_exact(&mut b)?;
            b.try_into()?
        };

        let mut salt = [0u8; 32];
        stream.read_exact(&mut salt)?;

        let mut nonce = Nonce::<A>::default();
        stream.read_exact(&mut nonce[..Self::PREFIX_SIZE])?;

        let key = hkdf::<A>(ikm, Some(&salt), opts.info)?;

        Ok(Reader {
            stream,
            nonce,
            aead: A::new(&key),
            buf: Buf::new(),
            eof: false,
            associated_data: opts.ad,
            version,
        })
    }
}

impl<'a, R, A, const C: usize> Reader<'a, R, A, C>
where
    R: Read + 'a,
    A: AeadInPlace,
    [(); C + A::TagSize::USIZE]:,
{
    fn do_read(&mut self, buf: &mut [u8]) -> Result<usize> {
        match self.buf.read(buf) {
            // Nothing to do here.
            Ok(0) if buf.is_empty() || self.eof => return Ok(0),
            // No remaining plaintext.
            Ok(0) => assert!(self.buf.is_empty()),
            Ok(n) => return Ok(n),
            Err(err) => return Err(err),
        };

        self.buf.reset();
        let n = self.buf.read_from(self.stream)?;
        if n < Self::TAG_SIZE {
            // The stream has been truncated, so it clearly
            // cannot be authenticated.
            return Err(Error::Authentication);
        }

        // Is this a partial chunk?
        self.eof = n < Self::BUF_SIZE;
        if self.eof {
            self.nonce[Self::EOF_IDX] = 1;
        }

        let (ciphertext, tag) = self.buf.split_at_mut(n - Self::TAG_SIZE);
        let mut ok = self
            .aead
            .decrypt_in_place_detached(
                &self.nonce,
                self.associated_data,
                ciphertext,
                Tag::<A>::from_slice(tag),
            )
            .is_ok();
        if self.version == Version::One && !ok && !self.eof {
            // It's possible that the final chunk is perfectly
            // aligned, so try again with the EOF nonce.
            self.nonce[Self::EOF_IDX] = 1;
            self.eof = true;
            ok = self
                .aead
                .decrypt_in_place_detached(
                    &self.nonce,
                    self.associated_data,
                    ciphertext,
                    Tag::<A>::from_slice(tag),
                )
                .is_ok();
        }
        if !ok {
            return Err(Error::Authentication);
        }

        if !self.eof {
            let ctr =
                BigEndian::read_u32(&self.nonce[Self::CTR_IDX..Self::EOF_IDX])
                    .checked_add(1)
                    .ok_or(Error::CounterOverflow)?;
            BigEndian::write_u32(
                &mut self.nonce[Self::CTR_IDX..Self::EOF_IDX],
                ctr,
            );
        }

        // Get rid of the tag.
        self.buf.truncate(n - Self::TAG_SIZE);

        self.buf.read(buf)
    }
}

#[cfg(not(feature = "std"))]
#[cfg_attr(docsrs, doc(cfg(not(feature = "std"))))]
impl<'a, R, A, const C: usize> Read for Reader<'a, R, A, C>
where
    R: Read + 'a,
    A: AeadInPlace,
    [(); C + A::TagSize::USIZE]:,
{
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.do_read(buf)
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl<'a, R, A, const C: usize> std::io::Read for Reader<'a, R, A, C>
where
    R: Read + 'a,
    A: AeadInPlace,
    [(); C + A::TagSize::USIZE]:,
{
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        crate::error::map_res(self.do_read(buf))
    }
}
