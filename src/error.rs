#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::boxed::Box;

use core::{convert::From, error, fmt, result};

/// Result is a specialized [`result::Result`] for this module.
pub type Result<T> = result::Result<T, Error>;

#[cfg(feature = "std")]
pub(crate) fn map_res<T>(res: Result<T>) -> std::io::Result<T> {
    res.map_err(|err| match err {
        Error::UnexpectedEof(_) => {
            std::io::Error::new(std::io::ErrorKind::UnexpectedEof, err)
        }
        Error::ShortWrite(_) => {
            std::io::Error::new(std::io::ErrorKind::WriteZero, err)
        }
        err => std::io::Error::new(std::io::ErrorKind::Other, err),
    })
}

/// An arbitrary error.
#[derive(Debug)]
pub struct OtherError {
    #[cfg(feature = "alloc")]
    inner: Box<dyn error::Error + Send + Sync>,
}

impl OtherError {
    /// Allocate an [`OtherError`].
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub fn new<E>(err: E) -> Self
    where
        E: Into<Box<dyn error::Error + Send + Sync>>,
    {
        Self { inner: err.into() }
    }

    /// Allocate an [`OtherError`].
    #[cfg(not(feature = "alloc"))]
    #[cfg_attr(docsrs, doc(cfg(not(feature = "alloc"))))]
    pub fn new<E>(_err: E) -> Self {
        Self {}
    }
}

impl fmt::Display for OtherError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        #[cfg(feature = "alloc")]
        {
            write!(f, "{}", self.inner)
        }
        #[cfg(not(feature = "alloc"))]
        {
            write!(f, "unknown error")
        }
    }
}

impl error::Error for OtherError {
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        self.inner.source()
    }
}

/// Error is the error type returned by this module.
#[derive(Debug)]
pub enum Error {
    /// The version in the stream's header is invalid.
    InvalidVersion(u32),
    /// The key size is larger than HKDF's upper bound of
    /// `255*D`.
    InvalidKeySize(hkdf::InvalidLength),
    /// The ciphertext could be decrypted.
    Authentication,
    /// The plaintext could be encrypted.
    Encryption(aead::Error),
    /// The CSPRNG failed.
    Rand(rand_core::Error),
    /// Too many chunks were written and the counter overflowed.
    CounterOverflow,
    /// The entire buffer could not be written.
    ///
    /// It contains the number of bytes written.
    ShortWrite(usize),
    /// Unexpected EOF while reading.
    ///
    /// It contains the number of bytes read.
    UnexpectedEof(usize),
    /// Some other error occurred.
    Other(OtherError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidVersion(v) => write!(f, "invalid version: {}", v),
            Error::InvalidKeySize(err) => {
                write!(f, "invalid key size: {}", err)
            }
            Error::Authentication => write!(f, "authentication error"),
            Error::Encryption(err) => write!(f, "encryption error: {}", err),
            Error::CounterOverflow => write!(f, "counter overflow"),
            Error::Rand(err) => write!(f, "CSPRNG failure: {}", err),
            Error::ShortWrite(n) => write!(f, "short write of {} bytes", n),
            Error::UnexpectedEof(n) => {
                write!(f, "unexpected EOF after {} bytes", n)
            }
            Error::Other(err) => write!(f, "{}", err),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Error::InvalidVersion(_) => None,
            Error::InvalidKeySize(_) => None,
            Error::Authentication => None,
            Error::Encryption(_) => None,
            Error::CounterOverflow => None,
            Error::Rand(_) => None,
            Error::ShortWrite(_) => None,
            Error::UnexpectedEof(_) => None,
            Error::Other(err) => Some(err),
        }
    }
}

impl From<hkdf::InvalidLength> for Error {
    fn from(value: hkdf::InvalidLength) -> Self {
        Error::InvalidKeySize(value)
    }
}

impl From<aead::Error> for Error {
    fn from(value: aead::Error) -> Self {
        Error::Encryption(value)
    }
}

impl From<rand_core::Error> for Error {
    fn from(value: rand_core::Error) -> Self {
        Error::Rand(value)
    }
}

impl From<OtherError> for Error {
    fn from(value: OtherError) -> Self {
        Error::Other(value)
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        match value.kind() {
            std::io::ErrorKind::UnexpectedEof => Error::UnexpectedEof(0),
            std::io::ErrorKind::WriteZero => Error::ShortWrite(0),
            _ => Error::Other(OtherError::new(Box::new(value))),
        }
    }
}
