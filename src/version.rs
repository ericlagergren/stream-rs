use core::{fmt, result};

/// Denotes different stream versions.
#[repr(u32)]
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum Version {
    /// The exact same as [stream].
    ///
    /// [stream]: https://github.com/ericlagergren/stream
    One = 1,
    /// The same as [`Version::One`], except that it does not
    /// allow the final chunk to be a full chunk.
    ///
    /// If the final chunk is a full chunk, a zero-sized chunk is
    /// appended afterward.
    Two = 2,
}

impl fmt::Display for Version {
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> result::Result<(), fmt::Error> {
        write!(f, "{}", *self as u32)
    }
}

impl fmt::Debug for Version {
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> result::Result<(), fmt::Error> {
        fmt::Display::fmt(self, f)
    }
}

impl Version {
    /// Converts the version to its big-endian representation.
    pub fn to_bytes(&self) -> [u8; 4] {
        (*self as u32).to_be_bytes()
    }
}

impl TryFrom<u32> for Version {
    type Error = crate::error::Error;

    fn try_from(v: u32) -> result::Result<Version, Self::Error> {
        match v {
            x if x == Version::One as u32 => Ok(Version::One),
            x if x == Version::Two as u32 => Ok(Version::Two),
            _ => Err(crate::error::Error::InvalidVersion(v)),
        }
    }
}

impl TryFrom<[u8; 4]> for Version {
    type Error = crate::error::Error;

    fn try_from(v: [u8; 4]) -> result::Result<Version, Self::Error> {
        Version::try_from(u32::from_be_bytes(v))
    }
}
