use crate::error::{Error, Result};

/// Read is roughly equivalent to [`std::io::Read`], but works
/// with `no_std`.
///
/// When the `std` feature is enabled, all types that implement
/// [`std::io::Read`] also implement [`Read`].
pub trait Read {
    /// Equivalent to [`std::io::Read::read`].
    fn read(&mut self, buf: &mut [u8]) -> Result<usize>;

    /// Equivalent to [`std::io::Read::read_exact`].
    ///
    /// If it reads fewer than `buf.len()` bytes, it returns
    /// [`Error::UnexpectedEof`].
    fn read_exact(&mut self, buf: &mut [u8]) -> Result<()> {
        match read_full(self, buf) {
            Ok(n) if n == buf.len() => Ok(()),
            Ok(n) => Err(Error::UnexpectedEof(n)),
            Err(err) => Err(err),
        }
    }

    /// Writes all data to `w`.
    fn write_to<W: Write + ?Sized>(&mut self, w: &mut W) -> Result<usize> {
        let mut buf = [0u8; 32 * 1024];
        let mut len = 0;
        loop {
            let nr = self.read(&mut buf)?;
            if nr == 0 {
                break;
            }
            len += w.write(&buf[..nr])?;
        }
        Ok(len)
    }
}

fn read_full<R: Read + ?Sized>(r: &mut R, buf: &mut [u8]) -> Result<usize> {
    let mut i = 0;
    while i < buf.len() {
        let n = r.read(&mut buf[i..])?;
        if n == 0 {
            break;
        }
        i += n;
    }
    Ok(i)
}

/// Write is roughly equivalent to [`std::io::Write`], but works
/// with `no_std`.
///
/// When the `std` feature is enabled, all types that implement
/// [`std::io::Write`] also implement [`Write`].
pub trait Write {
    /// Equivalent to [`std::io::Write::write`].
    fn write(&mut self, buf: &[u8]) -> Result<usize>;

    /// Equivalent to [`std::io::Write::write_all`].
    ///
    /// If it cannot write the entirety of `buf`, it returns
    /// [`Error::ShortWrite`].
    fn write_all(&mut self, mut buf: &[u8]) -> Result<()> {
        let mut nw = 0;
        while !buf.is_empty() {
            match self.write(buf) {
                Ok(0) => return Err(Error::ShortWrite(nw)),
                Ok(n) => {
                    nw += n;
                    buf = &buf[n..]
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Equivalent to [`std::io::Write::flush`].
    fn flush(&mut self) -> Result<()>;
}

#[cfg(feature = "std")]
mod std_io {
    use crate::{Read, Result, Write};

    impl<T: std::io::Read> Read for T {
        #[inline]
        fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
            loop {
                match std::io::Read::read(self, buf) {
                    Ok(n) => return Ok(n),
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(e.into()),
                }
            }
        }
    }

    impl<T: std::io::Write> Write for T {
        #[inline]
        fn write(&mut self, buf: &[u8]) -> Result<usize> {
            Ok(self.write(buf)?)
        }

        fn flush(&mut self) -> Result<()> {
            Ok(self.flush()?)
        }
    }
}

#[cfg(not(feature = "std"))]
mod no_std_io {
    extern crate alloc;

    use {
        crate::{Read, Result, Write},
        alloc::vec::Vec,
        core::{alloc::Allocator, cmp},
    };

    impl Read for &[u8] {
        #[inline]
        fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
            let n = cmp::min(buf.len(), self.len());
            let (head, tail) = self.split_at(n);
            if n == 1 {
                buf[0] = head[0];
            } else {
                buf[..n].copy_from_slice(head);
            }
            *self = tail;
            Ok(n)
        }
    }

    impl<A: Allocator> Write for Vec<u8, A> {
        #[inline]
        fn write(&mut self, buf: &[u8]) -> Result<usize> {
            self.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> Result<()> {
            Ok(())
        }
    }
}
