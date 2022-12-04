extern crate alloc;

use {
    crate::{
        error::Result,
        io::{Read, Write},
    },
    alloc::vec::Vec,
    core::{cmp::min, ops::Drop},
};

/// A fixed-length buffer.
#[derive(Clone, Debug)]
pub(crate) struct Buf<const N: usize> {
    /// Contents are data[read..write].
    /// Read at data[read], write at data[write].
    data: [u8; N],
    /// Read offset.
    read: usize,
    /// Write offset.
    write: usize,
}

#[cfg(test)]
macro_rules! buf {
    () => {
        Buf::new()
    };
    ($elem:expr; $n:expr) => {
        Buf::<$n>::from_elem($elem)
    };
}

impl<const N: usize> PartialEq<Vec<u8>> for Buf<N> {
    fn eq(&self, other: &Vec<u8>) -> bool {
        *self.remaining_slice() == other[..]
    }
}

impl<const N: usize> Default for Buf<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Buf<N> {
    pub const fn new() -> Self {
        Self::from_elem(0)
    }

    pub const fn from_elem(elem: u8) -> Self {
        Self {
            data: [elem; N],
            read: 0,
            write: 0,
        }
    }

    /// Reports whether all bytes have been read.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Reports whether the buffer is full and no more data can
    /// be written.
    pub fn is_full(&self) -> bool {
        self.len() == N
    }

    /// Returns the number of unread bytes in the buffer.
    pub fn len(&self) -> usize {
        self.write - self.read
    }

    /// Resets the buffer to empty.
    pub fn reset(&mut self) {
        self.read = 0;
        self.write = 0;
    }

    /// Discards all but the first n unread bytes in the buffer.
    pub fn truncate(&mut self, n: usize) {
        if n == 0 {
            self.reset();
            return;
        }
        self.write = self.read + n;
    }

    /// Returns the buffer's remaining capacity.
    pub fn remaining_capacity_mut(&mut self) -> &mut [u8] {
        &mut self.data[self.write..]
    }

    /// Returns the unread portion of the buffer.
    pub fn remaining_slice(&self) -> &[u8] {
        &self.data[self.read..self.write]
    }

    /// Returns the unread portion of the buffer as a mutable
    /// slice.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data[self.read..self.write]
    }

    /// Splits the unread portion of the buffer at mid, returning
    /// [0, mid) and [mid, N).
    pub fn split_at_mut(&mut self, mid: usize) -> (&mut [u8], &mut [u8]) {
        self.as_mut_slice().split_at_mut(mid)
    }

    /// Reads from `src` until the buffer is full or `src`
    /// reaches EOF.
    pub fn read_from<R: Read + ?Sized>(
        &mut self,
        src: &mut R,
    ) -> Result<usize> {
        let mut n = 0;
        while !self.is_full() {
            let m = src.read(self.remaining_capacity_mut())?;
            if m == 0 {
                break;
            }
            self.write += m;
            n += m;
        }
        Ok(n)
    }

    /// Writes the entire contents of the buffer to `src`.
    pub fn write_to<W: Write + ?Sized>(
        &mut self,
        src: &mut W,
    ) -> Result<usize> {
        let start = self.read;
        while !self.is_empty() {
            let m = src.write(self.remaining_slice())?;
            if m == 0 {
                break;
            }
            self.read += m;
        }
        let n = self.read - start;
        if n == 0 {
            self.reset();
        }
        Ok(n)
    }
}

impl<const N: usize> Drop for Buf<N> {
    fn drop(&mut self) {
        self.data.fill(0);
    }
}

impl<const N: usize> Read for Buf<N> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let src = self.remaining_slice();
        let n = min(src.len(), buf.len());
        buf[..n].copy_from_slice(&src[..n]);
        self.read += n;
        Ok(n)
    }
}

impl<const N: usize> Write for Buf<N> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let dst = self.remaining_capacity_mut();
        let n = min(dst.len(), buf.len());
        (dst[..n]).copy_from_slice(&buf[..n]);
        self.write += n;
        Ok(n)
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use {super::*, core::cmp};

    fn read_all<R: Read>(r: &mut R) -> Result<Vec<u8>> {
        let mut data = Vec::new();
        copy(r, &mut data)?;
        Ok(data)
    }

    fn copy<R, W>(src: &mut R, dst: &mut W) -> Result<u64>
    where
        R: Read + ?Sized,
        W: Write + ?Sized,
    {
        let mut buf = [0u8; 32 * 1024];
        let mut len = 0;
        loop {
            let nr = src.read(&mut buf)?;
            if nr == 0 {
                break;
            }
            len += dst.write(&buf[..nr])?;
        }
        Ok(len as u64)
    }

    struct SmallByteReader<'a, R: Read> {
        r: &'a mut R,
        off: usize,
        n: usize,
    }

    impl<'a, R: Read> SmallByteReader<'a, R> {
        fn new(r: &'a mut R) -> Self {
            Self { r, off: 0, n: 0 }
        }
    }

    impl<R: Read> Read for SmallByteReader<'_, R> {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
            if buf.len() == 0 {
                return Ok(0);
            }
            self.n = (self.n % 3) + 1;
            let n = cmp::min(self.n, buf.len());
            let nr = self.r.read(&mut buf[..n])?;
            self.off += nr;
            Ok(nr)
        }
    }

    fn test_reader<R: Read>(r: &mut R, content: &[u8]) {
        if content.len() > 0 {
            let n = r.read(&mut [0u8; 0][..]).unwrap();
            assert_eq!(n, 0);
        }
        let mut sbr = SmallByteReader::new(r);
        let data = read_all(&mut sbr).unwrap();
        assert_eq!(data, content);
        assert_eq!(0, r.read(&mut [0u8; 10][..]).unwrap());
    }

    #[test]
    fn test_buf_read() {
        const N: usize = 4096;
        const CONTENT: &'static str = "hello, world!";
        let mut b = Buf::<N>::new();
        b.write(CONTENT.as_bytes()).unwrap();
        test_reader(&mut b, CONTENT.as_bytes());
    }

    #[test]
    fn test_buf_read_from_write_to() {
        const N: usize = 4096;
        let mut b = buf![42u8; N];

        let src = vec![42u8; N];
        let nr = b.read_from(&mut &src[..]).unwrap();
        assert_eq!(nr, N);
        assert_eq!(b, src);

        let mut sink = Vec::new();
        let nw = b.write_to(&mut sink).unwrap();
        assert_eq!(nw, N);
        assert_eq!(sink.len(), N);
    }
}
