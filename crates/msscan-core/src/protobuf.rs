//! A minimal protobuf wire-format reader (no schema compilation, no allocation per field).

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Value<'a> {
    Varint(u64),
    Fixed64(u64),
    Bytes(&'a [u8]),
    Fixed32(u32),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Error {
    Truncated,
    BadWireType(u8),
    BadField,
}

pub struct Reader<'a> {
    d: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(d: &'a [u8]) -> Self {
        Reader { d, pos: 0 }
    }

    fn varint(&mut self) -> Result<u64, Error> {
        let mut v = 0u64;
        for i in 0..10 {
            let b = *self.d.get(self.pos).ok_or(Error::Truncated)?;
            self.pos += 1;
            v |= ((b & 0x7f) as u64) << (7 * i);
            if b & 0x80 == 0 {
                return Ok(v);
            }
        }
        Err(Error::BadField)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.pos.checked_add(n).ok_or(Error::Truncated)?;
        let s = self.d.get(self.pos..end).ok_or(Error::Truncated)?;
        self.pos = end;
        Ok(s)
    }

    /// The next (field number, value), or None at the end of the message.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<Option<(u32, Value<'a>)>, Error> {
        if self.pos >= self.d.len() {
            return Ok(None);
        }
        let key = self.varint()?;
        let field = (key >> 3) as u32;
        if field == 0 {
            return Err(Error::BadField);
        }
        let v = match (key & 7) as u8 {
            0 => Value::Varint(self.varint()?),
            1 => {
                let b = self.take(8)?;
                Value::Fixed64(u64::from_le_bytes(b.try_into().expect("8 bytes")))
            }
            2 => {
                let n = usize::try_from(self.varint()?).map_err(|_| Error::Truncated)?;
                Value::Bytes(self.take(n)?)
            }
            5 => {
                let b = self.take(4)?;
                Value::Fixed32(u32::from_le_bytes(b.try_into().expect("4 bytes")))
            }
            w => return Err(Error::BadWireType(w)),
        };
        Ok(Some((field, v)))
    }

    /// Every length-delimited value of `field`, failing on malformed input.
    pub fn bytes_fields(d: &'a [u8], field: u32) -> Result<Vec<&'a [u8]>, Error> {
        let mut r = Reader::new(d);
        let mut out = Vec::new();
        while let Some((f, v)) = r.next()? {
            if let (true, Value::Bytes(b)) = (f == field, v) {
                out.push(b);
            }
        }
        Ok(out)
    }

    /// Visit every field of a message.
    pub fn each(d: &'a [u8], mut f: impl FnMut(u32, Value<'a>) -> Result<(), Error>) -> Result<(), Error> {
        let mut r = Reader::new(d);
        while let Some((n, v)) = r.next()? {
            f(n, v)?;
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A tiny protobuf writer for tests.
    #[derive(Default, Clone)]
    pub struct W(pub Vec<u8>);

    impl W {
        pub fn varint_raw(mut self, mut v: u64) -> Self {
            loop {
                let b = (v & 0x7f) as u8;
                v >>= 7;
                if v == 0 {
                    self.0.push(b);
                    return self;
                }
                self.0.push(b | 0x80);
            }
        }
        pub fn varint(self, field: u32, v: u64) -> Self {
            self.varint_raw((field as u64) << 3).varint_raw(v)
        }
        pub fn bytes(self, field: u32, b: &[u8]) -> Self {
            let mut w = self.varint_raw(((field as u64) << 3) | 2).varint_raw(b.len() as u64);
            w.0.extend_from_slice(b);
            w
        }
        pub fn msg(self, field: u32, m: W) -> Self {
            self.bytes(field, &m.0)
        }
        pub fn str(self, field: u32, s: &str) -> Self {
            self.bytes(field, s.as_bytes())
        }
    }

    #[test]
    fn decodes_every_wire_type() {
        let mut w = W::default().varint(1, 300).str(2, "hi");
        w.0.extend_from_slice(&[0x19, 1, 0, 0, 0, 0, 0, 0, 0, 0x25, 2, 0, 0, 0]);
        let mut r = Reader::new(&w.0);
        assert_eq!(r.next().unwrap(), Some((1, Value::Varint(300))));
        assert_eq!(r.next().unwrap(), Some((2, Value::Bytes(b"hi"))));
        assert_eq!(r.next().unwrap(), Some((3, Value::Fixed64(1))));
        assert_eq!(r.next().unwrap(), Some((4, Value::Fixed32(2))));
        assert_eq!(r.next().unwrap(), None);
        assert_eq!(Reader::bytes_fields(&w.0, 2).unwrap(), vec![b"hi".as_slice()]);
    }

    #[test]
    fn rejects_malformed() {
        assert_eq!(Reader::new(&[0x0b]).next(), Err(Error::BadWireType(3)));
        assert_eq!(Reader::new(&[0x12, 5, 1]).next(), Err(Error::Truncated));
        assert_eq!(Reader::new(&[0x00]).next(), Err(Error::BadField));
        assert_eq!(
            Reader::new(&[0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]).next(),
            Err(Error::BadField)
        );
        assert_eq!(Reader::new(&[0x08]).next(), Err(Error::Truncated));
        assert!(Reader::each(&[0x08, 1, 0x10], |_, _| Ok(())).is_err());
    }
}
