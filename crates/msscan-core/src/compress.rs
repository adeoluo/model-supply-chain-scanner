//! Bounded decompression of the single-stream formats joblib and others wrap pickles in.

use std::io::Read;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec {
    Gzip,
    Zlib,
    Bzip2,
    Xz,
    Lzma,
    Lz4,
    Zstd,
}

impl Codec {
    pub fn name(self) -> &'static str {
        match self {
            Codec::Gzip => "gzip",
            Codec::Zlib => "zlib",
            Codec::Bzip2 => "bzip2",
            Codec::Xz => "xz",
            Codec::Lzma => "lzma",
            Codec::Lz4 => "lz4",
            Codec::Zstd => "zstd",
        }
    }
}

/// Recognize a compressed stream by its magic bytes.
pub fn detect(d: &[u8]) -> Option<Codec> {
    match d {
        [0x1f, 0x8b, ..] => Some(Codec::Gzip),
        [0x78, b, ..] if (0x7800u16 | *b as u16).is_multiple_of(31) && matches!(*b, 0x01 | 0x5e | 0x9c | 0xda) => {
            Some(Codec::Zlib)
        }
        [b'B', b'Z', b'h', ..] => Some(Codec::Bzip2),
        [0xfd, b'7', b'z', b'X', b'Z', 0x00, ..] => Some(Codec::Xz),
        [0x5d, 0x00, 0x00, ..] => Some(Codec::Lzma),
        [0x04, 0x22, 0x4d, 0x18, ..] => Some(Codec::Lz4),
        [0x28, 0xb5, 0x2f, 0xfd, ..] => Some(Codec::Zstd),
        _ => None,
    }
}

#[derive(Debug, PartialEq)]
pub enum Error {
    TooLarge(u64),
    Corrupt(String),
    Unsupported(&'static str),
}

fn bounded(mut r: impl Read, limit: u64) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    (&mut r)
        .take(limit + 1)
        .read_to_end(&mut out)
        .map_err(|e| Error::Corrupt(e.to_string()))?;
    if out.len() as u64 > limit {
        return Err(Error::TooLarge(limit));
    }
    Ok(out)
}

/// Decompress at most `limit` bytes.
pub fn decompress(codec: Codec, d: &[u8], limit: u64) -> Result<Vec<u8>, Error> {
    match codec {
        Codec::Gzip => bounded(flate2::read::MultiGzDecoder::new(d), limit),
        Codec::Zlib => bounded(flate2::read::ZlibDecoder::new(d), limit),
        Codec::Bzip2 => bounded(bzip2::read::MultiBzDecoder::new(d), limit),
        Codec::Lz4 => bounded(lz4_flex::frame::FrameDecoder::new(d), limit),
        Codec::Xz | Codec::Lzma => {
            let mut out = LimitedVec {
                buf: Vec::new(),
                limit,
                overflow: false,
            };
            let mut input = std::io::BufReader::new(d);
            let r = if codec == Codec::Xz {
                lzma_rs::xz_decompress(&mut input, &mut out)
            } else {
                lzma_rs::lzma_decompress(&mut input, &mut out)
            };
            match r {
                Ok(()) => Ok(out.buf),
                Err(_) if out.overflow => Err(Error::TooLarge(limit)),
                Err(e) => Err(Error::Corrupt(e.to_string())),
            }
        }
        Codec::Zstd => Err(Error::Unsupported("zstd")),
    }
}

/// A writer that refuses to grow past `limit` bytes.
struct LimitedVec {
    buf: Vec<u8>,
    limit: u64,
    overflow: bool,
}

impl std::io::Write for LimitedVec {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        if self.buf.len() as u64 + b.len() as u64 > self.limit {
            self.overflow = true;
            return Err(std::io::Error::other("decompression limit"));
        }
        self.buf.extend_from_slice(b);
        Ok(b.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn payload() -> Vec<u8> {
        b"\x80\x02cos\ngetcwd\n)R.".repeat(10)
    }

    #[test]
    fn round_trips_every_supported_codec() {
        let p = payload();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&p).unwrap();
        let gz = gz.finish().unwrap();
        let mut zl = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        zl.write_all(&p).unwrap();
        let zl = zl.finish().unwrap();
        let mut bz = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
        bz.write_all(&p).unwrap();
        let bz = bz.finish().unwrap();
        let mut xz = Vec::new();
        lzma_rs::xz_compress(&mut std::io::Cursor::new(&p), &mut xz).unwrap();
        let mut lz = Vec::new();
        lzma_rs::lzma_compress(&mut std::io::Cursor::new(&p), &mut lz).unwrap();
        let mut l4 = lz4_flex::frame::FrameEncoder::new(Vec::new());
        l4.write_all(&p).unwrap();
        let l4 = l4.finish().unwrap();
        for (blob, codec) in [
            (gz, Codec::Gzip),
            (zl, Codec::Zlib),
            (bz, Codec::Bzip2),
            (xz, Codec::Xz),
            (lz, Codec::Lzma),
            (l4, Codec::Lz4),
        ] {
            assert_eq!(detect(&blob), Some(codec), "{}", codec.name());
            assert_eq!(decompress(codec, &blob, 1 << 20).unwrap(), p);
            assert_eq!(
                decompress(codec, &blob, 10),
                Err(Error::TooLarge(10)),
                "{}",
                codec.name()
            );
        }
    }

    #[test]
    fn rejects_unknown_and_corrupt() {
        assert_eq!(detect(b"\x80\x02"), None);
        assert_eq!(detect(&[0x28, 0xb5, 0x2f, 0xfd]), Some(Codec::Zstd));
        assert_eq!(decompress(Codec::Zstd, b"", 10), Err(Error::Unsupported("zstd")));
        assert!(matches!(
            decompress(Codec::Gzip, &[0x1f, 0x8b, 0, 0], 10),
            Err(Error::Corrupt(_))
        ));
        assert!(matches!(
            decompress(Codec::Xz, &[0xfd, b'7', b'z', b'X', b'Z', 0], 10),
            Err(Error::Corrupt(_))
        ));
    }
}
