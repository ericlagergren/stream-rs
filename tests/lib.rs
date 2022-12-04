use {
    aead::{AeadCore, Key, KeyInit, KeySizeUser},
    aes::{
        cipher::{KeyIvInit, StreamCipher, Unsigned},
        Aes128Enc, Aes192Enc, Aes256Enc,
    },
    chacha20poly1305::XChaCha20Poly1305,
    flate2::read::GzDecoder,
    rand_core::{OsRng, RngCore},
    serde::{Deserialize, Serialize},
    std::{
        fs::File,
        io::{BufRead, BufReader},
        iter::Iterator,
        path::PathBuf,
    },
    stream::*,
};

const MFST_DIR: &str = env!("CARGO_MANIFEST_DIR");

fn rand_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    OsRng.fill_bytes(&mut b);
    b
}

struct RngIter<'a, R: RngCore>(&'a mut R);

impl<R: RngCore> Iterator for RngIter<'_, R> {
    type Item = u8;

    fn next(&mut self) -> Option<u8> {
        let mut b = [0u8; 1];
        self.0.fill_bytes(&mut b[..]);
        Some(b[0])
    }
}

impl<'a, R: RngCore> RngIter<'a, R> {
    fn new(rng: &'a mut R) -> RngIter<'a, R> {
        RngIter(rng)
    }
}

struct ReadWrapper<R: std::io::Read>(R);

impl<R: std::io::Read> Read for ReadWrapper<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        loop {
            match std::io::Read::read(&mut self.0, buf) {
                Ok(n) => return Ok(n),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(Error::Other(OtherError::new(e))),
            }
        }
    }
}

fn read_all<R: Read>(r: &mut R) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    r.write_to(&mut data)?;
    Ok(data)
}

#[derive(Serialize, Deserialize)]
struct TestVector {
    #[serde(rename(deserialize = "Seed"), with = "base64")]
    seed: Vec<u8>,
    #[serde(rename(deserialize = "Plaintext"), with = "base64")]
    plaintext: Vec<u8>,
    #[serde(rename(deserialize = "Ciphertext"), with = "base64")]
    ciphertext: Vec<u8>,
}

// https://users.rust-lang.org/t/serialize-a-vec-u8-to-json-as-base64/57781/2
mod base64 {
    use serde::{Deserialize, Serialize};
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(
        v: &Vec<u8>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        let base64 = base64::encode(v);
        String::serialize(&base64, s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Vec<u8>, D::Error> {
        let base64 = String::deserialize(d)?;
        base64::decode(base64.as_bytes())
            .map_err(|e| serde::de::Error::custom(e))
    }
}

fn new_key<T>(seed: &[u8]) -> Key<T>
where
    T: AeadCore + KeyInit,
{
    let iv = aes::Block::default();
    let mut c: Box<dyn StreamCipher> = match seed.len() {
        <Aes128Enc as KeySizeUser>::KeySize::USIZE => {
            Box::new(ctr::Ctr128BE::<Aes128Enc>::new(seed.into(), &iv))
        }
        <Aes192Enc as KeySizeUser>::KeySize::USIZE => {
            Box::new(ctr::Ctr128BE::<Aes192Enc>::new(seed.into(), &iv))
        }
        <Aes256Enc as KeySizeUser>::KeySize::USIZE => {
            Box::new(ctr::Ctr128BE::<Aes256Enc>::new(seed.into(), &iv))
        }
        _ => panic!("invalid seed length: {}", seed.len()),
    };
    let mut key = Key::<T>::default();
    c.apply_keystream(&mut key);
    key
}

#[test]
fn test_basic() {
    const C: usize = 65536;
    const N: usize = (C * 5) + (C / 2);

    let mut rng = OsRng;
    let plaintext: Vec<u8> = RngIter::new(&mut rng).take(N).collect();
    let key = new_key::<XChaCha20Poly1305>(&rand_bytes::<32>());

    let mut ciphertext = Vec::new();
    let mut wr = Writer::<_, XChaCha20Poly1305, C>::new(
        &mut ciphertext,
        &mut rng,
        &key.into(),
    )
    .unwrap();
    wr.write_all(&mut &plaintext[..]).unwrap();
    wr.flush().unwrap();

    let mut ciphertext = &ciphertext[..];
    let mut rd =
        Reader::<_, XChaCha20Poly1305>::new(&mut ciphertext, &key.into())
            .unwrap();
    let got = read_all(&mut rd).unwrap();
    assert_eq!(got, plaintext);
}

#[test]
fn test_golden() {
    let mut path = PathBuf::from(MFST_DIR);
    path.push("tests");
    path.push("testdata");
    path.push("golden.json.gz");

    let mut file = File::open(path).unwrap();
    let mut gzr = GzDecoder::new(&mut file);
    let reader = BufReader::new(&mut gzr);
    for line in reader.lines() {
        let test = serde_json::from_str::<TestVector>(&line.unwrap()).unwrap();
        let key = new_key::<XChaCha20Poly1305>(test.seed.as_slice());
        let mut ciphertext = &test.ciphertext[..];
        let mut rd =
            Reader::<_, XChaCha20Poly1305>::new(&mut ciphertext, &key.into())
                .unwrap();
        let got = read_all(&mut rd).unwrap();
        assert_eq!(got, test.plaintext);
    }
}

#[test]
fn test_v1_zero_size_eof() {
    const C: usize = 1;
    const N: usize = 2;

    let mut rng = OsRng;
    let plaintext: Vec<u8> = RngIter::new(&mut rng).take(N).collect();
    let key = new_key::<XChaCha20Poly1305>(&rand_bytes::<32>());
    let opts = WriterOpts::new().with_version(Version::One).build();

    let mut ciphertext = Vec::new();
    let mut wr = Writer::<_, XChaCha20Poly1305, C>::new_with(
        &mut ciphertext,
        &mut rng,
        &key.into(),
        opts,
    )
    .unwrap();
    wr.write_all(&mut &plaintext[..]).unwrap();
    wr.flush().unwrap();

    assert_eq!(
        ciphertext.len(),
        Writer::<(), XChaCha20Poly1305, C>::size(N, opts)
    );

    let mut ciphertext = &ciphertext[..];
    let mut rd =
        Reader::<_, XChaCha20Poly1305, C>::new(&mut ciphertext, &key.into())
            .unwrap();
    let got = read_all(&mut rd).unwrap();
    assert_eq!(got, plaintext);
}

#[test]
fn test_v2_zero_size_eof() {
    const C: usize = 1;
    const N: usize = 2;

    let mut rng = OsRng;
    let plaintext: Vec<u8> = RngIter::new(&mut rng).take(N).collect();
    let key = new_key::<XChaCha20Poly1305>(&rand_bytes::<32>());
    let opts = WriterOpts::new().with_version(Version::Two).build();

    let mut ciphertext = Vec::new();
    let mut wr = Writer::<_, XChaCha20Poly1305, C>::new_with(
        &mut ciphertext,
        &mut rng,
        &key.into(),
        opts,
    )
    .unwrap();
    wr.write_all(&mut &plaintext[..]).unwrap();
    wr.flush().unwrap();

    assert_eq!(
        ciphertext.len(),
        Writer::<(), XChaCha20Poly1305, C>::size(N, opts)
    );

    let mut ciphertext = &ciphertext[..];
    let mut rd =
        Reader::<_, XChaCha20Poly1305, C>::new(&mut ciphertext, &key.into())
            .unwrap();
    let got = read_all(&mut rd).unwrap();
    assert_eq!(got, plaintext);
}
