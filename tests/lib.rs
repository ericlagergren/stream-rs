#![feature(buf_read_has_data_left)]

use aead::{AeadCore, Key, KeyInit, KeySizeUser};
use aes::{
    cipher::{KeyIvInit, StreamCipher, Unsigned},
    Aes128Enc, Aes192Enc, Aes256Enc,
};
use chacha20poly1305::XChaCha20Poly1305;
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{BufRead, BufReader, Read},
    path::PathBuf,
};
use stream::Reader;

static MFST_DIR: &str = env!("CARGO_MANIFEST_DIR");

fn read_all<R: Read>(r: &mut R) -> std::io::Result<Vec<u8>> {
    let mut data = Vec::new();
    r.read_to_end(&mut data)?;
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
        let mut ciphertext = test.ciphertext.as_slice();
        let mut rd =
            Reader::<_, XChaCha20Poly1305>::new(&mut ciphertext, &key.into())
                .unwrap();
        let got = read_all(&mut rd).unwrap();
        assert_eq!(got, test.plaintext);
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
