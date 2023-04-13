// tests for header parsing:
// - duplicate paremeter name
// - additional (private, public) headers
// - for supporting all MUST BE UNDERSTOOD params

use std::{convert::Infallible, string::FromUtf8Error};

use jose::{
    format::{Compact, JsonFlattened},
    header::HeaderValue,
    jwa::{EcDSA, JsonWebSigningAlgorithm},
    jwk::{
        ec::p256::{P256PrivateKey, P256Signer, P256Verifier},
        JwkSigner,
    },
    jws::{
        FromRawPayload, IntoSigner, IntoVerifier, PayloadKind, ProvidePayload, Signer, Unverified,
        Verifier,
    },
    policy::{Checkable, StandardPolicy},
    Base64UrlString, JsonWebKey, Jws,
};

#[derive(Debug, PartialEq, Eq)]
struct StringPayload(String);

impl From<&str> for StringPayload {
    fn from(value: &str) -> Self {
        StringPayload(value.to_string())
    }
}

impl FromRawPayload for StringPayload {
    type Error = FromUtf8Error;

    fn from_raw_payload(payload: PayloadKind) -> Result<Self, Self::Error> {
        match payload {
            PayloadKind::Standard(s) => String::from_utf8(s.decode()).map(StringPayload),
        }
    }
}

impl ProvidePayload for StringPayload {
    type Error = Infallible;

    fn provide_payload<D: digest::Update>(
        &mut self,
        digest: &mut D,
    ) -> Result<PayloadKind, Self::Error> {
        let s = Base64UrlString::encode(&self.0);
        digest.update(s.as_bytes());
        Ok(PayloadKind::Standard(s))
    }
}

struct DummyDigest;
impl digest::Update for DummyDigest {
    fn update(&mut self, _data: &[u8]) {}
}

struct NoneKey;
impl Signer<[u8; 0]> for NoneKey {
    type Digest = DummyDigest;

    fn new_digest(&self) -> Self::Digest {
        DummyDigest
    }

    fn sign_digest(&mut self, _digest: Self::Digest) -> Result<[u8; 0], signature::Error> {
        Ok([])
    }

    fn algorithm(&self) -> JsonWebSigningAlgorithm {
        JsonWebSigningAlgorithm::None
    }
}

struct NoneVerifier;
impl Verifier for NoneVerifier {
    fn verify(&mut self, _: &[u8], _: &[u8]) -> Result<(), signature::Error> {
        Ok(())
    }
}

#[test]
fn none_verifier_roundtrip() {
    let jws = Jws::<Compact, _>::builder()
        .build(StringPayload::from("abc"))
        .unwrap();
    let jws_compact = jws.sign(&mut NoneKey).unwrap().encode();

    assert_eq!(
        jws_compact.to_string(),
        String::from("eyJhbGciOiJub25lIn0.YWJj.")
    );

    let parsed_jws = Unverified::<Jws<Compact, StringPayload>>::decode(jws_compact)
        .unwrap()
        .verify(&mut NoneVerifier)
        .unwrap();

    assert_eq!(parsed_jws.payload(), &StringPayload::from("abc"));
}

#[test]
fn sign_jws_using_p256() {
    let key = std::fs::read_to_string(format!(
        "{}/tests/keys/p256.json",
        env!("CARGO_MANIFEST_DIR"),
    ))
    .unwrap();

    let key: P256PrivateKey = serde_json::from_str(&key).unwrap();
    let mut signer: P256Signer = key
        .into_signer(JsonWebSigningAlgorithm::EcDSA(EcDSA::Es256))
        .unwrap();

    let jws = Jws::<Compact, _>::builder()
        .build(StringPayload::from("hello world!"))
        .unwrap()
        .sign(&mut signer)
        .unwrap()
        .encode();

    assert_eq!(
        jws.to_string().as_str(),
        "eyJhbGciOiJFUzI1NiJ9.aGVsbG8gd29ybGQh.\
         lVKmpTNK_Im3-JEpF1JzuXM-vP9tNSkR8785hqnYzOHd1__VVOeMzGW7nywUe7Xkp6Wlu3KgWXlvsxhQdU1PlQ"
    );
}

#[test]
fn deny_compact_jws_with_empty_protected_header() {
    let jws: Jws<Compact, StringPayload> = Jws::builder()
        .header(|b| b.algorithm(HeaderValue::Unprotected(JsonWebSigningAlgorithm::None)))
        .build(StringPayload::from("abc"))
        .unwrap();

    jws.sign(&mut NoneKey).unwrap_err();
}

#[test]
fn json_flattened_jws_with_no_protected_header() {
    let key = std::fs::read_to_string(format!(
        "{}/tests/keys/cookbook_hs256.json",
        env!("CARGO_MANIFEST_DIR"),
    ))
    .unwrap();

    let key: JsonWebKey = serde_json::from_str(&key).unwrap();
    let key = key.check(StandardPolicy::new()).unwrap();

    let mut signer = JwkSigner::try_from(key).unwrap();

    let payload = "It's a dangerous business, Frodo, going out your door. You step onto the road, \
                   and if you don't keep your feet, there's no knowing where you";

    let jws: Jws<JsonFlattened, StringPayload> = Jws::builder()
        .header(|b| b.algorithm(HeaderValue::Unprotected(JsonWebSigningAlgorithm::None)))
        .build(StringPayload::from(payload))
        .unwrap();

    let jws = jws.sign(&mut signer).unwrap();

    println!("{:#}", jws);
}

#[test]
fn smoke() {
    let key = std::fs::read_to_string(format!(
        "{}/tests/keys/p256.json",
        env!("CARGO_MANIFEST_DIR"),
    ))
    .unwrap();

    let key: P256PrivateKey = serde_json::from_str(&key).unwrap();

    let mut verifier: P256Verifier = key
        .clone()
        .into_verifier(JsonWebSigningAlgorithm::EcDSA(EcDSA::Es256))
        .unwrap();

    let mut signer: P256Signer = key
        .into_signer(JsonWebSigningAlgorithm::EcDSA(EcDSA::Es256))
        .unwrap();

    let payload = r#"{"iss":"joe","exp":1300819380,"http://example.com/is_root":true}"#;
    let payload = StringPayload::from(payload);

    let jws = Jws::<JsonFlattened, _>::builder()
        .header(|b| {
            b.algorithm(HeaderValue::Protected(JsonWebSigningAlgorithm::None))
                .typ(Some(HeaderValue::Protected(
                    "application/jwt".parse().unwrap(),
                )))
        })
        .build(payload)
        .unwrap()
        .sign(&mut signer)
        .unwrap()
        .encode();

    let parsed_jws = Unverified::<Jws<JsonFlattened, StringPayload>>::decode(jws)
        .unwrap()
        .verify(&mut verifier)
        .unwrap();

    println!("{:?}", parsed_jws);
}

// #[test]
// fn sign_jws_using_hs256() {
//     let key = std::fs::read_to_string(format!(
//         "{}/tests/keys/hs256.json",
//         env!("CARGO_MANIFEST_DIR")
//     ))
//     .unwrap();
//
//     let key: SymmetricJsonWebKey = serde_json::from_str(&key).unwrap();
//
//     match key {
//         SymmetricJsonWebKey::OctetSequence(ref key) => {
//             let mut signer: HmacKey<Hs256> = key
//                 .into_signer(JsonWebSigningAlgorithm::Hmac(Hmac::Hs256))
//                 .unwrap();
//             let jws = JWS::builder()
//                 .build(StringPayload("Here be dragons".to_string()))
//                 .sign(&mut signer)
//                 .unwrap();
//
//             println!("{}", jws.encode::<Compact>());
//         }
//         _ => panic!("unexpected key type"),
//     }
// }

// #[test]
// fn sign_jws_using_rsa() {
//     let key = std::fs::read_to_string(format!(
//         "{}/tests/keys/rsa.json",
//         env!("CARGO_MANIFEST_DIR")
//     ))
//     .unwrap();
//
//     let key = serde_json::from_str::<JsonWebKey>(&key)
//         .unwrap()
//         .check(StandardPolicy::default())
//         .unwrap();
//
//     let mut signer: JwkSigner = key.try_into().unwrap();
//
//     let jws = JWS::builder()
//         .build(StringPayload("Here be dragons".to_string()))
//         .sign(&mut signer)
//         .unwrap();
//
//     println!("{}", jws.encode::<Compact>());
// }
