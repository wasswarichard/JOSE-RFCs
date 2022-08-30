use std::{convert::Infallible, string::FromUtf8Error};

use jose::{
    format::Compact,
    jwa::{JsonWebAlgorithm, JsonWebSigningAlgorithm},
    jws::{FromRawPayload, ParseCompactError, PayloadKind, ProvidePayload, Signer, Unverified},
    Base64UrlString, JsonWebKey, JsonWebSignature,
};
use serde::Deserialize;
use serde_json::Value;

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

#[derive(Deserialize, Debug)]
#[serde(transparent)]
pub struct StringPayload(String);

impl FromRawPayload for StringPayload {
    type Error = std::string::FromUtf8Error;

    fn from_raw_payload(payload: PayloadKind) -> Result<Self, Self::Error> {
        match payload {
            PayloadKind::Standard(x) => String::from_utf8(x.decode()).map(StringPayload),
            _ => unreachable!(),
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

#[derive(Deserialize)]
pub struct TestSpec {
    #[serde(default)]
    reproducible: bool,
    input: TestInput,
    signing: TestSigning,
    output: TestOutput,
}

#[derive(Deserialize)]
pub struct TestSigning {
    protected_b64u: String,
    #[serde(rename = "sig-input")]
    sig_input: String,
}

#[derive(Deserialize)]
pub struct TestOutput {
    compact: String,
    // json: Value,
    json_flat: Value,
}

#[derive(Deserialize)]
pub struct TestInput {
    payload: StringPayload,
    key: JsonWebKey,
    alg: JsonWebAlgorithm,
}

pub fn get_spec_for_file(file: &str) -> TestSpec {
    let file = format!("tests/cookbook/jws/{}", file);
    let json = std::fs::read_to_string(file).expect("failed to read test spec file");
    serde_json::from_str::<TestSpec>(&json).expect("test specification does not match format")
}

macro_rules! json_spec_test {
    ($file:literal, $name:ident) => {
        paste::paste! {
            #[test]
            pub fn [<sign_ $name>]() {
                let spec = crate::get_spec_for_file($file);

                let jwk = spec
                    .input
                    .key
                    .into_builder()
                    .algorithm(Some(spec.input.alg))
                    .build_and_check(jose::policy::StandardPolicy::default())
                    .unwrap();

                let mut signer: jose::jwk::JwkSigner = jwk.try_into().unwrap();
                let jws = jose::JsonWebSignature::new(spec.input.payload)
                    .sign(&mut signer)
                    .unwrap();
                let compact = jws.clone().encode::<jose::format::Compact>();
                let json_flat = jws.encode::<jose::format::JsonFlattened>();

                if spec.reproducible {
                    // only if test is reproducible, we compare the whole string
                    assert_eq!(
                        compact.to_string(),
                        spec.output.compact,
                        "full compact representation didn't match"
                    );

                    assert_eq!(
                        json_flat.into_inner(),
                        spec.output.json_flat,
                        "full json flattened representation didn't match"
                    );
                } else {
                    // otherwise, compare header and sig-input
                    let header = compact.part(0).unwrap();
                    assert_eq!(
                        &**header, spec.signing.protected_b64u,
                        "base64 encoded header didn't match"
                    );

                    let payload = compact.part(1).unwrap();
                    let sig_input = format!("{}.{}", header, payload);

                    assert_eq!(sig_input, spec.signing.sig_input, "sig-input didn't match");
                }
            }

            #[test]
            pub fn [<verify_ $name>]() {
                use std::str::FromStr;

                let spec = crate::get_spec_for_file($file);

                let jwk = spec
                    .input
                    .key
                    .into_builder()
                    .algorithm(Some(spec.input.alg))
                    .build_and_check(jose::policy::StandardPolicy::default())
                    .unwrap();

                let mut verifier: jose::jwk::JwkVerifier = jwk.try_into().unwrap();

                let jws = jose::format::Compact::from_str(&spec.output.compact).unwrap();
                let res = jose::jws::Unverified::<jose::JsonWebSignature<crate::StringPayload>>::decode(jws)
                    .unwrap()
                    .verify(&mut verifier);
                assert!(res.is_ok(), "failed to verify key");
            }
        }
    };
}

pub mod cookbook {
    json_spec_test!("4_1.rsa_v15_signature.json", rsa_v15_signature);
    json_spec_test!("4_2.rsa-pss_signature.json", rsa_pss_signature);
    // uses P-521 curve which is not supported yet
    // json_spec_test!("4_3.ecdsa_signature.json", ecdsa_signature);
    json_spec_test!(
        "4_4.hmac-sha2_integrity_protection.json",
        hmac_integrity_protection
    );
    // detached content is not yet supported
    // json_spec_test!(
    //     "4_5.signature_with_detached_content.json",
    //     signature_with_detached_content
    // );

    // format for test file not yet supported
    // json_spec_test!(
    //     "4_6.protecting_specific_header_fields.json",
    //     protecting_specific_header_fields
    // );

    // format for test file not yet supported
    // json_spec_test!(
    //     "4_7.protecting_content_only.json",
    //     protecting_content_only
    // );

    // JSON generl format not yet supported by jose
    // json_spec_test!(
    //     "4_8.multiple_signatures.json",
    //     multuiple_signatures
    // );
}

#[test]
fn deny_jws_with_unsupported_crit_header() {
    let jws = JsonWebSignature::builder()
        .critical(vec!["foo".into()])
        .build(StringPayload(String::from("")))
        .sign(&mut NoneKey)
        .unwrap();
    let jws = jws.encode::<Compact>();

    let err = Unverified::<JsonWebSignature<StringPayload>>::decode(jws).unwrap_err();
    assert_eq!(
        err,
        ParseCompactError::<FromUtf8Error>::UnsupportedCriticalHeader
    );
}

#[test]
fn allow_jws_with_empty_crit_header() {
    let jws = JsonWebSignature::builder()
        .critical(vec![])
        .build(StringPayload(String::from("")))
        .sign(&mut NoneKey)
        .unwrap();
    let jws = jws.encode::<Compact>();

    Unverified::<JsonWebSignature<StringPayload>>::decode(jws).unwrap();
}
