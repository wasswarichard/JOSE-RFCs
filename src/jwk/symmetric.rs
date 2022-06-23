use alloc::{string::String, vec::Vec};

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{de::Error, Deserialize, Serialize};

use crate::base64_url::Base64UrlBytes;

/// <https://datatracker.ietf.org/doc/html/rfc7518#section-6.4>
#[non_exhaustive]
#[derive(Debug, PartialEq, Eq)]
pub enum SymmetricJsonWebKey {
    /// `oct` <https://datatracker.ietf.org/doc/html/rfc7518#section-6.4>
    OctetSequence(OctetSequence),
}

impl Serialize for SymmetricJsonWebKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            SymmetricJsonWebKey::OctetSequence(bytes) => {
                #[derive(Serialize)]
                struct Repr {
                    kty: &'static str,
                    k: String,
                }

                let encoded = Base64UrlUnpadded::encode_string(&bytes.0);

                Repr {
                    kty: "oct",
                    k: encoded,
                }
                .serialize(serializer)
            }
        }
    }
}

impl<'de> Deserialize<'de> for SymmetricJsonWebKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct OctetRepr {
            kty: String,
            k: Base64UrlBytes,
        }

        let repr = OctetRepr::deserialize(deserializer)?;

        if repr.kty != "oct" {
            return Err(D::Error::custom("`kty` field is required to be \"oct\""));
        }

        Ok(SymmetricJsonWebKey::OctetSequence(OctetSequence(repr.k.0)))
    }
}

/// <https://datatracker.ietf.org/doc/html/rfc7518#section-6.4.1>
#[derive(Debug, PartialEq, Eq)]
pub struct OctetSequence(pub(self) Vec<u8>);

use digest::{InvalidLength, Mac, Output};
use hmac::Hmac;
use sha2::{Sha256, Sha384, Sha512};

use crate::{
    jwa::{Hmac as Hs, JsonWebSigningAlgorithm},
    sign::{FromKey, InvalidSigningAlgorithmError},
    Signer,
};

/// An error that can occur then creating [`Hs256Signer`], [`Hs384Signer`] or
/// [`Hs512Signer`] from an [`OctetSequence`]
#[derive(Debug, thiserror_no_std::Error)]
pub enum FromOctetSequenceError {
    #[error(transparent)]
    InvalidSigning(#[from] InvalidSigningAlgorithmError),
    #[error(transparent)]
    InvalidLength(#[from] InvalidLength),
}

macro_rules! hs_signer {
    ($hash:ty, $name:ident, $alg:expr, $expected:pat_param) => {
        pub struct $name {
            key: Hmac<$hash>,
        }

        impl Signer<Output<Hmac<$hash>>> for $name {
            fn sign(&mut self, msg: &[u8]) -> Result<Output<Hmac<$hash>>, signature::Error> {
                self.key.update(msg);
                Ok(self.key.finalize_reset().into_bytes())
            }

            fn algorithm(&self) -> JsonWebSigningAlgorithm {
                JsonWebSigningAlgorithm::Hmac($alg)
            }
        }

        impl FromKey<OctetSequence, Output<Hmac<$hash>>> for $name {
            type Error = FromOctetSequenceError;

            fn from_key(
                key: OctetSequence,
                alg: JsonWebSigningAlgorithm,
            ) -> Result<$name, FromOctetSequenceError> {
                match alg {
                    JsonWebSigningAlgorithm::Hmac($expected) => {
                        let key: Hmac<$hash> = Hmac::new_from_slice(&key.0)?;
                        Ok(Self { key })
                    }
                    _ => Err(InvalidSigningAlgorithmError.into()),
                }
            }
        }
    };
}

hs_signer!(Sha256, Hs256Signer, Hs::Hs256, Hs::Hs256);
hs_signer!(Sha384, Hs384Signer, Hs::Hs384, Hs::Hs384);
hs_signer!(Sha512, Hs512Signer, Hs::Hs512, Hs::Hs512);
