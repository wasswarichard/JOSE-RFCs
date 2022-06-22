/// Digital Signature with ECDSA as defined in [section 3.4 of RFC 7518]
///
/// [section 3.4 of RFC 7518]: <https://datatracker.ietf.org/doc/html/rfc7518#section-3.4>
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EcDSA {
    /// ECDSA using P-256 and SHA-256
    Es256,
    /// ECDSA using P-384 and SHA-384
    Es384,
    /// ECDSA using P-521 and SHA-512
    Es512,
}
