use opaque_ke::argon2::Argon2;
use opaque_ke::ml_kem::MlKem768;
use opaque_ke::{CipherSuite, Ristretto255, TripleDh, TripleDhKem};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use sha2::{Sha256, Sha384, Sha512};

pub(crate) const RISTRETTO255_SHA512: &str = "ristretto255_sha512";
pub(crate) const P256_SHA256: &str = "p256_sha256";
pub(crate) const P384_SHA384: &str = "p384_sha384";
pub(crate) const P521_SHA512: &str = "p521_sha512";
pub(crate) const ML_KEM_768_RISTRETTO255_SHA512: &str = "ml_kem_768_ristretto255_sha512";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SuiteId {
    Ristretto255Sha512,
    P256Sha256,
    P384Sha384,
    P521Sha512,
    MlKem768Ristretto255Sha512,
}

impl SuiteId {
    pub(crate) fn all() -> [Self; 5] {
        [
            SuiteId::Ristretto255Sha512,
            SuiteId::P256Sha256,
            SuiteId::P384Sha384,
            SuiteId::P521Sha512,
            SuiteId::MlKem768Ristretto255Sha512,
        ]
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            SuiteId::Ristretto255Sha512 => RISTRETTO255_SHA512,
            SuiteId::P256Sha256 => P256_SHA256,
            SuiteId::P384Sha384 => P384_SHA384,
            SuiteId::P521Sha512 => P521_SHA512,
            SuiteId::MlKem768Ristretto255Sha512 => ML_KEM_768_RISTRETTO255_SHA512,
        }
    }

    pub(crate) fn available() -> Vec<&'static str> {
        Self::all().into_iter().map(SuiteId::as_str).collect()
    }
}

impl std::str::FromStr for SuiteId {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            RISTRETTO255_SHA512 => Ok(SuiteId::Ristretto255Sha512),
            P256_SHA256 => Ok(SuiteId::P256Sha256),
            P384_SHA384 => Ok(SuiteId::P384Sha384),
            P521_SHA512 => Ok(SuiteId::P521Sha512),
            ML_KEM_768_RISTRETTO255_SHA512 => Ok(SuiteId::MlKem768Ristretto255Sha512),
            _ => Err(()),
        }
    }
}

pub(crate) fn parse_suite(suite: Option<&str>) -> PyResult<SuiteId> {
    let raw = suite.unwrap_or(RISTRETTO255_SHA512);
    let normalized = raw.to_ascii_lowercase();
    normalized.parse::<SuiteId>().map_err(|_| {
        let available = SuiteId::available().join(", ");
        PyErr::new::<PyValueError, _>(format!(
            "unsupported cipher suite '{normalized}' (available: {available})"
        ))
    })
}

pub(crate) struct Ristretto255Sha512;

impl CipherSuite for Ristretto255Sha512 {
    type OprfCs = Ristretto255;
    type KeyExchange = TripleDh<Ristretto255, Sha512>;
    type Ksf = Argon2<'static>;
}

pub(crate) struct P256Sha256;

impl CipherSuite for P256Sha256 {
    type OprfCs = p256::NistP256;
    type KeyExchange = TripleDh<p256::NistP256, Sha256>;
    type Ksf = Argon2<'static>;
}

pub(crate) struct P384Sha384;

impl CipherSuite for P384Sha384 {
    type OprfCs = p384::NistP384;
    type KeyExchange = TripleDh<p384::NistP384, Sha384>;
    type Ksf = Argon2<'static>;
}

pub(crate) struct P521Sha512;

impl CipherSuite for P521Sha512 {
    type OprfCs = p521::NistP521;
    type KeyExchange = TripleDh<p521::NistP521, Sha512>;
    type Ksf = Argon2<'static>;
}

pub(crate) struct MlKem768Ristretto255Sha512;

impl CipherSuite for MlKem768Ristretto255Sha512 {
    type OprfCs = Ristretto255;
    type KeyExchange = TripleDhKem<Ristretto255, Sha512, MlKem768>;
    type Ksf = Argon2<'static>;
}
