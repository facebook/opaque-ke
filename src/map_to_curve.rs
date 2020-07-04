use crate::group::Group;
use curve25519_dalek::{edwards::EdwardsPoint, ristretto::RistrettoPoint};

use generic_array::GenericArray;
use hkdf::Hkdf;

pub trait GroupWithMapToCurve: Group {
    fn map_to_curve(password: &[u8], pepper: Option<&[u8]>) -> Self;
}

impl GroupWithMapToCurve for RistrettoPoint {
    fn map_to_curve(password: &[u8], pepper: Option<&[u8]>) -> Self {
        let (hashed_input, _) = Hkdf::<sha2::Sha512>::extract(pepper, password);
        <Self as Group>::hash_to_curve(GenericArray::from_slice(&hashed_input))
    }
}

impl GroupWithMapToCurve for EdwardsPoint {
    fn map_to_curve(password: &[u8], pepper: Option<&[u8]>) -> Self {
        let (hashed_input, _) = Hkdf::<sha2::Sha256>::extract(pepper, password);
        <Self as Group>::hash_to_curve(GenericArray::from_slice(&hashed_input))
    }
}
