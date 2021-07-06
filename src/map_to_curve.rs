// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Defines the GroupWithMapToCurve trait to specify how to map a password to a
//! curve point

use crate::errors::InternalPakeError;
use crate::group::Group;
use crate::hash::Hash;
use crate::serialization::i2osp;
use curve25519_dalek::ristretto::RistrettoPoint;
use digest::{BlockInput, Digest};
use generic_array::typenum::Unsigned;
use generic_array::GenericArray;

/// A subtrait of Group specifying how to hash a password into a point
pub trait GroupWithMapToCurve: Group {
    /// The ciphersuite identifier as dictated by
    /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-05.txt>
    const SUITE_ID: usize;

    /// transforms a password and domain separation tag (DST) into a curve point
    fn map_to_curve<H: Hash>(msg: &[u8], dst: &[u8]) -> Result<Self, InternalPakeError>;

    /// Hashes a slice of pseudo-random bytes to a scalar
    fn hash_to_scalar<H: Hash>(input: &[u8], dst: &[u8])
        -> Result<Self::Scalar, InternalPakeError>;

    /// Generates the contextString parameter as defined in
    /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-05.txt>
    fn get_context_string(mode: u8) -> Vec<u8> {
        [i2osp(mode as usize, 1), i2osp(Self::SUITE_ID, 2)].concat()
    }
}

impl GroupWithMapToCurve for RistrettoPoint {
    const SUITE_ID: usize = 0x0001;

    // Implements the hash_to_ristretto255() function from
    // https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-10.txt
    fn map_to_curve<H: Hash>(msg: &[u8], dst: &[u8]) -> Result<Self, InternalPakeError> {
        let uniform_bytes =
            expand_message_xmd::<H>(msg, dst, <H as Digest>::OutputSize::to_usize())?;
        Ok(<Self as Group>::hash_to_curve(
            &GenericArray::clone_from_slice(&uniform_bytes[..]),
        ))
    }

    fn hash_to_scalar<H: Hash>(
        input: &[u8],
        dst: &[u8],
    ) -> Result<Self::Scalar, InternalPakeError> {
        const LEN_IN_BYTES: usize = 64;
        let uniform_bytes = expand_message_xmd::<H>(input, dst, LEN_IN_BYTES)?;
        let mut bits = [0u8; LEN_IN_BYTES];
        bits.copy_from_slice(&uniform_bytes[..]);

        Ok(Self::Scalar::from_bytes_mod_order_wide(&bits))
    }
}

// Computes ceil(x / y)
fn div_ceil(x: usize, y: usize) -> usize {
    let additive = (x % y != 0) as usize;
    x / y + additive
}

fn xor(x: &[u8], y: &[u8]) -> Result<Vec<u8>, InternalPakeError> {
    if x.len() != y.len() {
        return Err(InternalPakeError::HashToCurveError);
    }

    Ok(x.iter().zip(y).map(|(&x1, &x2)| x1 ^ x2).collect())
}

/// Corresponds to the expand_message_xmd() function defined in
/// https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-10.txt
pub fn expand_message_xmd<H: Hash>(
    msg: &[u8],
    dst: &[u8],
    len_in_bytes: usize,
) -> Result<Vec<u8>, InternalPakeError> {
    let b_in_bytes = <H as Digest>::OutputSize::to_usize();
    let r_in_bytes = <H as BlockInput>::BlockSize::to_usize();

    let ell = div_ceil(len_in_bytes, b_in_bytes);
    if ell > 255 {
        return Err(InternalPakeError::HashToCurveError);
    }
    let dst_prime = [dst, &i2osp(dst.len(), 1)].concat();
    let z_pad = i2osp(0, r_in_bytes);
    let l_i_b_str = i2osp(len_in_bytes, 2);
    let msg_prime = [&z_pad, msg, &l_i_b_str, &i2osp(0, 1), &dst_prime].concat();

    let mut b: Vec<Vec<u8>> = vec![H::digest(&msg_prime).to_vec()]; // b[0]

    let mut h = H::new();
    h.update(&b[0]);
    h.update(&i2osp(1, 1));
    h.update(&dst_prime);
    b.push(h.finalize_reset().to_vec()); // b[1]

    let mut uniform_bytes: Vec<u8> = Vec::new();
    uniform_bytes.extend_from_slice(&b[1]);

    for i in 2..(ell + 1) {
        h.update(xor(&b[0], &b[i - 1])?);
        h.update(&i2osp(i, 1));
        h.update(&dst_prime);
        b.push(h.finalize_reset().to_vec()); // b[i]
        uniform_bytes.extend_from_slice(&b[i]);
    }

    Ok(uniform_bytes[..len_in_bytes].to_vec())
}

#[cfg(test)]
mod tests {

    struct Params {
        msg: &'static str,
        len_in_bytes: usize,
        uniform_bytes: &'static str,
    }

    #[test]
    fn test_expand_message_xmd() {
        // Test vectors taken from Section K.1 of https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-10.txt
        let test_vectors: Vec<Params> = vec![
            Params {
                msg: "",
                len_in_bytes: 0x20,
                uniform_bytes: "f659819a6473c1835b25ea59e3d38914c98b374f0970b7e4c\
                92181df928fca88",
            },
            Params {
                msg: "abc",
                len_in_bytes: 0x20,
                uniform_bytes: "1c38f7c211ef233367b2420d04798fa4698080a8901021a79\
                5a1151775fe4da7",
            },
            Params {
                msg: "abcdef0123456789",
                len_in_bytes: 0x20,
                uniform_bytes: "8f7e7b66791f0da0dbb5ec7c22ec637f79758c0a48170bfb7c4611bd304ece89",
            },
            Params {
                msg: "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\
                qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\
                qqqqqqqqqqqqqqqqqqqqqqqqq",
                len_in_bytes: 0x20,
                uniform_bytes: "72d5aa5ec810370d1f0013c0df2f1d65699494ee2a39f72e\
                1716b1b964e1c642",
            },
            Params {
                msg: "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                len_in_bytes: 0x20,
                uniform_bytes: "3b8e704fc48336aca4c2a12195b720882f2162a4b7b13a9c\
                350db46f429b771b",
            },
            Params {
                msg: "",
                len_in_bytes: 0x80,
                uniform_bytes: "8bcffd1a3cae24cf9cd7ab85628fd111bb17e3739d3b53f8\
                9580d217aa79526f1708354a76a402d3569d6a9d19ef3de4d0b991\
                e4f54b9f20dcde9b95a66824cbdf6c1a963a1913d43fd7ac443a02\
                fc5d9d8d77e2071b86ab114a9f34150954a7531da568a1ea8c7608\
                61c0cde2005afc2c114042ee7b5848f5303f0611cf297f",
            },
            Params {
                msg: "abc",
                len_in_bytes: 0x80,
                uniform_bytes: "fe994ec51bdaa821598047b3121c149b364b178606d5e72b\
                fbb713933acc29c186f316baecf7ea22212f2496ef3f785a27e84a\
                40d8b299cec56032763eceeff4c61bd1fe65ed81decafff4a31d01\
                98619c0aa0c6c51fca15520789925e813dcfd318b542f879944127\
                1f4db9ee3b8092a7a2e8d5b75b73e28fb1ab6b4573c192",
            },
            Params {
                msg: "abcdef0123456789",
                len_in_bytes: 0x80,
                uniform_bytes: "c9ec7941811b1e19ce98e21db28d22259354d4d0643e3011\
                75e2f474e030d32694e9dd5520dde93f3600d8edad94e5c3649030\
                88a7228cc9eff685d7eaac50d5a5a8229d083b51de4ccc3733917f\
                4b9535a819b445814890b7029b5de805bf62b33a4dc7e24acdf2c9\
                24e9fe50d55a6b832c8c84c7f82474b34e48c6d43867be",
            },
            Params {
                msg: "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\
                qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\
                qqqqqqqqqqqqqqqqqqqqqqqqq",
                len_in_bytes: 0x80,
                uniform_bytes: "48e256ddba722053ba462b2b93351fc966026e6d6db49318\
                9798181c5f3feea377b5a6f1d8368d7453faef715f9aecb078cd40\
                2cbd548c0e179c4ed1e4c7e5b048e0a39d31817b5b24f50db58bb3\
                720fe96ba53db947842120a068816ac05c159bb5266c63658b4f00\
                0cbf87b1209a225def8ef1dca917bcda79a1e42acd8069",
            },
            Params {
                msg: "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                len_in_bytes: 0x80,
                uniform_bytes: "396962db47f749ec3b5042ce2452b619607f27fd3939ece2\
                746a7614fb83a1d097f554df3927b084e55de92c7871430d6b95c2\
                a13896d8a33bc48587b1f66d21b128a1a8240d5b0c26dfe795a1a8\
                42a0807bb148b77c2ef82ed4b6c9f7fcb732e7f94466c8b51e52bf\
                378fba044a31f5cb44583a892f5969dcd73b3fa128816e",
            },
        ];
        let dst = "QUUX-V01-CS02-with-expander";

        for tv in test_vectors {
            let uniform_bytes = super::expand_message_xmd::<sha2::Sha256>(
                tv.msg.as_bytes(),
                dst.as_bytes(),
                tv.len_in_bytes,
            )
            .unwrap();
            assert_eq!(tv.uniform_bytes, hex::encode(uniform_bytes));
        }
    }
}
