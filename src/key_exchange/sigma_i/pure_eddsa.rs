// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! Key Exchange group implementation for Ed25519

use core::marker::PhantomData;

use rand::{CryptoRng, RngCore};
use zeroize::Zeroize;

use self::implementation::PureEddsaImpl;
use super::Group;
use crate::ciphersuite::CipherSuite;
use crate::errors::ProtocolError;
use crate::key_exchange::sigma_i::{Message, Role, SignatureGroup};
use crate::key_exchange::traits::{Deserialize, Serialize};

/// PureEdDSA for [`SigmaI`](crate::SigmaI).
pub struct PureEddsa<G>(PhantomData<G>);

impl<G: PureEddsaImpl> SignatureGroup for PureEddsa<G> {
    type Group = G;
    type Signature = G::Signature;
    type VerifyState<CS: CipherSuite, KE: Group> = G::VerifyState<CS, KE>;

    fn sign<'a, R: CryptoRng + RngCore, CS: CipherSuite, KE: Group>(
        sk: &<Self::Group as Group>::Sk,
        _: &mut R,
        message: Message<CS, KE>,
        role: Role,
    ) -> (Self::Signature, Self::VerifyState<CS, KE>) {
        G::sign(sk, message, role)
    }

    fn verify<CS: CipherSuite, KE: Group>(
        pk: &<Self::Group as Group>::Pk,
        state: Self::VerifyState<CS, KE>,
        signature: &Self::Signature,
        role: Role,
    ) -> Result<(), ProtocolError> {
        G::verify(pk, state, signature, role)
    }
}

pub(in super::super) mod implementation {
    use super::*;

    pub trait PureEddsaImpl: Group {
        type Signature: Clone + Deserialize + Serialize + Zeroize;
        type VerifyState<CS: CipherSuite, KE: Group>: Clone + Zeroize;

        fn sign<CS: CipherSuite, KE: Group>(
            sk: &Self::Sk,
            message: Message<CS, KE>,
            role: Role,
        ) -> (Self::Signature, Self::VerifyState<CS, KE>);

        fn verify<CS: CipherSuite, KE: Group>(
            pk: &Self::Pk,
            state: Self::VerifyState<CS, KE>,
            signature: &Self::Signature,
            role: Role,
        ) -> Result<(), ProtocolError>;
    }
}
