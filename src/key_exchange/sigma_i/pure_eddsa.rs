// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! PureEdDSA implementation for [`SigmaI`](crate::SigmaI). Currently only
//! supports [`Ed25519`](crate::Ed25519).

use core::marker::PhantomData;

use rand::{CryptoRng, RngCore};
use zeroize::Zeroize;

use self::implementation::PureEddsaImpl;
use super::{Message, MessageBuilder, SignatureProtocol};
use crate::ciphersuite::CipherSuite;
use crate::errors::ProtocolError;
use crate::key_exchange::group::Group;
use crate::key_exchange::sigma_i::CachedMessage;
use crate::key_exchange::traits::{Deserialize, Serialize};

/// PureEdDSA for [`SigmaI`](crate::SigmaI).
///
/// The ["verification state"](Self::VerifyState) is a [`CachedMessage`],
/// created by calling [`Message::to_cached()`].
pub struct PureEddsa<G>(PhantomData<G>);

impl<G: PureEddsaImpl> SignatureProtocol for PureEddsa<G> {
    type Group = G;
    type Signature = G::Signature;
    type VerifyState<CS: CipherSuite, KE: Group> = CachedMessage<CS, KE>;

    fn sign<'a, R: CryptoRng + RngCore, CS: CipherSuite, KE: Group>(
        sk: &G::Sk,
        _: &mut R,
        message: &Message<CS, KE>,
    ) -> (Self::Signature, Self::VerifyState<CS, KE>) {
        G::sign(sk, message)
    }

    fn verify<CS: CipherSuite, KE: Group>(
        pk: &G::Pk,
        message_builder: MessageBuilder<'_, CS>,
        state: Self::VerifyState<CS, KE>,
        signature: &Self::Signature,
    ) -> Result<(), ProtocolError> {
        G::verify(pk, message_builder, state, signature)
    }
}

pub(in super::super) mod implementation {
    use super::*;

    pub trait PureEddsaImpl: Group + Sized {
        type Signature: Clone + Deserialize + Serialize + Zeroize;

        fn sign<CS: CipherSuite, KE: Group>(
            sk: &Self::Sk,
            message: &Message<CS, KE>,
        ) -> (Self::Signature, CachedMessage<CS, KE>);

        fn verify<CS: CipherSuite, KE: Group>(
            pk: &Self::Pk,
            message_builder: MessageBuilder<'_, CS>,
            state: CachedMessage<CS, KE>,
            signature: &Self::Signature,
        ) -> Result<(), ProtocolError>;
    }
}
