use crate::{
    errors::ProtocolError,
    key_exchange::{
        finish_ke, generate_ke1, generate_ke2, generate_ke3, KE1Message, KE1State, KE2Message,
        KE2State, KE3Message, KE3State,
    },
    keypair::{KeyPair, SizedBytes},
};
use rand_core::{CryptoRng, RngCore};
use std::marker::PhantomData;

pub trait IStateTR {
    type Initial;
    type Next;
    type Output;
    type Error;
    fn generate(self, init_state: Self::Initial)
        -> Result<(Self::Next, Self::Output), Self::Error>;
}

pub trait RngGetter {
    type RNG: RngCore + CryptoRng;
    fn rng() -> Self::RNG;
}

pub trait InitiatorFirstStep: IStateTR<Initial = ()> + RngGetter {
    fn new(l1_component: Vec<u8>) -> Self;
}

pub trait ResponderFirstStep<KeyFormat>: IStateTR<Initial = ()> + RngGetter
where
    KeyFormat: KeyPair,
{
    type Proposer: InitiatorFirstStep;

    fn new(
        l1_component: Vec<u8>,
        l2_component: Vec<u8>,
        client_s_pk: <KeyFormat as KeyPair>::Repr,
        server_s_sk: <KeyFormat as KeyPair>::Repr,
        ke1m: <Self::Proposer as IStateTR>::Output,
    ) -> Self;
}

pub trait InitiatorFinalStep<FirstStep, KeyFormat>:
    IStateTR<Initial = <FirstStep as IStateTR>::Next>
where
    KeyFormat: KeyPair,
    FirstStep: InitiatorFirstStep,
{
    type Proposer: ResponderFirstStep<KeyFormat, Proposer = FirstStep>;

    fn new(
        l2_component: Vec<u8>,
        ke2m: <Self::Proposer as IStateTR>::Output,
        server_s_pk: <KeyFormat as KeyPair>::Repr,
        client_s_sk: <KeyFormat as KeyPair>::Repr,
    ) -> Self;
}

pub trait ResponderFinalStep<FirstStep, KeyFormat>:
    IStateTR<Initial = <FirstStep as IStateTR>::Next, Output = ()>
where
    KeyFormat: KeyPair,
    FirstStep: ResponderFirstStep<KeyFormat>,
{
    type Proposer: InitiatorFinalStep<FirstStep::Proposer, KeyFormat, Proposer = FirstStep>;

    fn new(
        // This unsightly constraint is the
        // precisely qualified version of `Self::Proposer::Output`
        ke3m: <Self::Proposer as IStateTR>::Output,
    ) -> Self;
}

////////////////////////////
// implementation for 3DH //
////////////////////////////

pub struct ThreeDHInitiator1<KeyFormat> {
    l1_component: Vec<u8>,
    _key_format: PhantomData<KeyFormat>,
}

// To be masked and replaced in #[cfg(test)]
impl<KeyFormat> RngGetter for ThreeDHInitiator1<KeyFormat> {
    type RNG = rand_core::OsRng;
    fn rng() -> Self::RNG {
        rand_core::OsRng
    }
}

impl<KeyFormat> IStateTR for ThreeDHInitiator1<KeyFormat>
where
    KeyFormat: KeyPair,
{
    type Initial = ();
    type Output = KE1Message;
    type Next = KE1State;
    type Error = ProtocolError;

    fn generate(self, _init_state: ()) -> Result<(KE1State, KE1Message), ProtocolError> {
        let mut rng = <Self as RngGetter>::rng();
        generate_ke1::<_, KeyFormat>(self.l1_component, &mut rng)
    }
}

impl<KeyFormat> InitiatorFirstStep for ThreeDHInitiator1<KeyFormat>
where
    KeyFormat: KeyPair,
{
    fn new(l1_component: Vec<u8>) -> Self {
        ThreeDHInitiator1 {
            l1_component,
            _key_format: PhantomData,
        }
    }
}

pub struct ThreeDHResponder1<KeyFormat: KeyPair> {
    l1_component: Vec<u8>,
    l2_component: Vec<u8>,
    client_s_pk: <KeyFormat as KeyPair>::Repr,
    server_s_sk: <KeyFormat as KeyPair>::Repr,
    ke1m: KE1Message,
}

impl<KeyFormat> RngGetter for ThreeDHResponder1<KeyFormat>
where
    KeyFormat: KeyPair,
{
    type RNG = rand_core::OsRng;
    fn rng() -> Self::RNG {
        rand_core::OsRng
    }
}

impl<KeyFormat> IStateTR for ThreeDHResponder1<KeyFormat>
where
    KeyFormat: KeyPair,
{
    type Initial = ();
    type Next = KE2State;
    type Output = KE2Message;
    type Error = ProtocolError;
    fn generate(self, _init_state: ()) -> Result<(KE2State, KE2Message), ProtocolError> {
        let mut rng = <Self as RngGetter>::rng();
        generate_ke2::<_, KeyFormat>(
            &mut rng,
            self.l1_component,
            self.l2_component,
            <KeyFormat as KeyPair>::Repr::from_bytes(&self.ke1m.client_e_pk)?,
            self.client_s_pk,
            self.server_s_sk,
            self.ke1m.client_nonce,
        )
    }
}

impl<KeyFormat> ResponderFirstStep<KeyFormat> for ThreeDHResponder1<KeyFormat>
where
    KeyFormat: KeyPair,
{
    type Proposer = ThreeDHInitiator1<KeyFormat>;

    fn new(
        l1_component: Vec<u8>,
        l2_component: Vec<u8>,
        client_s_pk: <KeyFormat as KeyPair>::Repr,
        server_s_sk: <KeyFormat as KeyPair>::Repr,
        ke1m: KE1Message,
    ) -> Self {
        ThreeDHResponder1 {
            l1_component,
            l2_component,
            client_s_pk,
            server_s_sk,
            ke1m,
        }
    }
}

pub struct ThreeDHInitiator2<KeyFormat: KeyPair> {
    l2_component: Vec<u8>,
    ke2m: KE2Message,
    server_s_pk: <KeyFormat as KeyPair>::Repr,
    client_s_sk: <KeyFormat as KeyPair>::Repr,
}

impl<KeyFormat> IStateTR for ThreeDHInitiator2<KeyFormat>
where
    KeyFormat: KeyPair,
{
    type Initial = KE1State;
    type Next = KE3State;
    type Output = KE3Message;
    type Error = ProtocolError;

    fn generate(self, init_state: KE1State) -> Result<(KE3State, KE3Message), ProtocolError> {
        generate_ke3::<KeyFormat>(
            self.l2_component,
            self.ke2m,
            &init_state,
            self.server_s_pk,
            self.client_s_sk,
        )
    }
}

impl<KeyFormat> InitiatorFinalStep<ThreeDHInitiator1<KeyFormat>, KeyFormat>
    for ThreeDHInitiator2<KeyFormat>
where
    KeyFormat: KeyPair,
{
    type Proposer = ThreeDHResponder1<KeyFormat>;

    fn new(
        l2_component: Vec<u8>,
        ke2m: KE2Message,
        server_s_pk: <KeyFormat as KeyPair>::Repr,
        client_s_sk: <KeyFormat as KeyPair>::Repr,
    ) -> Self {
        ThreeDHInitiator2 {
            l2_component,
            ke2m,
            server_s_pk,
            client_s_sk,
        }
    }
}

pub struct ThreeDHResponder2<KeyFormat> {
    _key_format: PhantomData<KeyFormat>,
    ke3m: KE3Message,
}

impl<KeyFormat> IStateTR for ThreeDHResponder2<KeyFormat>
where
    KeyFormat: KeyPair,
{
    type Initial = KE2State;
    type Next = KE3State;
    type Output = ();
    type Error = ProtocolError;
    fn generate(self, s: KE2State) -> Result<(KE3State, ()), ProtocolError> {
        let shared_secret = finish_ke(self.ke3m, &s)?;
        Ok((KE3State { shared_secret }, ()))
    }
}

impl<KeyFormat> ResponderFinalStep<ThreeDHResponder1<KeyFormat>, KeyFormat>
    for ThreeDHResponder2<KeyFormat>
where
    KeyFormat: KeyPair,
{
    type Proposer = ThreeDHInitiator2<KeyFormat>;

    fn new(ke3m: KE3Message) -> Self {
        ThreeDHResponder2 {
            _key_format: PhantomData,
            ke3m,
        }
    }
}
