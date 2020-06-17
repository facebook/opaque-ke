use crate::{
    errors::ProtocolError,
    indexed_state::{boxed_state, BoxStR, StateTR},
    key_exchange::{
        finish_ke, generate_ke1, generate_ke2, generate_ke3, KE1Message, KE1State, KE2Message,
        KE2State, KE3Message, KE3State,
    },
    keypair::{KeyPair, SizedBytes},
};
use rand_core::{CryptoRng, RngCore};

pub trait KeyExchangeInitiator<KeyFormat>: Sized
where
    KeyFormat: KeyPair,
{
    type InitialStep: StateTR<()>;
    type FinalStep: StateTR<<Self::InitialStep as StateTR<()>>::Next>;

    // The responder must understand our messages and agree on the key Format
    type Responder: KeyExchangeResponder<KeyFormat, Initiator = Self>;

    // client to server
    fn start<R: RngCore + CryptoRng>(
        l1_component: Vec<u8>,
        rng: &'static mut R,
    ) -> Self::InitialStep;

    // client to server
    fn finish(
        l2_component: Vec<u8>,
        ke2m: <<Self::Responder as KeyExchangeResponder<KeyFormat>>::InitialStep as StateTR<()>>::Output,
        server_s_pk: <KeyFormat as KeyPair>::Repr,
        client_s_sk: <KeyFormat as KeyPair>::Repr,
    ) -> Self::FinalStep;
}

pub trait KeyExchangeResponder<KeyFormat>: Sized
where
    KeyFormat: KeyPair,
{
    type InitialStep: StateTR<()>;
    type FinalStep: StateTR<<Self::InitialStep as StateTR<()>>::Next>;

    // The initiator must understand our messages and agree on the key Format
    type Initiator: KeyExchangeInitiator<KeyFormat, Responder = Self>;

    // server to client
    fn start<R: CryptoRng + RngCore>(
        l1_component: Vec<u8>,
        l2_component: Vec<u8>,
        client_s_pk: <KeyFormat as KeyPair>::Repr,
        server_s_sk: <KeyFormat as KeyPair>::Repr,
        ke1m: <<Self::Initiator as KeyExchangeInitiator<KeyFormat>>::InitialStep as StateTR<()>>::Output,
        rng: &'static mut R,
    ) -> Self::InitialStep;

    // server to client
    #[allow(clippy::type_complexity)] // associated type constraints across two paired traits
    fn finish(
        // This unsightly constraint is the
        // precisely qualified version of `Self::Initiator::FinalStep::Output`
        ke3m: <<Self::Initiator as KeyExchangeInitiator<KeyFormat>>::FinalStep as StateTR<
            <<Self::Initiator as KeyExchangeInitiator<KeyFormat>>::InitialStep as StateTR<()>>::Next,
        >>::Output,
    ) -> Self::FinalStep;
}

// KE3State, or the shared secret, is the type that's characteristic of this
// key exchange mode
impl<KeyFormat: KeyPair> KeyExchangeInitiator<KeyFormat> for KE3State
where
    KeyFormat::Repr: 'static,
{
    type InitialStep = BoxStR<'static, (), KE1State, KE1Message, ProtocolError>;
    type FinalStep = BoxStR<'static, KE1State, KE3State, KE3Message, ProtocolError>;

    type Responder = Self;

    fn start<R: RngCore + CryptoRng>(
        l1_component: Vec<u8>,
        rng: &'static mut R,
    ) -> Self::InitialStep {
        boxed_state(move |_| generate_ke1::<_, KeyFormat>(l1_component, rng))
    }

    fn finish(
        l2_component: Vec<u8>,
        ke2m: KE2Message,
        server_s_pk: <KeyFormat as KeyPair>::Repr,
        client_s_sk: <KeyFormat as KeyPair>::Repr,
    ) -> Self::FinalStep {
        boxed_state(move |ke1_state: KE1State| {
            generate_ke3::<KeyFormat>(l2_component, ke2m, &ke1_state, server_s_pk, client_s_sk)
        })
    }
}

impl<KeyFormat: KeyPair> KeyExchangeResponder<KeyFormat> for KE3State
where
    KeyFormat::Repr: 'static,
{
    type InitialStep = BoxStR<'static, (), KE2State, KE2Message, ProtocolError>;
    type FinalStep = BoxStR<'static, KE2State, KE3State, (), ProtocolError>;

    type Initiator = Self;

    fn start<R: CryptoRng + RngCore>(
        l1_component: Vec<u8>,
        l2_component: Vec<u8>,
        client_s_pk: <KeyFormat as KeyPair>::Repr,
        server_s_sk: <KeyFormat as KeyPair>::Repr,
        ke1m: KE1Message,
        rng: &'static mut R,
    ) -> Self::InitialStep {
        boxed_state(move |_| {
            generate_ke2::<_, KeyFormat>(
                rng,
                l1_component,
                l2_component,
                <KeyFormat as KeyPair>::Repr::from_bytes(&ke1m.client_e_pk)?,
                client_s_pk,
                server_s_sk,
                ke1m.client_nonce,
            )
        })
    }

    // server to client
    fn finish(ke3m: KE3Message) -> Self::FinalStep {
        boxed_state(move |ke2_state: KE2State| {
            let shared_secret = finish_ke(ke3m, &ke2_state)?;
            Ok((KE3State { shared_secret }, ()))
        })
    }
}
