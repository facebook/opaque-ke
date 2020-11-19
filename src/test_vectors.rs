// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Contains the tools used for test vector testing and generation

/// Struct used to hold the parameters for OPAQUE test vectors
pub struct TestVectorParameters {
    /// The client's static public key
    pub client_s_pk: Vec<u8>,
    /// The client's static private key
    pub client_s_sk: Vec<u8>,
    /// The client's ephemeral public key
    pub client_e_pk: Vec<u8>,
    /// The client's ephemeral private key
    pub client_e_sk: Vec<u8>,
    /// The server's static public key
    pub server_s_pk: Vec<u8>,
    /// The server's static private key
    pub server_s_sk: Vec<u8>,
    /// The server's ephemeral public key
    pub server_e_pk: Vec<u8>,
    /// The server's ephemeral private key
    pub server_e_sk: Vec<u8>,
    /// The user identity
    pub id_u: Vec<u8>,
    /// The server identity
    pub id_s: Vec<u8>,
    /// The password
    pub password: Vec<u8>,
    /// The client's random scalar used in OPRF evaluation
    pub blinding_factor: Vec<u8>,
    /// The server-side OPRF key
    pub oprf_key: Vec<u8>,
    /// The nonce used in construction of the envelope
    pub envelope_nonce: Vec<u8>,
    /// The client's nonce used in the AKE
    pub client_nonce: Vec<u8>,
    /// The server's nonce used in the AKE
    pub server_nonce: Vec<u8>,
    /// The first registration message
    pub r1: Vec<u8>,
    /// The second registration message
    pub r2: Vec<u8>,
    /// The third registration message
    pub r3: Vec<u8>,
    /// The first login message
    pub l1: Vec<u8>,
    /// The second login message
    pub l2: Vec<u8>,
    /// The third login message
    pub l3: Vec<u8>,
    /// The state stored on the client in the middle of registration
    pub client_registration_state: Vec<u8>,
    /// The state stored on the server in the middle of registration
    pub server_registration_state: Vec<u8>,
    /// The state stored on the client in the middle of login
    pub client_login_state: Vec<u8>,
    /// The state stored on the server in the middle of login
    pub server_login_state: Vec<u8>,
    /// The password file that the server stores after registration is complete
    pub password_file: Vec<u8>,
    /// The OPAQUE export key
    pub export_key: Vec<u8>,
    /// The shared secret output by the AKE from both parties
    pub shared_secret: Vec<u8>,
}

// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use rand_core::{CryptoRng, Error, RngCore};
use std::cmp::min;

/// A simple implementation of `RngCore` for testing purposes.
///
/// This generates a cyclic sequence (i.e. cycles over an initial buffer)
///
#[derive(Debug, Clone)]
pub struct CycleRng {
    v: Vec<u8>,
}

impl CycleRng {
    /// Create a `CycleRng`, yielding a sequence starting with
    /// `initial` and looping thereafter
    pub fn new(initial: Vec<u8>) -> Self {
        CycleRng { v: initial }
    }
}

fn rotate_left<T>(data: &mut [T], steps: usize) {
    if data.is_empty() {
        return;
    }
    let steps = steps % data.len();

    data[..steps].reverse();
    data[steps..].reverse();
    data.reverse();
}

impl RngCore for CycleRng {
    fn next_u32(&mut self) -> u32 {
        unimplemented!()
    }

    #[inline]
    fn next_u64(&mut self) -> u64 {
        unimplemented!()
    }

    #[inline]
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let len = min(self.v.len(), dest.len());
        (&mut dest[..len]).copy_from_slice(&self.v[..len]);
        rotate_left(&mut self.v, len);
    }

    #[inline]
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

// This is meant for testing only
impl CryptoRng for CycleRng {}
