// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use rand::{CryptoRng, Error, RngCore};
use std::cmp::min;

/// A simple implementation of `RngCore` for testing purposes.
///
/// This generates a cyclic sequence (i.e. cycles over an initial buffer)
///
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
