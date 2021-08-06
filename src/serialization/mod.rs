// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::vec::Vec;

use crate::errors::PakeError;

// Corresponds to the I2OSP() function from RFC8017
pub(crate) fn i2osp(input: usize, length: usize) -> Result<Vec<u8>, PakeError> {
    let sizeof_usize = core::mem::size_of::<usize>();

    // Check if input >= 256^length
    if (sizeof_usize as u32 - input.leading_zeros() / 8) > length as u32 {
        return Err(PakeError::SerializationError);
    }

    if length <= sizeof_usize {
        return Ok((&input.to_be_bytes()[sizeof_usize - length..]).to_vec());
    }

    let mut output = vec![0u8; length];
    output.splice(
        length - sizeof_usize..length,
        input.to_be_bytes().iter().cloned(),
    );
    Ok(output)
}

// Corresponds to the OS2IP() function from RFC8017
pub(crate) fn os2ip(input: &[u8]) -> Result<usize, PakeError> {
    if input.len() > core::mem::size_of::<usize>() {
        return Err(PakeError::SerializationError);
    }

    let mut output_array = [0u8; core::mem::size_of::<usize>()];
    output_array[core::mem::size_of::<usize>() - input.len()..].copy_from_slice(input);
    Ok(usize::from_be_bytes(output_array))
}

// Computes I2OSP(len(input), max_bytes) || input
pub(crate) fn serialize(input: &[u8], max_bytes: usize) -> Result<Vec<u8>, PakeError> {
    Ok([&i2osp(input.len(), max_bytes)?, input].concat())
}

// Tokenizes an input of the format I2OSP(len(input), max_bytes) || input, outputting
// (input, remainder)
pub(crate) fn tokenize(input: &[u8], size_bytes: usize) -> Result<(Vec<u8>, Vec<u8>), PakeError> {
    if size_bytes > core::mem::size_of::<usize>() || input.len() < size_bytes {
        return Err(PakeError::SerializationError);
    }

    let size = os2ip(&input[..size_bytes])?;
    if size_bytes + size > input.len() {
        return Err(PakeError::SerializationError);
    }

    Ok((
        input[size_bytes..size_bytes + size].to_vec(),
        input[size_bytes + size..].to_vec(),
    ))
}

/// Inner macro used for deriving `serde`'s `Serialize` and `Deserialize` traits.
macro_rules! impl_serialize_and_deserialize_for {
    ($t:ident) => {
        #[cfg(feature = "serialize")]
        impl<CS: CipherSuite> serde::Serialize for $t<CS> {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                if serializer.is_human_readable() {
                    serializer.serialize_str(&base64::encode(&self.serialize()))
                } else {
                    serializer.serialize_bytes(&self.serialize())
                }
            }
        }

        #[cfg(feature = "serialize")]
        impl<'de, CS: CipherSuite> serde::Deserialize<'de> for $t<CS> {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                if deserializer.is_human_readable() {
                    let s = <&str>::deserialize(deserializer)?;
                    $t::<CS>::deserialize(&base64::decode(s).map_err(serde::de::Error::custom)?)
                        .map_err(serde::de::Error::custom)
                } else {
                    struct ByteVisitor<CS: CipherSuite> {
                        marker: core::marker::PhantomData<CS>,
                    }
                    impl<'de, CS: CipherSuite> serde::de::Visitor<'de> for ByteVisitor<CS> {
                        type Value = $t<CS>;
                        fn expecting(
                            &self,
                            formatter: &mut core::fmt::Formatter,
                        ) -> core::fmt::Result {
                            formatter.write_str(core::concat!(
                                "the byte representation of a ",
                                core::stringify!($t)
                            ))
                        }

                        fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
                        where
                            E: serde::de::Error,
                        {
                            $t::<CS>::deserialize(value).map_err(|_| {
                                serde::de::Error::invalid_value(
                                    serde::de::Unexpected::Bytes(value),
                                    &core::concat!(
                                        "invalid byte sequence for ",
                                        core::stringify!($t)
                                    ),
                                )
                            })
                        }
                    }
                    deserializer.deserialize_bytes(ByteVisitor::<CS> {
                        marker: core::marker::PhantomData,
                    })
                }
            }
        }
    };
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod unit_tests {
    use super::*;

    // Test the error condition for I2OSP
    #[test]
    fn test_i2osp_err_check() {
        assert!(i2osp(0, 1).is_ok());

        assert!(i2osp(255, 1).is_ok());
        assert!(i2osp(256, 1).is_err());
        assert!(i2osp(257, 1).is_err());

        assert!(i2osp(256 * 256 - 1, 2).is_ok());
        assert!(i2osp(256 * 256, 2).is_err());
        assert!(i2osp(256 * 256 + 1, 2).is_err());
    }
}
