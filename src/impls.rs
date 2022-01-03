// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

/// Macro used for deriving `serde`'s `Serialize` and `Deserialize` traits.
macro_rules! impl_serialize_and_deserialize_for {
    ($item:ident$( where $($path:ty: $bound1:path $(| $bound2:path)*),+$(,)?)?) => {
        #[cfg(feature = "serde")]
        impl<CS: CipherSuite> serde_::Serialize for $item<CS>
        where
            <CS::Hash as CoreProxy>::Core: ProxyHash,
            <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
            Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
            $($($path: $bound1 $(+ $bound2)*),+)?
        {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde_::Serializer,
            {
                serializer.serialize_bytes(&self.serialize())
            }
        }

        #[cfg(feature = "serde")]
        impl<'de, CS: CipherSuite> serde_::Deserialize<'de> for $item<CS>
        where
            <CS::Hash as CoreProxy>::Core: ProxyHash,
            <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
            Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
        {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde_::Deserializer<'de>,
            {
                use serde_::de::Error;

                struct ByteVisitor<CS: CipherSuite>(core::marker::PhantomData<CS>)
                where
                    <CS::Hash as CoreProxy>::Core: ProxyHash,
                    <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
                    Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero;

                impl<'de, CS: CipherSuite> serde_::de::Visitor<'de> for ByteVisitor<CS>
                where
                    <CS::Hash as CoreProxy>::Core: ProxyHash,
                    <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
                    Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
                {
                    type Value = $item<CS>;

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
                        E: Error,
                    {
                        $item::<CS>::deserialize(value).map_err(|_| {
                            Error::invalid_value(
                                serde_::de::Unexpected::Bytes(value),
                                &core::concat!(
                                    "invalid byte sequence for ",
                                    core::stringify!($t)
                                ),
                            )
                        })
                    }
                }

                deserializer
                    .deserialize_bytes(ByteVisitor::<CS>(core::marker::PhantomData))
                    .map_err(Error::custom)
            }
        }
    };
}
