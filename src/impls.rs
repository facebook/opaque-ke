// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

macro_rules! impl_debug_eq_hash_for {
    (struct $name:ident$(<$($gen:ident$(: $bound:tt)?),+$(,)?>)?, [$field1:ident$(, $field2:ident)*$(,)?]$(, )?$([$($type:ty),+$(,)?]$(,)?)?) => {
        impl$(<$($gen$(: $bound)?),+>)? core::fmt::Debug for $name$(<$($gen),+>)?
        $(where $($type: core::fmt::Debug,)+)?
        {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.debug_struct("$name")
                .field("$field1", &self.$field1)
                $(.field("$field2", &self.$field2))*
                .finish()
            }
        }

        impl$(<$($gen$(: $bound)?),+>)? Eq for $name$(<$($gen),+>)?
        $(where $($type: Eq,)+)?
        {}

        impl$(<$($gen$(: $bound)?),+>)? PartialEq for $name$(<$($gen),+>)?
        $(where $($type: PartialEq,)+)?
        {
            fn eq(&self, other: &Self) -> bool {
                PartialEq::eq(&self.$field1, &other.$field1)
                $(&& PartialEq::eq(&self.$field2, &other.$field2))*
            }
        }

        impl$(<$($gen$(: $bound)?),+>)? core::hash::Hash for $name$(<$($gen),+>)?
        $(where $($type: core::hash::Hash,)+)?
        {
            fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
                core::hash::Hash::hash(&self.$field1, state);
                $(core::hash::Hash::hash(&self.$field2, state);)*
            }
        }
    };
    (tuple $name:ident$(<$($gen:ident$(: $bound:tt)?),+$(,)?>)?, [$field1:tt$(, $field2:tt)*$(,)?]$(, )?$([$($type:ty),+$(,)?]$(,)?)?) => {
        impl$(<$($gen$(: $bound)?),+>)? core::fmt::Debug for $name$(<$($gen),+>)?
        $(where $($type: core::fmt::Debug,)+)?
        {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.debug_tuple("$name")
                .field(&self.$field1)
                $(.field(&self.$field2))*
                .finish()
            }
        }

        impl$(<$($gen$(: $bound)?),+>)? Eq for $name$(<$($gen),+>)?
        $(where $($type: Eq,)+)?
        {}

        impl$(<$($gen$(: $bound)?),+>)? PartialEq for $name$(<$($gen),+>)?
        $(where $($type: PartialEq,)+)?
        {
            fn eq(&self, other: &Self) -> bool {
                PartialEq::eq(&self.$field1, &other.$field1)
                $(&& PartialEq::eq(&self.$field2, &other.$field2))*
            }
        }

        impl$(<$($gen$(: $bound)?),+>)? core::hash::Hash for $name$(<$($gen),+>)?
        $(where $($type: core::hash::Hash,)+)?
        {
            fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
                core::hash::Hash::hash(&self.$field1, state);
                $(core::hash::Hash::hash(&self.$field2, state);)*
            }
        }
    };
}

macro_rules! impl_clone_for {
    (struct $name:ident$(<$($gen:ident$(: $bound:tt)?),+$(,)?>)?, [$field1:ident$(, $field2:ident)*$(,)?]$(, )?$([$($type:ty),+$(,)?]$(,)?)?) => {
        impl$(<$($gen$(: $bound)?),+>)? Clone for $name$(<$($gen),+>)?
        $(where $($type: Clone,)+)?
        {
            fn clone(&self) -> Self {
                Self {
                    $field1: self.$field1.clone(),
                    $($field2: self.$field2.clone(),)*
                }
            }
        }
    };
    (tuple $name:ident$(<$($gen:ident$(: $bound:tt)?),+$(,)?>)?, [$field1:tt$(, $field2:tt)*$(,)?]$(, )?$([$($type:ty),+$(,)?]$(,)?)?) => {
        impl$(<$($gen$(: $bound)?),+>)? Clone for $name$(<$($gen),+>)?
        $(where $($type: Clone,)+)?
        {
            fn clone(&self) -> Self {
                Self(
                    self.$field1.clone(),
                    $(self.$field2.clone(),)*
                )
            }
        }
    };
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
