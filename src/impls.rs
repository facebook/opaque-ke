// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

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
                use serde::ser::Error;

                if serializer.is_human_readable() {
                    serializer
                        .serialize_str(&base64::encode(&self.serialize().map_err(Error::custom)?))
                } else {
                    serializer.serialize_bytes(&self.serialize().map_err(Error::custom)?)
                }
            }
        }

        #[cfg(feature = "serialize")]
        impl<'de, CS: CipherSuite> serde::Deserialize<'de> for $t<CS> {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                use serde::de::Error;

                if deserializer.is_human_readable() {
                    let s = <&str>::deserialize(deserializer)?;
                    Self::deserialize(&base64::decode(s).map_err(Error::custom)?)
                } else {
                    Self::deserialize(<&[u8]>::deserialize(deserializer)?)
                }
                .map_err(Error::custom)
            }
        }
    };
}
