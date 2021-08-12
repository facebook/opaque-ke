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
