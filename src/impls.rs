macro_rules! impl_debug_eq_hash_for {
    (struct $name:ident$(<$($gen:ident$(: $bound:tt)?),+$(,)?>)?, [$field1:ident$(, $field2:ident)*$(,)?]$(, )?$([$($type:ty),+$(,)?]$(,)?)?) => {
        impl$(<$($gen$(: $bound)?),+>)? std::fmt::Debug for $name$(<$($gen),+>)?
        $(where $($type: std::fmt::Debug,)+)?
        {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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

        impl$(<$($gen$(: $bound)?),+>)? std::hash::Hash for $name$(<$($gen),+>)?
        $(where $($type: std::hash::Hash,)+)?
        {
            fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
                std::hash::Hash::hash(&self.$field1, state);
                $(std::hash::Hash::hash(&self.$field2, state);)*
            }
        }
    };
    (tuple $name:ident$(<$($gen:ident$(: $bound:tt)?),+$(,)?>)?, [$field1:tt$(, $field2:tt)*$(,)?]$(, )?$([$($type:ty),+$(,)?]$(,)?)?) => {
        impl$(<$($gen$(: $bound)?),+>)? std::fmt::Debug for $name$(<$($gen),+>)?
        $(where $($type: std::fmt::Debug,)+)?
        {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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

        impl$(<$($gen$(: $bound)?),+>)? std::hash::Hash for $name$(<$($gen),+>)?
        $(where $($type: std::hash::Hash,)+)?
        {
            fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
                std::hash::Hash::hash(&self.$field1, state);
                $(std::hash::Hash::hash(&self.$field2, state);)*
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
