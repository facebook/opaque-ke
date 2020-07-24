// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! # Derive macros for opaque-ke

use proc_macro::TokenStream;
use quote::quote;
use syn::DeriveInput;

/// Derive TryFrom<&[u8], Error = InternalPakeError> for any T:
/// SizedBytes<Error = InternalPakeError>. This proc-macro is here to work
/// around the lack of specialization, but there's nothing otherwise clever
/// about it.
#[proc_macro_derive(TryFromForSizedBytes)]
pub fn try_from_for_sized_bytes(source: TokenStream) -> TokenStream {
    let ast: DeriveInput = syn::parse(source).expect("Incorrect macro input");
    let name = &ast.ident;
    let gen = quote! {
    impl<'a> TryFrom<&'a [u8]> for #name {
        type Error = InternalPakeError;

        fn try_from(bytes: &[u8]) -> Result<Self, InternalPakeError> {
            let expected_len = <Self as SizedBytes>::Len::to_usize();
            if bytes.len() != expected_len {
                return Err(InternalPakeError::SizeError {
                    name: "bytes",
                    len: expected_len,
                    actual_len: bytes.len(),
                });
            }
            let arr = GenericArray::from_slice(bytes);
            <Self as SizedBytes>::from_arr(arr)
        }
    }
    };
    gen.into()
}
