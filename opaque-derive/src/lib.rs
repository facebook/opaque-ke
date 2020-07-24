// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! # Derive macros for opaque-ke

use proc_macro2::TokenStream;
use quote::{quote, quote_spanned};
use syn::spanned::Spanned;
use syn::{
    parse_macro_input, parse_quote, Data, DeriveInput, Fields, GenericParam, Generics, Index,
};

/// Derive TryFrom<&[u8], Error = InternalPakeError> for any T:
/// SizedBytes<Error = InternalPakeError>. This proc-macro is here to work
/// around the lack of specialization, but there's nothing otherwise clever
/// about it.
#[proc_macro_derive(TryFromForSizedBytes)]
pub fn try_from_for_sized_bytes(source: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let ast: DeriveInput = syn::parse(source).expect("Incorrect macro input");
    let name = &ast.ident;

    // Add a bound `T: SizedBytes` to every type parameter T.
    let generics = add_trait_bounds(ast.generics);
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let gen = quote! {
        impl #impl_generics TryFrom<&[u8]> for #name #ty_generics #where_clause {
            type Error = InternalPakeError;

            fn try_from(bytes: &[u8]) -> Result<Self, InternalPakeError> {
                let expected_len = <<Self as SizedBytes>::Len as generic_array::typenum::Unsigned>::to_usize();
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

// Add a bound `T: SizedBytes` to every type parameter T.
fn add_trait_bounds(mut generics: Generics) -> Generics {
    for param in &mut generics.params {
        if let GenericParam::Type(ref mut type_param) = *param {
            type_param.bounds.push(parse_quote!(SizedBytes));
        }
    }
    generics
}

// create a type expression summing up the ::Len of each field
fn sum(data: &Data) -> TokenStream {
    match *data {
        Data::Struct(ref data) => {
            match data.fields {
                Fields::Named(ref fields) => {
                    let mut quote = None;
                    for f in fields.named.iter() {
                        let ty = &f.ty;
                        let res = quote_spanned! {f.span()=>
                            <#ty as SizedBytes>::Len
                        };
                        if let Some(ih) = quote {
                            quote = Some(quote! {
                                ::generic_array::typenum::Sum<#ih, #res>
                            });
                        } else {
                            quote = Some(res);
                        }
                    }
                    quote! {
                        #quote
                    }
                }
                Fields::Unnamed(ref fields) => {
                    let mut quote = None;
                    for f in fields.unnamed.iter() {
                        let ty = &f.ty;
                        let res = quote_spanned! {f.span()=>
                            <#ty as SizedBytes>::Len
                        };
                        if let Some(ih) = quote {
                            quote = Some(quote! {
                                ::generic_array::typenum::Sum<#ih, #res>
                            });
                        } else {
                            quote = Some(res);
                        }
                    }
                    quote! {
                        #quote
                    }
                }
                Fields::Unit => {
                    // Unit structs cannot own more than 0 bytes of heap memory.
                    unimplemented!()
                }
            }
        }
        Data::Enum(_) | Data::Union(_) => unimplemented!(),
    }
}

// Generate an expression to concatenate the to_arr of each field
fn byte_concatenation(data: &Data) -> TokenStream {
    match *data {
        Data::Struct(ref data) => {
            match data.fields {
                Fields::Named(ref fields) => {
                    let mut quote = None;
                    for f in fields.named.iter() {
                        let name = &f.ident;
                        let res = quote_spanned! {f.span()=>
                            SizedBytes::to_arr(&self.#name)
                        };
                        if let Some(ih) = quote {
                            quote = Some(quote! {
                                ::generic_array::sequence::Concat::concat(#ih, #res)
                            });
                        } else {
                            quote = Some(res);
                        }
                    }
                    quote! {
                        #quote
                    }
                }
                Fields::Unnamed(ref fields) => {
                    let mut quote = None;
                    for (i, f) in fields.unnamed.iter().enumerate() {
                        let index = Index::from(i);
                        let res = quote_spanned! {f.span()=>
                            SizedBytes::to_arr(&self.#index)
                        };
                        if let Some(ih) = quote {
                            quote = Some(quote! {
                                ::generic_array::sequence::Concat::concat(#ih, #res)
                            });
                        } else {
                            quote = Some(res);
                        }
                    }
                    quote! {
                        #quote
                    }
                }
                Fields::Unit => {
                    // Unit structs cannot own more than 0 bytes of heap memory.
                    quote!(0)
                }
            }
        }
        Data::Enum(_) | Data::Union(_) => unimplemented!(),
    }
}

// Generate an expression to concatenate the to_arr of each field
fn byte_splitting(constr: &proc_macro2::Ident, data: &Data) -> TokenStream {
    match *data {
        Data::Struct(ref data) => {
            match data.fields {
                Fields::Named(ref fields) => {
                    if fields.named.len() > 1 {
                        let setup: TokenStream = fields
                        .named
                        .iter()
                        .map(|f| {
                            let name = &f.ident;
                            quote_spanned! {f.span()=>
                                let (head, _tail) = generic_array::sequence::Split::split(_tail);
                                let #name = SizedBytes::from_arr(head)?;
                            }
                        })
                        .collect();

                        let conclude: TokenStream = fields
                            .named
                            .iter()
                            .map(|f| {
                                let name = &f.ident;
                                quote_spanned! {f.span()=>
                                    #name,
                                }
                            })
                            .collect();
                        quote! {
                            let _tail = arr;
                            #setup
                            Ok(#constr {
                                #conclude
                            })
                        }
                    } else {
                        // We short-circuit the splitting construction if we
                        // have but one field
                        let f = fields.named.iter().find(|_| true).unwrap();
                        let name = &f.ident;
                        quote_spanned! {f.span() =>
                                        let #name = SizedBytes::from_arr(arr)?;
                                        Ok(#constr {
                                            #name,
                                        })
                        }
                    }
                }
                Fields::Unnamed(ref fields) => {
                    let setup: TokenStream = fields
                        .unnamed
                        .iter()
                        .enumerate()
                        .map(|(i, f)| {
                            let index = Index::from(i);
                            quote_spanned! {f.span()=>
                                let (head, _tail) = generic_array::sequence::Split::split(_tail);
                                let n_#index = SizedBytes::from_arr(head)?;
                            }
                        })
                        .collect();

                    let conclude: TokenStream = fields
                        .unnamed
                        .iter()
                        .enumerate()
                        .map(|(i, f)| {
                            let index = Index::from(i);
                            quote_spanned! {f.span()=>
                                n_#index,
                            }
                        })
                        .collect();
                    quote! (
                        let _tail = arr;
                        #setup
                        Ok(#constr (
                            #conclude
                        ))
                    )
                }
                Fields::Unit => {
                    // Unit structs cannot own more than 0 bytes of heap memory.
                    quote!(0)
                }
            }
        }
        Data::Enum(_) | Data::Union(_) => unimplemented!(),
    }
}

#[proc_macro_derive(SizedBytes)]
pub fn derive_sized_bytes(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    // Add a bound `T: SizedBytes` to every type parameter T.
    let generics = add_trait_bounds(input.generics);
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    // Generate an expression to sum the type lengths of each field.
    let types_sum = sum(&input.data);

    // Generate an expression to concatenate each field.
    let to_arr_impl = byte_concatenation(&input.data);

    // Generate an expression to ingest each field.
    let from_arr_impl = byte_splitting(name, &input.data);

    quote! (
        impl #impl_generics SizedBytes for #name #ty_generics #where_clause {

            type Len = #types_sum;

            fn to_arr(&self) -> GenericArray<u8, Self::Len> {
                #to_arr_impl
            }

            fn from_arr(arr: &GenericArray<u8, Self::Len>) -> Result<Self, InternalPakeError> {
                #from_arr_impl
            }
        }
    )
    .into()
}
