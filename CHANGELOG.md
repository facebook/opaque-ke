# Changelog

## 4.0.1 (October 30, 2025)
* Fixing docs building issue

## 4.0.0 (October 23, 2025)
* Increased MSRV to 1.83
* Synced implementation with RFC 9807 (no core protocol changes)
* Added a SIGMA-I key exchange implementation
* Removed KeGroup type from the Ciphersuite trait (now part of KeyExchange type)
  * **Breaking: existing Ciphersuite trait definitions need to be updated**
* Ensured that dummy record is always created to avoid timing attack issues
* Modified the dummy registration file to only contain the public key
  instead of the keypair
  * **Breaking: existing `ServerSetup`s need to be updated**
    ```rust
    // Given `old` is a `ServerSetup` from `opaque-ke` v3.
    let old_serialized = old.serialize();

    type OldSeedLen = <<<OldCipherSuite as opaque_ke_3::CipherSuite>::OprfCs as voprf::CipherSuite>::Hash as OutputSizeUser>::OutputSize;
    type OldSkLen = <<OldCipherSuite as opaque_ke_3::CipherSuite>::KeGroup as opaque_ke_3::key_exchange::group::KeGroup>::SkLen;

    let (old_serialied_rest, old_fake_keypair_serialized): (
        GenericArray<u8, Sum<OldSeedLen, OldSkLen>>,
        _,
    ) = old_serialized.split();

    let old_fake_keypair =
        KeyPair::<<OldCipherSuite as opaque_ke_3::CipherSuite>::KeGroup>::from_private_key_slice(
            &old_fake_keypair_serialized,
        )
        .unwrap();
    let old_fake_pk_serialized = old_fake_keypair.public().serialize();

    let new_serialized = old_serialied_rest.concat(old_fake_pk_serialized);
    // Given `NewCipherSuite` is a `CipherSuite` implementation equivalent to `OldCipherSuite`.
    ServerSetup::<NewCipherSuite>::deserialize(&new_serialized).unwrap()
    ```
* Added remote OPRF seed support
* Replace remote private key trait with a state machine, facilitating async support.
* Serde de/serialization formats have been simplified
  * **Breaking: existing `ServerRegistration`s may need to be updated**
    ```rust
    // Given `old` is a `ServerRegistration` from `opaque-ke` v3.
    let old_serialized = old.serialize();
    // Given `NewCipherSuite` is a `CipherSuite` implementation equivalent to the old cipher suite.
    ServerRegistration::<NewCipherSuite>::deserialize(&old_serialized).unwrap()
    ```


## 3.0.0 (October 10, 2024)
* Synced implementation with draft-irtf-cfrg-opaque-16
  * **Breaking: protocol context string changed from `RFCXXXX` to `OPAQUEv1-`**
* Dropped unmaintained json crate in favor of serde_json
* Updated dependencies
* Increased MSRV to 1.74
* Adjusted curve25519 support logic
* Adjusted key generation logic to be in line with commit 727b9ac of
  https://github.com/cfrg/draft-irtf-cfrg-opaque
* Updated VOPRF to draft 19
  * **Breaking: backwards-incompatible changes introduced in OPRF protocol**
* Added P384 testing support
* Renaming of X25519 to Curve25519

## 2.0.0 (September 21, 2022)
* Synced implementation with draft-irtf-cfrg-opaque-10
* Changed argon2 salt length to recommended value (16 bytes)
* Fixed issue from 2.0.0-pre.2 not pinning voprf dependency correctly
* Split out VOPRF implementation into its own crate
* Added support for running the API without performing
  allocations
* Revamped the way the Group trait was used, so as to be more
  easily extendable to other groups
* Added support for p256 as the group and x25519 as the key exchange group
* Added common traits for each public-facing struct, including serde support

## 1.2.0 (October 7, 2021)

* Added explicit support for the thumbv6m-none-eabi target (no-std)

## 1.1.0 (August 18, 2021)

* Updated dependencies and bumped MSRV to 1.51
* Added no_std support

## 1.0.0 (July 19, 2021)

* Branched from v0.5.0
* Various security improvements: non-zero scalars, zeroizing on drop,
  constant-time operations, reflected value check, and adding an
  i2osp error condition

## 0.6.0 (June 30, 2021)

* Synced implementation with draft-irtf-cfrg-opaque-05, which changes
  the envelope structure and introduces a ServerSetup object to be
  maintained by the server
* Various security improvements: non-zero scalars, zeroizing on drop,
  constant-time operations
* Adding serde support behind a feature
* Supporting common traits (eb59676)
* Swapping out scrypt for argon2 (535b9b8) for the slow-hash feature
* Adding support for common traits on public structs
* Updated dependencies

## 0.5.1 (July 16, 2021)

* Various security improvements: non-zero scalars, zeroizing on drop,
  constant-time operations, reflected value check, and adding an
  i2osp error condition

## 0.5.0 (March 1, 2021)

* Removed dependency on generic-bytes-derive package

## 0.4.0 (February 26, 2021)

* Adherence to protocol format described in
  https://tools.ietf.org/html/draft-irtf-cfrg-opaque-03
* Renamed to_bytes() and try_from() to serialize() and deserialize() for
  top-level structs
* Conformed all message type parameters to be parameterized in the
  Ciphersuite object

## 0.3.1 (February 11, 2021)

* Re-exporting the rand library (and including it as a dependency instead of
  just rand_core)
* Exposing a convenience function for converting from byte array to Key type

## 0.3.0 (February 8, 2021)

* General API and documentation improvements, including the support of custom
  identifiers, optional result parameters, and the use of the export key
* Compliance with RFC 8017 on data serialization functions (I2OSP / OS2IP)
* Adherence to protocol format described in
  https://tools.ietf.org/html/draft-irtf-cfrg-opaque-02
* Added parameters for key exchange additional data
* Added simple_login and digital_locker examples

## 0.2.1 (October 22, 2020)

* Changed visibility of hash module to be public

## 0.2.0 (September 3, 2020)

* Added CipherSuite API for specifying underlying primitives
* Added support for specifying a slow password hashing function
* Collapsed SignalKeyPair to X25519KeyPair
* Updated the envelope implementation to match the suggested XOR-based
  construction in https://tools.ietf.org/html/draft-krawczyk-cfrg-opaque-06
* Included randomized tests for testing try_from crashes
* Implemented Elligator2 map instead of try-and-increment for hash-to-curve
* Added extensibility for supporting different key exchange protocols
* Added benchmarks for the OPRF & switchable dalek backend depending on platform

## 0.1.0 (June 5, 2020)

* Initial release
