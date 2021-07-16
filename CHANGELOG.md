# Changelog

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
