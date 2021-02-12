# Changelog

## 0.3.1 (February 11, 2020)

* Re-exporting the rand library (and including it as a dependency instead of
  just rand_core)
* Exposing a convenience function for converting from byte array to Key type

## 0.3.0 (February 8, 2020)

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
