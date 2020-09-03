# Changelog

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
