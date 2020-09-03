# Changelog

## 0.2.0 (September 3, 2020)

* Added CipherSuite API for specifying underlying primitives
* Added support for specifying a slow password hashing function
* Renamed SignalKeyPair to X25519KeyPair
* Updated the envelope implementation to match the suggested XOR-based
  construction in https://tools.ietf.org/html/draft-krawczyk-cfrg-opaque-06
* Included proptests for testing try_from crashes
* Implemented Elligator2 map in favor of try-and-increment for hash-to-curve
* Added extensibility for supporting different key exchange protocols

## 0.1.0 (June 5, 2020)

* Initial release
