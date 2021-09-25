##  The OPAQUE key exchange protocol ![Build Status](https://github.com/novifinancial/opaque-ke/workflows/Rust%20CI/badge.svg)

[OPAQUE](https://eprint.iacr.org/2018/163.pdf) is an asymmetric password-authenticated key exchange protocol. It allows a client to authenticate to a server using a password, without ever having to expose the plaintext password to the server.

This implementation is based on the [Internet Draft for OPAQUE](https://github.com/cfrg/draft-irtf-cfrg-opaque).

Background
----------

Asymmetric Password Authenticated Key Exchange (aPAKE) protocols are designed to provide password authentication and mutually authenticated key exchange without relying on PKI (except during user/password registration) and without disclosing passwords to servers or other entities other than the client machine.

OPAQUE is a PKI-free aPAKE that is secure against pre-computation attacks and capable of using a secret salt.

Documentation
-------------

The API can be found [here](https://docs.rs/opaque-ke/) along with an example for usage. More examples can be found in the [examples](./examples) directory.

Installation
------------

Add the following line to the dependencies of your `Cargo.toml`:

```
opaque-ke = "0.6.0"
```

### Minimum Supported Rust Version

Rust **1.51** or higher.

Resources
---------

- [OPAQUE academic publication](https://eprint.iacr.org/2018/163.pdf), including formal definitions and a proof of security
- [draft-irtf-cfrg-opaque-05](https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-05.html), containing a detailed (byte-level) specification for OPAQUE
- ["Let's talk about PAKE"](https://blog.cryptographyengineering.com/2018/10/19/lets-talk-about-pake/), an introductory blog post written by Matthew Green that covers OPAQUE
- [opaque-wasm](https://github.com/marucjmar/opaque-wasm), a WebAssembly package for this library

Contributors
------------

The authors of this code are Kevin Lewi
([@kevinlewi](https://github.com/kevinlewi)) and François Garillot ([@huitseeker](https://github.com/huitseeker)).
To learn more about contributing to this project, [see this document](./CONTRIBUTING.md).

#### Acknowledgments

Special thanks go to Hugo Krawczyk and Chris Wood for helping to clarify discrepancies and making suggestions for improving
this implementation. Additional credit goes to @daxpedda for adding no_std support, p256 support, and making other general
improvements to the library.


License
-------

This project is [MIT licensed](./LICENSE).
