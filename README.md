go-uefi
=======

A UEFI library written to interact with Linux efivars. The goal is to provide a
Go library to enable application authors to better utilize secure boot and UEFI.
This also includes unit-testing to ensure the library is compatible with
existing tools, and integration tests to ensure the library is able of deal with
future UEFI revisions.


## Current progress

* Reading from Linux efivars.
* Implements most Secure Boot relevant structs as defined in UEFI Spec Version 2.8 Errata A (February 14th 2020).
* Microsoft Authenticode support (still buggy).
    - Implements a subset of [PKCS7](https://tools.ietf.org/html/rfc2315).
    - PE/COFF checksumming.
* Example code implementing `sbsigntools`.
* Some support for parsing protocol structs.
* WIP top-level APIs.
* WIP integration tests utilizing [vmtest](https://github.com/anatol/vmtest).

# Goals

* Implement `sbsigntool` and/or `efitools`.
* Provide a sane top-level library.
* Move [`sbctl`](https://github.com/Foxboron/sbctl) to use this library.
* Provide low-level plumbing if needed.
* Decent documentation between code and specification.
* Integration tests towards [tianocore](https://www.tianocore.org/).
