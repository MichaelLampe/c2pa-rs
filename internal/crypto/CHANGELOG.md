# Changelog

All notable changes to this project will be documented in this file.

This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html), except that – as is typical in the Rust community – the minimum supported Rust version may be increased without a major version increase.

The format of this changelog is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [0.9.0](https://github.com/contentauth/c2pa-rs/compare/c2pa-crypto-v0.8.2...c2pa-crypto-v0.9.0)
_14 May 2025_

### Added

* [**breaking**] Improve error handling for CAWG ICA validation ([#1011](https://github.com/contentauth/c2pa-rs/pull/1011))

### Fixed

* Chore to fix unexpected build error

## [0.8.2](https://github.com/contentauth/c2pa-rs/compare/c2pa-crypto-v0.8.1...c2pa-crypto-v0.8.2)
_09 April 2025_

### Fixed

* Dup check with validation kind ([#1035](https://github.com/contentauth/c2pa-rs/pull/1035))

## [0.8.1](https://github.com/contentauth/c2pa-rs/compare/c2pa-crypto-v0.8.0...c2pa-crypto-v0.8.1)
_04 April 2025_

### Fixed

* Update openssl to address a recently-announced vulnerability ([#1024](https://github.com/contentauth/c2pa-rs/pull/1024))

## [0.8.0](https://github.com/contentauth/c2pa-rs/compare/c2pa-crypto-v0.7.2...c2pa-crypto-v0.8.0)
_03 April 2025_

### Added

* *(crypto)* Add ability to specify `content-type` header in `sign_v2_embedded` ([#1007](https://github.com/contentauth/c2pa-rs/pull/1007))

## [0.7.2](https://github.com/contentauth/c2pa-rs/compare/c2pa-crypto-v0.7.1...c2pa-crypto-v0.7.2)
_26 March 2025_

### Fixed

* Make sure manifests are signed with end-entity certs ([#997](https://github.com/contentauth/c2pa-rs/pull/997))
* Use correct list so that empty cert chains are processed ([#994](https://github.com/contentauth/c2pa-rs/pull/994))

## [0.7.0](https://github.com/contentauth/c2pa-rs/compare/c2pa-crypto-v0.6.2...c2pa-crypto-v0.7.0)
_18 March 2025_

### Added

* *(crypto)* Add new `sign_v2_embedded` API (#975)
* Simplify `StatusTracker` interface (#937)
* Add ES256 and ES384 Rust native signing (#941)
* Wasm32 wasi 0.41.0 (#888)

### Fixed

* Fix incorrect calculation for the reserved size (#965)
* Use older version of x509-certificate for wasm32-unknown (#934)

### Updated dependencies

* Bump x509-certificate to 0.24.0 (#957)

## [0.6.2](https://github.com/contentauth/c2pa-rs/compare/c2pa-crypto-v0.6.1...c2pa-crypto-v0.6.2)
_06 February 2025_

### Fixed

* P1363 fix to handle incorrect signers (#905)

## [0.6.1](https://github.com/contentauth/c2pa-rs/compare/c2pa-crypto-v0.6.0...c2pa-crypto-v0.6.1)
_31 January 2025_

### Fixed

* Remove dependency on SubtleCrypto (#881)

## [0.6.0](https://github.com/contentauth/c2pa-rs/compare/c2pa-crypto-v0.5.0...c2pa-crypto-v0.6.0)
_29 January 2025_

### Added

* Claim v2 (#707)

## [0.5.0](https://github.com/contentauth/c2pa-rs/compare/c2pa-crypto-v0.4.0...c2pa-crypto-v0.5.0)
_24 January 2025_

### Added

* *(crypto)* Make `box_size` parameter on `c2pa_crypto::cose::sign` an `Option` (#879)

### Fixed

* Bump coset requirement to 0.3.8 (#883)

## [0.4.0](https://github.com/contentauth/c2pa-rs/compare/c2pa-crypto-v0.3.1...c2pa-crypto-v0.4.0)
_22 January 2025_

### Added

* Change the definition of `Signer.raw_signer()` to return an `Option` defaulting to `None` (#869)

## [0.3.1](https://github.com/contentauth/c2pa-rs/compare/c2pa-crypto-v0.3.0...c2pa-crypto-v0.3.1)
_22 January 2025_

### Fixed

* Make alg enum exhaustive (#866)

## [0.3.0](https://github.com/contentauth/c2pa-rs/compare/c2pa-crypto-v0.2.0...c2pa-crypto-v0.3.0)
_16 January 2025_

### Added

* Add `rsa` crate support to `rust_native_crypto` feature (#853)
* Introduce new (experimental) `rust_native_crypto` feature (#850)
* Review `c2pa-crypto` crate API (#813)
* Add new function `c2pa_crypto::cose::signing_time_from_sign1` (#812)
* Move COSE signing into `c2pa_crypto` crate (#807)
* Move COSE timestamp generation into `c2pa_crypto` (#803)
* Move COSE signature verification into `c2pa_crypto` (#801)
* Make `AsyncRawSignatureValidator` available on all platforms (#800)
* Introduce `c2pa_crypto::Verifier::verify_trust` (#798)
* Introduce `c2pa_crypto::cose::Verifier` (#797)
* Consolidate implementations of `cert_chain_from_sign1` in `c2pa_crypto` (#796)
* Move `signing_alg_from_sign1` into `c2pa-crypto` (#795)
* Move `get_cose_sign1` into `c2pa-crypto` crate (#794)
* Move COSE OCSP support into c2pa-crypto (#793)
* Move `verify_trust` into `c2pa_crypto` (#784)
* Introduce `c2pa_crypto::CertificateAcceptancePolicy` (#779)
* Bump MSRV to 1.81.0 (#781)

### Fixed

* Disable the built-in async validators on non-WASM platforms (#855)
* Bring `claim_v2` changes from #707 into `c2pa_crypto` (#811)
* Improve usage of `#[cfg]` directives (#783)

### Updated dependencies

* Bump thiserror from 2.0.6 to 2.0.8 (#787)
* Bump rasn from 0.18.0 to 0.22.0 (#727)
* Bump thiserror from 1.0.69 to 2.0.6 (#770)

## [0.2.0](https://github.com/contentauth/c2pa-rs/compare/c2pa-crypto-v0.1.2...c2pa-crypto-v0.2.0)
_12 December 2024_

### Added

* Add `RawSigner` trait to `c2pa-crypto` (derived from `c2pa::Signer`) (#716)
* Move time stamp code into c2pa-crypto (#696)

### Fixed

* Compile `c2pa-crypto` with `cargo check` (#768)
* Verbose assertions for `is_none()` (#704)
* Remove `c2pa::Signer` dependency on `c2pa_crypto::TimeStampProvider` (#718)
* Treat Unicode-3.0 license as approved; unpin related dependencies (#693)

### Updated dependencies

* Bump chrono from 0.4.38 to 0.4.39 (#763)

## [0.1.2](https://github.com/contentauth/c2pa-rs/compare/c2pa-crypto-v0.1.1...c2pa-crypto-v0.1.2)
_24 October 2024_

### Fixed

* Fix badges in README

## [0.1.1](https://github.com/contentauth/c2pa-rs/compare/c2pa-crypto-v0.1.0...c2pa-crypto-v0.1.1)
_24 October 2024_

### Fixed

* Tweak changelog format

## [0.1.0](https://github.com/contentauth/c2pa-rs/releases/tag/c2pa-crypto-v0.1.0)
_24 October 2024_

### Added

* Create placeholders for forthcoming crates ([#645](https://github.com/contentauth/c2pa-rs/pull/645))
