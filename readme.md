# rust-spdm

[![RUN CODE](https://github.com/jyao1/rust-spdm/actions/workflows/main.yml/badge.svg)](https://github.com/jyao1/rust-spdm/actions/workflows/main.yml)
[![codecov](https://codecov.io/gh/jyao1/rust-spdm/branch/master/graph/badge.svg)](https://codecov.io/gh/jyao1/rust-spdm)

A rust version SPDM implementation.

## Features

### Specification

DSP0274 Security Protocol and Data Model (SPDM) Specification (version 1.0.1, version 1.1.2 and version 1.2.1)

DSP0277 Secured Messages using SPDM Specification (version 1.1.0)

### Implemented Requests and Responses

SPDM 1.0: GET_VERSION, GET_CAPABILITIES, NEGOTIATE_ALGORITHMS, GET_DIGESTS, GET_CERTIFICATE, CHALLENGE, and GET_MEASUREMENTS.

SPDM 1.1: KEY_EXCHANGE, FINISH, PSK_EXCHANGE, PSK_FINISH, END_SESSION, HEARTBEAT, KEY_UPDATE messages.

SPDM 1.2: N/A. New SPDM 1.2 messages are not supported yet.

### Cryptographic Algorithm Support

It depends on crypto wrapper. Current support algorithms:
* Hash: SHA2(256/384/512)
* Signature: RSA-SSA(2048/3072/4096) / RSA-PSS(2048/3072/4096) / ECDSA (P256/P384)
* KeyExchange: ECDHE(P256/P384)
* AEAD: AES_GCM(128/256) / ChaCha20Poly1305

## Documentation
All documents are put at [doc](./doc/) folder.

## Build Rust SPDM

### Checkout repo
```
git clone https://github.com/jyao1/rust-spdm.git
git submodule update --init --recursive
```

### Tools

1. Install [RUST](https://www.rust-lang.org/)

Please use nightly-2022-11-21.

2. Install [NASM](https://www.nasm.us/)

Please make sure nasm can be found in PATH.

3. Install [LLVM](https://llvm.org/)

Please make sure clang can be found in PATH.

4. Install [Perl](https://www.perl.org/)

    1.	This is for crate ring
    2.	This is for windows

Please make sure perl can be found in PATH.


Unset env (CC and AR):
```
export CC=
export AR=
```
Set the following environment variables:
```
export AR_x86_64_unknown_none=llvm-ar
export CC_x86_64_unknown_none=clang
```

### Build OS application

Enter linux shell or mingw shell (e.g. git bash) in windows.
```
cargo clippy
cargo fmt
cargo build
```

### Build `no_std` spdm
```
pushd spdmlib
cargo build -Z build-std=core,alloc,compiler_builtins --target x86_64-unknown-none --release --no-default-features --features="spdm-ring"
```

### Run emulator with default feature

Open one command windows and run:
```
cargo run -p spdm-responder-emu
```

Open another command windows and run:
```
cargo run -p spdm-requester-emu
```

### Run emulator with selected feature

The following list shows the supported combinations for both spdm-requester-emu and spdm-responder-emu


| Features                                                                | CryptoLibrary | Hashed transcript data support | Notes                                                              |
| ----------------------------------------------------------------------- | ------------- | ------------------------------ | ------------------------------------------------------------------ |
| spdm-ring                                                               | ring          | No                             | use ring as crypto library with hashed-transcript-data disabled    |
| spdm-ring,hashed-transcript-data                                        | ring          | Yes                            | use ring as crypto library with hashed-transcript-data enabled     |
| spdm-mbedtls                                                            | mbedtls       | No                             | use mbedtls as crypto library with hashed-transcript-data disabled |
| spdm-mbedtls,hashed-transcript-data,spdm-mbedtls-hashed-transcript-data | mbedtls       | Yes                            | use mbedtls as crypto library with hashed-transcript-data          |

For example, run the emulator with spdm-ring enabled and without hashed-transcript-data enabled.  
Open one command windows and run:
```
cargo run -p spdm-responder-emu --no-default-features --features "spdm-ring"
```

run the emulator with spdm-mbedtls enabled and with hashed-transcript-data enabled.  
Open another command windows and run:
```
cargo run -p spdm-requester-emu --no-default-features --features "spdm-mbedtls,hashed-transcript-data,spdm-mbedtls-hashed-transcript-data"
```


### Cross test with [spdm_emu](https://github.com/DMTF/spdm-emu)
Open one command windows in workspace and run:

```
git clone https://github.com/DMTF/spdm-emu.git
cd spdm-emu
git submodule update --init --recursive
mkdir build
cd build
cmake -G"NMake Makefiles" -DARCH=<x64|ia32> -DTOOLCHAIN=<toolchain> -DTARGET=<Debug|Release> -DCRYPTO=<mbedtls|openssl> ..
nmake copy_sample_key
nmake
cd bin
spdm_responder_emu.exe
```
In root folder of rust spdm repo, open a command window and run:
```
cargo run -p spdm-requester-emu
```

### Run test cases
Run `cargo test -- --test-threads=1` and `cargo test --no-default-features --features "spdmlib/std,spdmlib/spdm-ring" -- --test-threads=1`

To run a specific test, use `cargo test <test_func_name>`

To run test with println!() message, use `cargo test -- --nocapture`

## Known limitation
This package is only the sample code to show the concept. It does not have a full validation such as robustness functional test and fuzzing test. It does not meet the production quality yet. Any codes including the API definition, the libary and the drivers are subject to change.
