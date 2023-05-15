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
set CC=
set AR=
```
Set the following environment variables:
```
set AR_x86_64_unknown_none=llvm-ar
set CC_x86_64_unknown_none=clang
```

Replace ```set``` with ```export``` if you use Linux or the like.

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
For example, run the emulator without hashed-transcript-data feature be enabled  
Open one command windows and run:
```
cargo run -p spdm-responder-emu --no-default-features --features "spdmlib/std,spdmlib/spdm-ring"
```

Open another command windows and run:
```
cargo run -p spdm-requester-emu --no-default-features --features "spdmlib/std,spdmlib/spdm-ring"
```


Cross test with [spdm_emu](https://github.com/DMTF/spdm-emu) is supported,  
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
```
cargo test
```
or
```
cargo test --features "spdmlib/std,spdmlib/spdm-ring"
```

To run a specific test:
```
cargo test <test_func_name>
```

To run test with println!() message:
```
cargo test -- --nocapture
```

To run test with single thread:
```
cargo test -- --test-threads=1
```

## Known limitation
This package is only the sample code to show the concept. It does not have a full validation such as robustness functional test and fuzzing test. It does not meet the production quality yet. Any codes including the API definition, the libary and the drivers are subject to change.
