# rust-spdm

[![RUN CODE](https://github.com/jyao1/rust-spdm/actions/workflows/main.yml/badge.svg)](https://github.com/jyao1/rust-spdm/actions/workflows/main.yml)

A rust version SPDM implementation.

It is derived from https://github.com/DMTF/libspdm.

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

Please use nightly-2022-08-08.

2. Install [NASM](https://www.nasm.us/)

Please make sure nasm can be found in PATH.

3. Install [LLVM](https://llvm.org/)

Please make sure clang can be found in PATH.

4. Install [Perl](https://www.perl.org/)

    1.	This is for crate ring
    2.	This is for windows

Please make sure perl can be found in PATH.


For OS build, unset env (CC and AR):

```
set CC=
set AR=
```

For Non-std build, set env:
```
set AR_x86_64_unknown_uefi=llvm-ar
set CC_x86_64_unknown_uefi=clang
```

Replace ```set``` with ```export``` if you use Linux or the like.

### Build OS application

```
cargo clippy
cargo fmt
cargo build
```

### Build Non-std spdm
```
pushd spdmlib
cargo xbuild --target x86_64-unknown-uefi --release --no-default-features --features="spdm-ring"
```

### Run emulator

Open one command windows and run:
```
cargo run -p spdm-responder-emu
```

Open another command windows and run:
```
cargo run -p spdm-requester-emu
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

## Known limitation
This package is only the sample code to show the concept. It does not have a full validation such as robustness functional test and fuzzing test. It does not meet the production quality yet. Any codes including the API definition, the libary and the drivers are subject to change.
