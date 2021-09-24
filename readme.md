# rust-spdm

A rust version SPDM implementation.

It is derived from https://github.com/jyao1/openspdm.

## Build Rust SPDM

### Tools

1. Install [RUST](https://www.rust-lang.org/)

please use nightly-2021-08-20.

2. Install [NASM](https://www.nasm.us/)

Please make sure nasm can be found in PATH.

3. Install LLVM

Please make sure clang can be found in PATH.

For OS build, unset env (CC and AR):

```
set CC=
set AR=
```

### Build

```
cargo build
cargo clippy
cargo fmt
```

### Run

Open one command windows and run:
```
cargo run -p spdm-responder-emu
```

Open another command windows and run:
```
cargo run -p spdm-requester-emu
```

## Known limitation
This package is only the sample code to show the concept. It does not have a full validation such as robustness functional test and fuzzing test. It does not meet the production quality yet. Any codes including the API definition, the libary and the drivers are subject to change.
