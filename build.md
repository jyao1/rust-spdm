# Build Rust SPDM

## Tools

1. Install [RUST](https://www.rust-lang.org/)

please use nightly-2020-11-09.

2. Install [NASM](https://www.nasm.us/)

Please make sure nasm can be found in PATH.

3. Install LLVM

Please make sure clang can be found in PATH.

For OS build, unset env (CC and AR):

```
set CC=
set AR=
```

## Build

```
cargo build
cargo clippy
cargo fmt
```

## Run

Open one command windows and run:
```
cargo run -p spdm-responder-emu
```

Open another command windows and run:
```
cargo run -p spdm-requester-emu
```