### Rust Memory Safety & Undefined Behavior Detection

https://github.com/sslab-gatech/Rudra

[Currently rust can't work in the workspace(2021-08-31)](https://github.com/sslab-gatech/Rudra/issues/11)

The use of docker will have a depend problem.

https://github.com/sslab-gatech/Rudra/blob/master/DEV.md

`cp -r rust-spdm rust-spdm-rudra`

Modify the content of the  rust-toolchain file as 2020-08-26

install crates

```
rustup component add rustc-dev
rustup component add miri
```

set up environment variable

```
export RUDRA_RUST_CHANNEL=nightly-2020-08-26
export RUDRA_RUNNER_HOME=$HOME/rudra-home

export RUSTFLAGS="-L $HOME/.rustup/toolchains/${RUDRA_RUST_CHANNEL}-x86_64-unknown-linux-gnu/lib"
export LD_LIBRARY_PATH="${LD_LIBRARY_PATH}:$HOME/.rustup/toolchains/${RUDRA_RUST_CHANNEL}-x86_64-unknown-linux-gnu/lib"
```

clone rudra project and install rudra

```
git clone https://github.com/sslab-gatech/Rudra.git
cd rudra
./install-release.sh
```

Rudra corresponds to the folder or file

```
rudra --crate-type lib tests/unsafe_destructor/normal1.rs  # for single file testing (you need to set library include path, or use `cargo run` instead)
cd spdmlib
cargo rudra  # for crate compilation
```