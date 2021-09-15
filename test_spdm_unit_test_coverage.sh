#!/bin/bash
cargo clean

git clean -f

rm -rf ./target *.prof*

export RUSTFLAGS="-Zinstrument-coverage"
export LLVM_PROFILE_FILE="your_name-%p-%m.profraw"

cargo build

cargo test tests_requester

grcov . --binary-path ./target/debug/ -s . -t html --branch --ignore-not-existing -o ./target/debug/coverage/

grcov . --binary-path ./target/debug/ -s . -t lcov --branch --ignore-not-existing -o ./lcov.infoba