#!/bin/bash

set -euo pipefail

usage() {
    cat <<EOM
Usage: $(basename "$0") [OPTION]...
  -c Run check
  -b Build target
  -r Build and run tests
  -h Show help info
EOM
}

echo_command() {
    set -x
    "$@"
    set +x
}

check() {
    echo "Checking..."
    set -x
    cargo check
    cargo fmt --all -- --check
    cargo clippy -- -D warnings

    pushd spdmlib_crypto_mbedtls
    cargo check
    cargo clippy -- -D warnings
    popd
    set +x
}

build() {
    pushd spdmlib
    echo "Building Rust-SPDM..."
    cargo build

    echo "Building Rust-SPDM with no-default-features..."
    echo_command cargo build --release --no-default-features

    echo "Building Rust-SPDM with spdm-ring feature..."
    echo_command cargo build --release --no-default-features --features=spdm-ring
 
    echo "Building Rust-SPDM with spdm-ring,hashed-transcript-data feature..."
    echo_command cargo build --release --no-default-features --features=spdm-ring,hashed-transcript-data

    echo "Building Rust-SPDM in no std with no-default-features..."
    echo_command cargo build -Z build-std=core,alloc,compiler_builtins --target x86_64-unknown-none --release --no-default-features
    
    echo "Building Rust-SPDM in no std with spdm-ring feature..."
    echo_command cargo build -Z build-std=core,alloc,compiler_builtins --target x86_64-unknown-none --release --no-default-features --features="spdm-ring"

    echo "Building Rust-SPDM in no std with spdm-ring,hashed-transcript-data feature..."
    echo_command cargo build -Z build-std=core,alloc,compiler_builtins --target x86_64-unknown-none --release --no-default-features --features="spdm-ring,hashed-transcript-data"
    popd

    echo "Building spdm-requester-emu..."
    echo_command cargo build -p spdm-requester-emu

    echo "Building spdm-responder-emu..."
    echo_command cargo build -p spdm-responder-emu

    echo "Building tdisp..."
    echo_command cargo build -p tdisp
}

run() {
    echo "Running tests..."
    cargo test

    echo "Running requester and responder..."
    echo_command cargo run -p spdm-responder-emu &
    sleep 5
    echo_command cargo run -p spdm-requester-emu
}

CHECK_OPTION=false
BUILD_OPTION=false
RUN_OPTION=false

process_args() {
    while getopts ":cbrfh" option; do
        case "${option}" in
        c)
            CHECK_OPTION=true
            ;;
        b)
            BUILD_OPTION=true
            ;;
        r)
            RUN_OPTION=true
            ;;
        h)
            usage
            exit 0
            ;;
        *)
            echo "Invalid option '-$OPTARG'"
            usage
            exit 1
            ;;
        esac
    done
}

main() {
    if [[ ${CHECK_OPTION} == true ]]; then
        check
        exit 0
    fi
    if [[ ${BUILD_OPTION} == true ]]; then
        build
        exit 0
    fi
    build
    if [[ ${RUN_OPTION} == true ]]; then
        run
    fi
}

process_args "$@"
main
