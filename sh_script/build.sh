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

trap cleanup exit

cleanup() {
    kill -9 $(ps aux | grep spdm-responder | grep emu | awk '{print $2}') || true
    kill -9 $(ps aux | grep spdm_responder_emu | grep emu | awk '{print $2}') || true
}

check() {
    echo "Checking..."
    set -x
    cargo check
    cargo fmt --all -- --check
    cargo clippy -- -D warnings -A clippy::only-used-in-recursion -A clippy::result-large-err
    
    pushd spdmlib_crypto_mbedtls
    cargo check
    cargo clippy -- -D warnings -A clippy::only-used-in-recursion -A clippy::result-large-err
    popd
    set +x
}


build_mbedtls() {
    pushd mbedtls
    cp ../include/mbedtls/config.h ./include/mbedtls/
    CURRENT_DIR=`pwd`/../include
    export CFLAGS="-I$CURRENT_DIR -nostdlibinc -isystem -ffunction-sections -fdata-sections -fPIE"
    make clean
    make lib -j ${nproc:-1}
    unset CFLAGS
    popd
}

build_mbedtls_c_build_env() {
    if [ -v CC ]; then
        CC_BACKUP=$CC
    fi
    if [ -v AR ]; then
        AR_BACKUP=$AR
    fi
    export CC=clang
    export AR=llvm-ar
    "$@"
    if [ -v CC_BACKUP ]; then
        CC=$CC_BACKUP;export $CC
    else
        unset CC
    fi
    if [ -v AR_BACKUP ]; then
        AR=$AR_BACKUP;export $AR
    else
        unset AR
    fi
}

build_mbedtls_crate() {
    echo "Building Mbedtls library for Rust-SPDM..."
    build_mbedtls_c_build_env build_mbedtls
}

RUSTFLAGS=${RUSTFLAGS:-}
build() {
    pushd spdmlib_crypto_mbedtls
    if [ "${RUNNER_OS:-Linux}" == "Linux" ]; then
        build_mbedtls_crate
    fi
    popd
    
    pushd spdmlib
    echo "Building Rust-SPDM..."
    cargo build
    
    echo "Building Rust-SPDM with no-default-features..."
    echo_command cargo build --release --no-default-features
    
    echo "Building Rust-SPDM with spdm-ring feature..."
    echo_command cargo build --release --no-default-features --features=spdm-ring
    
    echo "Building Rust-SPDM with spdm-ring,hashed-transcript-data feature..."
    echo_command cargo build --release --no-default-features --features=spdm-ring,hashed-transcript-data
    
    echo "Building Rust-SPDM with spdm-ring,hashed-transcript-data,mut-auth feature..."
    echo_command cargo build --release --no-default-features --features=spdm-ring,hashed-transcript-data,mut-auth

    if [ -z "$RUSTFLAGS" ]; then
        echo "Building Rust-SPDM in no std with no-default-features..."
        echo_command cargo build -Z build-std=core,alloc,compiler_builtins --target x86_64-unknown-none --release --no-default-features
    
        echo "Building Rust-SPDM in no std with spdm-ring feature..."
        echo_command cargo build -Z build-std=core,alloc,compiler_builtins --target x86_64-unknown-none --release --no-default-features --features="spdm-ring"
    
        echo "Building Rust-SPDM in no std with spdm-ring,hashed-transcript-data feature..."
        echo_command cargo build -Z build-std=core,alloc,compiler_builtins --target x86_64-unknown-none --release --no-default-features --features="spdm-ring,hashed-transcript-data"
    
        echo "Building Rust-SPDM in no std with spdm-ring,hashed-transcript-data,mut-auth feature..."
        echo_command cargo build -Z build-std=core,alloc,compiler_builtins --target x86_64-unknown-none --release --no-default-features --features="spdm-ring,hashed-transcript-data,mut-auth"
    fi

    popd
    
    echo "Building spdm-requester-emu..."
    echo_command cargo build -p spdm-requester-emu
    
    echo "Building spdm-responder-emu..."
    echo_command cargo build -p spdm-responder-emu
}

RUN_REQUESTER_FEATURES=${RUN_REQUESTER_FEATURES:-spdm-ring,hashed-transcript-data}
RUN_RESPONDER_FEATURES=${RUN_RESPONDER_FEATURES:-spdm-ring,hashed-transcript-data}
RUN_REQUESTER_MUTAUTH_FEATURES="${RUN_REQUESTER_FEATURES},mut-auth"
RUN_RESPONDER_MUTAUTH_FEATURES="${RUN_RESPONDER_FEATURES},mut-auth"

run_with_spdm_emu() {
    echo "Running with spdm-emu..."
    pushd test_key
    chmod +x ./spdm_responder_emu
    echo_command  ./spdm_responder_emu --trans PCI_DOE &
    popd
    sleep 5
    echo_command cargo run -p spdm-requester-emu --no-default-features --features="$RUN_RESPONDER_FEATURES"
    cleanup
    
    echo_command cargo run -p spdm-responder-emu --no-default-features --features="$RUN_REQUESTER_FEATURES" &
    sleep 5
    pushd test_key
    chmod +x ./spdm_requester_emu
    echo_command  ./spdm_requester_emu --trans PCI_DOE --exe_conn DIGEST,CERT,CHAL,MEAS --exe_session KEY_EX,PSK,KEY_UPDATE,HEARTBEAT,MEAS,DIGEST,CERT
    popd
}

run_with_spdm_emu_mut_auth() {
    echo "Running mutual authentication with spdm-emu..."
    pushd test_key
    chmod +x ./spdm_responder_emu
    echo_command  ./spdm_responder_emu --trans PCI_DOE --mut_auth DIGESTS --req_asym ECDSA_P384 --basic_mut_auth NO &
    popd
    sleep 5
    echo_command cargo run -p spdm-requester-emu --no-default-features --features="$RUN_RESPONDER_MUTAUTH_FEATURES"
    cleanup
    
    echo_command cargo run -p spdm-responder-emu --no-default-features --features="$RUN_REQUESTER_MUTAUTH_FEATURES" &
    sleep 5
    pushd test_key
    chmod +x ./spdm_requester_emu
    echo_command  ./spdm_requester_emu --trans PCI_DOE --req_asym ECDSA_P384 --exe_conn DIGEST,CERT,CHAL,MEAS --exe_session KEY_EX,PSK,KEY_UPDATE,HEARTBEAT,MEAS,DIGEST,CERT
    popd
}

run_basic_test() {
    echo "Running basic tests..."
    echo_command cargo test -- --test-threads=1
    echo_command cargo test --no-default-features --features "spdmlib/std,spdmlib/spdm-ring" -- --test-threads=1
    echo "Running basic tests finished..."

    echo "Running spdmlib-test..."
    pushd test/spdmlib-test
    echo_command cargo test -- --test-threads=1
    echo_command cargo test --no-default-features -- --test-threads=1
    popd
}

run_rust_spdm_emu() {
    echo "Running requester and responder..."
    echo_command cargo run -p spdm-responder-emu --no-default-features --features="$RUN_REQUESTER_FEATURES" &
    sleep 5
    echo_command cargo run -p spdm-requester-emu --no-default-features --features="$RUN_RESPONDER_FEATURES"
    cleanup
}

run_rust_spdm_emu_mut_auth() {
    echo "Running requester and responder mutual authentication..."
    echo $RUN_REQUESTER_MUTAUTH_FEATURES
    echo_command cargo run -p spdm-responder-emu --no-default-features --features="$RUN_REQUESTER_MUTAUTH_FEATURES" &
    sleep 5
    echo_command cargo run -p spdm-requester-emu --no-default-features --features="$RUN_RESPONDER_MUTAUTH_FEATURES"
    cleanup
}

run() {
    run_basic_test
    run_rust_spdm_emu
    run_rust_spdm_emu_mut_auth
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
    ./sh_script/pre-build.sh

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
        if [ "$RUNNER_OS" == "Linux" ]; then
            run_with_spdm_emu
            run_with_spdm_emu_mut_auth
        fi
    fi
}

process_args "$@"
main