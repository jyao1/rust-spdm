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
}

SPDM_EMU_PRE_BUILD_NAME=${SPDM_EMU_PRE_BUILD_NAME:-spdm-emu-v2.3.1.tar.bz2}
SPDM_EMU_PRE_BUILD_URL=${SPDM_EMU_PRE_BUILD_URL:-https://github.com/longlongyang/spdm-emu/releases/download/2.3.1/spdm-emu-v2.3.1.tar.bz2}

download_spdm_emu() {
    if [ -f ${SPDM_EMU_PRE_BUILD_NAME} ]
    then
        echo "spdm-emu File exist ${SPDM_EMU_PRE_BUILD_NAME}"
    else
        curl -LJO ${SPDM_EMU_PRE_BUILD_URL}
        tar xf ${SPDM_EMU_PRE_BUILD_NAME}
    fi
    
}

RUN_REQUESTER_FEATURES=${RUN_REQUESTER_FEATURES:-spdm-ring,hashed-transcript-data}
RUN_RESPONDER_FEATURES=${RUN_RESPONDER_FEATURES:-spdm-ring,hashed-transcript-data}

run_with_spdm_emu() {
    echo "Running with spdm-emu..."
    pushd spdm-emu-v2.3.1
    echo_command  ./spdm_responder_emu --ver 1.2 --trans PCI_DOE &
    popd
    sleep 5
    echo_command cargo run -p spdm-requester-emu --no-default-features --features="$RUN_RESPONDER_FEATURES"
    cleanup
    
    echo_command cargo run -p spdm-responder-emu --no-default-features --features="$RUN_REQUESTER_FEATURES" &
    sleep 5
    pushd spdm-emu-v2.3.1
    echo_command  ./spdm_requester_emu --ver 1.2 --trans PCI_DOE
    popd
}

run_basic_test() {
    echo "Running basic tests..."
    echo_command cargo test -- --test-threads=1
    echo_command cargo test --no-default-features --features "spdmlib/std,spdmlib/spdm-ring" -- --test-threads=1
    echo "Running basic tests finished..."
}

run_rust_spdm_emu() {
    echo "Running requester and responder..."
    echo_command cargo run -p spdm-responder-emu --no-default-features --features="$RUN_REQUESTER_FEATURES" &
    sleep 5
    echo_command cargo run -p spdm-requester-emu --no-default-features --features="$RUN_RESPONDER_FEATURES"
    cleanup
}

run() {
    run_basic_test
    run_rust_spdm_emu
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
            download_spdm_emu
            run_with_spdm_emu
        fi
    fi
}

process_args "$@"
main