#!/bin/bash

# pkill screen

usage() {
    cat <<EOM
Usage: $(basename "$0") [OPTION]...
  -c [Scoverage|Gcoverage]
  -b Build only
  -n <Fuzz crate Name> Run specific fuzz
  -h Show help info
EOM
    exit 0
}

coverage_type=""

process_args() {
    while getopts ":bc:n:h" option; do
        case "${option}" in
        c) coverage_type=${OPTARG} ;;
        b) build_only="true" ;;
        n) fuzz_target_name=${OPTARG} ;;
        h) usage ;;
        esac
    done
}

process_args $@

if [[ ! $PWD =~ rust-spdm$ ]]; then
    pushd ..
fi

if [ ! -d "fuzz-target/out" ]; then
    mkdir fuzz-target/out
else # add rm mkdir:
    rm -rf fuzz-target/out
    mkdir -p fuzz-target/out
fi

for i in fuzz-target/out/*; do

    if [[ ! -f $i/default/crashes ]]; then
        break
    fi

    if [[ "$(ls -A $i/default/crashes)" != "" ]]; then
        echo -e "\033[31m There are some crashes \033[0m"
        echo -e "\033[31m Path in fuzz-target/out/$i/default/crashes \033[0m"
        exit
    fi
done

if [ ! ${build_only} ]; then
    if [ "core" != $(cat /proc/sys/kernel/core_pattern) ]; then
        if [ $(id -u) -ne 0 ]; then
            sudo su - root <<EOF
        echo core >/proc/sys/kernel/core_pattern;
        pushd /sys/devices/system/cpu;
        echo performance | tee cpu*/cpufreq/scaling_governor;
        popd;
        echo "root path is $PWD";
        exit;
EOF
        else
            echo core >/proc/sys/kernel/core_pattern
            pushd /sys/devices/system/cpu
            echo performance | tee cpu*/cpufreq/scaling_governor
            popd
        fi
    fi
fi

rm -rf fuzz-target/out/*
cmds=(
    "version_rsp"
    "capability_rsp"
    "algorithm_rsp"
    "digest_rsp"
    "certificate_rsp"
    "challenge_rsp"
    "measurement_rsp"
    "keyexchange_rsp"
    "pskexchange_rsp"
    "finish_rsp"
    "psk_finish_rsp"
    "heartbeat_rsp"
    "key_update_rsp"
    "end_session_rsp"
    "version_req"
    "capability_req"
    "algorithm_req"
    "digest_req"
    "certificate_req"
    "challenge_req" #remove cert_chain = REQ_CERT_CHAIN_DATA >> OK
    "measurement_req"
    "key_exchange_req" #remove cert_chain = REQ_CERT_CHAIN_DATA >> OK
    "psk_exchange_req" #remove cert_chain = REQ_CERT_CHAIN_DATA >> OK
    "finish_req"       #remove cert_chain = REQ_CERT_CHAIN_DATA >> OK
    "psk_finish_req"
    "heartbeat_req"
    "key_update_req"
    "end_session_req"
)

buildpackage=''
for i in ${cmds[@]}; do
    buildpackage="-p $i $buildpackage"
done

echo "cargo afl build --features fuzz $buildpackage"

if [[ $coverage_type == "Scoverage" ]]; then
    echo "$coverage_type"
    export RUSTFLAGS="-Zinstrument-coverage"
    export LLVM_PROFILE_FILE='fuzz_run%m.profraw'
fi

if [[ $coverage_type == "Gcoverage" ]]; then
    echo "$coverage_type"
    export CARGO_INCREMENTAL=0
    export RUSTDOCFLAGS="-Cpanic=abort"
    export RUSTFLAGS="-Zprofile -Ccodegen-units=1 -Copt-level=0 -Clink-dead-code -Coverflow-checks=off -Zpanic_abort_tests -Cpanic=abort"
fi

if [[ $fuzz_target_name ]]; then
    cargo afl build --features fuzz -p $fuzz_target_name
else
    cargo afl build --features fuzz $buildpackage
fi

if [ ! ${build_only} ]; then
    if [[ $fuzz_target_name ]]; then
        timeout 10 cargo afl fuzz -i fuzz-target/in/${fuzz_target_name} -o fuzz-target/out/${fuzz_target_name} target/debug/${fuzz_target_name}
    else
        for ((i = 0; i < ${#cmds[*]}; i++)); do
            # echo ${cmds[$i]}
            # screen -ls | grep ${cmds[$i]}
            # if [[ $? -ne 0 ]]
            # then
            # screen -dmS ${cmds[$i]}
            # fi
            # screen -x -S ${cmds[$i]} -p 0 -X stuff "cargo afl fuzz -i fuzz-target/in/${cmds[$i]} -o fuzz-target/out/${cmds[$i]} target/debug/${cmds[$i]}"
            # screen -x -S ${cmds[$i]} -p 0 -X stuff $'\n'
            # sleep 3600
            # screen -S ${cmds[$i]} -X quit
            # sleep 5
            timeout 10 cargo afl fuzz -i fuzz-target/in/${cmds[$i]} -o fuzz-target/out/${cmds[$i]} target/debug/${cmds[$i]}
        done
    fi
fi

if [[ $coverage_type == "Scoverage" || $coverage_type == "Gcoverage" ]]; then
    grcov . -s . --binary-path ./target/debug/ -t html --branch --ignore-not-existing -o ./target/debug/fuzz_coverage/
    unset RUSTFLAGS
    unset LLVM_PROFILE_FILE
    unset CARGO_INCREMENTAL
    unset RUSTDOCFLAGS
    unset RUSTFLAGS
    echo "-------------------over--------------------------"
fi
