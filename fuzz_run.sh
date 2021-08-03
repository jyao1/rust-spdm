#!/bin/bash

pkill screen

cmds=(
"rspversion"
"rspcapability"
"rspalgorithm"
"rspdigest"
"rspcertificate"
"rspchallenge"
"rspmeasurement"
"rspkeyexchange"
"rsppskexchange"
"reqversion"
"reqcapability"
"reqalgorithm"
"reqdigest"
"reqcertificate"
"reqchallenge"
"reqmeasurement"
"key_exchange_req"
"psk_exchange_req"
)

buildpackage=''
for i in ${cmds[@]};do
    buildpackage="-p $i $buildpackage";
done

echo "cargo afl build $buildpackage"

unset RUSTFLAGS
unset LLVM_PROFILE_FILE

if [[ $1 = "Scoverage" ]]; then
    echo "$1"
    export RUSTFLAGS="-Zinstrument-coverage"
    export LLVM_PROFILE_FILE='fuzz_run%p%2m.profraw'
fi 

if [[ $1 = "Gcoverage" ]]; then
    echo "$1"
    export CARGO_INCREMENTAL=0
    export RUSTDOCFLAGS="-Cpanic=abort"
    export RUSTFLAGS="-Zprofile -Ccodegen-units=1 -Copt-level=0 -Clink-dead-code -Coverflow-checks=off -Zpanic_abort_tests -Cpanic=abort"
fi

cargo afl build $buildpackage

for ((i=0;i<${#cmds[*]};i++))
do
    echo ${cmds[$i]}
    screen -ls | grep ${cmds[$i]}
    if [[ $? -ne 0 ]]
    then
    screen -dmS ${cmds[$i]}
    fi 
    screen -x -S ${cmds[$i]} -p 0 -X stuff "cargo afl fuzz -i fuzz-target/in -o fuzz-target/out/${cmds[$i]} target/debug/${cmds[$i]}"
    screen -x -S ${cmds[$i]} -p 0 -X stuff $'\n'
    sleep 3600
    screen -S ${cmds[$i]} -X quit
done

if [[ $1 = "Scoverage" || $1 = "Gcoverage" ]]; then
grcov . -s . --binary-path ./target/debug/ -t html --branch --ignore-not-existing -o ./target/debug/fuzz_coverage/
fi