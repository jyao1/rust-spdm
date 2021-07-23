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

for ((i=0;i<${#cmds[*]};i++))
do
    echo llvm-profdata merge -sparse ${cmds[$i]}*.profraw -o ${cmds[$i]}.profdata
    llvm-profdata merge -sparse ${cmds[$i]}*.profraw -o ${cmds[$i]}.profdata
    echo "llvm-cov export -Xdemangler=rustfilt target/debug/${cmds[$i]} --instr-profile=${cmds[$i]}.profdata --format=lcov > ${cmds[$i]}.info"
    llvm-cov export -Xdemangler=rustfilt target/debug/${cmds[$i]} --instr-profile=${cmds[$i]}.profdata --format=lcov > ${cmds[$i]}.info
    sleep 2
done

grcov . -s . --binary-path ./target/debug/ -t html --branch --ignore-not-existing -o ./target/debug/coverage/