#!/bin/bash

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

echo $buildpackage

RUSTFLAGS="-Zinstrument-coverage" cargo afl build $buildpackage

for ((i=0;i<${#cmds[*]};i++))
do
    echo ${cmds[$i]}
    screen -ls | grep ${cmds[$i]}
    if [[ $? -ne 0 ]]
    then
    screen -dmS ${cmds[$i]}
    fi 
    screen -x -S ${cmds[$i]} -p 0 -X stuff "LLVM_PROFILE_FILE='${cmds[$i]}%2m.profraw' cargo afl fuzz -i fuzz-target/in -o fuzz-target/out/${cmds[$i]} target/debug/${cmds[$i]}"
    screen -x -S ${cmds[$i]} -p 0 -X stuff $'\n'
    sleep 3600
    screen -S ${cmds[$i]} -X quit
done