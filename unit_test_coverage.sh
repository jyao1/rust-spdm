#!/bin/bash

implement=`$(RUSTFLAGS="-Zinstrument-coverage" LLVM_PROFILE_FILE="cargotest-%m.profraw" cargo test --tests)`


route=(
    "codec"
    "spdmlib"
    "test/spdm-requester-emu"
    "test/spdm-responder-emu"
    "."
)

name=(
    "codec"
    "spdmlib"
    "spdm_requester_emu"
    "spdm_responder_emu"
    "test_client_server"    
)

for ((i = 0; i < ${#name[*]}; i++))
do
    llvm-profdata merge -sparse ${route[i]}/cargotest-*.profraw -o ${name[i]}.profdata
    llvm-cov export target/debug/deps/${name[i]}-*.exe --instr-profile=${name[i]}.profdata --format=lcov >${name[i]}.info
done

grcov codec.info spdmlib.info spdm_requester_emu.info spdm_responder_emu.info test_client_server.info -s . --binary-path ./target/debug/ -t html --branch --ignore-not-existing -o ./target/debug/coverage/
