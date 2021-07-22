### source coded coverage

**grcov has a bug in Windows, please run the command line with administrator**

​	[bug issues](https://github.com/mozilla/grcov/issues/561)

1. Install the grcov:

   `cargo install grcov`

2. Installl the llvm-tools or llvm-tools-preview component:

   `rustup component add llvm-tools-preview`

3. Ensure that the following environment variable is set up:

    `export RUSTFLAGS="-Zinstrument-coverage"`

4. Runtest your code:

   `Since there may be more than one test binary, apply %m in the filename pattern. This generates unique names for each test binary. (Otherwise, each executed test binary would overwrite the coverage results from the previous binary.)`             
   ```bash
   LLVM_PROFILE_FILE="cargotest-%m.profraw" cargo test --tests
   ```

5. generate raw coverage profiling data:

   `You should have one or more .profraw files now, one for each test binary. Run the profdata tool to merge them:`
   ```bash
   llvm-profdata merge -sparse codec/cargotest-*.profraw -o codeccargotest.profdata

   llvm-profdata merge -sparse spdmlib/cargotest-*.profraw -o spdmlibcargotest.profdata

   llvm-profdata merge -sparse test/spdm-requester-emu/cargotest-*.profraw -o requestercargotest.profdata

   llvm-profdata merge -sparse test/spdm-responder-emu/cargotest-*.profraw -o respondercargotest.profdata
   
   llvm-profdata merge -sparse cargotest-*.profraw -o cargotest.profdata
   ```

6. Creating coverage reports:

   ```bash
    llvm-cov export target/debug/deps/codec-*.exe --instr-profile=codeccargotest.profdata --format=lcov > codeccargotest.info

   llvm-cov export target/debug/deps/spdmlib-*.exe --instr-profile=spdmlibcargotest.profdata --format=lcov > spdmlibcargotest.info

   llvm-cov export target/debug/deps/spdm_requester_emu-*.exe --instr-profile=requestercargotest.profdata --format=lcov > requestercargotest.info

   llvm-cov export target/debug/deps/spdm_responder_emu-*.exe--instr-profile=respondercargotest.profdata --format=lcov > respondercargotest.info
   
   llvm-cov export target/debug/deps/test_client_server-*.exe --instr-profile=cargotest.profdata --format=lcov > cargotest.info
   
   grcov codeccargotest.info spdmlibcargotest.info requestercargotest.info respondercargotest.info cargotest.info -s . --binary-path ./target/debug/ -t html --branch --ignore-not-existing -o ./target/debug/coverage/
   ```

7. Create coverage reports through tools:
   ```bash
   cd rust-sdpm
   UnitTestCoverge.sh
   ```
   
8. View report:
`browser open the target/debug/coverage/index.html`

Reference:

​[rust-code-coverage-sample](https://github.com/marco-c/rust-code-coverage-sample)

​	[source_based_code_coverage](https://doc.rust-lang.org/beta/unstable-book/compiler-flags/source-based-code-coverage.html#running-the-instrumented-binary-to-generate-raw-coverage-profiling-data)

​	[grcov](https://github.com/mozilla/grcov)

