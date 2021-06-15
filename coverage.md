### source coded coverage

**grcov has a bug in Windows, please run the command line with administrator**

​	[bug issues](https://github.com/mozilla/grcov/issues/561)

1. Install the grcov:

   `cargo install grcov`

2. Installl the llvm-tools or llvm-tools-preview component:

   `rustup component add llvm-tools-preview`

3. Ensure that the following environment variable is set up:

    `export RUSTFLAGS="-Zinstrument-coverage"`

4. Build your code:

   ```bash
   cd rust-sdpm
   cargo build -p spdm-responder-emu
   cargo build -p spdm-requester-emu
   ```

5. generate raw coverage profiling data:

   ```bash
   LLVM_PROFILE_FILE="responder.profraw" target/debug/spdm-responder-emu.exe &
   LLVM_PROFILE_FILE="requester.profraw" target/debug/spdm-requester-emu.exe
   ```

6. Creating coverage reports:

   ```bash
   llvm-profdata.exe merge -sparse requester.profraw responder.profraw -o total.profdata
   llvm-cov.exe export -Xdemangler=rustfilt target/debug/spdm-responder-emu.exe target/debug/spdm-requester-emu.exe --instr-profile=total.profdata --format=lcov > lcov.info
   grcov . -s . --binary-path ./target/debug/ -t html --branch --ignore-not-existing -o ./target/debug/coverage/
   ```

7. View report:

   browser open the target/debug/coverage/index.html

Reference:

​	[rust-code-coverage-sample](https://github.com/marco-c/rust-code-coverage-sample)

​	[source_based_code_coverage](https://doc.rust-lang.org/beta/unstable-book/compiler-flags/source-based-code-coverage.html#running-the-instrumented-binary-to-generate-raw-coverage-profiling-data)

​	[grcov](https://github.com/mozilla/grcov)

