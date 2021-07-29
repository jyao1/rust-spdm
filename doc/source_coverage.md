### source coded coverage

**grcov has a bug in Windows, please run the command line with administrator**

​	[bug issues](https://github.com/mozilla/grcov/issues/561)

**A source-based code coverage implementation, enabled with -Z instrument-coverage, which uses LLVM's native, efficient coverage instrumentation to generate very precise coverage data.**
   
   [instrument-coverage environment](https://doc.rust-lang.org/nightly/unstable-book/compiler-flags/instrument-coverage.html)

1. Install the grcov:

   `cargo install grcov`

2. Installl the llvm-tools or llvm-tools-preview component:

   `rustup component add llvm-tools-preview`

3. Ensure that the following environment variable is set up:

    `export RUSTFLAGS="-Zinstrument-coverage"`
    `export LLVM_PROFILE_FILE="rust-spdm-%p%m.profraw"`

4. Build your code:

   ```bash
   cd rust-sdpm
   cargo build -p spdm-responder-emu -p spdm-requester-emu

   ```

5. generate raw coverage profiling data:

   ```bash
   cargo run -p spdm-responder-emu & 
   cargo run -p spdm-requester-emu
   ```

6. Creating source based coverage reports:

   ```bash
   grcov . -s . --binary-path ./target/debug/ -t html --branch --ignore-not-existing -o ./target/debug/source_coverage/
   ```

7. View report:

   browser open the target/debug/coverage/index.html

Reference:

​	[rust-code-coverage-sample](https://github.com/marco-c/rust-code-coverage-sample)

​	[source_based_code_coverage](https://doc.rust-lang.org/beta/unstable-book/compiler-flags/source-based-code-coverage.html#running-the-instrumented-binary-to-generate-raw-coverage-profiling-data)

​	[grcov](https://github.com/mozilla/grcov)

