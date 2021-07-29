### source coded coverage

**grcov has a bug in Windows, please run the command line with administrator**

​	[bug issues](https://github.com/mozilla/grcov/issues/561)

1. Install the grcov:

   `cargo install grcov`

2. Installl the llvm-tools or llvm-tools-preview component:

   `rustup component add llvm-tools-preview`

3. Ensure that the following environment variable is set up:

    `export RUSTFLAGS="-Zinstrument-coverage"`

    `export LLVM_PROFILE_FILE="your_name-%p-%m.profraw"`

4. Runtest your code:

   ```bash
   cargo build

   cargo test
   ```
5. Creating coverage reports:

   ```bash
   grcov . --binary-path ./target/debug/ -s . -t html --branch --ignore-not-existing -o ./target/debug/coverage/
   ```

6. Create coverage reports through tools:
   ```bash
   cd rust-sdpm
   UnitTestCoverge.sh
   ```
   
7. View report:

   `browser open the target/debug/coverage/index.html`

Reference:

​[rust-code-coverage-sample](https://github.com/marco-c/rust-code-coverage-sample)

​	[source_based_code_coverage](https://doc.rust-lang.org/beta/unstable-book/compiler-flags/source-based-code-coverage.html#running-the-instrumented-binary-to-generate-raw-coverage-profiling-data)

​	[grcov](https://github.com/mozilla/grcov)

