### Gcov based coverage

**A GCC-compatible, gcov-based coverage implementation, enabled with -Z profile, which derives coverage data based on DebugInfo.**

  [profile environment](https://doc.rust-lang.org/nightly/unstable-book/compiler-flags/profile.html)

**Export the flags needed to instrument the program to collect code coverage, and the flags needed to work around**
**some Rust features that are incompatible with gcov-based instrumentation.**

1. Install the grcov:

   `cargo install grcov`

2. Installl the llvm-tools or llvm-tools-preview component:

   `rustup component add llvm-tools-preview`

3. Ensure that the following environment variable is set up:

  ```bash
  export CARGO_INCREMENTAL=0
  export RUSTDOCFLAGS="-Cpanic=abort"
  export RUSTFLAGS="-Zprofile -Ccodegen-units=1 -Copt-level=0 -Clink-dead-code -Coverflow-checks=off -Zpanic_abort_tests -Cpanic=abort"
  ```

4. Build your code:

   ```bash
   cd rust-sdpm
   cargo build -p spdm-responder-emu -p spdm-requester-emu
   ```

5. Run the program (you can replace this with `cargo test` if you want to collect code coverage for your tests).
  ```bash
  cargo run -p spdm-responder-emu & 
  cargo run -p spdm-requester-emu
  ```

6. Generate a HTML report in the coverage/ directory.
  ```bash
    grcov . -s . --binary-path ./target/debug/ -t html --branch --ignore-not-existing -o ./target/debug/gcov_coverage/
  ```

Reference:

​	[rust-code-coverage-sample](https://github.com/marco-c/rust-code-coverage-sample)

​	[source_based_code_coverage](https://doc.rust-lang.org/beta/unstable-book/compiler-flags/source-based-code-coverage.html#running-the-instrumented-binary-to-generate-raw-coverage-profiling-data)

​	[grcov](https://github.com/mozilla/grcov)