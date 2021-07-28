rm -rf ./target

# Export the flags needed to instrument the program to collect code coverage, and the flags needed to work around
# some Rust features that are incompatible with gcov-based instrumentation.
export CARGO_INCREMENTAL=0
export RUSTDOCFLAGS="-Cpanic=abort"
export RUSTFLAGS="-Zprofile -Ccodegen-units=1 -Copt-level=0 -Clink-dead-code -Coverflow-checks=off -Zpanic_abort_tests -Cpanic=abort"

# Build the program
 Build your code:

   ```bash
   cd rust-sdpm
   cargo run -p spdm-responder-emu & cargo run -p spdm-requester-emu
   ```

# Run the program (you can replace this with `cargo test` if you want to collect code coverage for your tests).
cargo test

# Generate a HTML report in the coverage/ directory.
grcov . --llvm -s . -t html --branch --ignore-not-existing -o ./coverage/

