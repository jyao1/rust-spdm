# rust fuzzing

## Setup

### Requirements

### Tools

- C compiler (e.g. gcc or clang)
- make

### Platform

afl.rs works on x86-64 Linux and x86-64 macOS.

`cargo install afl`

### Upgrading

`cargo install --force afl`

### Provide starting inputs

```
mkdir in 
echo "1234567890" > in/input1
echo "abcdef" > in/input2
```

### Build the fuzz target

## example Build rspversion

`cargo afl build`

### Start fuzzing

`cargo afl fuzz -i fuzz-target/in -o fuzz-target/outrspversion target/debug/rspversion`

As soon as you run this command, you should see AFL’s interface start up:

![image-20210628084437384](fuzz-target/fuzz1.png)

### view coverage 

If you need to check coverage, follow the coverage.md operation, View multiple fuzz coverage results.

    ```
    RUSTFLAGS="-Zinstrument-coverage" cargo afl build -p rspversion
    LLVM_PROFILE_FILE="rspversion.profraw" cargo afl fuzz -i fuzz-target/in -o fuzz-target/outrspversion target/debug/rspversion
    llvm-profdata merge -sparse rspversion.profraw -o rspversion.profdata
    llvm-cov export -Xdemangler=rustfilt fuzz-target/responder/rspversion/target/debug/rspversion --instr-profile=total.profdata --format=lcov > rspversion.info

    RUSTFLAGS="-Zinstrument-coverage" cargo afl build -p rspcapability
    LLVM_PROFILE_FILE="rspcapability.profraw" cargo afl fuzz -i fuzz-target/in -o fuzz-target/outrspcapability target/debug/rspcapability
    llvm-profdata merge -sparse rspcapability.profraw -o rspcapability.profdata
    llvm-cov export -Xdemangler=rustfilt fuzz-target/responder/rspversion/target/debug/rspcapability --instr-profile=total.profdata --format=lcov > rspcapability.info

    grcov . -s . --binary-path ./target/debug/ -t html --branch --ignore-not-existing -o ./target/debug/coverage/
    ```

### reference

[Rust Fuzz Book](https://rust-fuzz.github.io/book/afl/setup.html)