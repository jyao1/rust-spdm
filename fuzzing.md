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

`cargo afl build`

### Start fuzzing

`cargo afl fuzz -i in -o out target/debug/rspversion target/debug/capability target/debug/algorithm `

As soon as you run this command, you should see AFL’s interface start up:

![image-20210628084437384](fuzz-target/fuzz1.png)

### reference

[Rust Fuzz Book](https://rust-fuzz.github.io/book/afl/setup.html)