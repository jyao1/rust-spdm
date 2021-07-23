### fuzz crash view

If the reqcapability has a crash

`cargo  r -p reqcapability [--manifest-path reqcapability Cargo.toml path] --features analysis crash_file`

**Run in the rust-spdm path**

```
path/rust-spdm
cargo r -p reqcapability --manifest-path fuzz-target/requester/reqcapability/Cargo.toml --features analysis path/carsh_file

$cargo r -p reqcapability --manifest-path fuzz-target/requester/reqcapability/Cargo.toml --features analysis fuzz-target/out/reqcapability/default/crashes/id:000000,sig:06,src:000016+000021,time:600170,op:splice,rep:16
```

**Run in the crash crate**

```
path/rust-spdm/fuzz-target/requester/reqcapability
cargo r -p reqcapability --features analysis path/crash_file 

$cargo r -p reqcapability --features analysis ../../out/reqcapability/default/crashes/id:000000,sig:06,src:000016+000021,time:600170,op:splice,rep:16
```

