### fuzz crash view

If the reqcapability has a crash

`cargo  r -p reqcapability [--manifest-path reqcapability Cargo.toml path] --features analyze crash_file`

**Run in the rust-spdm path**

```
path/rust-spdm
cargo r -p reqcapability --manifest-path fuzz-target/requester/reqcapability/Cargo.toml --features analyze path/carsh_file

$cargo r -p reqcapability --manifest-path fuzz-target/requester/reqcapability/Cargo.toml --features analyze fuzz-target/out/reqcapability/default/crashes/id:000000,sig:06,src:000016+000021,time:600170,op:splice,rep:16
```

**Run in the crash crate**

```
path/rust-spdm/fuzz-target/requester/reqcapability
cargo r -p reqcapability --features analyze path/crash_file 

$cargo r -p reqcapability --features analyze ../../out/reqcapability/default/crashes/id:000000,sig:06,src:000016+000021,time:600170,op:splice,rep:16
```

