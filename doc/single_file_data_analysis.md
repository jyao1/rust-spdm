### Analyze a piece of data to run

If you have some data to test

```
if args.len() < 2 {
    // Here you can replace the single-step debugging value in the fuzzdata array.
    let fuzzdata = [1, 26, 0, 1, 0, 0, 0, 128, 0, 0, 2, 0, 0, 4, 128, 0, 0, 2, 11, 4, 128, 0, 0, 2, 0, 246, 255, 10, 128, 0, 0, 11, 4, 0, 0, 0];
    fuzz_send_receive_spdm_version(&fuzzdata);
} 
```

`cargo  r -p package`

### Analyze the contents of a file as input

If some data is written in the file

```
let args: Vec<String> = std::env::args().collect();
if args.len() < 2 {

} else {
    let path = &args[1];
    let data = std::fs::read(path).expect("read crash file fail");
    fuzz_send_receive_spdm_version(data.as_slice());
}
```
`cargo r -p package -- file_address`
