# spdm_crypto_mbedtls

This library wrapper mbedtls crypto interface for spdmlib.

## Mbedtls version

Tested mbedtls version is mbedtls-2.28.1

## Build

```
# build mbedtls library
pushd spdmlib_crypto_mbedtls/mbedtls
cp ../include/mbedtls/config.h ./include/mbedtls/
export CFLAGS="-I`pwd`/../include -nostdlibinc -isystem -ffunction-sections -fdata-sections -fPIE"
make lib -j${nproc}
popd

# test rust spdm_crypto_mbedtls library
pushd spdmlib_crypto_mbedtls
cargo build
cargo test
popd
```

## Build library for x86_64-unknown-none target

```
export CFLAGS="-I`pwd`/../include -nostdlibinc -isystem -ffunction-sections -fdata-sections --target=x86_64-unknown-windows-gnu -U_MSC_VER -U__MINGW32__"
make lib -j${nproc}
```

