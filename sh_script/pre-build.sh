#!/bin/bash

format-patch() {
    # apply the patch set for ring
    pushd external/ring
    git reset --hard 9cc0d45f4d8521f467bb3a621e74b1535e118188
    git clean -xdf
    git apply ../patches/ring/0001-Support-x86_64-unknown-none-target.patch
    popd
    
    # apply the patch set for webpki
    pushd external/webpki
    git reset --hard 0b7cbf2d327d7665d9d06072bf46b2e7ca05f065
    git clean -xdf
    git apply ../patches/webpki/0001-Add-support-for-verifying-certificate-chain-with-EKU.patch
    popd
}

format-patch
