module OpenSSL::EVP;

my Str $lib;
BEGIN {
    if $*VM.config<dll> ~~ /dll/ {
        # we're on windows, different library name
        $lib = 'libeay32.dll';
    } else {
        $lib = 'libssl';
    }
}

use NativeCall;

our sub EVP_PKEY_get1_RSA(OpaquePointer --> OpaquePointer) is native($lib) { ... }
our sub EVP_PKEY_free(OpaquePointer) is native($lib) { ... }

our sub EVP_CIPHER_CTX_new(--> OpaquePointer) is native($lib) { ... }
our sub EVP_CIPHER_CTX_free(OpaquePointer) is native($lib) { ... }

our sub EVP_EncryptInit(OpaquePointer, OpaquePointer, Blob, Blob --> int32) is native($lib) { ... }
our sub EVP_EncryptUpdate(OpaquePointer, Blob, CArray[int32], Blob, int32 --> int32) is native($lib) { ... }
our sub EVP_EncryptFinal(OpaquePointer, Blob, CArray[int32] --> int32) is native($lib) { ... }

our sub EVP_DecryptInit(OpaquePointer, OpaquePointer, Blob, Blob --> int32) is native($lib) { ... }
our sub EVP_DecryptUpdate(OpaquePointer, Blob, CArray[int32], Blob, int32 --> int32) is native($lib) { ... }
our sub EVP_DecryptFinal(OpaquePointer, Blob, CArray[int32] --> int32) is native($lib) { ... }

# ciphers
our sub EVP_aes_128_cbc( --> OpaquePointer) is native($lib) { ... }
our sub EVP_aes_192_cbc( --> OpaquePointer) is native($lib) { ... }
our sub EVP_aes_256_cbc( --> OpaquePointer) is native($lib) { ... }
