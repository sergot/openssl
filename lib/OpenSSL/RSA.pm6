module OpenSSL::RSA;

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

our sub RSA_sign(int32, Blob, int32, Blob, CArray, OpaquePointer --> int32) is native($lib) { ... }
our sub RSA_verify(int32, Blob, int32, Blob, int32, OpaquePointer --> int32) is native($lib) { ... }

our sub RSA_size(OpaquePointer --> int32) is native($lib) { ... }
our sub RSA_free(OpaquePointer) is native($lib) { ... }
