unit module OpenSSL::Stack;

use NativeCall;
use OpenSSL::NativeLib;

class OpenSSL::Stack is repr('CStruct') {
    has int32 $.num;
    has CArray[CArray[uint8]] $.data;
    has int32 $.sorted;
    has int32 $.num_alloc;
    has Pointer $.comp;
}

our sub sk_num(OpenSSL::Stack) returns int32 is native(&gen-lib) { ... }
our sub sk_value(OpenSSL::Stack, int32) returns Pointer is native(&gen-lib) { ... }
our sub sk_free(OpenSSL::Stack) is native(&gen-lib) { ... }
