unit module OpenSSL::Err;

use OpenSSL::NativeLib;
use NativeCall;

our sub ERR_error_string(int32 $e, Str $ret) returns Str is native(&gen-lib) { ... };

our sub ERR_get_error() returns ulonglong is native(&gen-lib) { ... };
