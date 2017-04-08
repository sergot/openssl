use OpenSSL::NativeLib;
use NativeCall;

unit module OpenSSL::Digest;

our constant MD5_DIGEST_LENGTH    = 16;
our constant SHA1_DIGEST_LENGTH   = 20;
our constant SHA256_DIGEST_LENGTH = 32;

sub MD5( Blob, size_t, Blob ) is native(&gen-lib)    { ... }
sub SHA1( Blob, size_t, Blob ) is native(&gen-lib)   { ... }
sub SHA256( Blob, size_t, Blob ) is native(&gen-lib) { ... }

sub md5(Blob $msg) is export {
     my $digest = buf8.allocate(MD5_DIGEST_LENGTH);
     MD5($msg, $msg.bytes, $digest);
     $digest;
}

sub sha1(Blob $msg) is export {
     my $digest = buf8.allocate(SHA1_DIGEST_LENGTH);
     SHA1($msg, $msg.bytes, $digest);
     $digest;
}

sub sha256(Blob $msg) is export {
     my $digest = buf8.allocate(SHA256_DIGEST_LENGTH);
     SHA256($msg, $msg.bytes, $digest);
     $digest;
}

