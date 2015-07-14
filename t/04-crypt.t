use v6;
use Test;

plan 6;

use OpenSSL::CryptTools;

ok 1, 'can load module';

my $ciphertext = encrypt("asdf".encode, :aes256, :iv(("0" x 16).encode), :key(('x' x 32).encode));
ok $ciphertext, 'can encrypt';
ok $ciphertext ne "asdf".encode, 'encrypt changes data';

my $plaintext = decrypt($ciphertext, :aes256, :iv(("0" x 16).encode), :key(('x' x 32).encode));
ok $plaintext, 'can decrypt';
is $plaintext, "asdf".encode, 'decrypt gets correct data';

# AES Test Vector
my $key = pack("H*", "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
my $test = pack("H*", "f69f2445df4f9b17ad2b417be66c3710");
my $iv = pack("H*", "39F23369A9D9BACFA530E26304231461");

$ciphertext = encrypt($test, :aes256, :$iv, :$key);
my $expected = $ciphertext.unpack("H*").substr(0,32); # remove padding
ok  "b2eb05e2c39be9fcda6c19078c6a9d1b" eq $expected, "got expected";
