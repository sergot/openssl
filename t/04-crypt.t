use v6;
use Test;

plan 5;

use OpenSSL::CryptTools;

ok 1, 'can load module';

my $ciphertext = encrypt("asdf".encode, :aes256, :iv(("0" x 16).encode), :key(('x' x 32).encode));
ok $ciphertext, 'can encrypt';
ok $ciphertext ne "asdf".encode, 'encrypt changes data';

my $plaintext = decrypt($ciphertext, :aes256, :iv(("0" x 16).encode), :key(('x' x 32).encode));
ok $plaintext, 'can decrypt';
is $plaintext, "asdf".encode, 'decrypt gets correct data';
