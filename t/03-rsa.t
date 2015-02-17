use v6;
use Test;

plan 4;

use OpenSSL::RSATools;

my $pem = slurp 't/key.pem';

my $rsa = OpenSSL::RSAKey.new(private-pem => $pem);
ok $rsa, 'Can create RSAKey object from pem encoded private key';

my $data = 'as df jk l';

my $signature = $rsa.sign($data.encode);
ok $signature ~~ Blob && $signature.bytes, 'Signed data using RSAKey';

ok $rsa.verify($data.encode, $signature), 'Can verify correctly';
ok !$rsa.verify("asdf".encode, $signature), 'verify fails on different data';
