use OpenSSL;
use Test;

plan 3;

my $ssl = OpenSSL.new(:version(3));

isa_ok $ssl, OpenSSL, 'new 1/3';
is $ssl.ctx.method.version, 768, 'new 2/3';

$ssl = OpenSSL.new;
is $ssl.ctx.method.version, 771, 'new 3/3';
