use OpenSSL;
use Test;

plan 1;

my $ssl = OpenSSL.new;
isa_ok $ssl, OpenSSL, 'new';
