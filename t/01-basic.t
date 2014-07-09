use OpenSSL;
use Test;

plan 7;

my $ssl = OpenSSL.new(:version(3), :client);

isa_ok $ssl, OpenSSL, 'new 1/3';
is $ssl.ctx.method.version, 768, 'new 2/3';

$ssl = OpenSSL.new(:client);
is $ssl.ctx.method.version, 771, 'new 3/3';

ok $ssl.set-fd(1), 'set-fd';

$ssl.set-connect-state;
is $ssl.ssl.server, 0, 'set-accept-state';

ok $ssl.connect, 'connect';

ok $ssl.close, 'close';
