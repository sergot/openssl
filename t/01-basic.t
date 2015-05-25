use OpenSSL;
use Test;

plan 9;

my $ssl = OpenSSL.new(:version(3), :client);

isa-ok $ssl, OpenSSL, 'new 1/3';
is $ssl.ctx.method.version, 768, 'new 2/3';

$ssl = OpenSSL.new(:client);
is $ssl.ctx.method.version, 769, 'new 3/3';

# wrong fd here
ok $ssl.set-fd(111), 'set-fd';

$ssl.set-connect-state;
is $ssl.ssl.server, 0, 'set-accept-state';

ok $ssl.connect, 'connect';

ok $ssl.write("GET / HTTP/1.1\r\n\r\n"), 'write';

ok $ssl.read(1) == 0, 'read';

ok $ssl.close, 'close';
