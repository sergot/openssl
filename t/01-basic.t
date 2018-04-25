use OpenSSL;
use Test;

plan 9;

my $ssl = OpenSSL.new(:version(1), :client);

isa-ok $ssl, OpenSSL, 'new 1/3';
is $ssl.ctx.method.version, 0x301, 'new 2/3';

$ssl = OpenSSL.new(:client);
# On OpenSSL 1.1.0, we have TLS_client_method which returns the special
# value 0x10000. Older OpenSSL use SSLv23_client_method() whose .version
# is equal to the highest one available.
   try { OpenSSL::Method::TLS_client_method()     } ?? is $ssl.ctx.method.version, 0x10000, 'new 3/3'
!! try { OpenSSL::Method::TLSv1_2_client_method() } ?? is $ssl.ctx.method.version, 0x00303, 'new 3/3'
!! try { OpenSSL::Method::TLSv1_1_client_method() } ?? is $ssl.ctx.method.version, 0x00302, 'new 3/3'
!! try { OpenSSL::Method::TLSv1_client_method()   } ?? is $ssl.ctx.method.version, 0x00301, 'new 3/3'
!! flunk 'new 3/3';

# wrong fd here
ok $ssl.set-fd(111), 'set-fd';

$ssl.set-connect-state;
is $ssl.ssl.server, 0, 'set-accept-state';

ok $ssl.connect, 'connect';

ok $ssl.write("GET / HTTP/1.1\r\n\r\n"), 'write';

ok $ssl.read(1) == 0, 'read';

ok $ssl.close, 'close';
