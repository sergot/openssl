use OpenSSL;
use Test;

plan 4;

my $ssl = OpenSSL.new(:version(3), :client);
my $s = IO::Socket::INET.new(:host('google.com'), :port(443));
is $ssl.set-socket($s), 0, 'set-socket success';
$ssl.set-connect-state;
is $ssl.connect, 1, 'connect success';
is $ssl.write("GET / HTTP/1.1\r\nHost:www.google.com\r\nConnection:close\r\n\r\n"), 57, 'write success';

#slurp it all up
my $result = '';
loop {
    my $tmp = $ssl.read(1024);
    if $tmp.chars {
        $result ~= $tmp;
    } else {
        last;
    }
}

$ssl.close;
$s.close;

ok $result ~~ /200 \s+ OK/, 'Got good response';