#!/usr/bin/env perl6

use v6.c;

use Test;

use OpenSSL;

my $ssl = OpenSSL.new(:client);

my $sock = IO::Socket::INET.new(host => 'api.soundcloud.com', port => 443);

is $ssl.set-socket($sock), 0, 'set-socket success';
$ssl.set-connect-state;
is $ssl.connect, 1, 'connect success';
ok $ssl.write("GET / HTTP/1.1\r\nHost: api.soundcloud.com\r\nConnection:close\r\n\r\n"), 'write success';
ok $ssl.read(1024).chars, "and got some data back";


done-testing;
# vim: expandtab shiftwidth=4 ft=perl6
