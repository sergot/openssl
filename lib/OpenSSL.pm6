unit class OpenSSL;

use OpenSSL::SSL;
use OpenSSL::Bio;
use OpenSSL::Err;
use OpenSSL::EVP;

use NativeCall;

has OpenSSL::Ctx::SSL_CTX $.ctx;
has OpenSSL::SSL::SSL $.ssl;
has $.client;

has $.using-bio = False;
has $.bio-read-buf = buf8.new;
has $.net-write;
has $.net-read;

has $.net-bio;
has $.internal-bio;

method new(Bool :$client = False, Int :$version?) {

    # make a simple call to ensure libeay32.dll is loaded before ssleay32.dll (on windows)
    #
    # if we're using our bundled .dll files, and we try to load ssleay32.dll first, LoadLibrary
    # can't find the required libeay32.dll anywhere in the path, and so fails to load the dll
    OpenSSL::EVP::EVP_aes_128_cbc();

    OpenSSL::SSL::SSL_library_init();
    OpenSSL::SSL::SSL_load_error_strings();

    my $method;
    if $version.defined {
        given $version {
            when 2 {
                $method = ($client ?? OpenSSL::Method::SSLv2_client_method() !! OpenSSL::Method::SSLv2_server_method());
            }
            when 3 {
                $method = ($client ?? OpenSSL::Method::SSLv3_client_method() !! OpenSSL::Method::SSLv3_server_method());
            }
            default {
                $method = ($client ?? OpenSSL::Method::TLSv1_client_method() !! OpenSSL::Method::TLSv1_server_method());
            }
        }
    }
    else {
        $method = $client ?? OpenSSL::Method::TLSv1_client_method() !! OpenSSL::Method::TLSv1_server_method();
    }
    my $ctx     = OpenSSL::Ctx::SSL_CTX_new( $method );
    my $ssl     = OpenSSL::SSL::SSL_new( $ctx );

    self.bless(:$ctx, :$ssl, :$client);
}

method set-fd(int32 $fd) {
    OpenSSL::SSL::SSL_set_fd($!ssl, $fd);
}

method set-socket(IO::Socket $s) {
    # see http://wiki.openssl.org/index.php/Manual:BIO_s_bio(3)

    $!using-bio = True;
    my $n-ptr = CArray[OpaquePointer].new;
    $n-ptr[0] = OpaquePointer;
    my $i-ptr = CArray[OpaquePointer].new;
    $i-ptr[0] = OpaquePointer;

    my $ret = OpenSSL::Bio::BIO_new_bio_pair($n-ptr, 0, $i-ptr, 0);
    if $ret == 0 {
        my $e = OpenSSL::Err::ERR_get_error();
        say "err code: $e";
        say OpenSSL::Err::ERR_error_string($e);
    }
    $!net-bio = $n-ptr[0];
    $!internal-bio = $i-ptr[0];
    OpenSSL::SSL::SSL_set_bio($!ssl, $.internal-bio, $.internal-bio);

    $!net-write = -> $buf {
        $s.write($buf);
    }

    $!net-read = -> $n = Inf {
        $s.recv($n, :bin);
    }
    0;
}

method bio-write {
    # if we're handling the network in P6, dump everything we can
    if $.using-bio {
        my $cbuf = buf8.new;
        $cbuf[1024] = 0;
        while (my $len = OpenSSL::Bio::BIO_read($.net-bio, $cbuf, 1024)) > 0 {
            my $buf = $cbuf.subbuf(0, $len);
            $.net-write.($buf);
        }
    }
}
method bio-read {
    # if we're handling the network in P6, read everything we can
    my $read = 0;
    if $.using-bio {
        if $!bio-read-buf.bytes == 0 {
            $!bio-read-buf = $.net-read.();
        }
        $read = $!bio-read-buf.bytes;
        my $bytes = OpenSSL::Bio::BIO_write($.net-bio, $!bio-read-buf, $!bio-read-buf.bytes);
        $!bio-read-buf = $!bio-read-buf.subbuf($bytes);
    }
    return $read;
}
method handle-error($code) {
    my $e = OpenSSL::SSL::SSL_get_error($!ssl, $code);
    return 0 unless $e;
    my $try-recover = -1;
    if $e == 2 && $.using-bio { # SSL_ERROR_WANT_READ
        $.bio-write;
        my $read = $.bio-read;
        $try-recover = 1 if $read;
    } elsif $e == 3 && $.using-bio { # SSL_ERROR_WANT_WRITE
        $.bio-write;
        $try-recover = 1;
    } else {
        # we don't know what to do with it - pass the error up the stack
        $try-recover = -1;
    }

    $try-recover;
}

method set-connect-state {
    OpenSSL::SSL::SSL_set_connect_state($!ssl);
}

method set-accept-state {
    OpenSSL::SSL::SSL_set_accept_state($!ssl);
}

method connect {
    my $ret;

    loop {
        $ret = OpenSSL::SSL::SSL_connect($!ssl);

        my $e = $.handle-error($ret);
        last unless $e > 0;
    }

    $ret;
}

method accept {
    my $ret;

    loop {
        $ret = OpenSSL::SSL::SSL_accept($!ssl);

        my $e = $.handle-error($ret);
        last unless $e > 0;
    }

    $ret;
}

multi method write(Str $s) {
    $.write($s.encode);
}

multi method write(Blob $b) {
    my int32 $n = $b.bytes;
    my $ret;

    loop {
        $ret = OpenSSL::SSL::SSL_write($!ssl, $b, $n);

        my $e = $.handle-error($ret);
        last unless $e > 0;
    }

    $.bio-write;

    $ret;
}

method read(Int $n, Bool :$bin) {
    my int32 $count = $n;
    my $carray = buf8.new;
    $carray[$n-1] = 0;
    my $total-read = 0;
    my $buf = buf8.new;
    loop {
        my $read = OpenSSL::SSL::SSL_read($!ssl, $carray, $count - $total-read);

        $total-read += $read if $read > 0;
        $buf ~= $carray.subbuf(0, $read) if $read > 0;

        last if $total-read >= $n;

        my $e = 0;
        $e = $.handle-error($read) if $read < 0;
        last if $e <= 0 || $total-read >= $n;
    }

    return $bin ?? $buf !! $buf.decode('latin-1');
}

method use-certificate-file(Str $file) {
    # only PEM file so far : TODO : more file types
    if OpenSSL::Ctx::SSL_CTX_use_certificate_file($!ctx, $file, 1) <= 0 {
        die "Failed to set certificate file";
    }
}

method use-privatekey-file(Str $file) {
    # only PEM file so far : TODO : more file types
    if OpenSSL::Ctx::SSL_CTX_use_PrivateKey_file($!ctx, $file, 1) <= 0 {
        die "Failed to set PrivateKey file";
    }
}

method check-private-key {
    unless OpenSSL::Ctx::SSL_CTX_check_private_key($!ctx) {
        die "Private key does not match the public certificate";
    }
}

method shutdown {
    OpenSSL::SSL::SSL_shutdown($.ssl);
}

method ctx-free {
    OpenSSL::Ctx::SSL_CTX_free($!ctx);
}

method ssl-free {
    OpenSSL::SSL::SSL_free($!ssl);
    if $.using-bio {
        # $.internal-bio is freed by the SSL_free call
        OpenSSL::Bio::BIO_free($.net-bio);
    }
}

method close {
    until self.shutdown {};
    self.ssl-free;
    self.ctx-free;
    1;
}

=begin pod

=head1 NAME

OpenSSL - OpenSSL bindings

=head1 SYNOPSIS

    use OpenSSL;
    my $openssl = OpenSSL.new;
    $openssl.set-fd(123);
    $openssl.write("GET / HTTP/1.1\r\nHost: somehost\r\n\r\n");

=head1 DESCRIPTION

A module which provides OpenSSL bindings, making us able to set up a TLS/SSL connection.

=head1 METHODS

=head2 method new

    method new(Bool :$client = False, Int :$version?)

A constructor. Initializes OpenSSL library, sets method and context.

=head2 method set-fd

    method set-fd(OpenSSL:, int32 $fd)

Assings connection's file descriptor (file handle) $fd to the SSL object.

To get the $fd we should use C to set up the connection. (See L<NativeCall>)
I hope we will be able to use Perl 6's IO::Socket module instead of
connecting through C soon-ish.

=head2 method set-connect-state

    method set-connect-state(OpenSSL:)

Sets SSL object to connect (client) state.

Use it when you want to connect to SSL servers.

=head2 method set-accept-state

    method set-accept-state(OpenSSL:)

Sets SSL object to accept (server) state.

Use it when you want to provide an SSL server.

=head2 method connect

    method connect(OpenSSL:)

Connects to the server using $fd (passed using .set-fd).

Does all the SSL stuff like handshaking.

=head2 method accept

    method accept(OpenSSL:)

Accepts new client connection.

Does all the SSL stuff like handshaking.

=head2 method write

    method write(OpenSSL:, Str $s)

Sends $s to the other side (server/client).

=head2 method read

    method read(OpenSSL:, Int $n, Bool :$bin)

Reads $n bytes from the other side (server/client).

Bool :$bin if we want it to return Buf instead of Str.

=head2 method use-certificate-file

    method use-certificate-file(OpenSSL:, Str $file)

Assings a certificate (from file) to the SSL object.

=head2 method use-privatekey-file

    method use-privatekey-file(OpenSSL:, Str $file)

Assings a private key (from file) to the SSL object.

=head2 method check-private-key

    method check-private-key(OpenSSL:)

Checks if private key is valid.

=head2 method shutdown

    method shutdown(OpenSSL:)

Turns off the connection.

=head2 method ctx-free

    method ctx-free(OpenSSL:)

Frees C's SSL_CTX struct.

=head2 method ssl-free

    method ssl-free(OpenSSL:)

Frees C's SSL struct.

=head2 method close

    method close(OpenSSL:)

Closes the connection.

Unlike .shutdown it calls ssl-free, ctx-free, and then it shutdowns.

=head1 SEE ALSO

L<IO::Socket::SSL>

=end pod
