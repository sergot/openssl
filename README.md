OpenSSL [![Build Status](https://travis-ci.org/sergot/openssl.svg?branch=master)](https://travis-ci.org/sergot/openssl) [![Build status](https://ci.appveyor.com/api/projects/status/ck9w128qd34rylu2/branch/master?svg=true)](https://ci.appveyor.com/project/skinkade/openssl/branch/master)
=======

OpenSSL bindings for Perl 6

## OpenSSL

Socket connection class. You probably want to use IO::Socket::SSL instead of this
(low-level) interface.

    use OpenSSL;

    my $ssl = OpenSSL.new(:version(3), :client);
    my $s = IO::Socket::INET.new(:$host, :port(443));
    $ssl.set-socket($s);
    $ssl.set-connect-state;
    $ssl.connect
    # $ssl.write, etc

## OpenSSL::RSATools

Public key signing tools

    use OpenSSL::RSATools;

    my $pem = slurp 'key.pem';
    my $rsa = OpenSSL::RSAKey.new(private-pem => $pem);
    my $data = 'as df jk l';
    my $signature = $rsa.sign($data.encode);
    my $rsa = OpenSSL::RSAKey.new(public-pem => $public);
    if $rsa.verify($data.encode, $signature) { ... }

## OpenSSL::CryptTools

Symmetric encryption tools (currently only AES256/192/128 encrypt/decrypt)

    use OpenSSL::CryptTools;

    my $ciphertext = encrypt("asdf".encode,
                             :aes256,
                             :iv(("0" x 16).encode),
                             :key(('x' x 32).encode));
    my $plaintext = decrypt($ciphertext,
                            :aes256,
                            :iv(("0" x 16).encode),
                            :key(('x' x 32).encode));

## OpenSSL::Digest

Digest Functions (currently only md5/sha1/sha256)

    use OpenSSL::Digest;
    my Blob $digest = md5("xyz".encode);
