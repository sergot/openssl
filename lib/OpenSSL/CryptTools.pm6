use OpenSSL::EVP;
use NativeCall;

module OpenSSL::CryptTools;

our sub encrypt(Blob $plaintext, :$key, :$iv, :$aes256!) is export {
    my $ctx = OpenSSL::EVP::EVP_CIPHER_CTX_new();

    my $cipher = OpenSSL::EVP::EVP_aes_256_cbc();
    if $key.bytes != 256/8 {
        die "Key is not 256 bits";
    }
    if $iv.bytes != 128/8 {
        die "Key is not 128 bits";
    }
    # way bigger than needed
    my $bufsize = $plaintext.bytes * 2;
    $bufsize = 64 if $bufsize < 64;

    OpenSSL::EVP::EVP_EncryptInit($ctx, $cipher, $key, $iv);

    my $part = buf8.new;
    $part[$bufsize] = 0;
    my $partsize = CArray[int32].new;
    $partsize[0] = $bufsize;
    OpenSSL::EVP::EVP_EncryptUpdate($ctx, $part, $partsize, $plaintext, $plaintext.bytes);

    my $out = $part.subbuf(0, $partsize[0]);
    $partsize[0] = $bufsize;

    OpenSSL::EVP::EVP_EncryptFinal($ctx, $part, $partsize);
    $out ~= $part.subbuf(0, $partsize[0]);

    OpenSSL::EVP::EVP_CIPHER_CTX_free($ctx);

    return $out;
}

our sub decrypt(Blob $ciphertext, :$key, :$iv, :$aes256!) is export {
    my $ctx = OpenSSL::EVP::EVP_CIPHER_CTX_new();

    my $cipher = OpenSSL::EVP::EVP_aes_256_cbc();
    if $key.bytes != 256/8 {
        die "Key is not 256 bits";
    }
    if $iv.bytes != 128/8 {
        die "Key is not 128 bits";
    }
    # way bigger than needed
    my $bufsize = $ciphertext.bytes * 2;
    $bufsize = 64 if $bufsize < 64;

    OpenSSL::EVP::EVP_DecryptInit($ctx, $cipher, $key, $iv);

    my $part = buf8.new;
    $part[$bufsize] = 0;
    my $partsize = CArray[int32].new;
    $partsize[0] = $bufsize;
    OpenSSL::EVP::EVP_DecryptUpdate($ctx, $part, $partsize, $ciphertext, $ciphertext.bytes);

    my $out = $part.subbuf(0, $partsize[0]);
    $partsize[0] = $bufsize;

    OpenSSL::EVP::EVP_DecryptFinal($ctx, $part, $partsize);
    $out ~= $part.subbuf(0, $partsize[0]);

    OpenSSL::EVP::EVP_CIPHER_CTX_free($ctx);

    return $out;
}
