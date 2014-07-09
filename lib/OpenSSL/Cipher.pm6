module OpenSSL::Cipher;

use NativeCall;

class SSL_CIPHER is repr('CStruct') {
    has int32 $.valid;
    has Str $.name;
    has int $.id;

    has int $.algorithm_mkey;
    has int $.algorithm_auth;
    has int $.algorithm_enc;
    has int $.algorithm_mac;
    has int $.algorithm_ssl;

    has int $.algo_strength;
    has int $.algorithm2;
    has int32 $.strength_bits;
    has int32 $.alg_bits;
}

