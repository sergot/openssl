module OpenSSL;

use NativeCall;

class BIO_METHOD is repr('CStruct') {
    has int32 $.type;
    has Str $.name;
}

class BIO is repr('CStruct') {
    has BIO_METHOD $.method;
    # some functions ?
    has Str $.cb_arg;

    has int32 $.init;
    has int32 $.shutdown;
    has int32 $.flags;
    has int32 $.retry_reason;
    has int32 $.num;
    has OpaquePointer $.ptr;

    has BIO $.next_bio;
    has BIO $.prev_bio;

    has int32 $.references;
    has int $.num_read;
    has int $.num_write;

    # ex_data ?
}

class SSL_METHOD is repr('CStruct') {
    has int32 $.version;
}

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

class SSL_SESSION is repr('CStruct') {
    has int32 $.ssl_version;
}

class SSL_CTX is repr('CStruct') {
    has SSL_METHOD $.method;
}

class SSL is repr('CStruct') {
    has int32 $.version;
    has int32 $.type;

    has SSL_METHOD $.method;

    has BIO $.rbio;
    has BIO $.wbio;
    has BIO $.bbio;

    has int32 $.rwstate;

    has int32 $.in_handshake;

    # function
    has OpaquePointer $.handshake_func;

    has int32 $.server;

    has int32 $.new_session;

    has int32 $.quiet_shutdown;
    has int32 $.shutdown;

    has int32 $.state;
    has int32 $.rstate;
}

# init funcs
our sub SSL_library_init() is native('libssl')                                 { * }
our sub SSL_load_error_strings() is native('libssl')                           { * }

# method funcs
our sub SSLv2_client_method() returns SSL_METHOD is native('libssl')           { * }
our sub SSLv2_server_method() returns SSL_METHOD is native('libssl')           { * }
our sub SSLv2_method() returns SSL_METHOD is native('libssl')                  { * }
our sub SSLv3_client_method() returns SSL_METHOD is native('libssl')           { * }
our sub SSLv3_server_method() returns SSL_METHOD is native('libssl')           { * }
our sub SSLv3_method() returns SSL_METHOD is native('libssl')                  { * }
our sub SSLv23_client_method() returns SSL_METHOD is native('libssl')          { * }
our sub SSLv23_server_method() returns SSL_METHOD is native('libssl')          { * }
our sub SSLv23_method() returns SSL_METHOD is native('libssl')                 { * }

# ctx funcs
our sub SSL_CTX_new(SSL_METHOD) returns SSL_CTX is native('libssl')            { * }
our sub SSL_CTX_free(SSL_CTX) is native('libssl')                              { * }

# ssl funcs
our sub SSL_new(SSL_CTX) returns SSL is native('libssl')                       { * }
our sub SSL_set_fd(SSL, int32) returns int32 is native('libssl')               { * }
our sub SSL_shutdown(SSL) returns int32 is native('libssl')                    { * }
our sub SSL_free(SSL) is native('libssl')                                      { * }
our sub SSL_get_error(SSL, int32) returns int32 is native('libssl')            { * }
our sub SSL_accept(SSL) returns int32 is native('libssl')                      { * }
our sub SSL_connect(SSL) returns int32 is native('libssl')                     { * }
our sub SSL_read(SSL, CArray[uint8], int32) returns int32 is native('libssl')  { * }
our sub SSL_write(SSL, CArray[uint8], int32) returns int32 is native('libssl') { * }
our sub SSL_set_connect_state(SSL) is native('libssl')                         { * }
our sub SSL_set_accept_state(SSL) is native('libssl')                          { * }
