#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>


#include "openssl/crypto.h"
#include "openssl/ssl.h"
#include "openssl/err.h"

#include "iflfortls.h"
#include "iflfortls_common.h"

SSL_CTX *create_context()
{
    SSL_CTX *ctx;

    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        printf("SSL ctx new failed\n");
        return NULL;
    }

    printf("SSL context created\n");

    if (SSL_CTX_use_certificate_file(ctx, SERVER_CERT_FILE, SSL_FILETYPE_PEM) != 1) {
        printf("Load Server cert %s failed\n", SERVER_CERT_FILE);
        goto err;
    }

    printf("Loaded server cert %s on context\n", SERVER_CERT_FILE);

    if (SSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY_FILE, SSL_FILETYPE_ASN1) != 1) {
        printf("Load Server key %s failed\n", SERVER_KEY_FILE);
        goto err;
    }

    printf("Loaded server key %s on context\n", SERVER_KEY_FILE);

    SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_3);
    printf("SSL context configurations completed\n");

    return ctx;
err:
    SSL_CTX_free(ctx);
    return NULL;
}

void log_bin(char *buf, int buf_len, const char *txt)
{
    int i;
    printf("[%s]", txt);
    for (i = 0; i < buf_len; i++) {
        printf(" %x", buf[i] & 0xFF);
    }
    printf("\n");
}

int read_cb(BIO *bio, char *buf, int buf_len)
{
    int fd = -1;
    int ret;
    BIO_get_fd(bio, &fd);
    if (fd >= 0) {
        ret = recv(fd, buf, buf_len, 0);
        log_bin(buf, ret, "READ_CB");
        return ret;
    }
    printf("read_cb: Invalid fd\n");
    return -1;
}

int register_sock_cb(SSL *ssl, int fd)
{
    const BIO_METHOD *bmeth_orig;
    BIO_METHOD *bmeth;
    BIO *bio;
    bmeth_orig = BIO_s_socket();
    bmeth = BIO_meth_new(BIO_TYPE_SOCKET, "TCP_socket");
    if (!bmeth_orig || !bmeth) {
        printf("BIO meth creation failed\n");
        return -1;
    }
    BIO_meth_set_write(bmeth, BIO_meth_get_write(bmeth_orig));
    BIO_meth_set_read(bmeth, read_cb);
    BIO_meth_set_ctrl(bmeth, BIO_meth_get_ctrl(bmeth_orig));
    BIO_meth_set_create(bmeth, BIO_meth_get_create(bmeth_orig));
    BIO_meth_set_puts(bmeth, BIO_meth_get_puts(bmeth_orig));
    BIO_meth_set_destroy(bmeth, BIO_meth_get_destroy(bmeth_orig));

    bio = BIO_new(bmeth);
    if (!bio) {
        printf("BIO new failed\n");
        goto err;
    }
    BIO_set_fd(bio, fd, BIO_NOCLOSE);
    SSL_set_bio(ssl, bio, bio);
    printf("BIO callback set successfully\n");
    return 0;
err:
    BIO_meth_free(bmeth);
    return -1;
}

SSL *create_ssl_object(SSL_CTX *ctx, int lfd)
{
    SSL *ssl;
    EC_KEY *ecdh;
    int fd;

    fd = do_tcp_accept(lfd);
    if (fd < 0) {
        printf("TCP connection establishment failed\n");
        return NULL;
    }

    ssl = SSL_new(ctx);
    if (!ssl) {
        printf("SSL object creation failed\n");
        return NULL;
    }

    SSL_set_fd(ssl, fd);
    if (register_sock_cb(ssl, fd)) {
        printf("Registering sock cb failed\n");
        goto err;
    }

    ecdh = EC_KEY_new_by_curve_name(EC_CURVE_NAME);
    if (!ecdh) {
        printf("ECDH generation failed\n");
        goto err;
    }

    SSL_set_tmp_ecdh(ssl, ecdh);
    EC_KEY_free(ecdh);
    ecdh = NULL;

    printf("SSL object creation finished\n");

    return ssl;
err:
    SSL_free(ssl);
    return NULL;
}

#define MAX_MKEY_SIZE 2048

int do_tls_connection(SSL_CTX *ctx, int lfd)
{
    SSL *ssl = NULL;
    SSL_SESSION *ssl_session;
    int fd;
    int ret;
    unsigned char *mkey;
    size_t mkey_size;
    int i;

    ssl = create_ssl_object(ctx, lfd);
    if (!ssl) {
        goto err;
    }

    fd = SSL_get_fd(ssl);

    ret = SSL_accept(ssl); 
    if (ret != 1) {
        printf("SSL accept failed%d\n", ret);
        goto err;
    }

    ssl_session = SSL_get_session(ssl);
    mkey_size = SSL_SESSION_get_master_key(ssl_session, NULL, 0);
    printf("Master key size=%zu\n", mkey_size);
    if (mkey_size < MAX_MKEY_SIZE) {
        mkey = malloc(mkey_size);
    }
    if (!mkey) {
        printf("Master buf not allocated\n");
        goto err;
    }
    SSL_SESSION_get_master_key(ssl_session, mkey, mkey_size);
    for (i = 0; i < mkey_size; i++) {
        printf("%x ", mkey[i]);
    }
    printf("\n");
    free(mkey);
    mkey = NULL;

    printf("SSL accept succeeded\n");
    SSL_free(ssl);
    CLOSE_FD(fd);

    return 0;
err:
    printf("ERR: %s\n", ERR_func_error_string(ERR_get_error()));
    if (ssl) {
        SSL_free(ssl);
    }
    CLOSE_FD(fd);
    return -1;
}

int tls12_server()
{
    SSL_CTX *ctx;
    int lfd;

    ctx = create_context();
    if (!ctx) {
        return -1;
    }

    lfd = do_tcp_listen(SERVER_IP, SERVER_PORT);
    if (lfd < 0) {
        printf("TCP listen socket creation failed\n");
        goto err;
    }

    do {
        if (do_tls_connection(ctx, lfd)) {
            printf("TLS connection failed\n\n\n");
        } else {
            printf("TLS connection SUCCEEDED\n\n\n");
        }
    } while(1);

    CLOSE_FD(lfd);
    SSL_CTX_free(ctx);
    return 0;
err:
    CLOSE_FD(lfd);
    return -1;
}

int main()
{
    printf("\nOpenSSL version: %s, %s\n", OpenSSL_version(OPENSSL_VERSION), OpenSSL_version(OPENSSL_BUILT_ON));
    if (tls12_server()) {
        printf("TLS12 server connection failed\n");
    }
}

