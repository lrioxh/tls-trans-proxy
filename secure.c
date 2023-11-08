#include "secure.h"

/*
 *TLS configure
 */
SSL_CTX *SSL_CTX_new_s(const SSL_METHOD *method){
    SSL_CTX *ctx = SSL_CTX_new(method);
    /*错误信息输出到标准输出，需要调用SSL_load_error_strings()*/
    if (ctx == NULL){
        perror("SSL_CTX_new failed\n");
        ERR_print_errors_fp(stderr); 
        exit(1);
    }
    return ctx;
}

int SSL_CTX_load_verify_locations_s(SSL_CTX *ctx, const char *CAfile, const char *CApath){
    if (SSL_CTX_load_verify_locations(ctx, CAfile, CApath) == 0) {
        perror("SSL_CTX_load_verify_locations failed\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    return 1;
}

int SSL_CTX_use_certificate_file_s(SSL_CTX *ctx, const char *file, int type){
    if (SSL_CTX_use_certificate_file(ctx, file, type) != 1) {
        perror("SSL_CTX_use_certificate_file failed\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    return 1;
}

int SSL_CTX_use_PrivateKey_file_s(SSL_CTX *ctx, const char *file, int type){
    if (SSL_CTX_use_PrivateKey_file(ctx, file, type) != 1) {
        perror("SSL_CTX_use_PrivateKey_file failed\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    return 1;
}

int SSL_CTX_check_private_key_s(const SSL_CTX *ctx){
    if (SSL_CTX_check_private_key(ctx) != 1) {
        perror("SSL_CTX_check_private_key failed\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    return 1;
}

int SSL_CTX_set_ciphersuites_s(SSL_CTX *ctx, const char *str){
    if (SSL_CTX_set_ciphersuites(ctx, str) != 1) {
        perror("SSL_CTX_set_ciphersuites failed\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }
}

/*
 *TLS connect
 */
SSL *SSL_new_s(SSL_CTX *ctx){
    SSL* ssl = SSL_new(ctx);
    if (ssl == NULL) {
        perror("SSL_new failed\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    return ssl;
}

int SSL_set_fd_s(SSL *s, int fd){
    if (SSL_set_fd(s, fd) == 0) {
        perror("SSL_set_fd failed\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    return 1;
}

int SSL_accept_s(SSL *ssl){
    if (SSL_accept(ssl) != 1) {
        perror("SSL_accept failed\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    return 1;
}

int SSL_connect_s(SSL *ssl){
    if(SSL_connect(ssl) == 0){
        perror("SSL_connect failed\n");
        ERR_print_errors_fp(stderr); 
        exit(1);
    }
    return 1;
}

X509 *SSL_get1_peer_certificate_s(const SSL *s){
    X509* cert = SSL_get1_peer_certificate(s);
    if (cert == NULL) {
        perror("SSL_get1_peer_certificate_s failed\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    return cert;
}

char *X509_NAME_oneline_s(const X509_NAME *a, char *buf, int size){
    char *str = X509_NAME_oneline(a, buf, size);
    if (str == NULL) {
        perror("X509_NAME_oneline_s failed\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    return str;
}

/*
 *Socket
 */
int socket_s(int domain, int type, int protocol){
    int fd = socket(domain, type, protocol);
    if (fd == -1) {
        perror("socket failed\n");
        exit(1);
    }
    return fd;
}

int bind_s(int sockfd, const struct sockaddr *addr, socklen_t addrlen){
    if (bind(sockfd, addr, addrlen) == -1) {
        perror("bind failed\n");
        exit(1);
    }
}

int listen_s(int sockfd, int backlog){
    if (listen(sockfd, backlog) == -1) {
        perror("listen failed\n");
        exit(1);
    }
}

int accept_s(int sockfd, struct sockaddr *addr, socklen_t *addrlen){
    int fd = accept(sockfd, addr, addrlen);
    if (fd == -1) {
        perror("accept failed\n");
        exit(1);
    }
    return fd;
}

int connect_s(int sockfd, const struct sockaddr *addr, socklen_t addrlen){
    int ret = connect(sockfd, addr, addrlen);
    if(ret == -1){
        perror("connect error");
        exit(1);
    }
    return ret;
}


/*IO*/
ssize_t read_s(int fildes, void *buf, size_t nbyte){
    ssize_t ret = read(fildes, buf, nbyte);
    if(ret == -1){
        perror("read error\n");
        exit(1);
    }
    return ret;
}

ssize_t write_s(int fildes, const void *buf, size_t nbyte){
    if (write(fildes, buf, nbyte) == -1) {
        perror("write error\n");
        exit(1);
    }
    return 1;
}

int SSL_read_s(SSL *ssl, void *buf, int num){
    int ret = SSL_read(ssl, buf, num);
    if (ret == -1) {
        perror("SSL_read error\n");
        exit(1);
    }
    return ret;
}

int SSL_write_s(SSL *ssl, const void *buf, int num){
    if (SSL_write(ssl, buf, num) == -1) {
        perror("SSL_write error\n");
        exit(1);
    }
    return 1;
}
