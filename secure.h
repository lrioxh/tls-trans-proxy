#ifndef _SECURE_H_
#define _SECURE_H_s

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h> 
#include <arpa/inet.h>

/*TLS configure*/
SSL_CTX *SSL_CTX_new_s(const SSL_METHOD *method);
int SSL_CTX_load_verify_locations_s(SSL_CTX *ctx, const char *CAfile, const char *CApath);
int SSL_CTX_use_certificate_file_s(SSL_CTX *ctx, const char *file, int type);
int SSL_CTX_use_PrivateKey_file_s(SSL_CTX *ctx, const char *file, int type);
int SSL_CTX_check_private_key_s(const SSL_CTX *ctx);
int SSL_CTX_set_ciphersuites_s(SSL_CTX *ctx, const char *str);

/*TLS connect*/
SSL *SSL_new_s(SSL_CTX *ctx);
int SSL_set_fd_s(SSL *s, int fd);
int SSL_accept_s(SSL *ssl);
int SSL_connect_s(SSL *ssl);
X509 *SSL_get1_peer_certificate_s(const SSL *s);
char *X509_NAME_oneline_s(const X509_NAME *a, char *buf, int size);

/*Socket*/
int socket_s(int domain, int type, int protocol);
int bind_s(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int listen_s(int sockfd, int backlog);
int accept_s(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int connect_s(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

/*IO*/
ssize_t read_s(int fildes, void *buf, size_t nbyte);
ssize_t write_s(int fildes, const void *buf, size_t nbyte);
int SSL_read_s(SSL *ssl, void *buf, int num);
int SSL_write_s(SSL *ssl, const void *buf, int num);


#endif
