#ifndef _RROXY_LIB_H_
#define _PROXY_LIB_H_


#include "include/utils.h"
#include "include/tls1_lib.h"

//orient
#define C2S (1)
#define S2C (-1)
#define GET_2BYTE(buf) (((buf)[0] << 8) | (buf)[1])
#define GET_3BYTE(buf) (((buf)[0] << 16) | ((buf)[1] << 8) | (buf)[2])

typedef struct key_block_st
{
    uint8_t client_write_MAC_key[SHA256_DIGEST_LENGTH];
    uint8_t server_write_MAC_key[SHA256_DIGEST_LENGTH];
    uint8_t client_write_key[AES_BLOCK_SIZE];
    uint8_t server_write_key[AES_BLOCK_SIZE];
    // uint8_t client_write_IV[AES_BLOCK_SIZE];
    // uint8_t server_write_IV[AES_BLOCK_SIZE];
} KEY_block;

typedef struct proxy_states_st
{
    EVP_MD *md;
    X509 *cert_proxy;
    X509 *cert_server;
    RSA *rsa_priv_key;
    KEY_block *key_block;
    // uint8_t *client_HS_buf;
    // uint8_t *server_HS_buf;
    // size_t client_HS_len;
    // size_t server_HS_len;
    uint8_t random_server[SSL3_RANDOM_SIZE];
    uint8_t random_client[SSL3_RANDOM_SIZE];
    uint8_t master_secret[SSL3_MASTER_SECRET_SIZE];

    //ems
    // KEY_block *key_block_s;
    // uint8_t master_secret_s[SSL3_MASTER_SECRET_SIZE];
    // SHA256_CTX ems_hash_client;
    // SHA256_CTX ems_hash_server;

    // HMAC_CTX *mac_client;
    // HMAC_CTX *mac_server;
    // EVP_MD_CTX *mac_client;
    // EVP_MD_CTX *mac_server;
    SHA256_CTX hs_hash_client;
    SHA256_CTX hs_hash_server;
    SHA256_CTX hs_hash_client_check;
    SHA256_CTX hs_hash_server_check;
    AES_KEY aes_cache;

    uint16_t version;
    uint16_t ems ; /*0: no ems, 1: active ems*/
    SSL_CIPHER *cipher;


} ProxyStates;

ProxyStates *initProxyStates(void);
void freeProxyStates(ProxyStates *states);
void hash_HS_before(ProxyStates *states, char *src, size_t len, char orient);
void hash_HS_after(ProxyStates *states, uint8_t *src, size_t len, char orient);
int loadCertFile(ProxyStates *states, const char *cert_path, const char *key_path);
void praseHandshake(ProxyStates *states, uint8_t *buf, size_t len, char orient);
int exchangeCert(ProxyStates *states, char *buf, size_t len, size_t len_left);
int getKeyBlock(ProxyStates *states, char *buf, size_t len, size_t len_left, char orient);
int reFinish(ProxyStates *states, uint8_t *buf, size_t len, char orient);
int deApplication(ProxyStates *states, uint8_t *buf, size_t len, char orient);
int handleMsg(ProxyStates *states, char *buf, size_t len, char orient);
int reHandshake(ProxyStates *states);

#endif