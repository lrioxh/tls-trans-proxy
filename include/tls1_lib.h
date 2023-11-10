#ifndef _TLS1_LIB_H_
#define _TLS1_LIB_H_


#include <openssl/ssl.h>
#include <openssl/kdf.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

#define RSA_2048_SIZE 256
#define AES_BITS_LEN 128
#define TLS_HEAD_LEN 5
#define HS_HEAD_LEN 4
#define RC_SEQ_LEN 8

void print_public_key(X509 *cert);
void print_subject_info(X509 *cert);
int aes128_decrypt(AES_KEY *aes, uint8_t *out, uint8_t *in, int len, uint8_t *key, uint8_t *iv);
int aes128_encrypt(AES_KEY *aes, uint8_t *out, uint8_t *in, int len, uint8_t *key, uint8_t *iv);
uint8_t *sha_256(uint8_t *out, const uint8_t *d1, size_t n1, const uint8_t *d2, size_t n2);
int hmac(EVP_MD *md, uint8_t *out, size_t *out_len, uint8_t *key, size_t key_len,
                uint8_t *in1, size_t in1_len, uint8_t *in2, size_t in2_len, uint8_t *in3,
                size_t in3_len, uint8_t *in4, size_t in4_len);
int EVP_digest_sign(EVP_MD *md, uint8_t *out, size_t *out_len, uint8_t *key, size_t key_len,
                           uint8_t *in1, size_t in1_len, uint8_t *in2, size_t in2_len, uint8_t *in3,
                           size_t in3_len);
int EVP_digest_sign_ex(EVP_MD *md, uint8_t *out, size_t *out_len, uint8_t *key,
                              size_t key_len, uint8_t *in1, size_t in1_len, uint8_t *in2,
                              size_t in2_len, uint8_t *in3, size_t in3_len);
int tls12_PRF(const EVP_MD *md, uint8_t *out, size_t out_len, const uint8_t *secret,
                     size_t secret_len, const uint8_t *label, size_t label_len,
                     const uint8_t *seed1, size_t seed1_len, const uint8_t *seed2, size_t seed2_len,
                     const uint8_t *seed3, size_t seed3_len);


#endif