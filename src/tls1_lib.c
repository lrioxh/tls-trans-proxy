

#include "include/tls1_lib.h"

void print_public_key(X509 *cert)
{
    EVP_PKEY *pubkey = X509_get_pubkey(cert);
    if (pubkey)
    {
        switch (EVP_PKEY_id(pubkey))
        {
            case EVP_PKEY_RSA: {
                RSA *rsa = EVP_PKEY_get1_RSA(pubkey);
                if (rsa)
                {
                    printf("公钥(%d)\n", RSA_size(rsa));
                    RSA_print_fp(stdout, rsa, 0);
                }
                RSA_free(rsa);
                break;
            }
            default: printf("未知的公钥类型\n");
        }
        EVP_PKEY_free(pubkey);
    }
}

void print_subject_info(X509 *cert)
{
    X509_NAME *subject_name = X509_get_subject_name(cert);
    if (subject_name)
    {
        int nid;
        char buffer[256];

        // 打印通用名 (Common Name)
        nid = NID_commonName;
        X509_NAME_get_text_by_NID(subject_name, nid, buffer, sizeof(buffer));
        printf("通用名 (Common Name): %s\n", buffer);

        // 打印国家 (C)
        nid = NID_countryName;
        X509_NAME_get_text_by_NID(subject_name, nid, buffer, sizeof(buffer));
        printf("国家 (Country): %s\n", buffer);

        // 打印组织 (O)
        nid = NID_organizationName;
        X509_NAME_get_text_by_NID(subject_name, nid, buffer, sizeof(buffer));
        printf("组织 (Organization): %s\n", buffer);

        // 打印组织单位 (OU)
        nid = NID_organizationalUnitName;
        X509_NAME_get_text_by_NID(subject_name, nid, buffer, sizeof(buffer));
        printf("组织单位 (Organizational Unit): %s\n", buffer);

        // 打印邮箱地址 (Email)
        nid = NID_pkcs9_emailAddress;
        X509_NAME_get_text_by_NID(subject_name, nid, buffer, sizeof(buffer));
        printf("邮箱地址 (Email): %s\n", buffer);
    }
}

int aes128_decrypt(AES_KEY *aes, uint8_t *out, uint8_t *in, int len, uint8_t *key, uint8_t *iv)
{ // TODO:AES_set_*_key in get_keys; encrypt apart
    if (!in || !iv || !out || !key) return 0;
    // AES_KEY aes;
    uint8_t iv_cache[AES_BLOCK_SIZE] = {0};
    memmove(iv_cache, iv, AES_BLOCK_SIZE);
    if (AES_set_decrypt_key(key, AES_BITS_LEN, aes) < 0)
    {
        return 0;
    }
    AES_cbc_encrypt(in, out, len, aes, iv_cache, AES_DECRYPT);
    return 1;
}
int aes128_encrypt(AES_KEY *aes, uint8_t *out, uint8_t *in, int len, uint8_t *key, uint8_t *iv)
{
    if (!in || !iv || !out || !key) return 0;
    // AES_KEY aes;
    uint8_t iv_cache[AES_BLOCK_SIZE] = {0};
    memmove(iv_cache, iv, AES_BLOCK_SIZE);
    if (AES_set_encrypt_key(key, AES_BITS_LEN, aes) < 0)
    {
        return 0;
    }
    AES_cbc_encrypt(in, out, len, aes, iv_cache, AES_ENCRYPT);
    return 1;
}

uint8_t *sha_256(uint8_t *out, const uint8_t *d1, size_t n1, const uint8_t *d2, size_t n2)
{ // TODO: use SHA256_Update apart
    SHA256_CTX c;
    static uint8_t m[SHA256_DIGEST_LENGTH];

    if (out == NULL) out = m;
    SHA256_Init(&c);
    SHA256_Update(&c, d1, n1);
    SHA256_Update(&c, d2, n2);
    SHA256_Final(out, &c);
    OPENSSL_cleanse(&c, sizeof(c));
    return (out);
}

int hmac(EVP_MD *md, uint8_t *out, size_t *out_len, uint8_t *key, size_t key_len,
                uint8_t *in1, size_t in1_len, uint8_t *in2, size_t in2_len, uint8_t *in3,
                size_t in3_len, uint8_t *in4, size_t in4_len)
{ // calculate mac
    // TODO: use states->mac_client instead of ctx
    HMAC_CTX *ctx = HMAC_CTX_new();
    if (ctx == NULL || HMAC_Init_ex(ctx, key, key_len, md, NULL) <= 0 ||
        HMAC_Update(ctx, in1, in1_len) <= 0 || HMAC_Update(ctx, in2, in2_len) <= 0 ||
        HMAC_Update(ctx, in3, in3_len) <= 0 || HMAC_Update(ctx, in4, in4_len) <= 0 ||
        HMAC_Final(ctx, out, out_len) <= 0)
    {
        HMAC_CTX_free(ctx);
        return 0;
    }
    HMAC_CTX_free(ctx);
    return 1;
}
int EVP_digest_sign(EVP_MD *md, uint8_t *out, size_t *out_len, uint8_t *key, size_t key_len,
                           uint8_t *in1, size_t in1_len, uint8_t *in2, size_t in2_len, uint8_t *in3,
                           size_t in3_len)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_PKEY *mac_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, NULL, key, key_len);
    // EVP_DigestSignInit(ctx, NULL, md, NULL, mac_key);
    if (EVP_DigestSignInit(ctx, NULL, md, NULL, mac_key) <= 0 ||
        EVP_DigestSignUpdate(ctx, in1, in1_len) <= 0 ||
        EVP_DigestSignUpdate(ctx, in2, in2_len) <= 0 ||
        EVP_DigestSignUpdate(ctx, in3, in3_len) <= 0 || EVP_DigestSignFinal(ctx, out, out_len) <= 0)
    {
        EVP_PKEY_free(mac_key);
        EVP_MD_CTX_free(ctx);
        printf("mac error\n");
        return 0;
    }
    EVP_PKEY_free(mac_key);
    EVP_MD_CTX_free(ctx);
    return 1;
}
int EVP_digest_sign_ex(EVP_MD *md, uint8_t *out, size_t *out_len, uint8_t *key,
                              size_t key_len, uint8_t *in1, size_t in1_len, uint8_t *in2,
                              size_t in2_len, uint8_t *in3, size_t in3_len)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_PKEY *mac_key = EVP_PKEY_new_raw_private_key_ex(NULL, "HMAC", NULL, key, key_len);
    // EVP_PKEY *mac_key = EVP_PKEY_new_raw_private_key_ex(libctx, "HMAC", propq, key, key_len);
    // EVP_DigestSignInit(ctx, NULL, md, NULL, mac_key);
    // if (EVP_DigestSignInit_ex(ctx, NULL, EVP_MD_name(md), libctx, propq, mac_key, NULL) <= 0 ||
    if (EVP_DigestSignInit_ex(ctx, NULL, EVP_MD_name(md), NULL, NULL, mac_key, NULL) <= 0 ||
        EVP_DigestSignUpdate(ctx, in1, in1_len) <= 0 ||
        EVP_DigestSignUpdate(ctx, in2, in2_len) <= 0 ||
        EVP_DigestSignUpdate(ctx, in3, in3_len) <= 0 || EVP_DigestSignFinal(ctx, out, out_len) <= 0)
    {
        EVP_PKEY_free(mac_key);
        EVP_MD_CTX_free(ctx);
        printf("mac error\n");
        return 0;
    }
    EVP_PKEY_free(mac_key);
    EVP_MD_CTX_free(ctx);
    return 1;
}
int tls12_PRF(const EVP_MD *md, uint8_t *out, size_t out_len, const uint8_t *secret,
                     size_t secret_len, const uint8_t *label, size_t label_len,
                     const uint8_t *seed1, size_t seed1_len, const uint8_t *seed2, size_t seed2_len,
                     const uint8_t *seed3, size_t seed3_len)
{
    EVP_PKEY_CTX *pctx = NULL;
    int ret = 0;
    if (md == NULL)
    {
        return 0;
    }
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_TLS1_PRF, NULL);
    if (pctx == NULL || EVP_PKEY_derive_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_tls1_prf_md(pctx, md) <= 0 ||
        EVP_PKEY_CTX_set1_tls1_prf_secret(pctx, secret, (int)secret_len) <= 0 ||
        EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, label, (int)label_len) <= 0 ||
        EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed1, (int)seed1_len) <= 0 ||
        EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed2, (int)seed2_len) <= 0 ||
        EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed3, (int)seed3_len) <= 0 ||
        EVP_PKEY_derive(pctx, out, &out_len) <= 0)
    {
        goto err;
    }
    ret = 1;
err:
    EVP_PKEY_CTX_free(pctx);
    return ret;
}

SSL_CIPHER *get_cipher_by_id(uint16_t id){
    // int total=sk_SSL_CIPHER_num()
}