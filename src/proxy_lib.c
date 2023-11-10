
#include "include/prxoy_lib.h"

ProxyStates *initProxyStates(void)
{
    ProxyStates *states = (ProxyStates *)malloc(sizeof(ProxyStates));
    states->version = NULL;
    states->md = NULL;
    states->cert_proxy = NULL;
    states->cert_server = NULL;
    states->key_block = (KEY_block *)malloc(sizeof(KEY_block));
    // states->client_HS_buf = (uint8_t *)malloc(BUFSIZE * sizeof(char));
    // states->server_HS_buf = (uint8_t *)malloc(BUFSIZE * sizeof(char));

    // SHA256_Init(&states->ems_hash_client);
    // SHA256_Init(&states->ems_hash_server);
    SHA256_Init(&states->hs_hash_client);
    SHA256_Init(&states->hs_hash_server);
    SHA256_Init(&states->hs_hash_client_check);
    SHA256_Init(&states->hs_hash_server_check);
    // states->mac_client = HMAC_CTX_new();
    // states->mac_server = HMAC_CTX_new();
    // states->mac_client = EVP_MD_CTX_new();
    // states->mac_server = EVP_MD_CTX_new();

    return states;
}
void freeProxyStates(ProxyStates *states)
{
    // free(states->client_HS_buf);
    // free(states->server_HS_buf);
    free(states->key_block);
    X509_free(states->cert_proxy);
    X509_free(states->cert_server);
    RSA_free(states->rsa_priv_key);
    EVP_MD_free(states->md);

    OPENSSL_cleanse(&states->hs_hash_client, sizeof(SHA256_CTX));
    OPENSSL_cleanse(&states->hs_hash_server, sizeof(SHA256_CTX));
    OPENSSL_cleanse(&states->hs_hash_client_check, sizeof(SHA256_CTX));
    OPENSSL_cleanse(&states->hs_hash_server_check, sizeof(SHA256_CTX));
    // HMAC_CTX_free(states->mac_client);
    // HMAC_CTX_free(states->mac_server);
    // EVP_MD_CTX_free(states->mac_client);
    // EVP_MD_CTX_free(states->mac_client);

    free(states);
}

// proxy func
void hash_HS_before(ProxyStates *states, char *src, size_t len, char orient)
{
    if (orient == C2S)
    {
        // memmove(states->client_HS_buf + states->client_HS_len, src, len);
        // states->client_HS_len += len;
        SHA256_Update(&states->hs_hash_client, src, len);
        SHA256_Update(&states->hs_hash_client_check, src, len);
    }
    else
    {
        // memmove(states->server_HS_buf + states->server_HS_len, src, len);
        // states->server_HS_len += len;
        SHA256_Update(&states->hs_hash_server, src, len);
        SHA256_Update(&states->hs_hash_server_check, src, len);
    }
}

void hash_HS_after(ProxyStates *states, uint8_t *src, size_t len, char orient)
{
    if (orient == C2S)
    {
        // memmove(states->server_HS_buf + states->server_HS_len, src, len);
        // states->server_HS_len += len;
        SHA256_Update(&states->hs_hash_server, src, len);
        SHA256_Update(&states->hs_hash_server_check, src, len);
    }
    else
    {
        // memmove(states->client_HS_buf + states->client_HS_len, src, len);
        // states->client_HS_len += len;
        SHA256_Update(&states->hs_hash_client, src, len);
        SHA256_Update(&states->hs_hash_client_check, src, len);
    }
}

int loadCertFile(ProxyStates *states, const char *cert_path, const char *key_path)
{
    FILE *cert_file = NULL;
    BIO *bio = NULL; // 声明BIO结构体
    // 打开证书文件
    cert_file = fopen(cert_path, "rb");
    if (!cert_file)
    {
        fprintf(stderr, "无法打开证书文件\n");
        return 0;
    }
    // 读取证书
    states->cert_proxy = PEM_read_X509(cert_file, NULL, NULL, NULL);
    if (!states->cert_proxy)
    {
        fprintf(stderr, "无法解析证书\n");
        fclose(cert_file);
        return 0;
    }
    // print_subject_info(cert_proxy);
    bio = BIO_new_file(key_path, "rb");
    if (!bio)
    {
        fprintf(stderr, "无法打开私钥文件\n");
        return 0;
    }
    states->rsa_priv_key = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
    if (!states->rsa_priv_key)
    {
        fprintf(stderr, "无法解析私钥\n");

        BIO_free(bio);
        return 0;
    }
    BIO_free(bio);
    fclose(cert_file);
    return 1;
}

void praseClientHello(ProxyStates *states, uint8_t *buf, size_t len, char orient)
{
    // handshake type
    uint8_t *p = buf + TLS_HEAD_LEN;
    uint16_t cipher_suites_length = 2;
    // uint16_t start_pos = 3;
    uint8_t session_id_length = p[38];

    // 解析会话 ID(39+)
    if (session_id_length > 0)
    {
        printf(" Session ID: ");
        print_hex(p + 39, session_id_length);
        printf("\n");
    }
    // 解析随机数（7-38 字节）
    // if (orient == C2S)
    // {
    memmove(states->random_client, p + 6, SSL3_RANDOM_SIZE);
    cipher_suites_length = GET_2BYTE(p + 38 + session_id_length + 1);

    // 解析加密套件
    printf(" Cipher Suites: ");
    print_hex(p + 41 + session_id_length, cipher_suites_length);
    printf("\n");

    // 解析压缩算法
    uint8_t compression_methods_length = p[41 + session_id_length + cipher_suites_length];
    if (compression_methods_length > 0)
    {
        printf(" Compression Methods: ");
        print_hex(p + 41 + session_id_length + cipher_suites_length + 1,
                  compression_methods_length);
        printf("\n");
    }
}

void praseServerHello(ProxyStates *states, uint8_t *buf, size_t len, char orient)
{
    // handshake type
    uint8_t *p = buf + TLS_HEAD_LEN;
    uint16_t cipher_suites_length = 2;
    uint16_t start_pos = 1;
    uint8_t session_id_length = p[38];
    // 解析协议版本（5-6 字节）
    states->version = GET_2BYTE(p + 4);
    printf(" Protocol Version: ");
    print_hex((uint8_t *)&states->version, 2);
    printf("\n");

    // 解析会话 ID(39+)
    if (session_id_length > 0)
    {
        printf(" Session ID: ");
        print_hex(p + 39, session_id_length);
        printf("\n");
    }
    // 解析随机数（7-38 字节）
    memmove(states->random_server, p + 6, SSL3_RANDOM_SIZE);

    // 解析加密套件
    uint16_t cipher_suit = GET_2BYTE(p + 39 + session_id_length);
    // SSL_CIPHER *cipher=
    printf(" Cipher Suites: ");
    print_hex((uint8_t *)&cipher_suit, 2);
    printf("\n");
    states->md = EVP_sha256();

    // 解析压缩算法
    uint8_t compression_methods_length = p[39 + session_id_length + cipher_suites_length];
    if (compression_methods_length > 0)
    {
        printf(" Compression Methods: ");
        print_hex(p + 39 + session_id_length + cipher_suites_length + 1,
                  compression_methods_length);
        printf("\n");
    }
}

int exchangeCert(ProxyStates *states, char *buf, size_t len, size_t len_left)
{
    uint8_t *bytes_cert_server = buf + 15;
    // len-=15;
    int len_cert_server = len - 15;
    states->cert_server = d2i_X509(NULL, &bytes_cert_server, len_cert_server);

    // 获取证书的二进制比特流
    uint8_t *bytes_cert_proxy = NULL;
    int len_cert_proxy = i2d_X509(states->cert_proxy, &bytes_cert_proxy);
    if (len_cert_proxy > 0)
    {
        // print_hex(buf+15,len_cert_server);
        // copy to buf
        memmove(buf + 15 + len_cert_proxy, buf + 15 + len_cert_server, len_left + 1);
        memmove(buf + 15, bytes_cert_proxy, len_cert_proxy);
        // print_hex(buf+15,len_cert_proxy);

        // set buf lenth
        num_to_byte(len_cert_proxy, buf + 12, 3);
        num_to_byte(len_cert_proxy + 3, buf + 9, 3);
        num_to_byte(len_cert_proxy + 6, buf + 6, 3);
        num_to_byte(len_cert_proxy + 10, buf + 3, 2);

        OPENSSL_free(bytes_cert_proxy);
    }
    else
    {
        fprintf(stderr, "i2d_X509 调用失败\n");
    }
    return len_cert_proxy - len_cert_server;
}

int getKeyBlock(ProxyStates *states, char *buf, size_t len, size_t len_left, char orient)
{
    uint8_t *preMaster_en = buf + 11;
    int len_preMaster_en = len - 11;
    // RSA *rsa_prxyPriv = NULL; // 声明RSA结构体

    uint8_t preMaster_de[SSL3_MASTER_SECRET_SIZE] = {0};

    // 从文件中加载私钥
    // bio = BIO_new_file(states->proxy_pkey_path, "rb");
    // // states->rsa_priv_key = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
    // BIO_free(bio);
    int decryptedLength = RSA_private_decrypt(len_preMaster_en, preMaster_en, preMaster_de,
                                              states->rsa_priv_key, RSA_PKCS1_PADDING);

    if (decryptedLength == -1)
    {
        // 解密失败
        printf("解密失败\n");
    }
    else
    {
        // 解密成功
        printf("pms: ");
        print_hex(preMaster_de, SSL3_MASTER_SECRET_SIZE);
        printf("\n");
        // hash_HS_before(states, buf + TLS_HEAD_LEN, len - TLS_HEAD_LEN, orient);

        // uint8_t *encryptedData = NULL;
        // encryptedData = (uint8_t *)malloc(RSA_2048_SIZE);
        uint8_t encryptedData[RSA_2048_SIZE] = {0};

        // 计算PRF
        tls12_PRF(states->md, states->master_secret, SSL3_MASTER_SECRET_SIZE, preMaster_de,
                  SSL3_MASTER_SECRET_SIZE, TLS_MD_MASTER_SECRET_CONST,
                  TLS_MD_MASTER_SECRET_CONST_SIZE, states->random_client, SSL3_RANDOM_SIZE,
                  states->random_server, SSL3_RANDOM_SIZE, NULL, 0);
        tls12_PRF(states->md, (uint8_t *)(states->key_block), sizeof(KEY_block),
                  states->master_secret, SSL3_MASTER_SECRET_SIZE, TLS_MD_KEY_EXPANSION_CONST,
                  TLS_MD_KEY_EXPANSION_CONST_SIZE, states->random_server, SSL3_RANDOM_SIZE,
                  states->random_client, SSL3_RANDOM_SIZE, NULL, 0);
        // printf("randoms:\n");
        // print_hex(random_client, 32);
        // printf("\n");
        // print_hex(random_server, 32);
        // printf("\n");
        printf("keys:\n");
        print_hex(states->master_secret, 48);
        printf("\n");
        print_hex(states->key_block->client_write_key, 16);
        printf("\n");
        print_hex(states->key_block->client_write_MAC_key, 32);
        printf("\n");
        // AES_set_decrypt_key(states->key_block->client_write_key, AES_BITS_LEN,
        // &states->aes_client); AES_set_decrypt_key(states->key_block->server_write_key,
        // AES_BITS_LEN, &states->aes_server);
        //  HMAC_Init_ex(states->mac_client,
        // states->key_block->client_write_MAC_key,
        //              SHA256_DIGEST_LENGTH, states->md, NULL);
        // HMAC_Init_ex(states->mac_server, states->key_block->server_write_MAC_key,
        //              SHA256_DIGEST_LENGTH, states->md, NULL);
        // in cipher spec
        // EVP_PKEY *mac_key = EVP_PKEY_new_raw_private_key(
        //     EVP_PKEY_HMAC, NULL, states->key_block->client_write_MAC_key, 32);
        // EVP_DigestSignInit(states->mac_client, NULL, states->md, NULL, mac_key);
        // mac_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, NULL,
        //                                        states->key_block->client_write_MAC_key, 32);
        // EVP_DigestSignInit(states->mac_server, NULL, states->md, NULL, mac_key);

        // recrypt pms to server
        EVP_PKEY *pubKey = X509_get_pubkey(states->cert_server);
        RSA *rsa_servPub = EVP_PKEY_get1_RSA(pubKey);
        int encryptedLength = RSA_public_encrypt(SSL3_MASTER_SECRET_SIZE, preMaster_de,
                                                 encryptedData, rsa_servPub, RSA_PKCS1_PADDING);

        RSA_free(rsa_servPub);
        EVP_PKEY_free(pubKey);
        if (encryptedLength != len_preMaster_en)
        {
            memmove(buf + 11 + encryptedLength, buf + len, len_left);
        }
        memmove(buf + 11, encryptedData, encryptedLength);

        // hash_HS_after(states, buf + TLS_HEAD_LEN, len - TLS_HEAD_LEN, orient);
        // free(encryptedData);
        return encryptedLength - len_preMaster_en;
    }
}

int reFinish(ProxyStates *states, uint8_t *buf, size_t len, char orient)
{
    // const EVP_MD *md = EVP_sha256();
    // size_t mac_len = len - TLS_HEAD_LEN - AES_BLOCK_SIZE;
    // size_t verify_len = 12;
    uint8_t finish[SHA256_DIGEST_LENGTH] = {0};
    uint8_t recved_finish[SHA256_DIGEST_LENGTH] = {0};
    uint8_t sha[SHA256_DIGEST_LENGTH] = {0};
    uint8_t mac_head[13] = {0};
    uint8_t mac[SHA256_DIGEST_LENGTH] = {0};
    uint8_t encrypted_finish[SHA256_DIGEST_LENGTH] = {0};
    // uint8_t *recved_finish = (uint8_t *)malloc(len - TLS_HEAD_LEN - AES_BLOCK_SIZE);
    uint8_t *iv = buf + TLS_HEAD_LEN;

    num_to_byte(SSL3_MT_FINISHED, finish, 1);
    num_to_byte(TLS1_FINISH_MAC_LENGTH, finish + 1, 3);
    num_to_byte(0, mac_head, RC_SEQ_LEN);
    gen_TLS_head(SSL3_RT_HANDSHAKE, states->version, AES_BLOCK_SIZE*3, mac_head + 8);
    gen_padding(15, finish + AES_BLOCK_SIZE);

    if (orient == C2S)
    {
        aes128_decrypt(&states->aes_cache, recved_finish, iv + AES_BLOCK_SIZE, SHA256_DIGEST_LENGTH,
                       states->key_block->client_write_key, iv);
        print_hex(recved_finish, SHA256_DIGEST_LENGTH);
        printf("\n");
        SHA256_Final(sha, &states->hs_hash_client_check);
        tls12_PRF(states->md, finish + HS_HEAD_LEN, TLS1_FINISH_MAC_LENGTH, states->master_secret,
                  SSL3_MASTER_SECRET_SIZE, TLS_MD_CLIENT_FINISH_CONST,
                  TLS_MD_CLIENT_FINISH_CONST_SIZE, sha, SHA256_DIGEST_LENGTH, NULL, 0, NULL, 0);
        print_hex(finish, SHA256_DIGEST_LENGTH);
        printf("\n");

        SHA256_Final(sha, &states->hs_hash_server);
        tls12_PRF(states->md, finish + HS_HEAD_LEN, TLS1_FINISH_MAC_LENGTH, states->master_secret,
                  SSL3_MASTER_SECRET_SIZE, TLS_MD_CLIENT_FINISH_CONST,
                  TLS_MD_CLIENT_FINISH_CONST_SIZE, sha, SHA256_DIGEST_LENGTH, NULL, 0, NULL, 0);

        aes128_encrypt(&states->aes_cache, encrypted_finish, finish, SHA256_DIGEST_LENGTH,
                       states->key_block->client_write_key, iv);
        // print_hex(encrypted_finish, SHA256_DIGEST_LENGTH);
        // printf("\n");
        hmac(states->md, mac, NULL, states->key_block->client_write_MAC_key, SHA256_DIGEST_LENGTH,
             mac_head, sizeof(mac_head), iv, AES_BLOCK_SIZE, encrypted_finish, SHA256_DIGEST_LENGTH,
             NULL, 0);
    }
    else
    {
        aes128_decrypt(&states->aes_cache, recved_finish, iv + AES_BLOCK_SIZE, SHA256_DIGEST_LENGTH,
                       states->key_block->server_write_key, iv);
        print_hex(recved_finish, SHA256_DIGEST_LENGTH);
        printf("\n");
        SHA256_Final(sha, &states->hs_hash_server_check);
        tls12_PRF(states->md, finish + HS_HEAD_LEN, TLS1_FINISH_MAC_LENGTH, states->master_secret,
                  SSL3_MASTER_SECRET_SIZE, TLS_MD_SERVER_FINISH_CONST,
                  TLS_MD_SERVER_FINISH_CONST_SIZE, sha, SHA256_DIGEST_LENGTH, NULL, 0, NULL, 0);
        print_hex(finish, SHA256_DIGEST_LENGTH);
        printf("\n");

        SHA256_Final(sha, &states->hs_hash_client);
        tls12_PRF(states->md, finish + HS_HEAD_LEN, TLS1_FINISH_MAC_LENGTH, states->master_secret,
                  SSL3_MASTER_SECRET_SIZE, TLS_MD_SERVER_FINISH_CONST,
                  TLS_MD_SERVER_FINISH_CONST_SIZE, sha, SHA256_DIGEST_LENGTH, NULL, 0, NULL, 0);
        // print_hex(finish, SHA256_DIGEST_LENGTH);
        // printf("\n");
        aes128_encrypt(&states->aes_cache, encrypted_finish, finish, SHA256_DIGEST_LENGTH,
                       states->key_block->server_write_key, iv);
        hmac(states->md, mac, NULL, states->key_block->server_write_MAC_key, SHA256_DIGEST_LENGTH,
             mac_head, sizeof(mac_head), iv, AES_BLOCK_SIZE, encrypted_finish, SHA256_DIGEST_LENGTH,
             NULL, 0);
    }

    // print_hex(buf + TLS_HEAD_LEN, 16); // iv
    // printf("\n");
    // print_hex(buf + TLS_HEAD_LEN + AES_BLOCK_SIZE, len - TLS_HEAD_LEN - AES_BLOCK_SIZE);
    // printf("\n");
    print_hex(finish, 32);
    printf("\n");
    print_hex(mac, SHA256_DIGEST_LENGTH);
    printf("\n");

    memmove(buf + TLS_HEAD_LEN + AES_BLOCK_SIZE, encrypted_finish, SHA256_DIGEST_LENGTH);
    memmove(buf + TLS_HEAD_LEN + AES_BLOCK_SIZE + SHA256_DIGEST_LENGTH, mac, SHA256_DIGEST_LENGTH);

    hash_HS_before(states, recved_finish, AES_BLOCK_SIZE, orient);
    hash_HS_after(states, finish, AES_BLOCK_SIZE, orient);

    // free(recved_finish);
}

// int newSessionTicketExchange(ProxyStates *states, uint8_t *buf, size_t len, size_t len_left,
//                              char orient)
// {
//     size_t lenPlaintext = len - 5 - 4 - 64 - 6;
//     uint8_t *statePlaintext = (uint8_t *)malloc(lenPlaintext);
//     uint8_t cache[160] = {0};
//     aes128_decrypt(&states->aes_server, buf + TLS_HEAD_LEN + HS_HEAD_LEN + 32 + 6,
//     statePlaintext,
//                    lenPlaintext, states->key_block->server_write_key, buf + 5 + 4 + 6 + 16);
//     for (size_t i = 128; i > 32; i -= 16)
//     {
//         aes128_decrypt(&states->aes_server, buf + (len - i), cache, i - 32,
//                        states->key_block->server_write_key, buf + 5 + 4 + 6 + 16);
//         print_hex(buf + (len - 128), i - 32);
//         printf("\n");
//         print_hex(cache, i - 32);
//         printf("\n");
//     }
//     // print_hex(buf + TLS_HEAD_LEN + HS_HEAD_LEN + 32 + 6, lenPlaintext);
//     // printf("\n");
//     // print_hex(statePlaintext, lenPlaintext);
//     // printf("\n");

//     free(statePlaintext);
// }
int deApplication(ProxyStates *states, uint8_t *buf, size_t len, char orient)
{
    uint8_t *iv = buf + TLS_HEAD_LEN;
    size_t data_len = len - TLS_HEAD_LEN - AES_BLOCK_SIZE;
    uint8_t *de_data = (uint8_t *)malloc(data_len);
    if (orient == C2S)
    {
        aes128_decrypt(&states->aes_cache, de_data, iv + AES_BLOCK_SIZE, data_len,
                       states->key_block->client_write_key, iv);
    }
    else
    {
        aes128_decrypt(&states->aes_cache, de_data, iv + AES_BLOCK_SIZE, data_len,
                       states->key_block->server_write_key, iv);
    }
    print_hex(de_data, data_len);
    printf("\n");
    uint8_t padding_len = *(de_data + data_len - SHA256_DIGEST_LENGTH - 1) + 1;
    printf("plaintext: ");
    print_char(de_data, data_len - SHA256_DIGEST_LENGTH - padding_len);
    printf("\n");
    
}
int handleMsg(ProxyStates *states, char *buf, size_t len, char orient)
{
    uint8_t *p = NULL;
    size_t i = 0;
    char finished = 0;
    uint8_t content_type = 0;
    uint16_t content_lenth = 0;
    int diff = 0;
    while (i < len)
    {
        p = buf + i;
        content_type = p[0];
        content_lenth = GET_2BYTE(p + 3) + TLS_HEAD_LEN;

        if (content_type == SSL3_RT_HANDSHAKE)
        { // Handshake message
            // ommit
            if (p[TLS_HEAD_LEN] == SSL3_MT_HELLO_REQUEST)
            {
                printf("Hello Request\n");
                goto nextContent;
            }
            else if (p[TLS_HEAD_LEN] == SSL3_MT_FINISHED || finished == SSL3_MT_FINISHED)
            {
                printf("Finished\n");
                reFinish(states, p, content_lenth, orient);
                finished = 0;
                // hash_HS_after(states, p + TLS_HEAD_LEN, content_lenth - TLS_HEAD_LEN - 32,
                // orient);
                goto nextContent;
            }

            hash_HS_before(states, p + TLS_HEAD_LEN, content_lenth - TLS_HEAD_LEN, orient);

            if (p[TLS_HEAD_LEN] == SSL3_MT_CLIENT_KEY_EXCHANGE)
            {
                printf("Client Key Exchange:\n");
                diff = getKeyBlock(states, p, content_lenth, len - i - content_lenth, orient);

                content_lenth += diff;
                len += diff;
                // goto nextContent;
            }
            // plaintext
            // hash_HS_before(states, p + TLS_HEAD_LEN, content_lenth - TLS_HEAD_LEN, orient);
            else if (p[TLS_HEAD_LEN] == SSL3_MT_CLIENT_HELLO)
            { // Client Hello
                printf("Client Hello:\n");
                praseClientHello(states, p, content_lenth, orient);
            }
            else if (p[TLS_HEAD_LEN] == SSL3_MT_SERVER_HELLO)
            { // Server Hello
                printf("Server Hello:\n");
                praseServerHello(states, p, content_lenth, orient);
            }
            else if (p[TLS_HEAD_LEN] == SSL3_MT_NEWSESSION_TICKET)
            {
                printf("New Session Ticket:\n");
                // newSessionTicketExchange(states, p, content_lenth, len - i - content_lenth,
                // orient);
            }
            else if (p[TLS_HEAD_LEN] == SSL3_MT_CERTIFICATE)
            {
                printf("Certificate:\n");

                diff = exchangeCert(states, p, content_lenth, len - i - content_lenth);
                content_lenth += diff;
                len += diff;
            }
            else if (p[TLS_HEAD_LEN] == SSL3_MT_SERVER_KEY_EXCHANGE)
            {
                printf("Server Key Exchange:\n");
            }
            else if (p[TLS_HEAD_LEN] == SSL3_MT_CERTIFICATE_REQUEST)
            {
                printf("Certificate Request:\n");
            }
            else if (p[TLS_HEAD_LEN] == SSL3_MT_SERVER_DONE)
            {
                printf("Server Hello Done:\n");
            }
            else if (p[TLS_HEAD_LEN] == SSL3_MT_CERTIFICATE_VERIFY)
            {
                printf("Certificate Verify:\n");
            }

            hash_HS_after(states, p + TLS_HEAD_LEN, content_lenth - TLS_HEAD_LEN, orient);
        }
        else if (content_type == SSL3_RT_CHANGE_CIPHER_SPEC)
        {
            printf("ChangeCipherSpec\n");
            finished = 20;
        }
        else if (content_type == SSL3_RT_ALERT)
        {
            printf("Alert\n");
        }
        else if (content_type == SSL3_RT_APPLICATION_DATA)
        {
            printf("Application\n");
            deApplication(states, p, content_lenth, orient);
        }
    nextContent:
        i += content_lenth;
    }
    return len;
}

int reHandshake(ProxyStates *states)
{
    SHA256_Init(&states->hs_hash_client);
    SHA256_Init(&states->hs_hash_server);
    SHA256_Init(&states->hs_hash_client_check);
    SHA256_Init(&states->hs_hash_server_check);
}
