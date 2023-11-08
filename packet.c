#include "packet.h"
#include "secure.h"

void print_hex(char *label, unsigned char *data, int len){
    printf("%s:", label);
    int i;
    for(i=0;i<len;i++){
        printf("%02X", data[i]);
    }
    printf("\n");
}

void get_hex_length3(unsigned char new_len[], int number, int cert_len){
    new_len[0] = (number >> 8) & 0xFF;
    new_len[1] = number & 0xFF;
    number -= 4;
    new_len[2] = 11 & 0xFF;
    new_len[3] = (number >> 16) & 0xFF;
    new_len[4] = (number >> 8) & 0xFF;
    new_len[5] = number & 0xFF;
    number -= 3;
    new_len[6] = (number >> 16) & 0xFF;
    new_len[7] = (number >> 8) & 0xFF;
    new_len[8] = number & 0xFF;
    new_len[9] = (cert_len >> 16) & 0xFF;
    new_len[10] = (cert_len >> 8) & 0xFF;
    new_len[11] = cert_len & 0xFF;
}

/*获取客户端握手报文的随机数，并将握手报文转发给服务器*/
void clienthellomsg(struct SecParams *sec_params, struct HandshakeRecord *Handsha_rec, int clientfd, int serverfd){
    unsigned char buf[BUFSIZ];
    int j, ret = read_s(clientfd, buf, BUFSIZ);
    memcpy(sec_params->client_random, buf + 11, 32);
    memcpy(Handsha_rec->clihello, buf, ret);
    printf("client random : ");
    for(j = 0; j < 32; j++){
        printf("%02X", sec_params->client_random[j]);
    }
    printf("\n");
    Handsha_rec->clilen = ret;
    write_s(serverfd, buf, ret);
}

void cert_replace(struct SecParams *sec_params, struct HandshakeRecord *Handsha_rec, struct Certificate *cert, int clientfd, int len[]){
    unsigned char buf[BUFSIZ];
    X509 *Xcert = NULL;
    FILE *key_file  = fopen(AGENT_CERTIFICATE, "rb");
    OpenSSL_add_all_algorithms();
    Xcert = PEM_read_X509(key_file, NULL, NULL, NULL);
    unsigned char *certData = NULL;
    int certLength = i2d_X509(Xcert, &certData);     //代理证书的长度
    int new_certlen = len[1] + certLength - len[2]; //替换证书后的报文长度

    unsigned char new_len[12];
    get_hex_length3(new_len, new_certlen, certLength);
    memcpy(buf, Handsha_rec->serverhello, len[0]);
    memcpy(buf + len[0], new_len, 12);
    memcpy(buf + len[0] + 12, certData, certLength);
    memcpy(buf + len[0] + 12 + certLength, Handsha_rec->serverhello + len[0] + 12 + len[2], Handsha_rec->serlen - len[0] - 12 - len[2]); 

    memcpy(Handsha_rec->new_serhello, buf, Handsha_rec->serlen + certLength - len[2]);
    Handsha_rec->new_serlen = Handsha_rec->serlen + certLength - len[2];

    if(len[3] == 1)
        write_s(clientfd, buf, Handsha_rec->new_serlen); //替换证书后发送给客户端
}


/*提取serverhello报文的随机数，并将握手报文和证书转发给客户端*/
void serverhellomsg(struct SecParams *sec_params, struct HandshakeRecord *Handsha_rec, struct Certificate *cert, int clientfd, int serverfd){
    unsigned char buf[BUFSIZ];
    int i, ret = read_s(serverfd, buf, sizeof(buf));
    memcpy(sec_params->server_random, buf + 11, 32);
    memcpy(Handsha_rec->serverhello, buf, ret);
    Handsha_rec->serlen = ret;

    printf("server random : ");
    for(i = 0; i < 32; i++){
        printf("%02X", sec_params->server_random[i]);
    }
    printf("\n");

    int record_len[4];
    uint16_t serhello_len = (buf[3] << 8) | buf[4];

    Handsha_rec->no_head_serlen = serhello_len;
    Handsha_rec->no_head_oldserlen = serhello_len;
    memcpy(Handsha_rec->no_head_serhello, buf + 5, serhello_len);
    memcpy(Handsha_rec->no_head_oldser, buf + 5, serhello_len);

    serhello_len += 5;
    uint16_t all_cert_len = (buf[serhello_len + 3] << 8) | buf[serhello_len + 4];
    record_len[0] = serhello_len + 3;    //serverhello总报文长度 + 证书报文头3字节
    record_len[1] = all_cert_len;        //证书总长度
    record_len[2] = (buf[serhello_len + 12] << 16) | (buf[serhello_len + 13] << 8) | buf[serhello_len + 14]; //服务器证书的长度
    record_len[3] = 1; //这里第四个数代表着报文是否发送过去，之后把变量整合到结构体中会删除

    cert->pkey_len = record_len[2];

    /*原来的serverhello报文，用于计算客户端的verify-data*/
    
    memcpy(Handsha_rec->no_head_oldser + Handsha_rec->no_head_oldserlen, buf + serhello_len + 5, all_cert_len);
    Handsha_rec->no_head_oldserlen += all_cert_len;
    int done_len = (buf[5 + serhello_len + all_cert_len + 3] << 8) | buf[5 + serhello_len + all_cert_len + 4];
    memcpy(Handsha_rec->no_head_oldser + Handsha_rec->no_head_oldserlen, buf+10+serhello_len+all_cert_len, done_len);
    Handsha_rec->no_head_oldserlen += done_len;

    //保存服务器的公钥证书，用于加密PMS
    memcpy(cert->ser_rsa_key, buf + record_len[0] + 12, record_len[2]);
    // 替换代理服务器的证书
    cert_replace(sec_params, Handsha_rec, cert, clientfd, record_len);
    memset(buf, 0, BUFSIZ);
    memcpy(buf, Handsha_rec->new_serhello, Handsha_rec->new_serlen);
    all_cert_len = (buf[serhello_len + 3] << 8) | buf[serhello_len + 4];
    memcpy(Handsha_rec->no_head_serhello + Handsha_rec->no_head_serlen, buf + 5 + serhello_len, all_cert_len);
    Handsha_rec->no_head_serlen += all_cert_len;
    int last_len = (buf[5 + serhello_len + all_cert_len + 3] << 8) | buf[5 + serhello_len + all_cert_len + 4];
    memcpy(Handsha_rec->no_head_serhello + Handsha_rec->no_head_serlen, buf + 10 + serhello_len + all_cert_len, last_len);
    Handsha_rec->no_head_serlen += last_len;
    
}

/*提取加密的预主密钥和cli_key_exc报文*/
void extractPMS(int clientfd, struct SecParams *sec_params, struct HandshakeRecord *Handsha_rec){
    unsigned char buf[BUFSIZ];
    int i, ret = read_s(clientfd, buf, sizeof(buf));
    memcpy(Handsha_rec->cli_key_exc, buf, ret);
    Handsha_rec->cli_exc_len = ret;
    int flag = 1;
    for(i = 0; i < ret; i++){
        if(buf[i] == 0x16 && buf[i+1] == 0x03 && buf[i+2] == 0x03){
            if(flag == 0){
                flag += 1;
                continue;
            } else if(flag == 1){
                memcpy(sec_params->EPMS, buf + i + 11, 256);
                flag++;
            } else if(flag == 2){
                Handsha_rec->cli_finish_len = (buf[i + 3] << 8) | buf[i + 4];
                memcpy(Handsha_rec->cli_enc_finished, buf + i + 5, Handsha_rec->cli_finish_len);
            }
        }
    }
    
}

/*解密PMS*/
void EPMS_decrypt(struct SecParams *sec_params){
    EVP_PKEY *private_key = NULL;
    FILE *key_file  = fopen(AGENT_PRIVATE_KEY, "rb");
    if (!key_file) {
        perror("Failed to open private key file");
        exit(1);
    }
    private_key = EVP_PKEY_new();
    if (!private_key) {
        perror("Private key allocation error");
        exit(1);
    }
    if (!PEM_read_PrivateKey(key_file, &private_key, NULL, NULL)) {
        perror("Private key reading error");
        exit(1);
    }
    fclose(key_file);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(private_key, NULL);
    if (!ctx) {
        perror("Context allocation error");
        exit(1);
    }

    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        perror("Decrypt initialization error");
        exit(1);
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
        perror("Padding setting error");
        exit(1);
    }
    size_t outlen = 0, inlen = 256;
    if (EVP_PKEY_decrypt(ctx, NULL, &outlen, sec_params->EPMS, inlen) <= 0) {
        perror("Decryption parameter setup error");
        exit(1);
    }
    unsigned char *out = OPENSSL_malloc(outlen);
    if (EVP_PKEY_decrypt(ctx, out, &outlen, sec_params->EPMS, inlen) <= 0) {
        perror("Decryption error");
        exit(1);
    }
    memcpy(sec_params->PMS, out, 48);
    int i;
    printf("PMS:");
    for(i = 0; i < outlen; i++){
        printf("%02X", sec_params->PMS[i]);
    }
    printf("\n");
    OPENSSL_free(out);
}

/*用服务器RSA公钥再加密PMS，并替换原有的EPMS和客户端证书*/
void Re_Encrypt_PMS(struct SecParams *sec_params, struct HandshakeRecord *Handsha_rec, struct Certificate *cert, const unsigned char *ser_rsa_key, int serverfd){
    OpenSSL_add_all_algorithms();
    X509 *Xcert = NULL;
    const char *outputFilePath = "/home/cheng/ssl_analysi_9_month/certificate/temp.crt"; // 指定输出文件的路径
    Xcert = d2i_X509(NULL, &ser_rsa_key, cert->pkey_len); // 还原 X.509 证书对象
    if (Xcert == NULL) {
        perror("Xcert is null");
        exit(1);
    } else {
        FILE *outputFile = fopen(outputFilePath, "wb"); //创建临时的服务器证书
        if (outputFile) {
            if (!PEM_write_X509(outputFile, Xcert)) {
                perror("save Xcert error\n");
            } 
            fclose(outputFile);
        }
        X509_free(Xcert);
    }
    FILE *key_file  = fopen(outputFilePath, "rb");
    Xcert = PEM_read_X509(key_file, NULL, NULL, NULL);
    EVP_PKEY *pubkey = X509_get_pubkey(Xcert);
    if (!pubkey) {
        perror("Error extracting public key");
        X509_free(Xcert);
        exit(1);
    }
    fclose(key_file);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pubkey, NULL);
    if (!ctx) {
        perror("Context allocation error");
        exit(1);
    }
    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        perror("encrypt initialization error");
        exit(1);
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0){
        perror("Padding setting error");
        exit(1);
    }
    unsigned char *Re_Encry_PMS;
    size_t outlen = 0, inlen = 48;
    if (EVP_PKEY_encrypt(ctx, NULL, &outlen, sec_params->PMS, inlen) <= 0){
        perror("Decryption parameter setup error");
        exit(1);
    }
    Re_Encry_PMS = OPENSSL_malloc(outlen);
    if (EVP_PKEY_encrypt(ctx, Re_Encry_PMS, &outlen, sec_params->PMS, inlen) <= 0){
        perror("Re_encryption Decryption error");
        exit(1);
    }
    EVP_PKEY_free(pubkey);

    int flag = 1, i;
    unsigned char buf[BUFSIZ];
    for(i = 0; ; i++){
        if(Handsha_rec->cli_key_exc[i] == 0x16 && Handsha_rec->cli_key_exc[i+1] == 0x03 && Handsha_rec->cli_key_exc[i+2] == 0x03){
            if(flag == 0){
                flag = 1;
                continue;
            } else {
                memcpy(buf, Handsha_rec->cli_key_exc, i + 11);
                memcpy(buf + i + 11, Re_Encry_PMS, 256);
                memcpy(buf + i + 256 + 11, Handsha_rec->cli_key_exc + i + 11 + 256, Handsha_rec->cli_exc_len - i - 11 -256);
                break;
            }
        }
    }
    memcpy(Handsha_rec->new_cli_key_exc, buf, Handsha_rec->cli_exc_len);

    //write_s(serverfd, buf, Handsha_rec->cli_exc_len);

    // printf("cli_exc:");
    // for(i = 0; i < l; i++){
    //     printf("%02X", Handsha_rec->new_cli_key_exc[i]);
    // }
    // printf("\n");
    
    // int record_len[4];
    // record_len[0] = 3; //报文头部3字节
    // record_len[1] = (cli_key_exc[3] << 8) | cli_key_exc[4]; //证书总长度
    // record_len[2] = (buf[12] << 16) | (buf[13] << 8) | buf[14]; //客户端证书的长度
    // record_len[3] = 1; //1发，-1不发
    // cert_replace(l, serverfd, AGENT_CERTIFICATE, cli_key_exc, record_len); //把客户端证书替换为代理证书
}


void RSA_Signiture(size_t rec_len, int serverfd, unsigned char *cli_key_exc, const unsigned char *AGENT_PRI_KEY){
    
}

static int tls1_PRF(const void *seed1, size_t seed1_len,
                    const void *seed2, size_t seed2_len,
                    const void *seed3, size_t seed3_len,
                    const void *seed4, size_t seed4_len,
                    const void *seed5, size_t seed5_len,
                    const unsigned char *sec, size_t slen,
                    unsigned char *out, size_t olen, int fatal){
    const EVP_MD *md = EVP_sha256();
    EVP_PKEY_CTX *pctx = NULL;
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_TLS1_PRF, NULL);
    int ret = 0;
    if (pctx == NULL || EVP_PKEY_derive_init(pctx) <= 0
            || EVP_PKEY_CTX_set_tls1_prf_md(pctx, md) <= 0
            || EVP_PKEY_CTX_set1_tls1_prf_secret(pctx, sec, (int)slen) <= 0
            || EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed1, (int)seed1_len) <= 0
            || EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed2, (int)seed2_len) <= 0
            || EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed3, (int)seed3_len) <= 0
            || EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed4, (int)seed4_len) <= 0
            || EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed5, (int)seed5_len) <= 0
            || EVP_PKEY_derive(pctx, out, &olen) <= 0) {
            goto err;
        }
    ret = 1;

 err:
    EVP_PKEY_CTX_free(pctx);
    return ret;
}

void Master_Secret(struct SecParams *sec_params){
    const EVP_MD *md = EVP_sha256();
    unsigned char random[64];
    memcpy(random, sec_params->client_random, 32);
    memcpy(random + 32, sec_params->server_random, 32);
    int ret = tls1_PRF(TLS_MD_MASTER_SECRET_CONST, 
                       TLS_MD_MASTER_SECRET_CONST_SIZE,
                        random, 64,
                        NULL, 0,
                        NULL, 0,
                        NULL, 0, sec_params->PMS, 48, sec_params->master_secret,
                        SSL3_MASTER_SECRET_SIZE, 1);
    if (!ret) {
        printf("ssl prf failed \r\n");
        exit(1);
    }
    int i;
    printf("master_secret:");
    for(i = 0; i < 48; i++){
        printf("%02X", sec_params->master_secret[i]);
    }
    printf("\n");
}

void Hash_SHA256(unsigned char *data, unsigned int len, unsigned char *out){
    OpenSSL_add_all_digests(); // 初始化所有摘要算法
    unsigned int finished_len; // 存储消息的摘要长度
    const EVP_MD *md = EVP_sha256();
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        perror("EVP_MD_CTX error");
        exit(1);
    }   
    if(!EVP_DigestInit_ex(mdctx, md, NULL)){
        perror("EVP_DigestInit_ex error");
        exit(1);
    }
    if(!EVP_DigestUpdate(mdctx, data, len)){
        perror("EVP_DigestUpdate2 error");
        exit(1);
    }
    if(!EVP_DigestFinal(mdctx, out, &finished_len)){
        perror("EVP_DigestFinal error");
        exit(1);
    }
    EVP_MD_CTX_free(mdctx);
}


void Digest_Generate(struct SecParams *sec_params, struct HandshakeRecord *Handsha_rec){
    int len = 0, ret;
    unsigned char message[BUFSIZ];
    len = Handsha_rec->clilen - 5;
    memcpy(message, Handsha_rec->clihello + 5, Handsha_rec->clilen - 5);
    memcpy(message + len, Handsha_rec->no_head_serhello, Handsha_rec->no_head_serlen);
    len += Handsha_rec->no_head_serlen;
    int cli_key_len = (Handsha_rec->cli_key_exc[3]<<8) | Handsha_rec->cli_key_exc[4];
    memcpy(message + len, Handsha_rec->cli_key_exc + 5, cli_key_len);
    len += cli_key_len;

    memcpy(Handsha_rec->cli_message, message, len);
    Handsha_rec->cli_message_len = len;
    unsigned char finished_value[EVP_MAX_MD_SIZE]; // 存储 Finished 消息的摘要
    Hash_SHA256(message, len, finished_value);
    unsigned char finished_hash[32];
    ret = tls1_PRF(
                TLS_MD_CLIENT_FINISH_CONST, TLS_MD_CLIENT_FINISH_CONST_SIZE, 
                finished_value, 32,
                NULL, 0,
                NULL, 0,
                NULL, 0,
                sec_params->master_secret, 48,
                finished_hash, 32, 1);
    unsigned char head[4] = {0x14, 0x00, 0x00, 0x0C};
    memcpy(sec_params->cli_finished, head, 4);
    memcpy(sec_params->cli_finished + 4, finished_hash, 12);
    int i;
    // printf("digest:");
    // for(i = 0; i < 16; i++){
    //     printf("%02X", sec_params->cli_finished[i]);
    // }
    // printf("\n");    
}

void Sessionkey(struct SecParams *sec_params){
    unsigned char random[64];
    memcpy(random, sec_params->server_random, 32);
    memcpy(random + 32, sec_params->client_random, 32);
    int ret = tls1_PRF(TLS_MD_KEY_EXPANSION_CONST, TLS_MD_KEY_EXPANSION_CONST_SIZE,
                    random, 64,
                    NULL, 0,
                    NULL, 0, 
                    NULL, 0,
                    sec_params->master_secret, SSL3_MASTER_SECRET_SIZE,
                    sec_params->sessionkey, 128, 1);
    memcpy(sec_params->client_write_MAC_key, sec_params->sessionkey, 32);
    memcpy(sec_params->server_write_MAC_key, sec_params->sessionkey + 32, 32);
    memcpy(sec_params->client_write_key, sec_params->sessionkey + 64, 16);
    memcpy(sec_params->server_write_key, sec_params->sessionkey + 80, 16);
    memcpy(sec_params->client_write_IV, sec_params->sessionkey + 96, 16);
    memcpy(sec_params->server_write_IV, sec_params->sessionkey + 112, 16);
    
    int i;
    printf("client key:");
    for(i = 0; i < 16; i++){
        printf("%02X", sec_params->client_write_key[i]);
    }
    printf("\n");

}

int aes128_decrypt(unsigned char *data, unsigned char *key, unsigned char *IV, unsigned char *out, int data_len){
    int len = 0, final_len = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, IV)){
        perror("EVP_DecryptInit_ex error");
        exit(1);
    }
    EVP_CIPHER_CTX_set_padding(ctx, 0); // 1 表示启用填充，0 表示禁用填充
    if(!EVP_DecryptUpdate(ctx, out, &len, data, data_len)){
        perror("EVP_DecryptUpdate error");
        exit(1);
    }
    if(1 != EVP_DecryptFinal_ex(ctx, out + len, &final_len)){
        perror("EVP_DecryptFinal_ex error");
        exit(1);
    }
    EVP_CIPHER_CTX_free(ctx);
    return len;
}

int aes128_encrypt(unsigned char *data, unsigned char *key, unsigned char *IV, unsigned char *out, int *outlen, int data_len){
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(ctx == NULL) goto err1;
    int ciphertext_len = 0, final_len = 0, ret = 1;
    if(!EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, IV)
      ||!EVP_CIPHER_CTX_set_padding(ctx, 0)
      ||!EVP_EncryptUpdate(ctx, out, &ciphertext_len, data, data_len)
      ||!EVP_EncryptFinal_ex(ctx, data + ciphertext_len, &final_len)){
        ret = 0;
        goto err1;
    }
    ciphertext_len += final_len;
    *outlen = ciphertext_len;
 err1:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int MAC_SHA256(unsigned char *data, unsigned char *key, unsigned char *out, int data_len){
    const EVP_MD *md = EVP_sha256();
    unsigned int len = 0;
    HMAC(md, key, 32, data, data_len, out, &len);
    print_hex("MAC", out, len);
    return 1;
}


void reconfig_cli_finished(struct SecParams *sec_params, struct HandshakeRecord *Handsha_rec){
    int i, len = 0;
    unsigned char plaintext[1024];
    unsigned char IV[16];
    memcpy(IV, Handsha_rec->cli_enc_finished, 16); //加密message的前16字节为IV，后64为加密finished
    memcpy(sec_params->finished_IV, IV, 16);
    unsigned char text[64];
    memcpy(text, Handsha_rec->cli_enc_finished + 16, 64);

    aes128_decrypt(text, sec_params->client_write_key, sec_params->finished_IV, plaintext, 64);
    
    /*计算verify_data*/
    unsigned char finished[128] = {0x14, 0x00, 0x00, 0x0C};
    unsigned char message[BUFSIZ];
    len = Handsha_rec->clilen - 5;
    memcpy(message, Handsha_rec->clihello + 5, Handsha_rec->clilen - 5);
    memcpy(message + len, Handsha_rec->no_head_oldser, Handsha_rec->no_head_oldserlen);
    len += Handsha_rec->no_head_oldserlen;
    int cli_key_len = (Handsha_rec->new_cli_key_exc[3]<<8) | Handsha_rec->new_cli_key_exc[4];
    memcpy(message + len, Handsha_rec->new_cli_key_exc + 5, cli_key_len);
    len += cli_key_len;

    unsigned char finished_value[EVP_MAX_MD_SIZE]; // 存储 Finished 消息的摘要
    Hash_SHA256(message, len, finished_value);
    unsigned char finished_hash[32];
    int ret = tls1_PRF(
                TLS_MD_CLIENT_FINISH_CONST, TLS_MD_CLIENT_FINISH_CONST_SIZE, 
                finished_value, 32,
                NULL, 0,
                NULL, 0,
                NULL, 0,
                sec_params->master_secret, 48,
                finished_hash, 32, 1);
    memcpy(finished + 4, finished_hash, 12);
    memcpy(sec_params->new_cli_finished, finished, 16);
    // printf("new digest:");
    // for(i = 0; i < 16; i++){
    //     printf("%02X", finished[i]);
    // }
    // printf("\n"); 
}

void reconfig_cli_exc(struct SecParams *sec_params, struct HandshakeRecord *Handsha_rec, int serverfd){
    unsigned char enc_finished[32];
    int len = 0, i;
    unsigned char padding[16] = {0x0F, 0x0F, 0x0F, 0x0F
                            , 0x0F, 0x0F, 0x0F, 0x0F
                            , 0x0F, 0x0F, 0x0F, 0x0F
                            , 0x0F, 0x0F, 0x0F, 0x0F};
    memcpy(sec_params->new_cli_finished + 16, padding, 16);
    if(!aes128_encrypt(sec_params->new_cli_finished, sec_params->client_write_key, sec_params->finished_IV,
                    enc_finished, &len, 32)){
        perror("aes128_encrypt error");
        exit(1);
    }
    
    unsigned char out[32], data[85], send[8196], finish[48+13];
    unsigned char proto[5] = {0x16, 0x03, 0x03, 0x00, 0x50};
    unsigned char head[13] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                                 0x16, 0x03, 0x03, 0x00, 0x30};
    unsigned char key[32];
    unsigned char encrypt_aes_data[32];
    memcpy(key, sec_params->client_write_MAC_key, 32);

    memcpy(data, proto, 5);
    memcpy(data + 5, sec_params->finished_IV, 16);
    memcpy(data + 21, enc_finished, 32);

    memcpy(finish, head, 13);
    memcpy(finish + 13, sec_params->finished_IV, 16);
    memcpy(finish + 29, enc_finished, 32);
    MAC_SHA256(finish, key, out, 61);

    memcpy(data + 53, out, 32);
    memcpy(send, Handsha_rec->new_cli_key_exc, Handsha_rec->cli_exc_len - 85);
    memcpy(send + Handsha_rec->cli_exc_len - 85, data, 85);
    write_s(serverfd, send, Handsha_rec->cli_exc_len);

}

/*计算服务端的verify_data*/
void reconfig_ser_finished(struct SecParams *sec_params, struct HandshakeRecord *Handsha_rec, int serverfd){
    unsigned char message[BUFSIZ], buf[BUFSIZ];
    int ret = read(serverfd, buf, sizeof(buf));
    memcpy(Handsha_rec->new_session_tic, buf, ret);
    Handsha_rec->new_sessi_len = ret;
    int tlen = (buf[3] << 8) | buf[4];

    int len = Handsha_rec->clilen - 5;
    memcpy(message, Handsha_rec->clihello + 5, Handsha_rec->clilen - 5);
    memcpy(message + len, Handsha_rec->no_head_serhello, Handsha_rec->no_head_serlen);
    len += Handsha_rec->no_head_serlen;
    
    int cli_key_len = (Handsha_rec->cli_key_exc[3]<<8) | Handsha_rec->cli_key_exc[4];
    memcpy(message + len, Handsha_rec->cli_key_exc + 5, cli_key_len);
    len += cli_key_len;
    memcpy(message + len, sec_params->cli_finished, 16);
    len += 16;

    memcpy(message + len, buf + 5, tlen);
    len += tlen;

    unsigned char finished_value[EVP_MAX_MD_SIZE]; // 存储 Finished 消息的摘要
    Hash_SHA256(message, len, finished_value);
    unsigned char finished_hash[32];
    ret = tls1_PRF(
                TLS_MD_SERVER_FINISH_CONST, TLS_MD_SERVER_FINISH_CONST_SIZE, 
                finished_value, 32,
                NULL, 0,
                NULL, 0,
                NULL, 0,
                sec_params->master_secret, 48,
                finished_hash, 32, 1);
    unsigned char head[16] = {0x14, 0x00, 0x00, 0x0C};
    memcpy(head + 4, finished_hash, 12);
    memcpy(sec_params->new_ser_finished, head, 16);
    print_hex("server verify-data", sec_params->new_ser_finished, 16);
}

/*重构new——session——ticket*/
void reconfig_ser_new_sessi_t(struct SecParams *sec_params, struct HandshakeRecord *Handsha_rec, int clientfd, int serverfd){
    reconfig_ser_finished(sec_params, Handsha_rec, serverfd);
    unsigned char ser_finished[128], message[1024];
    int tlen = (Handsha_rec->new_session_tic[3] << 8) | Handsha_rec->new_session_tic[4];
    memcpy(message, Handsha_rec->new_session_tic, 11 + tlen);
    memcpy(ser_finished, Handsha_rec->new_session_tic + 11 + tlen, Handsha_rec->new_sessi_len - 11 - tlen);
    int finish_len = (ser_finished[3] << 8) | ser_finished[4];

    memcpy(sec_params->ser_finished_IV, ser_finished + 5, 16);
    int len;
    unsigned char enc_finished[32], hash[61], MAC[32];
    unsigned char padding[16] = {
        0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F,
        0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F
    };
    unsigned char head[13] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x16, 0x03, 0x03, 0x00, 0x30
    };
    memcpy(sec_params->new_ser_finished + 16, padding, 16);
    if(!aes128_encrypt(sec_params->new_ser_finished, sec_params->server_write_key, sec_params->ser_finished_IV,
                    enc_finished, &len, 32)){
        perror("aes128_encrypt error");
        exit(1);
    }
    memcpy(hash, head, 13);
    memcpy(hash + 13, sec_params->ser_finished_IV, 16);
    memcpy(hash + 29, enc_finished, len);
    MAC_SHA256(hash, sec_params->server_write_MAC_key, MAC, 29 + len);

    memcpy(ser_finished + 21, enc_finished, len);
    memcpy(ser_finished + 21 + len, MAC, 32);
    memcpy(message + 11 + tlen, ser_finished, finish_len + 5);

    write_s(clientfd, message, finish_len + 16 + tlen);
}

void applicationDecrypt(unsigned char *input, size_t inlen, int receivefd, int sendfd){

}

void PacketAnalysis(unsigned char *data, struct SecParams *sec_params, struct HandshakeRecord *Handsha_rec, struct Certificate *cert, int clientfd, int serverfd, int len){
    char content_type = data[0];
    switch (content_type)
    {
        case ClientHello:
            clienthellomsg(sec_params, Handsha_rec, clientfd, serverfd);
            break;
        case ServerHello:
            serverhellomsg(sec_params, Handsha_rec, cert, clientfd, serverfd);
            break;    
        
        case ClientKeyExchange:
            extractPMS(clientfd, sec_params, Handsha_rec);
            EPMS_decrypt(sec_params);
            Re_Encrypt_PMS(sec_params, Handsha_rec, cert, cert->ser_rsa_key, serverfd);
            Master_Secret(sec_params);
            Digest_Generate(sec_params, Handsha_rec);
            Sessionkey(sec_params);
            reconfig_cli_finished(sec_params, Handsha_rec);
            reconfig_cli_exc(sec_params, Handsha_rec, serverfd);
        
        case NewSessionTicket:
            reconfig_ser_new_sessi_t(sec_params, Handsha_rec, clientfd, serverfd);

        default:
            break;
    }
}
