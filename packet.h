#ifndef _PACKET_H_
#define _PACKET_H_

#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/kdf.h>
#include <openssl/hmac.h>
#include "content_type.h"

#define AGENT_CERTIFICATE "/home/cheng/ssl_analysi_9_month/certificate/agent.crt"
#define AGENT_PRIVATE_KEY "/home/cheng/ssl_analysi_9_month/certificate/agent.key"
#define CA_CERTIFICATE "/home/cheng/ssl_analysi_9_month/certificate/ca.crt"

struct SecParams{
    unsigned char digest[32];

    unsigned char client_random[64];   
    unsigned char server_random[64]; 

    unsigned char master_secret[48];  
    unsigned char EPMS[256];
    unsigned char PMS[48];

    unsigned char sessionkey[128];
    unsigned char client_write_MAC_key[32];
    unsigned char server_write_MAC_key[32];
    unsigned char client_write_key[16];
    unsigned char server_write_key[16];
    unsigned char client_write_IV[16];
    unsigned char server_write_IV[16];

    unsigned char cli_finished[32];
    unsigned char finished_IV[16];
    unsigned char new_cli_finished[32];

    unsigned char new_ser_finished[32];
    unsigned char ser_finished_IV[32];

};

struct Certificate{
    size_t pkey_len;        //服务器公钥证书的长度  
    unsigned char ser_rsa_key[BUFSIZ];    
    unsigned char cli_rsa_key[BUFSIZ];
};

struct HandshakeRecord{
    size_t clilen;          //client_hello报文长度
    size_t serlen;          //server_hello报文长度
    size_t cli_exc_len;     //client_key_exchange报文长度

    size_t new_clilen;        
    size_t new_serlen;         
    size_t new_cli_exc_len; 

    size_t cli_finish_len;         
    size_t ser_finish_len;

    size_t no_head_serlen;
    size_t cli_message_len;
    size_t no_head_oldserlen;
    
    size_t new_sessi_len;

    unsigned char serverhello[BUFSIZ];
    unsigned char new_serhello[BUFSIZ]; //替换证书或者密钥后的新报文
    unsigned char no_head_serhello[BUFSIZ];
    unsigned char no_head_oldser[BUFSIZ];

    unsigned char clihello[BUFSIZ];
    unsigned char new_clihello[BUFSIZ];

    unsigned char cli_key_exc[BUFSIZ];
    unsigned char new_cli_key_exc[BUFSIZ];
    unsigned char sub_cli_key_exc[BUFSIZ];
    
    
    unsigned char cli_enc_finished[128];
    unsigned char ser_enc_finished[128];

    unsigned char cli_message[BUFSIZ];
    unsigned char ser_message[BUFSIZ];

    unsigned char new_session_tic[BUFSIZ];


};
void print_hex(char *label, unsigned char *data, int len);
void PacketAnalysis(unsigned char *data, struct SecParams *sec_params, struct HandshakeRecord *Handsha_rec, struct Certificate *cert, int clientfd, int serverfd, int len);
void clienthellomsg(struct SecParams *sec_params, struct HandshakeRecord *Handsha_rec, int clientfd, int serverfd);
void serverhellomsg(struct SecParams *sec_params, struct HandshakeRecord *Handsha_rec, struct Certificate *cert, int clientfd, int serverfd);
void extractPMS(int clientfd, struct SecParams *sec_params, struct HandshakeRecord *Handsha_rec);
void EPMS_decrypt(struct SecParams *sec_params);
void cert_replace(struct SecParams *sec_params, struct HandshakeRecord *Handsha_rec, struct Certificate *cert, int clientfd, int len[]);
void Re_Encrypt_PMS(struct SecParams *sec_params, struct HandshakeRecord *Handsha_rec, struct Certificate *cert, const unsigned char *ser_rsa_key, int serverfd);
void RSA_Signiture(size_t rec_len, int serverfd, unsigned char *cli_key_exc, const unsigned char *AGENT_PRI_KEY);
void Master_Secret(struct SecParams *sec_params); 
static int tls1_PRF(const void *seed1, size_t seed1_len,
                    const void *seed2, size_t seed2_len,
                    const void *seed3, size_t seed3_len,
                    const void *seed4, size_t seed4_len,
                    const void *seed5, size_t seed5_len,
                    const unsigned char *sec, size_t slen,
                    unsigned char *out, size_t olen, int fatal);

void Sessionkey(struct SecParams *sec_params);
void Digest_Generate(struct SecParams *sec_params, struct HandshakeRecord *Handsha_rec);
void Hash_SHA256(unsigned char *data, unsigned int len, unsigned char *out);
int aes128_decrypt(unsigned char *data, unsigned char *key, unsigned char *IV, unsigned char *out, int data_len);
int aes128_encrypt(unsigned char *data, unsigned char *key, unsigned char *IV, unsigned char *out, int *outlen, int data_len);
int MAC_SHA256(unsigned char *data, unsigned char *key, unsigned char *out, int data_len);
void reconfig_cli_finished(struct SecParams *sec_params, struct HandshakeRecord *Handsha_rec);
void reconfig_cli_exc(struct SecParams *sec_params, struct HandshakeRecord *Handsha_rec, int serverfd);
void reconfig_ser_finished(struct SecParams *sec_params, struct HandshakeRecord *Handsha_rec, int serverfd);
void reconfig_ser_new_sessi_t(struct SecParams *sec_params, struct HandshakeRecord *Handsha_rec, int clientfd, int serverfd);
void applicationDecrypt(unsigned char *input, size_t inlen, int receivefd, int sendfd);
#endif
