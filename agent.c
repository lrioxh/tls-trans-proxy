#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "secure.h"
#include "packet.h"

#define CLIENT_PORT 9527
#define SERVER_PORT 9528

int main(){
    /*
     * 设置一个统一的TLS配置结构
    */ 
    SSL_library_init();
    SSL_load_error_strings();

    /*创建一个新的ssl配置结构*/
    SSL_CTX *agent_ctx = SSL_CTX_new_s(TLS_method());
        

    if (SSL_CTX_set_min_proto_version(agent_ctx, TLS1_2_VERSION) != 1) {
        fprintf(stderr, "Error setting minimum protocol version.\n");
        return 1;
    }

    if (SSL_CTX_set_max_proto_version(agent_ctx, TLS1_2_VERSION) != 1) {
        fprintf(stderr, "Error setting maximum protocol version.\n");
        return 1;
    }

    /*设置证书验证模式*/
    SSL_CTX_set_verify(agent_ctx, SSL_VERIFY_PEER, NULL);

    /*加载CA证书*/
    SSL_CTX_load_verify_locations_s(agent_ctx, CA_CERTIFICATE, NULL);

    /*加载中间人证书*/
    SSL_CTX_use_certificate_file_s(agent_ctx, AGENT_CERTIFICATE, SSL_FILETYPE_PEM);

    /*加载中间人私钥*/
    SSL_CTX_use_PrivateKey_file_s(agent_ctx, AGENT_PRIVATE_KEY, SSL_FILETYPE_PEM);

    /*检查公钥私钥是否匹配*/
    SSL_CTX_check_private_key_s(agent_ctx);

    /*设置加密算法套件*/
    SSL_CTX_set_ciphersuites_s(agent_ctx, "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256");

    SSL_CTX_set_mode(agent_ctx, SSL_MODE_AUTO_RETRY);

    /*
    *创建第一个socket，获取文件描述符Client_to_agent_sfd
    *中间人作为服务器与客户端建立tls连接
    */
    int Client_to_agent_sfd;
    Client_to_agent_sfd = socket_s(AF_INET, SOCK_STREAM, 0); //创建一个监听的套接字

    /*
    绑定IP地址和端口号
    */
    struct sockaddr_in Serveraddr;
    Serveraddr.sin_family = AF_INET;
    Serveraddr.sin_port = htons(SERVER_PORT);
    Serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
    socklen_t Serveraddr_len = sizeof(Serveraddr);
    int ret = bind_s(Client_to_agent_sfd, (struct sockaddr *)&Serveraddr, Serveraddr_len);
 
    /*
    设置同时接受连接上限
    */
    ret = listen_s(Client_to_agent_sfd, 128);

    /*
    与客户端建立连接,获取与客户端建立连接的新文件描述符
    */
    int Agent_to_Client_cfd;
    char ClientIp[1024];
    struct sockaddr_in Clientaddr;//输出参数，不需要显式初始化
    socklen_t Client_len = sizeof(Clientaddr);
    Agent_to_Client_cfd = accept_s(Client_to_agent_sfd, (struct sockaddr *)&Clientaddr, &Client_len); 

    write_s(STDOUT_FILENO, "Client to Agent TCP connect\n", sizeof("Client to Agent TCP connect\n"));

    /*
    *中间人作为客户端向服务器发起TCP请求
    */
    int Agent_to_server_fd = socket_s(AF_INET, SOCK_STREAM, 0);
    
    struct sockaddr_in Agentaddr;
    Agentaddr.sin_family = AF_INET;
    Agentaddr.sin_port = htons(CLIENT_PORT);
    inet_pton(AF_INET, "192.168.144.1", &Agentaddr.sin_addr.s_addr);
    socklen_t Agentaddr_len = sizeof(Agentaddr);
    ret = connect_s(Agent_to_server_fd, (struct sockaddr *)&Agentaddr, Agentaddr_len);

    write_s(STDOUT_FILENO, "Agent to Server TCP connect\n", sizeof("Agent to Server TCP connect\n"));
    
    struct SecParams *sec_params = (struct SecParams *)malloc(sizeof(struct SecParams));
    struct HandshakeRecord *Handsha_rec = (struct HandshakeRecord *)malloc(sizeof(struct HandshakeRecord));
    struct Certificate *cert = (struct Certificate *)malloc(sizeof(struct Certificate));

    clienthellomsg(sec_params, Handsha_rec, Agent_to_Client_cfd, Agent_to_server_fd);
    serverhellomsg(sec_params, Handsha_rec, cert, Agent_to_Client_cfd, Agent_to_server_fd);
    extractPMS(Agent_to_Client_cfd, sec_params, Handsha_rec);
    EPMS_decrypt(sec_params);
    Re_Encrypt_PMS(sec_params, Handsha_rec, cert, cert->ser_rsa_key,Agent_to_server_fd);

    //RSA_Signiture(cli_exc_len, Agent_to_server_fd, cli_key_exc, AGENT_PRIVATE_KEY);
    Master_Secret(sec_params);
    Digest_Generate(sec_params, Handsha_rec);
    Sessionkey(sec_params);
    reconfig_cli_finished(sec_params, Handsha_rec);
    reconfig_cli_exc(sec_params, Handsha_rec, Agent_to_server_fd);
    reconfig_ser_new_sessi_t(sec_params, Handsha_rec, Agent_to_Client_cfd, Agent_to_server_fd);

    while(1){
        unsigned char buf[4096], buf2[4096];
        int ret = read_s(Agent_to_Client_cfd, buf, sizeof(buf));
        write_s(Agent_to_server_fd, buf, ret);

        unsigned char decrypt_data[ret], IV[16];
        memcpy(IV, buf + 5, 16);
        int len = aes128_decrypt(buf + 21, sec_params->client_write_key, IV, decrypt_data, ret - 21 - 32);
        if(decrypt_data[0] == '#')
            break;
        print_hex("client data", decrypt_data, len);

        ret = read_s(Agent_to_server_fd, buf2, sizeof(buf2));
        write_s(Agent_to_Client_cfd, buf2, ret);
        memcpy(IV, buf2 + 5, 16);
        len = aes128_decrypt(buf2 + 21, sec_params->server_write_key, IV, decrypt_data, ret - 21 - 32);
        print_hex("server data", decrypt_data, len);
    }

    SSL_CTX_free(agent_ctx);

    return 0;
}

