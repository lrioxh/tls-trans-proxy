# tls trans proxy

在socket tcp通信基础上，通过代理获取/改变tls握手报文，获得密钥解密C/S tls通信，实现tls透明代理。

环境：linux、openssl 3.0

协议栈：

- TLS12_RSA_AES128_SHA256

  > 1. 获取C&S random
  > 2. 替换certificate证书
  > 3. 解密client key exchange报文获取pre master secret，再加密发送服务器
  > 4. PRF导出与C&S一致的master secret和key bolck
  > 5. 重构握手finished。PRF导出C&S侧verify data，aes加密并计算mac

TODO:

- EMS

- ECDHE
- session 复用

- tls1.3