//utils: basic func

#include "include/utils.h"


void print_hex(const uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; i++)
    {
        if (i % 16 == 0)
        {
            printf(" ");
        }
        printf("%02X", buf[i]);
    }
}

void print_char(const uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; i++)
    {
        printf("%c", buf[i]);
    }
    // printf("\n");
}

uint8_t *num_to_byte(size_t num, uint8_t *buf, size_t buf_len)
{
    for (int i = buf_len - 1; i >= 0; i--)
    {
        buf[i] = num & 0xFF; // 取最低8位
        num >>= 8;              // 向右移动8位
    }
    return buf;
}
uint8_t *gen_TLS_head(uint8_t type, uint16_t ver, uint16_t len, uint8_t *out)
{
    num_to_byte(type, out, 1);
    num_to_byte(ver, out + 1, 2);
    num_to_byte(len, out + 3, 2);
    return out;
}
uint8_t *gen_padding(uint8_t len, uint8_t *out)
{
    for (uint8_t i = 0; i <= len; i++)
    {
        num_to_byte(len, out + i, 1);
    }
    return out;
}