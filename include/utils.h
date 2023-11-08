#ifndef _UTILS_H_
#define _UTILS_H_

#include <stdio.h>
#include <stdlib.h>
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned long size_t;

void print_hex(const uint8_t *buf, size_t len);
void print_char(const uint8_t *buf, size_t len);
uint8_t *num_to_byte(size_t num, uint8_t *buf, size_t buf_len);
uint8_t *gen_TLS_head(uint8_t type, uint16_t ver, uint16_t len, uint8_t *out);
uint8_t *gen_padding(uint8_t len, uint8_t *out);

#endif