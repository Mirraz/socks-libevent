#ifndef SOCKS_PROTO_H
#define SOCKS_PROTO_H

#include <stdint.h>

#include "task.h"

typedef union {
	uint8_t ipv4[4];
	uint8_t ipv6[16];
	char domain_name[256]; // 255 + 1 for ending '\0'
} address_union;

typedef unsigned int socks5_state_type;

typedef union {
	uint8_t auth_header[2];
	struct {
		uint8_t methods[256];
		unsigned char nmethods;
	} auth;
	uint8_t connect_header[4];
	struct {
		address_union address;
		uint16_t port;
		uint8_t domain_name_len;
		unsigned char cmd;
		unsigned char addr_type;
	} connect;
} socks5_context_union;

typedef struct {
	task_struct task;
	int client_sockfd;
	int connect_sockfd;
	struct {
		socks5_state_type state;
		socks5_context_union ctx;
	} socks5_ctx;
} socks5_arg_struct;

typedef enum {
	SOCKS5_RES_TASK,
	SOCKS5_RES_ERROR,
	SOCKS5_RES_WRONG_DATA,
	SOCKS5_RES_REFUSED,
	SOCKS5_RES_HANGUP,
	SOCKS5_RES_DONE,
} socks5_result_enum;

void socks5_init(socks5_arg_struct *socks5_arg, int client_sockfd);
int socks5(socks5_arg_struct *socks5_arg);
int get_client_sockfd(socks5_arg_struct *socks5_arg);
int get_connect_sockfd(socks5_arg_struct *socks5_arg);
task_struct *get_task(socks5_arg_struct *socks5_arg);

#endif/*SOCKS_PROTO_H*/

