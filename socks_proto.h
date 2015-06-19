#ifndef SOCKS_SERVER_HANDLE_CLIENT_H
#define SOCKS_SERVER_HANDLE_CLIENT_H

#include <stdint.h>
#include <stddef.h>

typedef union {
	uint8_t ipv4[4];
	uint8_t ipv6[16];
	char domain_name[256]; // 255 + 1 for ending '\0'
} address_union;

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
	void *buf;
	size_t count;
} read_task_struct;

typedef unsigned int socks5_state_type;

typedef struct {
	int client_sockfd;
	int connect_sockfd;
	read_task_struct read_task;
	socks5_state_type state;
	socks5_context_union ctx;
} socks5_arg_struct;

void socks5_clinet_init(socks5_arg_struct *socks5_arg, int client_sockfd);
int socks5_client_read_cb(socks5_arg_struct *socks5_arg);

#endif/*SOCKS_SERVER_HANDLE_CLIENT_H*/

