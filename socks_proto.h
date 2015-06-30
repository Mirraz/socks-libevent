#ifndef SOCKS_PROTO_H
#define SOCKS_PROTO_H

#include <stdint.h>

#include "task.h"

typedef union {
	uint8_t ipv4[4];
	uint8_t ipv6[16];
	struct {
		char name[256];  // 255 + 1 for ending '\0'
		uint8_t name_len;
	} domain;
} host_union;

typedef unsigned int socks5_state_type;

typedef union {
	uint8_t header[2];
	struct {
		uint8_t methods[256];
		unsigned char nmethods;
	} methods;
	uint8_t response[2];
} auth_context_union;

typedef union {
	uint8_t header[4];
	struct {
		unsigned char cmd;
		unsigned char rep;
		union {
			struct {
				host_union host;
				uint16_t port;
				unsigned char addr_type;
			} request_addr;
			struct {
				char domain_name[256];
				char port_str[6];			// max len = 5 (for 65535) +1 for ending '\0'
				struct addrinfo hints;
				struct addrinfo *res;
			} getaddrinfo_args;
			struct {
				struct sockaddr_storage addr;
				socklen_t addr_len;
			} connect_addr;
		} conn;
	} req;
	uint8_t response[10];
} request_context_union;

typedef union {
	auth_context_union auth;
	request_context_union req;
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
	SOCKS5_RES_AGAIN,
	SOCKS5_RES_DONE,
} socks5_result_enum;

void socks5_init(socks5_arg_struct *socks5_arg, int client_sockfd);
int socks5(socks5_arg_struct *socks5_arg);
int get_client_sockfd(socks5_arg_struct *socks5_arg);
int get_connect_sockfd(socks5_arg_struct *socks5_arg);
task_struct *get_task(socks5_arg_struct *socks5_arg);

#endif/*SOCKS_PROTO_H*/

