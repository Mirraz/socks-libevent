#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <memory.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "socks_proto.h"
#include "task.h"



static inline socks5_state_type get_state(socks5_arg_struct *socks5_arg) {
	return socks5_arg->socks5_ctx.state;
}

static inline void set_next_state(socks5_arg_struct *socks5_arg, socks5_state_type state) {
	socks5_arg->socks5_ctx.state = state;
}

static inline socks5_state_type get_next_state(socks5_arg_struct *socks5_arg) {
	return socks5_arg->socks5_ctx.state;
}

static inline socks5_context_union* get_ctx(socks5_arg_struct *socks5_arg) {
	return &socks5_arg->socks5_ctx.ctx;
}

int get_client_sockfd(socks5_arg_struct *socks5_arg) {
	return socks5_arg->client_sockfd;
}

static inline void set_client_sockfd(socks5_arg_struct *socks5_arg, int client_sockfd) {
	socks5_arg->client_sockfd = client_sockfd;
}

int get_connect_sockfd(socks5_arg_struct *socks5_arg) {
	return socks5_arg->connect_sockfd;
}

static inline void set_connect_sockfd(socks5_arg_struct *socks5_arg, int connect_sockfd) {
	socks5_arg->connect_sockfd = connect_sockfd;
}

task_struct *get_task(socks5_arg_struct *socks5_arg) {
	return &socks5_arg->task;
}



static inline void read_shedule(socks5_arg_struct *socks5_arg, void *buf, size_t count) {
	task_struct *task = get_task(socks5_arg);
	task->type = TASK_READ;
	fill_read_task(&task->data.read_task, get_client_sockfd(socks5_arg), buf, count);
}

static inline void getaddrinfo_shedule(socks5_arg_struct *socks5_arg,
		const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) {
	task_struct *task = get_task(socks5_arg);
	task->type = TASK_GETADDRINFO;
	fill_getaddrinfo_task(&task->data.getaddrinfo_task, node, service, hints, res);
}

static inline void connect_shedule(socks5_arg_struct *socks5_arg, int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
	task_struct *task = get_task(socks5_arg);
	task->type = TASK_CONNECT;
	fill_connect_task(&task->data.connect_task, sockfd, addr, addrlen);
}



/********************/
ssize_t write_wrapper(int fd, const void *buf, size_t count) {
	ssize_t write_bytes = write(fd, buf, count);
	if (write_bytes < 0) {
		if (errno == ECONNRESET) return -1;
		else {perror("write"); exit(1);}
	}
	if (write_bytes == 0) return -1;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-compare"
	assert(write_bytes <= count);
#pragma GCC diagnostic pop
	return write_bytes;
}

int write_all(int fd, const void *buf, size_t count) {
	ssize_t write_bytes;
	while (count > 0) {
		write_bytes = write_wrapper(fd, buf, count);
		if (write_bytes <= 0) return -1;
		buf   += write_bytes;
		count -= write_bytes;
	}
	return 0;
}
/********************/



typedef enum {
	STATE_AUTH_HEADER,
	STATE_AUTH_METHODS,
	STATE_CONNECT_HEADER,
	STATE_CONNECT_ADDR,
	STATE_CONNECT_ADDR_DOMAIN_LEN,
	STATE_CONNECT_ADDR_DOMAIN_NAME,
	STATE_CONNECT_PORT,
	STATE_DONE,
} socks5_states_enum;

#define SOCKS_VER 5

static void socks5_connect_init(socks5_arg_struct *socks5_arg);

typedef enum {
	AUTH_NO_AUTHENTICATION = 0,
	AUTH_GSSAPI = 1,
	AUTH_USERNAME_PASSWORD = 2,
	AUTH_NO_ACCEPTABLE_METHODS = 0xFF,
} auth_method_enum;

static void socks5_auth_init(socks5_arg_struct *socks5_arg) {
	socks5_context_union *ctx = get_ctx(socks5_arg);
	read_shedule(socks5_arg, &ctx->auth_header, 2);
	set_next_state(socks5_arg, STATE_AUTH_HEADER);
}

static int socks5_auth(socks5_arg_struct *socks5_arg) {
	switch (get_state(socks5_arg)) {
		case STATE_AUTH_HEADER: {
			socks5_context_union *ctx = get_ctx(socks5_arg);
			uint8_t *buffer = ctx->auth_header;
			
			unsigned char ver = buffer[0];
			unsigned char nmethods = buffer[1];
			if (ver != SOCKS_VER) return SOCKS5_RES_WRONG_DATA;
			if (nmethods == 0) return SOCKS5_RES_WRONG_DATA;
			
			ctx->auth.nmethods = nmethods;
			read_shedule(socks5_arg, &ctx->auth.methods, nmethods);
			set_next_state(socks5_arg, STATE_AUTH_METHODS);
			return SOCKS5_RES_TASK;
		}
		case STATE_AUTH_METHODS: {
			socks5_context_union *ctx = get_ctx(socks5_arg);
			unsigned char nmethods = ctx->auth.nmethods;
			uint8_t *methods = ctx->auth.methods;
			int client_sockfd = get_client_sockfd(socks5_arg);
			
			unsigned int i;
			bool method_noauth_found = false;
			for (i=0; i<nmethods; ++i) {
				unsigned char method = methods[i];
				if (method == AUTH_NO_AUTHENTICATION) {method_noauth_found = true; break;}
			}
			uint8_t resp_buf[2] = {SOCKS_VER};
			if (method_noauth_found) resp_buf[1] = AUTH_NO_AUTHENTICATION;
			else                     resp_buf[1] = AUTH_NO_ACCEPTABLE_METHODS;
			if (write_all(client_sockfd, resp_buf, sizeof(resp_buf))) return SOCKS5_RES_HANGUP;
			if (!method_noauth_found) return SOCKS5_RES_REFUSED;

			socks5_connect_init(socks5_arg);
			return SOCKS5_RES_TASK;
		}
		default:
			assert(0);
	}
}

typedef enum {
	ATYP_IPV4   = 1,
	ATYP_DOMAIN = 3,
	ATYP_IPV6   = 4,
} addr_type_enum;

typedef enum {
	CMD_CONNECT = 1,
	CMD_BIND    = 2,
	CMD_UDP     = 3,
} cmd_enum;

typedef enum {
	REP_SUCCEEDED = 0,
	REP_GENERAL_SOCKS_SERVER_FAILURE = 1,
	REP_CONN_NOT_ALLOWED_BY_RULESET = 2,
	REP_NETWORK_UNREACHABLE = 3,
	REP_HOST_UNREACHABLE = 4,
	REP_CONNECTION_REFUSED = 5,
	REP_TTL_EXPIRED = 6,
	REP_COMMAND_NOT_SUPPORTED = 7,
	REP_ADDRESS_TYPE_NOT_SUPPORTED = 8,
} rep_enum;

static int make_sockaddr(unsigned char addr_type, address_union *address, unsigned int port,
			struct sockaddr **addr_p, socklen_t *addr_len_p) {
	switch (addr_type) {
		case ATYP_IPV4: {
			struct sockaddr_in *connect_sin = malloc(sizeof(struct sockaddr_in));
			if (connect_sin == NULL) {perror("malloc"); exit(1);} // TODO
			memset(connect_sin, 0, sizeof(struct sockaddr_in));
			connect_sin->sin_family = AF_INET;
			connect_sin->sin_port = htons(port);
			memcpy(&(connect_sin->sin_addr.s_addr), address->ipv4, 4);
			*addr_p = (struct sockaddr *)connect_sin;
			*addr_len_p = sizeof(struct sockaddr_in);
			break;
		}
		case ATYP_IPV6: {
			struct sockaddr_in6 *connect_sin6 = malloc(sizeof(struct sockaddr_in6));
			if (connect_sin6 == NULL) {perror("malloc"); exit(1);} // TODO
			memset(connect_sin6, 0, sizeof(struct sockaddr_in6));
			connect_sin6->sin6_family = AF_INET6;
			connect_sin6->sin6_port = htons(port);
			memcpy(&(connect_sin6->sin6_addr.s6_addr), address->ipv6, 16);
			*addr_p = (struct sockaddr *)connect_sin6;
			*addr_len_p = sizeof(struct sockaddr_in6);
			break;
		}
		case ATYP_DOMAIN: {
			char port_str[6]; // max len = 5 (for 65535) +1 for ending '\0'
			int printed = snprintf(port_str, sizeof(port_str), "%u", port);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-compare"
			assert(printed > 0 && printed < sizeof(port_str));
#pragma GCC diagnostic pop
			(void)printed;
			struct addrinfo hints;
			memset(&hints, 0, sizeof(hints));
			hints.ai_family = AF_UNSPEC;
			struct addrinfo *res;
			int ret = getaddrinfo(address->domain_name, port_str, &hints, &res);
			if (ret == EAI_NONAME || ret == EAI_NODATA ) return REP_HOST_UNREACHABLE;
			else if (ret != 0) {printf("getaddrinfo: %s", gai_strerror(ret)); exit(1);}
			
			unsigned int addr_len = res->ai_addrlen;
			struct sockaddr *addr = malloc(addr_len);
			if (addr == NULL) {perror("malloc"); exit(1);} // TODO
			memcpy(addr, res->ai_addr, addr_len);
			freeaddrinfo(res);
			*addr_p = addr;
			*addr_len_p = addr_len;
			break;
		}
	}
	return 0;
}

static void socks5_connect_init(socks5_arg_struct *socks5_arg) {
	socks5_context_union *ctx = get_ctx(socks5_arg);
	read_shedule(socks5_arg, &ctx->connect_header, 4);
	set_next_state(socks5_arg, STATE_CONNECT_HEADER);
}

static int socks5_connect(socks5_arg_struct *socks5_arg) {
	switch (get_state(socks5_arg)) {
		case STATE_CONNECT_HEADER: {
			socks5_context_union *ctx = get_ctx(socks5_arg);
			uint8_t *buffer = ctx->connect_header;
			
			unsigned char ver       = buffer[0];
			unsigned char cmd       = buffer[1];
			unsigned char reserved  = buffer[2];
			unsigned char addr_type = buffer[3];
			if (ver != SOCKS_VER) return SOCKS5_RES_WRONG_DATA;
			if (reserved != 0) return SOCKS5_RES_WRONG_DATA;
			if (!(addr_type == ATYP_IPV4 || addr_type == ATYP_DOMAIN || addr_type == ATYP_IPV6)) return SOCKS5_RES_WRONG_DATA;
			
			ctx->connect.cmd = cmd;
			ctx->connect.addr_type = addr_type;
			
			switch (addr_type) {
				case ATYP_IPV4: {
					read_shedule(socks5_arg, &ctx->connect.address.ipv4, 4);
					set_next_state(socks5_arg, STATE_CONNECT_ADDR);
					break;
				}
				case ATYP_IPV6: {
					read_shedule(socks5_arg, &ctx->connect.address.ipv6, 16);
					set_next_state(socks5_arg, STATE_CONNECT_ADDR);
					break;
				}
				case ATYP_DOMAIN: {
					read_shedule(socks5_arg, &ctx->connect.domain_name_len, 1);
					set_next_state(socks5_arg, STATE_CONNECT_ADDR_DOMAIN_LEN);
					break;
				}
			}
			return SOCKS5_RES_TASK;
		}
		case STATE_CONNECT_ADDR_DOMAIN_LEN: {
			socks5_context_union *ctx = get_ctx(socks5_arg);
			unsigned char domain_name_len = ctx->connect.domain_name_len;
			
			if (domain_name_len == 0) return SOCKS5_RES_WRONG_DATA;
			assert(sizeof(char) == 1);
			
			read_shedule(socks5_arg, &ctx->connect.address.domain_name, domain_name_len);
			set_next_state(socks5_arg, STATE_CONNECT_ADDR_DOMAIN_NAME);
			return SOCKS5_RES_TASK;
		}
		case STATE_CONNECT_ADDR_DOMAIN_NAME: {
			socks5_context_union *ctx = get_ctx(socks5_arg);
			ctx->connect.address.domain_name[ctx->connect.domain_name_len] = '\0';
			// not break
		}
		case STATE_CONNECT_ADDR: {
			socks5_context_union *ctx = get_ctx(socks5_arg);
			read_shedule(socks5_arg, &ctx->connect.port, 2);
			set_next_state(socks5_arg, STATE_CONNECT_PORT);
			return SOCKS5_RES_TASK;
		}
		case STATE_CONNECT_PORT: {
			socks5_context_union *ctx = get_ctx(socks5_arg);
			ctx->connect.port = ntohs(ctx->connect.port);
			
			unsigned char cmd = ctx->connect.cmd;
			unsigned char addr_type = ctx->connect.addr_type;
			address_union *addr = &ctx->connect.address;
			unsigned int port = ctx->connect.port;
			int client_sockfd = get_client_sockfd(socks5_arg);
			
			uint8_t resp_buf[10] = {
				SOCKS_VER, 0/*rep*/, 0/*rsv*/, ATYP_IPV4,
				0, 0, 0, 0/*bind.ipv4*/,
				0, 0/*bind.port*/
			};
			unsigned char rep;
			int connect_sockfd = -1;
			if (cmd == CMD_CONNECT) {
				rep = REP_SUCCEEDED;
		
				struct sockaddr *connect_addr;
				socklen_t connect_addr_len;
				int ret = make_sockaddr(addr_type, addr, port, &connect_addr, &connect_addr_len);
				assert(ret >= 0);
				if (ret > 0) {
					rep = ret;
				} else {
					connect_sockfd = socket(connect_addr->sa_family, SOCK_STREAM, 0);
					if (connect_sockfd < 0) {perror("socket"); exit(1);} // TODO
					
					if (connect(connect_sockfd, connect_addr, connect_addr_len)) {
						if (errno == ECONNREFUSED || errno == ENETUNREACH || errno == ETIMEDOUT) {
							switch (errno) {
								case ECONNREFUSED:
									rep = REP_CONNECTION_REFUSED;
									break;
								case ETIMEDOUT:
									rep = REP_HOST_UNREACHABLE;
									break;
								case ENETUNREACH:
									rep = REP_NETWORK_UNREACHABLE;
									break;
							}
							if (close(connect_sockfd)) {perror("close"); exit(1);} // TODO
						} else {perror("connect"); exit(1);} // TODO
					} else {
						set_connect_sockfd(socks5_arg, connect_sockfd);
					}
					
					free(connect_addr);
				}
			} else {
				rep = REP_COMMAND_NOT_SUPPORTED;
			}
			resp_buf[1] = rep;
			if (write_all(client_sockfd, resp_buf, sizeof(resp_buf))) {
				if (connect_sockfd != -1) {
					if (close(connect_sockfd)) {perror("close"); exit(1);} // TODO
				}
				return SOCKS5_RES_HANGUP;
			}
			if (rep != REP_SUCCEEDED) return SOCKS5_RES_REFUSED;
			
			set_next_state(socks5_arg, STATE_DONE);
			return SOCKS5_RES_DONE;
		}
		default:
			assert(0);
	}
}

void socks5_init(socks5_arg_struct *socks5_arg, int client_sockfd) {
	set_client_sockfd(socks5_arg, client_sockfd);
	socks5_auth_init(socks5_arg);
}

int socks5(socks5_arg_struct *socks5_arg) {
	switch (get_state(socks5_arg)) {
		case STATE_AUTH_HEADER:
		case STATE_AUTH_METHODS:
			return socks5_auth(socks5_arg);
		case STATE_CONNECT_HEADER:
		case STATE_CONNECT_ADDR:
		case STATE_CONNECT_ADDR_DOMAIN_LEN:
		case STATE_CONNECT_ADDR_DOMAIN_NAME:
		case STATE_CONNECT_PORT:
			return socks5_connect(socks5_arg);
		default:
			assert(0);
	}
}

