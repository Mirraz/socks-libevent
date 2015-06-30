#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <memory.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "socks_proto.h"
#include "task.h"
#include "common.h"

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

static inline void write_shedule(socks5_arg_struct *socks5_arg, void *buf, size_t count) {
	task_struct *task = get_task(socks5_arg);
	task->type = TASK_WRITE;
	fill_write_task(&task->data.write_task, get_client_sockfd(socks5_arg), buf, count);
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

static inline int read_result(socks5_arg_struct *socks5_arg) {
	task_struct *task = get_task(socks5_arg);
	assert(task->type == TASK_READ);
	return get_read_result(&task->data.read_task);
}

static inline int write_result(socks5_arg_struct *socks5_arg) {
	task_struct *task = get_task(socks5_arg);
	assert(task->type == TASK_WRITE);
	return get_write_result(&task->data.write_task);
}

static inline int getaddrinfo_result(socks5_arg_struct *socks5_arg) {
	task_struct *task = get_task(socks5_arg);
	assert(task->type == TASK_GETADDRINFO);
	return get_getaddrinfo_result(&task->data.getaddrinfo_task);
}

static inline int connect_result(socks5_arg_struct *socks5_arg) {
	task_struct *task = get_task(socks5_arg);
	assert(task->type == TASK_CONNECT);
	return get_connect_result(&task->data.connect_task);
}



typedef enum {
	STATE_AUTH_HEADER,
	STATE_AUTH_METHODS,
	STATE_AUTH_RESPONSE,
	STATE_REQ_HEADER,
	STATE_REQ_ADDR_DOMAIN_LEN,
	STATE_REQ_ADDR_DOMAIN_NAME,
	STATE_REQ_ADDR_IP,
	STATE_REQ_ADDR_LABEL,
	STATE_REQ_PORT,
	STATE_REQ_GETADDRINFO,
	STATE_REQ_SOCKADDR_LABEL,
	STATE_REQ_CONNECT,
	STATE_REQ_RESPONSE_LABEL,
	STATE_REQ_RESPONSE,
	STATE_DONE,
} socks5_states_enum;

#define SOCKS_VER 5

static void socks5_req_init(socks5_arg_struct *socks5_arg);

typedef enum {
	AUTH_NO_AUTHENTICATION = 0,
	AUTH_GSSAPI = 1,
	AUTH_USERNAME_PASSWORD = 2,
	AUTH_NO_ACCEPTABLE_METHODS = 0xFF,
} auth_method_enum;

static void socks5_auth_init(socks5_arg_struct *socks5_arg) {
	socks5_context_union *ctx = get_ctx(socks5_arg);
	assert(sizeof(ctx->auth.header) == 2);
	read_shedule(socks5_arg, &ctx->auth.header, 2);
	set_next_state(socks5_arg, STATE_AUTH_HEADER);
}

static int socks5_auth(socks5_arg_struct *socks5_arg) {
	switch (get_state(socks5_arg)) {
		case STATE_AUTH_HEADER: {
			socks5_context_union *ctx = get_ctx(socks5_arg);
			uint8_t *buffer = ctx->auth.header;
			
			unsigned char ver = buffer[0];
			unsigned char nmethods = buffer[1];
			if (ver != SOCKS_VER) return SOCKS5_RES_WRONG_DATA;
			if (nmethods == 0) return SOCKS5_RES_WRONG_DATA;
			
			ctx->auth.methods.nmethods = nmethods;
			read_shedule(socks5_arg, &ctx->auth.methods.methods, nmethods);
			set_next_state(socks5_arg, STATE_AUTH_METHODS);
			return SOCKS5_RES_TASK;
		}
		case STATE_AUTH_METHODS: {
			int ret = read_result(socks5_arg);
			if (ret == ECONNRESET) return SOCKS5_RES_HANGUP;
			else if (ret) return SOCKS5_RES_ERROR;
			
			socks5_context_union *ctx = get_ctx(socks5_arg);
			unsigned char nmethods = ctx->auth.methods.nmethods;
			uint8_t *methods = ctx->auth.methods.methods;
			
			unsigned int i;
			bool method_noauth_found = false;
			for (i=0; i<nmethods; ++i) {
				unsigned char method = methods[i];
				if (method == AUTH_NO_AUTHENTICATION) {method_noauth_found = true; break;}
			}
			
			uint8_t *resp_buf = ctx->auth.response;
			resp_buf[0] = SOCKS_VER;
			resp_buf[1] = method_noauth_found ? AUTH_NO_AUTHENTICATION : AUTH_NO_ACCEPTABLE_METHODS;
			
			assert(sizeof(ctx->auth.response) == 2);
			write_shedule(socks5_arg, resp_buf, 2);
			set_next_state(socks5_arg, STATE_AUTH_RESPONSE);
			return SOCKS5_RES_TASK;
		}
		case STATE_AUTH_RESPONSE: {
			int ret = write_result(socks5_arg);
			if (ret == ECONNRESET) return SOCKS5_RES_HANGUP;
			else if (ret) return SOCKS5_RES_ERROR;
			
			socks5_context_union *ctx = get_ctx(socks5_arg);
			uint8_t resp_code = ctx->auth.response[1];
			if (resp_code == AUTH_NO_ACCEPTABLE_METHODS) return SOCKS5_RES_REFUSED;

			socks5_req_init(socks5_arg);
			return SOCKS5_RES_TASK;
		}
		default:
			assert(0);
			return SOCKS5_RES_ERROR;
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

static void socks5_req_init(socks5_arg_struct *socks5_arg) {
	socks5_context_union *ctx = get_ctx(socks5_arg);
	assert(sizeof(ctx->req.header) == 4);
	read_shedule(socks5_arg, &ctx->req.header, 4);
	set_next_state(socks5_arg, STATE_REQ_HEADER);
}

static int socks5_req(socks5_arg_struct *socks5_arg) {
	switch (get_state(socks5_arg)) {
		case STATE_REQ_HEADER: {
			int ret = read_result(socks5_arg);
			if (ret == ECONNRESET) return SOCKS5_RES_HANGUP;
			else if (ret) return SOCKS5_RES_ERROR;
			
			socks5_context_union *ctx = get_ctx(socks5_arg);
			uint8_t *buffer = ctx->req.header;
			
			unsigned char ver       = buffer[0];
			unsigned char cmd       = buffer[1];
			unsigned char reserved  = buffer[2];
			unsigned char addr_type = buffer[3];
			if (ver != SOCKS_VER) return SOCKS5_RES_WRONG_DATA;
			if (reserved != 0) return SOCKS5_RES_WRONG_DATA;
			if (!(addr_type == ATYP_IPV4 || addr_type == ATYP_DOMAIN || addr_type == ATYP_IPV6)) return SOCKS5_RES_WRONG_DATA;
			
			ctx->req.req.cmd = cmd;
			ctx->req.req.rep = REP_SUCCEEDED;
			ctx->req.req.conn.request_addr.addr_type = addr_type;
			
			switch (addr_type) {
				case ATYP_IPV4: {
					read_shedule(socks5_arg, &ctx->req.req.conn.request_addr.host.ipv4, 4);
					set_next_state(socks5_arg, STATE_REQ_ADDR_IP);
					break;
				}
				case ATYP_IPV6: {
					read_shedule(socks5_arg, &ctx->req.req.conn.request_addr.host.ipv6, 16);
					set_next_state(socks5_arg, STATE_REQ_ADDR_IP);
					break;
				}
				case ATYP_DOMAIN: {
					read_shedule(socks5_arg, &ctx->req.req.conn.request_addr.host.domain.name_len, 1);
					set_next_state(socks5_arg, STATE_REQ_ADDR_DOMAIN_LEN);
					break;
				}
				default:
					assert(0);
					return SOCKS5_RES_ERROR;
			}
			return SOCKS5_RES_TASK;
		}
		case STATE_REQ_ADDR_DOMAIN_LEN: {
			int ret = read_result(socks5_arg);
			if (ret == ECONNRESET) return SOCKS5_RES_HANGUP;
			else if (ret) return SOCKS5_RES_ERROR;
			
			socks5_context_union *ctx = get_ctx(socks5_arg);
			unsigned char domain_name_len = ctx->req.req.conn.request_addr.host.domain.name_len;
			
			if (domain_name_len == 0) return SOCKS5_RES_WRONG_DATA;
			assert(sizeof(char) == 1);
			
			read_shedule(socks5_arg, &ctx->req.req.conn.request_addr.host.domain.name, domain_name_len);
			set_next_state(socks5_arg, STATE_REQ_ADDR_DOMAIN_NAME);
			return SOCKS5_RES_TASK;
		}
		case STATE_REQ_ADDR_DOMAIN_NAME: {
			int ret = read_result(socks5_arg);
			if (ret == ECONNRESET) return SOCKS5_RES_HANGUP;
			else if (ret) return SOCKS5_RES_ERROR;
			
			socks5_context_union *ctx = get_ctx(socks5_arg);
			unsigned char domain_name_len = ctx->req.req.conn.request_addr.host.domain.name_len;
			char *domain_name             = ctx->req.req.conn.request_addr.host.domain.name;
			domain_name[domain_name_len] = '\0';
			set_next_state(socks5_arg, STATE_REQ_ADDR_LABEL);
			return SOCKS5_RES_AGAIN;
		}
		case STATE_REQ_ADDR_IP: {
			int ret = read_result(socks5_arg);
			if (ret == ECONNRESET) return SOCKS5_RES_HANGUP;
			else if (ret) return SOCKS5_RES_ERROR;
			// not break
		}
		case STATE_REQ_ADDR_LABEL: {
			socks5_context_union *ctx = get_ctx(socks5_arg);
			assert(sizeof(ctx->req.req.conn.request_addr.port) == 2);
			read_shedule(socks5_arg, &ctx->req.req.conn.request_addr.port, 2);
			set_next_state(socks5_arg, STATE_REQ_PORT);
			return SOCKS5_RES_TASK;
		}
		case STATE_REQ_PORT: {
			int ret = read_result(socks5_arg);
			if (ret == ECONNRESET) return SOCKS5_RES_HANGUP;
			else if (ret) return SOCKS5_RES_ERROR;
			
			socks5_context_union *ctx = get_ctx(socks5_arg);
			ctx->req.req.conn.request_addr.port = ntohs(ctx->req.req.conn.request_addr.port);
			
			unsigned char cmd = ctx->req.req.cmd;
			if (cmd != CMD_CONNECT) {
				ctx->req.req.rep = REP_HOST_UNREACHABLE;
				set_next_state(socks5_arg, STATE_REQ_RESPONSE_LABEL);
				return SOCKS5_RES_AGAIN;
			}
			
			unsigned char addr_type = ctx->req.req.conn.request_addr.addr_type;
			host_union *host = &ctx->req.req.conn.request_addr.host;
			unsigned int port = ctx->req.req.conn.request_addr.port;
			
			switch (addr_type) {
				case ATYP_IPV4: {
					struct sockaddr_in *connect_sin = (struct sockaddr_in *)&ctx->req.req.conn.connect_addr.addr;
					assert(sizeof(ctx->req.req.conn.connect_addr.addr) >= sizeof(struct sockaddr_in));
					memmove(&(connect_sin->sin_addr.s_addr), host->ipv4, 4);
					connect_sin->sin_family = AF_INET;
					connect_sin->sin_port = htons(port);
					ctx->req.req.conn.connect_addr.addr_len = sizeof(struct sockaddr_in);
					break;
				}
				case ATYP_IPV6: {
					struct sockaddr_in6 *connect_sin6 = (struct sockaddr_in6 *)&ctx->req.req.conn.connect_addr.addr;
					assert(sizeof(ctx->req.req.conn.connect_addr.addr) >= sizeof(struct sockaddr_in6));
					memmove(&(connect_sin6->sin6_addr.s6_addr), host->ipv6, 16);
					connect_sin6->sin6_family = AF_INET6;
					connect_sin6->sin6_port = htons(port);
					connect_sin6->sin6_flowinfo = 0;
					connect_sin6->sin6_scope_id = 0;
					ctx->req.req.conn.connect_addr.addr_len = sizeof(struct sockaddr_in6);
					break;
				}
				case ATYP_DOMAIN: {
					char *domain_name      =  ctx->req.req.conn.getaddrinfo_args.domain_name;
					char *port_str         =  ctx->req.req.conn.getaddrinfo_args.port_str;
					struct addrinfo *hints = &ctx->req.req.conn.getaddrinfo_args.hints;
					struct addrinfo **res  = &ctx->req.req.conn.getaddrinfo_args.res;
					memmove(domain_name, host->domain.name, host->domain.name_len);
					int printed = snprintf(port_str, sizeof(ctx->req.req.conn.getaddrinfo_args.port_str), "%u", port);
					assert(printed > 0 && (unsigned int)printed < sizeof(port_str));
					(void)printed;
					memset(hints, 0, sizeof(struct addrinfo));
					hints->ai_family = AF_UNSPEC;
					getaddrinfo_shedule(socks5_arg, domain_name, port_str, hints, res);
					set_next_state(socks5_arg, STATE_REQ_GETADDRINFO);
					return SOCKS5_RES_TASK;
				}
			}
			set_next_state(socks5_arg, STATE_REQ_SOCKADDR_LABEL);
			return SOCKS5_RES_AGAIN;
		}
		case STATE_REQ_GETADDRINFO: {
			int ret = getaddrinfo_result(socks5_arg);
			socks5_context_union *ctx = get_ctx(socks5_arg);
			if (ret == EAI_NONAME || ret == EAI_NODATA ) {
				ctx->req.req.rep = REP_HOST_UNREACHABLE;
				set_next_state(socks5_arg, STATE_REQ_RESPONSE_LABEL);
				return SOCKS5_RES_AGAIN;
			} else if (ret != 0) {
				printf_err("getaddrinfo: %s\n", gai_strerror(ret));
				return SOCKS5_RES_ERROR;
			}
			
			struct addrinfo *res  = ctx->req.req.conn.getaddrinfo_args.res;
			
			unsigned int addr_len = res->ai_addrlen;
			struct sockaddr_storage *addr = &ctx->req.req.conn.connect_addr.addr;
			assert(sizeof(ctx->req.req.conn.connect_addr.addr) >= addr_len);
			memmove(addr, res->ai_addr, addr_len);
			ctx->req.req.conn.connect_addr.addr_len = addr_len;
			
			freeaddrinfo(res);
			// not break
		}
		case STATE_REQ_SOCKADDR_LABEL: {
			socks5_context_union *ctx = get_ctx(socks5_arg);
			struct sockaddr_storage *addr = &ctx->req.req.conn.connect_addr.addr;
			unsigned int addr_len =  ctx->req.req.conn.connect_addr.addr_len;
			
			int connect_sockfd = socket(addr->ss_family, SOCK_STREAM, 0);
			if (connect_sockfd < 0) {perror("socket"); return SOCKS5_RES_ERROR;}
			if (make_socket_nonblocking(connect_sockfd)) {perror("fcntl"); return SOCKS5_RES_ERROR;}
			set_connect_sockfd(socks5_arg, connect_sockfd);
			
			connect_shedule(socks5_arg, connect_sockfd, (struct sockaddr *)addr, addr_len);
			set_next_state(socks5_arg, STATE_REQ_CONNECT);
			return SOCKS5_RES_TASK;
		}
		case STATE_REQ_CONNECT: {
			int ret = connect_result(socks5_arg);
			socks5_context_union *ctx = get_ctx(socks5_arg);
			if (ret == ECONNREFUSED || ret == ENETUNREACH || ret == ETIMEDOUT) {
				unsigned char rep;
				switch (ret) {
					case ECONNREFUSED:
						rep = REP_CONNECTION_REFUSED;
						break;
					case ETIMEDOUT:
						rep = REP_HOST_UNREACHABLE;
						break;
					case ENETUNREACH:
						rep = REP_NETWORK_UNREACHABLE;
						break;
					default:
						assert(0);
						return SOCKS5_RES_ERROR;
				}
				ctx->req.req.rep = rep;
				set_next_state(socks5_arg, STATE_REQ_RESPONSE_LABEL);
				return SOCKS5_RES_AGAIN;
			} else if (ret) {
				return SOCKS5_RES_ERROR;
			}
			// not break;
		}
		case STATE_REQ_RESPONSE_LABEL: {
			socks5_context_union *ctx = get_ctx(socks5_arg);
			unsigned char rep = ctx->req.req.rep;
			uint8_t *resp_buf = ctx->req.response;
			assert(sizeof(ctx->req.response) == 10);
			memset(resp_buf, 0, 10);
			resp_buf[0] = SOCKS_VER;
			resp_buf[1] = rep;
			resp_buf[3] = ATYP_IPV4;
			
			write_shedule(socks5_arg, resp_buf, 10);
			set_next_state(socks5_arg, STATE_REQ_RESPONSE);
			return SOCKS5_RES_TASK;
		}
		case STATE_REQ_RESPONSE: {
			int ret = write_result(socks5_arg);
			if (ret == ECONNRESET) return SOCKS5_RES_HANGUP;
			else if (ret) return SOCKS5_RES_ERROR;
			
			socks5_context_union *ctx = get_ctx(socks5_arg);
			uint8_t resp_code = ctx->req.response[1];
			if (resp_code != REP_SUCCEEDED) return SOCKS5_RES_REFUSED;
			set_next_state(socks5_arg, STATE_DONE);
			return SOCKS5_RES_DONE;
		}
		default:
			assert(0);
			return SOCKS5_RES_ERROR;
	}
}

void socks5_init(socks5_arg_struct *socks5_arg, int client_sockfd) {
	set_client_sockfd(socks5_arg, client_sockfd);
	set_connect_sockfd(socks5_arg, -1);
	socks5_auth_init(socks5_arg);
}

int socks5_impl(socks5_arg_struct *socks5_arg) {
	switch (get_state(socks5_arg)) {
		case STATE_AUTH_HEADER:
		case STATE_AUTH_METHODS:
		case STATE_AUTH_RESPONSE:
			return socks5_auth(socks5_arg);
		case STATE_REQ_HEADER:
		case STATE_REQ_ADDR_DOMAIN_LEN:
		case STATE_REQ_ADDR_DOMAIN_NAME:
		case STATE_REQ_ADDR_IP:
		case STATE_REQ_ADDR_LABEL:
		case STATE_REQ_PORT:
		case STATE_REQ_GETADDRINFO:
		case STATE_REQ_SOCKADDR_LABEL:
		case STATE_REQ_CONNECT:
		case STATE_REQ_RESPONSE_LABEL:
		case STATE_REQ_RESPONSE:
			return socks5_req(socks5_arg);
		default:
			assert(0);
			return SOCKS5_RES_ERROR;
	}
}

#ifndef NDEBUG
const char *state_str(socks5_state_type state) {
	switch (state) {
		case STATE_AUTH_HEADER:
			return "STATE_AUTH_HEADER";
		case STATE_AUTH_METHODS:
			return "STATE_AUTH_METHODS";
		case STATE_AUTH_RESPONSE:
			return "STATE_AUTH_RESPONSE";
		case STATE_REQ_HEADER:
			return "STATE_REQ_HEADER";
		case STATE_REQ_ADDR_DOMAIN_LEN:
			return "STATE_REQ_ADDR_DOMAIN_LEN";
		case STATE_REQ_ADDR_DOMAIN_NAME:
			return "STATE_REQ_ADDR_DOMAIN_NAME";
		case STATE_REQ_ADDR_IP:
			return "STATE_REQ_ADDR_IP";
		case STATE_REQ_ADDR_LABEL:
			return "STATE_REQ_ADDR_LABEL";
		case STATE_REQ_PORT:
			return "STATE_REQ_PORT";
		case STATE_REQ_GETADDRINFO:
			return "STATE_REQ_GETADDRINFO";
		case STATE_REQ_SOCKADDR_LABEL:
			return "STATE_REQ_SOCKADDR_LABEL";
		case STATE_REQ_CONNECT:
			return "STATE_REQ_CONNECT";
		case STATE_REQ_RESPONSE_LABEL:
			return "STATE_REQ_RESPONSE_LABEL";
		case STATE_REQ_RESPONSE:
			return "STATE_REQ_RESPONSE";
		case STATE_DONE:
			return "STATE_DONE";
		default:
			assert(0);
			return NULL;
	}
}

const char *res_str(int res) {
	switch(res) {
		case SOCKS5_RES_TASK:
			return "SOCKS5_RES_TASK";
		case SOCKS5_RES_ERROR:
			return "SOCKS5_RES_ERROR";
		case SOCKS5_RES_WRONG_DATA:
			return "SOCKS5_RES_WRONG_DATA";
		case SOCKS5_RES_REFUSED:
			return "SOCKS5_RES_REFUSED";
		case SOCKS5_RES_HANGUP:
			return "SOCKS5_RES_HANGUP";
		case SOCKS5_RES_AGAIN:
			return "SOCKS5_RES_AGAIN";
		case SOCKS5_RES_DONE:
			return "SOCKS5_RES_DONE";
		default:
			assert(0);
			return NULL;
	}
}
#endif

int socks5(socks5_arg_struct *socks5_arg) {
#ifndef NDEBUG
	socks5_state_type begin_state = get_state(socks5_arg);
#endif
	int res = socks5_impl(socks5_arg);
#ifndef NDEBUG
	socks5_state_type end_state = get_state(socks5_arg);
	//printf("%s\t%s\t%s\n", state_str(begin_state), res_str(res), state_str(end_state));
	(void)begin_state;
	(void)end_state;
#endif
	return res;
}

