#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <assert.h>
#include <memory.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>

void printf_and_exit(const char *format, ...) {
   va_list arglist;
   va_start(arglist, format);
   vfprintf(stderr, format, arglist);
   va_end(arglist);
   fprintf(stderr, "\n");
   exit(EXIT_FAILURE);
}

void perror_and_exit(const char *s) {
	perror(s);
	exit(EXIT_FAILURE);
}

ssize_t read_wrapper(int fd, void *buf, size_t count) {
	ssize_t read_bytes = read(fd, buf, count);
	if (read_bytes < 0) {
		if (errno == ECONNRESET) return -1;
		else perror_and_exit("read");
	}
	if (read_bytes == 0) return -1;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-compare"
	assert(read_bytes <= count);
#pragma GCC diagnostic pop
	return read_bytes;
}

ssize_t write_wrapper(int fd, const void *buf, size_t count) {
	ssize_t write_bytes = write(fd, buf, count);
	if (write_bytes < 0) {
		if (errno == ECONNRESET) return -1;
		else perror_and_exit("write");
	}
	if (write_bytes == 0) return -1;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-compare"
	assert(write_bytes <= count);
#pragma GCC diagnostic pop
	return write_bytes;
}

int read_all(int fd, void *buf, size_t count) {
	ssize_t read_bytes;
	while (count > 0) {
		read_bytes = read_wrapper(fd, buf, count);
		if (read_bytes <= 0) return -1;
		buf   += read_bytes;
		count -= read_bytes;
	}
	return 0;
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

#define SOCKS_VER 5

typedef enum {
	AUTH_NO_AUTHENTICATION = 0,
	AUTH_GSSAPI = 1,
	AUTH_USERNAME_PASSWORD = 2,
	AUTH_NO_ACCEPTABLE_METHODS = 0xFF,
} auth_method_enum;

int socks5_auth(int client_sockfd) {
	static uint8_t buffer[256];								// thread unsafe
	if (read_all(client_sockfd, buffer, 2)) return -2;
	unsigned char ver = buffer[0];
	unsigned char nmethods = buffer[1];
	if (ver != SOCKS_VER) return -1;
	if (nmethods == 0) return -1;
	if (read_all(client_sockfd, buffer, nmethods)) return -2;
	unsigned int i;
	bool method_noauth_found = false;
	for (i=0; i<nmethods; ++i) {
		unsigned char method = buffer[i];
		if (method == AUTH_NO_AUTHENTICATION) {method_noauth_found = true; break;}
	}
	uint8_t resp_buf[2] = {SOCKS_VER};
	if (method_noauth_found) resp_buf[1] = AUTH_NO_AUTHENTICATION;
	else                     resp_buf[1] = AUTH_NO_ACCEPTABLE_METHODS;
	if (write_all(client_sockfd, resp_buf, sizeof(resp_buf))) return -2;
	return (method_noauth_found ? 0 : 1);
}

typedef union {
	uint8_t ipv4[4];
	uint8_t ipv6[16];
	char domain_name[256]; // 255 + 1 for ending '\0'
} address_union;

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

int make_sockaddr(unsigned char addr_type, address_union *address, unsigned int port,
			struct sockaddr **addr_p, socklen_t *addr_len_p) {
	switch (addr_type) {
		case ATYP_IPV4: {
			struct sockaddr_in *connect_sin = malloc(sizeof(struct sockaddr_in));
			if (connect_sin == NULL) perror_and_exit("malloc");
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
			if (connect_sin6 == NULL) perror_and_exit("malloc");
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
			else if (ret != 0) printf_and_exit("getaddrinfo: %s", gai_strerror(ret));
			
			unsigned int addr_len = res->ai_addrlen;
			struct sockaddr *addr = malloc(addr_len);
			if (addr == NULL) perror_and_exit("malloc");
			memcpy(addr, res->ai_addr, addr_len);
			freeaddrinfo(res);
			*addr_p = addr;
			*addr_len_p = addr_len;
			break;
		}
	}
	return 0;
}

int socks5_connect(int client_sockfd, int *connect_sockfd_p) {
	uint8_t buffer[4];
	if (read_all(client_sockfd, buffer, 4)) return -2;
	unsigned char ver       = buffer[0];
	unsigned char cmd       = buffer[1];
	unsigned char reserved  = buffer[2];
	unsigned char addr_type = buffer[3];
	if (ver != SOCKS_VER) return -1;
	if (reserved != 0) return -1;
	if (!(addr_type == ATYP_IPV4 || addr_type == ATYP_DOMAIN || addr_type == ATYP_IPV6)) return -1;
	static address_union address;									// thread unsafe
	switch (addr_type) {
		case ATYP_IPV4: {
			if (read_all(client_sockfd, address.ipv4, 4)) return -2;
			break;
		}
		case ATYP_IPV6: {
			if (read_all(client_sockfd, address.ipv6, 16)) return -2;
			break;
		}
		case ATYP_DOMAIN: {
			if (read_all(client_sockfd, buffer, 1)) return -2;
			unsigned char domain_name_len = buffer[0];
			if (domain_name_len == 0) return -1;
			assert(sizeof(char) == 1);
			if (read_all(client_sockfd, address.domain_name, domain_name_len)) return -2;
			address.domain_name[domain_name_len] = 0;
			break;
		}
	}
	if (read_all(client_sockfd, buffer, 2)) return -2;
	unsigned int port = ntohs(*(uint16_t *)buffer);
	
	uint8_t resp_buf[10] = {
		SOCKS_VER, 0/*rep*/, 0/*rsv*/, ATYP_IPV4,
		0, 0, 0, 0/*bind.ipv4*/,
		0, 0/*bind.port*/
	};
	unsigned char rep;
	if (cmd == CMD_CONNECT) {
		rep = REP_SUCCEEDED;
		
		struct sockaddr *connect_addr;
		socklen_t connect_addr_len;
		int ret = make_sockaddr(addr_type, &address, port, &connect_addr, &connect_addr_len);
		assert(ret >= 0);
		if (ret > 0) {
			rep = ret;
		} else {
			int connect_sockfd = socket(connect_addr->sa_family, SOCK_STREAM, 0);
			if (connect_sockfd < 0) perror_and_exit("socket");
			
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
					if (close(connect_sockfd)) perror_and_exit("close");
				} else perror_and_exit("connect");
			} else {
				*connect_sockfd_p = connect_sockfd;
			}
			
			free(connect_addr);
		}
	} else {
		rep = REP_COMMAND_NOT_SUPPORTED;
	}
	resp_buf[1] = rep;
	if (write_all(client_sockfd, resp_buf, sizeof(resp_buf))) {
		if (rep == REP_SUCCEEDED) {
			if (close(*connect_sockfd_p)) perror_and_exit("close");
		}
		return -2;
	}
	return (rep == REP_SUCCEEDED ? 0 : 1);
}

#define data_buf_size (1024*1024)
#define fds_count 2

int transfer_data(int client_sockfd, int connect_sockfd) {
	static uint8_t data_buf[data_buf_size];						// thread unsafe
	struct pollfd fds[fds_count] = {
		{.fd =  client_sockfd, .events = POLLIN},
		{.fd = connect_sockfd, .events = POLLIN},
	};
	int fd_to_write[fds_count] = {connect_sockfd, client_sockfd};
	int poll_count;
	unsigned int i;
	ssize_t read_bytes;
	while (true) {
		poll_count = poll(fds, fds_count, -1);
		assert(poll_count != 0);
		if (poll_count < 0) perror_and_exit("poll");
		
		for (i=0; i<fds_count && poll_count>0; ++i) {
			if (fds[i].revents == 0) continue;
			--poll_count;
			if (fds[i].revents & POLLIN) {
				read_bytes = read_wrapper(fds[i].fd, data_buf, data_buf_size);
				if (read_bytes <= 0) return 1;
				if (write_all(fd_to_write[i], data_buf, read_bytes)) return 1;
			}
			if (fds[i].revents & POLLHUP) return 1;
			if ((fds[i].revents & ~(POLLIN | POLLHUP)) != 0) perror_and_exit("poll error event");
		}
	}
}

void socks5(int client_sockfd) {
	do {
		if (socks5_auth(client_sockfd)) break;
		int connect_sockfd;
		if (socks5_connect(client_sockfd, &connect_sockfd)) break;
		transfer_data(client_sockfd, connect_sockfd);
		if (close(connect_sockfd)) perror_and_exit("close");
	} while (false);
	if (close(client_sockfd)) perror_and_exit("close");
}

#define MAXPENDING 5

int main(int argc, char* argv[]) {
	(void)argc;
	(void)argv;
	if (signal(SIGCHLD, SIG_IGN) == SIG_ERR) perror_and_exit("signal");

	int port = 9090;

	int server_sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (server_sockfd < 0) perror_and_exit("socket");
	
	int yes = 1;
	if (setsockopt(server_sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes))) perror_and_exit("setsockopt");
	
	const struct sockaddr_in server_sin = {
		.sin_family = AF_INET,
		.sin_port = htons(port),
		.sin_addr = {.s_addr = htonl(INADDR_LOOPBACK)}
	};
	if (bind(server_sockfd, (const struct sockaddr*) &server_sin, sizeof(server_sin))) perror_and_exit("bind");
	
	if (listen(server_sockfd, MAXPENDING)) perror_and_exit("listen");
	
	struct sockaddr_in client_sin;
	socklen_t client_sin_len;
	int client_sockfd;
	while (true) {
		client_sin_len = sizeof(client_sin);
		client_sockfd = accept(server_sockfd, (struct sockaddr *)&client_sin, &client_sin_len);
		if (client_sockfd < 0) perror_and_exit("accept");

		pid_t pid = fork();
		if (pid < 0) perror_and_exit("fork");
		if (pid == 0) {
			if (close(server_sockfd)) perror_and_exit("close");
			socks5(client_sockfd);
			exit(EXIT_SUCCESS);
		} else {
			if (close(client_sockfd)) perror_and_exit("close");
		}
	}
	
	if (close(server_sockfd)) perror_and_exit("close");
	printf("SUCCESS\n");
	return 0;
}

