#include <event2/event.h>
#include <event2/dns.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <getopt.h>
#include <memory.h>
#include <limits.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>

#include "transfer.h"
#include "handle_client.h"
#include "common.h"
#include "stack.h"

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

void everror_and_exit(const char *s) {
	perror_and_exit(s);
}

typedef struct {
	struct sockaddr_storage addr;
	socklen_t addr_len;
} server_bind_addr_struct;

typedef struct {
	server_bind_addr_struct server_bind_addr;
	size_t transfer_buffer_size;
} global_config_struct;

typedef struct {
	int server_sockfd;
	client_handler_common_struct bases;
	struct event *int_signal_event;
	struct event *server_event;
} global_resources_struct;

#define INTERRUPT_SIGNAL SIGINT

void signal_cb(evutil_socket_t signum, short ev_flag, void *arg) {
	struct event_base *base = (struct event_base *)arg;
	assert(ev_flag == EV_SIGNAL);
	(void)ev_flag;
	switch(signum) {
		case INTERRUPT_SIGNAL: {
			if (event_base_loopbreak(base)) {everror("event_base_loopbreak"); return;}
			break;
		}
		default:
			assert(0);
	}
}

void server_accept_cb(evutil_socket_t server_sockfd, short ev_flag, void *arg) {
	client_handler_common_struct *bases = (client_handler_common_struct *)arg;
	assert(ev_flag == EV_READ);
	(void)ev_flag;
	
	int client_sockfd = accept(server_sockfd, NULL, NULL);
	if (client_sockfd < 0) {perror("accept"); return;}
	
	if (make_socket_nonblocking(client_sockfd)) {
		perror("fcntl");
		if (close(client_sockfd)) perror("close");
		return;
	}
	
	client_handler_construct_and_run(bases, client_sockfd);
}

void setup_server_socket(global_config_struct *global_config, global_resources_struct *global_resources) {
	server_bind_addr_struct *server_bind_addr = &global_config->server_bind_addr;
	struct sockaddr_storage *addr = &server_bind_addr->addr;
	socklen_t addr_len = server_bind_addr->addr_len;

	int server_sockfd = socket(addr->ss_family, SOCK_STREAM, 0);
	if (server_sockfd < 0) perror_and_exit("socket");
	
	int yes = 1;
	if (setsockopt(server_sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes))) perror_and_exit("setsockopt");
	
	if (bind(server_sockfd, (struct sockaddr *)addr, addr_len)) perror_and_exit("bind");
	
	global_resources->server_sockfd = server_sockfd;
}

#define MAXPENDING 5

void listen_server_socket(global_resources_struct *global_resources) {
	if (listen(global_resources->server_sockfd, MAXPENDING)) perror_and_exit("listen");
}

void setup_events(global_resources_struct *global_resources) {
	struct event_base *base = event_base_new();
	if (base == NULL) everror_and_exit("event_base_new");
	global_resources->bases.base = base;
	
	struct evdns_base *dns_base = evdns_base_new(base, EVDNS_BASE_INITIALIZE_NAMESERVERS);
	if (dns_base == NULL) everror_and_exit("evdns_base_new");
	if (evdns_base_set_option(dns_base, "randomize-case", "0")) everror_and_exit("evdns_base_set_option");
	global_resources->bases.dns_base = dns_base;
	
	struct event *int_signal_event = evsignal_new(base, INTERRUPT_SIGNAL, signal_cb, global_resources->bases.base);
	if (int_signal_event == NULL) everror_and_exit("evsignal_new");
	global_resources->int_signal_event = int_signal_event;
	if (event_add(int_signal_event, NULL)) everror_and_exit("event_add");
	
	struct event *server_event = event_new(base, global_resources->server_sockfd, EV_READ|EV_PERSIST,
			server_accept_cb, &global_resources->bases);
	if (server_event == NULL) everror_and_exit("event_new");
	global_resources->server_event = server_event;
	if (event_add(server_event, NULL)) everror_and_exit("event_add");
}

void dispatch(global_resources_struct *global_resources) {
	if (event_base_dispatch(global_resources->bases.base)) everror_and_exit("event_base_dispatch");
}

typedef bool (*events_filter_type)(const struct event *event);
typedef void (*event_cb_arg_destruct_type)(struct event *event);

typedef struct {
	stack_struct events_stack;
	events_filter_type events_filter;
} enum_clients_events_cb_arg_struct;

int enum_clients_events_cb(const struct event_base *base, const struct event *event, void *arg) {
	(void)base;
	enum_clients_events_cb_arg_struct *cb_arg = (enum_clients_events_cb_arg_struct *)arg;
	if (cb_arg->events_filter(event)) stack_push(&cb_arg->events_stack, event);
	return 0;
}

void free_all_clients_events(struct event_base *base, events_filter_type filter, event_cb_arg_destruct_type destruct) {
	enum_clients_events_cb_arg_struct arg;
	stack_new(&arg.events_stack);
	arg.events_filter = filter;
	while (event_base_foreach_event(base, enum_clients_events_cb, &arg) > 0);
	while (!stack_is_empty(&arg.events_stack)) {
		struct event *event = stack_pop(&arg.events_stack);
		assert(event != NULL);
		if (event_del(event)) everror("event_del");
		destruct(event);
		event_free(event);
	}
}

void close_all(global_resources_struct *global_resources) {
	if (event_del(global_resources->int_signal_event)) everror("event_del");
	event_free(global_resources->int_signal_event);
	
	if (event_del(global_resources->server_event)) everror("event_del");
	event_free(global_resources->server_event);
	
	free_all_clients_events(global_resources->bases.base, client_handler_events_filter, client_handler_destruct);
	free_all_clients_events(global_resources->bases.base, transfer_events_filter, transfer_destruct);
	
	evdns_base_free(global_resources->bases.dns_base, 0);
	event_base_free(global_resources->bases.base);
	
	if (close(global_resources->server_sockfd)) perror("close");
}

void run(global_config_struct *global_config) {
	global_resources_struct global_resources;
	
	setup_server_socket(global_config, &global_resources);
	global_resources.bases.transfer_buffer_size = global_config->transfer_buffer_size;
	setup_events(&global_resources);
	listen_server_socket(&global_resources);
	dispatch(&global_resources);
	close_all(&global_resources);
}

#define default_transfer_buffer_size (64*1024)
#define default_bind_port 1080
#define default_bind_addr INADDR_LOOPBACK

#if default_transfer_buffer_size > SSIZE_MAX
#	error
#endif

#define LARGE_PORT_NUMBER 65536
#if default_bind_port <=0 || default_bind_port >= LARGE_PORT_NUMBER
#	error
#endif

void print_help(const char *prog_name) {
	printf(
		"Usage: %s [-hps] [--bind-ip <ip>|-bind-ipv6 <ipv6>]\n"
		"    -h, --help               display this help and exit\n"
		"        --bind-ip <ip>       bind to IP address <ip> (default: 127.0.0.1)\n"
		"        --bind-ipv6 <ipv6>   bind to IPv6 address <ipv6>\n"
		"    -p, --port <port>        bind to <port> (default: %u)\n"
		"    -s, --size <size>        assing two transfer buffers of <size> bytes\n"
		"                             for every client (default: 64K)\n",
#if default_transfer_buffer_size != 64*1024
#	warning
#endif
		prog_name, default_bind_port
	);
}

typedef struct {
	char *bind_ipv4;
	char *bind_ipv6;
	char *bind_port;
	char *transfer_buffer_size;
} cmdline_args_struct;

void parse_args(int argc, char* argv[], cmdline_args_struct *args) {
	args->bind_ipv4 = NULL;
	args->bind_ipv6 = NULL;
	args->bind_port = NULL;
	args->transfer_buffer_size = NULL;
	
	static const char optstring[] = "hp:s:";
	static const struct option longopts[] = {
		{"help",      no_argument,       0, 'h'},
		{"bind-ip",   required_argument, 0, '4'},
		{"bind-ipv6", required_argument, 0, '6'},
		{"port",      required_argument, 0, 'p'},
		{"size",      required_argument, 0, 's'},
		{0, 0, 0, 0}
	};
	int longindex = 0;
	int c;
	while (1) {
		c = getopt_long (argc, argv, optstring, longopts, &longindex);
		if (c == -1) break;
		switch (c) {
			case 'h':
				print_help(argv[0]);
				exit(EXIT_SUCCESS);
				break;
			case '4':
				args->bind_ipv4 = optarg;
				break;
			case '6':
				args->bind_ipv6 = optarg;
				break;
			case 'p':
				args->bind_port = optarg;
				break;
			case 's':
				args->transfer_buffer_size = optarg;
				break;
			default:
				goto print_help_and_exit_err;
		}
	}

	if (optind < argc) goto print_help_and_exit_err;
	
	if (args->bind_ipv4 != NULL && args->bind_ipv6 != NULL) goto print_help_and_exit_err;
	
	return;

print_help_and_exit_err:
	print_help(argv[0]);
	exit(EXIT_FAILURE);
}

void process_args(int argc, char* argv[], global_config_struct *global_config) {
	cmdline_args_struct args_;
	cmdline_args_struct *args = &args_;
	parse_args(argc, argv, args);
	
	in_port_t port;
	{
		if (args->bind_port != NULL) {
			int p = atoi(args->bind_port);
			if (p <= 0 || p >= LARGE_PORT_NUMBER)
				printf_and_exit("invalid port");
			else
				port = (in_port_t)p;
		} else {
			port = default_bind_port;
		}
	}
	
	{
		server_bind_addr_struct *server_bind_addr = &global_config->server_bind_addr;
		
		assert(args->bind_ipv4 == NULL || args->bind_ipv6 == NULL);
		if (args->bind_ipv6 != NULL) {
			assert(sizeof(server_bind_addr->addr) >= sizeof(struct sockaddr_in6));
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&server_bind_addr->addr;
			memset(sin6, 0, sizeof(struct sockaddr_in6));
			sin6->sin6_family = AF_INET6;
			sin6->sin6_port = htons(port);
			int ret = inet_pton(AF_INET6, args->bind_ipv6, &sin6->sin6_addr);
			if (ret < 0) perror_and_exit("inet_pton");
			else if (ret != 1) printf_and_exit("invalid ipv6 address");
			
			server_bind_addr->addr_len = sizeof(struct sockaddr_in6);
		} else {
			assert(sizeof(server_bind_addr->addr) >= sizeof(struct sockaddr_in));
			struct sockaddr_in *sin = (struct sockaddr_in *)&server_bind_addr->addr;
			sin->sin_family = AF_INET;
			sin->sin_port = htons(port);
			if (args->bind_ipv4 == NULL) {
				sin->sin_addr.s_addr = htonl(default_bind_addr);
			} else {
				if (!inet_aton(args->bind_ipv4, &sin->sin_addr)) printf_and_exit("invalid ip address");
			}
			
			server_bind_addr->addr_len = sizeof(struct sockaddr_in);
		}
	}
	
	size_t transfer_buffer_size;
	{
		if (args->transfer_buffer_size != NULL) {
			long long int size = atoll(args->transfer_buffer_size);
			if (size <= 0)
				printf_and_exit("invalid transfer buffer size");
			else if (size == LONG_MAX || size > SSIZE_MAX)
				printf_and_exit("too large transfer buffer size");
			else
				transfer_buffer_size = (size_t)size;
		} else {
			transfer_buffer_size = default_transfer_buffer_size;
		}
	}
	global_config->transfer_buffer_size = transfer_buffer_size;
}

int main(int argc, char* argv[]) {
	global_config_struct global_config;
	process_args(argc, argv, &global_config);
	run(&global_config);
#ifndef NDEBUG
	printf_err("DONE");
#endif
	return 0;
}

