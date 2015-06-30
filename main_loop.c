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
	struct event_base *base;
	struct evdns_base *dns_base;
} bases_struct;

typedef struct {
	int server_sockfd;
	bases_struct bases;
	struct event *int_signal_event;
	struct event *server_event;
} global_resources_struct;

void signal_cb(evutil_socket_t signum, short ev_flag, void *arg) {
	struct event_base *base = (struct event_base *)arg;
	assert(ev_flag == EV_SIGNAL);
	(void)ev_flag;
	switch(signum) {
		case SIGINT: {
			if (event_base_loopbreak(base)) {everror("event_base_loopbreak"); return;}
			break;
		}
	}
}

void server_accept_cb(evutil_socket_t server_sockfd, short ev_flag, void *arg) {
	bases_struct *bases = (bases_struct *)arg;
	assert(ev_flag == EV_READ);
	(void)ev_flag;
	
	int client_sockfd = accept(server_sockfd, NULL, NULL);
	if (client_sockfd < 0) {perror("accept"); return;}
	
	if (make_socket_nonblocking(client_sockfd)) {
		perror("fcntl");
		if (close(client_sockfd)) perror("close");
		return;
	}
	
	client_handler_construct_and_run(bases->base, bases->dns_base, client_sockfd);
}

// TODO
/*
struct event_list_node_struct_;
typedef struct event_list_node_struct_ event_list_node_struct;
struct event_list_node_struct_{
	struct event *event;
	event_list_node_struct *next;
};

int enum_client_read_events_cb(const struct event_base *base, const struct event *event, void *arg) {
	(void)base;
	event_callback_fn cb = event_get_callback(event);
	if (cb != &client_read_cb) return 0;

	event_list_node_struct **event_list_tail_p = (event_list_node_struct **)arg;
	event_list_node_struct *event_list_node_next = malloc(sizeof(event_list_node_struct));
	if (event_list_node_next == NULL) perror_and_exit("malloc");
	event_list_node_next->event = (struct event *)event;
	event_list_node_next->next = NULL;
	(*event_list_tail_p)->next = event_list_node_next;
	*event_list_tail_p = event_list_node_next;
	return 0;
}

void free_all_client_read_events(struct event_base *base) {
	event_list_node_struct *event_list_head = malloc(sizeof(event_list_node_struct));
	if (event_list_head == NULL) perror_and_exit("malloc");
	event_list_head->event = NULL;
	event_list_head->next = NULL;
	event_list_node_struct *event_list_tail = event_list_head;
	while(event_base_foreach_event(base, enum_client_read_events_cb, &event_list_tail) > 0);
	(void)event_list_tail;
	event_list_node_struct *event_list_node = event_list_head;
	event_list_head = event_list_head->next;
	free(event_list_node);
	
	while(event_list_head != NULL) {
		event_list_node = event_list_head;
		event_list_head = event_list_head->next;
		
		struct event *event = event_list_node->event;
		void *arg = event_get_callback_arg(event);
		assert(arg != NULL);
		evutil_socket_t client_sockfd = event_get_fd(event);
		assert(client_sockfd >= 0);
		del_and_free_client_read_event(event, arg, client_sockfd);
		
		free(event_list_node);
	}
}
*/

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
	global_resources->bases.dns_base = dns_base;
	if (evdns_base_set_option(dns_base, "randomize-case", "0")) everror_and_exit("evdns_base_set_option");
	
	struct event *int_signal_event = evsignal_new(base, SIGINT, signal_cb, global_resources->bases.base);
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

void close_all(global_resources_struct *global_resources) {
	if (event_del(global_resources->int_signal_event)) everror("event_del");
	event_free(global_resources->int_signal_event);
	
	if (event_del(global_resources->server_event)) everror("event_del");
	event_free(global_resources->server_event);
	
	client_handler_destruct_all(global_resources->bases.base);
	transfer_destruct_all(global_resources->bases.base);
	
	evdns_base_free(global_resources->bases.dns_base, 0);
	
	event_base_free(global_resources->bases.base);
	
	if (close(global_resources->server_sockfd)) perror("close");
}

void run(global_config_struct *global_config) {
	global_resources_struct global_resources;
	
	setup_server_socket(global_config, &global_resources);
	setup_events(&global_resources);
	listen_server_socket(&global_resources);
	dispatch(&global_resources);
	close_all(&global_resources);
}

void print_help() {
	// TODO
	printf("help\n");
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
				print_help();
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
	if (args->bind_port == NULL) goto print_help_and_exit_err;
	
	return;

print_help_and_exit_err:
	print_help();
	exit(EXIT_FAILURE);
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

