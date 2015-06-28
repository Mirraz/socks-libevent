#include <event2/event.h>
#include <event2/dns.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
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
	
	struct sockaddr_in client_sin;
	socklen_t client_sin_len = sizeof(client_sin);
	int client_sockfd = accept(server_sockfd, (struct sockaddr *)&client_sin, &client_sin_len);
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

void setup_server_socket(global_resources_struct *global_resources) {
	unsigned int port = 9091;

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

void run() {
	global_resources_struct global_resources;
	setup_server_socket(&global_resources);
	setup_events(&global_resources);
	listen_server_socket(&global_resources);
	if (event_base_dispatch(global_resources.bases.base)) everror_and_exit("event_base_dispatch");
	close_all(&global_resources);
}

int main(int argc, char* argv[]) {
	(void)argc;
	(void)argv;
	run();
	printf("DONE\n");
	return 0;
}
