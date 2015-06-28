#include <event2/event.h>
#include <event2/dns.h>
#include <event2/util.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>

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
} signal_cb_arg_struct;

void signal_cb(evutil_socket_t signum, short ev_flag, void *arg) {
	signal_cb_arg_struct *signal_cb_arg = (signal_cb_arg_struct *)arg;
	assert(ev_flag == EV_SIGNAL);
	(void)ev_flag;
	switch(signum) {
		case SIGINT: {
			if (event_base_loopbreak(signal_cb_arg->base)) everror_and_exit("event_base_loopbreak");
			break;
		}
	}
}

typedef struct {
	struct event_base *base;
	struct evdns_base *dns_base;
} server_accept_cb_arg_struct;

void server_accept_cb(evutil_socket_t server_sockfd, short ev_flag, void *arg) {
	server_accept_cb_arg_struct *server_accept_cb_arg = (server_accept_cb_arg_struct *)arg;
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
	
	client_handler_construct_and_run(server_accept_cb_arg->base, server_accept_cb_arg->dns_base, client_sockfd);
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

#define MAXPENDING 5

void run() {
	/* setup server socket */
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
	
	if (listen(server_sockfd, MAXPENDING)) perror_and_exit("listen");

	/* setup and run event loop */
	struct event_base *base = event_base_new();
	if (base == NULL) everror_and_exit("event_base_new");
	
	struct evdns_base *dns_base = evdns_base_new(base, EVDNS_BASE_INITIALIZE_NAMESERVERS);
	if (dns_base == NULL) everror_and_exit("evdns_base_new");
	if (evdns_base_set_option(dns_base, "randomize-case", "0")) everror_and_exit("evdns_base_set_option");
	
	signal_cb_arg_struct signal_cb_arg = {.base = base};
	struct event *int_signal_event = evsignal_new(base, SIGINT, signal_cb, &signal_cb_arg);
	if (int_signal_event == NULL) everror_and_exit("evsignal_new");
	if (event_add(int_signal_event, NULL)) everror_and_exit("event_add");
	
	server_accept_cb_arg_struct server_accept_cb_arg = {.base = base, .dns_base = dns_base};
	struct event *server_event = event_new(base, server_sockfd, EV_READ|EV_PERSIST,
			server_accept_cb, &server_accept_cb_arg);
	if (server_event == NULL) everror_and_exit("event_new");
	if (event_add(server_event, NULL)) everror_and_exit("event_add");
	
	if (event_base_dispatch(base)) everror_and_exit("event_base_dispatch");
	
	/* close all */
	if (event_del(int_signal_event)) everror_and_exit("event_del");
	event_free(int_signal_event);
	
	if (event_del(server_event)) everror_and_exit("event_del");
	event_free(server_event);
	
	//free_all_client_read_events(base);
	
	event_base_free(base);
	
	if (close(server_sockfd)) perror_and_exit("close");
}

int main(int argc, char* argv[]) {
	(void)argc;
	(void)argv;
	run();
	printf("DONE\n");
	return 0;
}
