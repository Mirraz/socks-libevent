#ifndef HANDLE_CLIENT_H
#define HANDLE_CLIENT_H

#include <event2/event.h>
#include <event2/dns.h>
#include <stdbool.h>

typedef struct {
	struct event_base *base;
	struct evdns_base *dns_base;
	size_t transfer_buffer_size;
} client_handler_common_struct;

void client_handler_construct_and_run(client_handler_common_struct *common, int client_sockfd);
bool client_handler_events_filter(const struct event *event);
void client_handler_destruct(struct event *event);
typedef void client_handler_dns_req_struct;
void client_handler_destruct_dns_req(client_handler_dns_req_struct *dns_req);

#endif/*HANDLE_CLIENT_H*/

