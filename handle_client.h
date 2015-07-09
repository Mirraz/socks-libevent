#ifndef HANDLE_CLIENT_H
#define HANDLE_CLIENT_H

#include <event2/event.h>
#include <event2/dns.h>
#include <stdbool.h>

#include "set.h"

void client_handler_construct_and_run(struct event_base *base, struct evdns_base *dns_base,
		set_struct *dns_requests, int client_sockfd);
bool client_handler_events_filter(const struct event *event);
void client_handler_destruct(struct event *event);
typedef void client_handler_dns_req_struct;
void client_handler_destruct_dns_req(client_handler_dns_req_struct *dns_req);

#endif/*HANDLE_CLIENT_H*/

