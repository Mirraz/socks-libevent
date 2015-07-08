#ifndef HANDLE_CLIENT_H
#define HANDLE_CLIENT_H

#include <event2/event.h>
#include <event2/dns.h>
#include <stdbool.h>

void client_handler_construct_and_run(struct event_base *base, struct evdns_base *dns_base, int client_sockfd);
bool client_handler_events_filter(const struct event *event);
void client_handler_destruct(struct event *event);

#endif/*HANDLE_CLIENT_H*/

