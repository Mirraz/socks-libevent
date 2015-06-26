#ifndef HANDLE_CLIENT_H
#define HANDLE_CLIENT_H

#include <event2/event.h>
#include <event2/dns.h>

void client_handler_construct_and_run(struct event_base *base, struct evdns_base *dns_base, int client_sockfd);
void client_handler_destruct_all(struct event_base *base);

#endif/*HANDLE_CLIENT_H*/

