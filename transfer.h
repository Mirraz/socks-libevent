#ifndef TRANSFER_H
#define TRANSFER_H

#include <event2/event.h>
#include <stdbool.h>

void transfer_construct_and_run(struct event_base *base, int fd0, int fd1);
bool transfer_events_filter(const struct event *event);
void transfer_destruct(struct event *event);

#endif/*TRANSFER_H*/

