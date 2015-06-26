#ifndef TRANSFER_H
#define TRANSFER_H

#include <event2/event.h>

void transfer_construct_and_run(struct event_base *base, int fd0, int fd1);
void transfer_destruct_all(struct event_base *base);

#endif/*TRANSFER_H*/

