#include <event2/event.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <unistd.h>
#include <errno.h>
#ifndef NDEBUG
#	include <limits.h>
#endif

#include "transfer.h"
#include "common.h"

struct transfer_struct_;
typedef struct transfer_struct_ transfer_struct;
struct transfer_struct_ {
	transfer_struct *reverse_transfer;
	struct event *event_read;
	struct event *event_write; // write to reverse_transfer->fd
	size_t buffer_size;
	size_t head_begin;
	size_t head_end;
	size_t tail_end;
	int fd;
	bool event_read_active;
	bool event_write_active;
	uint8_t buffer[];
};

static void destruct_half(transfer_struct *transfer) {
	if (transfer->event_read_active)
		if (event_del(transfer->event_read)) everror("event_del");
	if (transfer->event_write_active)
		if (event_del(transfer->event_write)) everror("event_del");
	event_free(transfer->event_read);
	event_free(transfer->event_write);
	if (close(transfer->fd)) perror("close");
	free(transfer);
}

static void destruct(transfer_struct *transfer) {
	destruct_half(transfer->reverse_transfer);
	destruct_half(transfer);
}

/*
[hb .  .  .  .  .  .  .  .  he .  . ]
                            tb
                            te
[.  .  .  .  .  hb .  .  .  he .  . ]
                            tb
                            te
[tb .  .  te .  hb .  .  .  he .  . ]
[hb .  .  he .  .  .  .  .  .  .  . ]
          tb
          te

											read	write1
0	0 = hb = he = tb = te = 0		empty	1,2		-
1	0 = hb < he = tb = te < sz				1,2		3,0
2	0 = hb < he = tb = te = sz		full	-		3,0
3	0 < hb < he = tb = te <= sz				3,4,5	3,0
4	0 = tb < te < hb < he <= sz				4,5		4,(1)
5	0 = tb < te = hb < he <= sz		full	-		4,(1)
*/

static inline bool is_full(transfer_struct *transfer) {
	return (transfer->tail_end == transfer->head_begin && transfer->head_begin != 0) ||
			(transfer->head_begin == 0 && transfer->head_end == transfer->buffer_size);
}

static inline bool is_not_full(transfer_struct *transfer) {
	return (transfer->tail_end < transfer->head_begin) ||
			(transfer->tail_end == transfer->head_end && (transfer->head_begin > 0 || transfer->head_end < transfer->buffer_size));
}

static inline bool is_empty(transfer_struct *transfer) {
	return transfer->head_begin == transfer->head_end;
}

static inline bool is_not_empty(transfer_struct *transfer) {
	return !is_empty(transfer);
}

/* return:
	< 0 -- -errno
	= 0 -- success
	= 1 -- success, buffer has become full
*/
static int read_data(int sockfd, transfer_struct *transfer) {
	if (transfer->tail_end < transfer->head_end) { // tail exists
		assert(transfer->tail_end < transfer->head_begin); // buffer is not full
		ssize_t bytes = read_wrapper(sockfd, &transfer->buffer[transfer->tail_end],
				transfer->head_begin - transfer->tail_end);
		if (bytes <= 0) return bytes;
		assert((size_t)bytes <= transfer->head_begin - transfer->tail_end);
		transfer->tail_end += bytes;
		return (transfer->tail_end == transfer->head_begin); // buffer has become full
	} else {
		assert(transfer->tail_end == transfer->head_end); // tail doesn't exist
		size_t free_in_head_size = transfer->head_begin - 0;
		size_t free_in_tail_size = transfer->buffer_size - transfer->head_end;
		assert(free_in_head_size > 0 || free_in_tail_size > 0); // buffer is not full
		if (free_in_head_size > free_in_tail_size) {
			// read to new tail
			ssize_t bytes = read_wrapper(sockfd, &transfer->buffer[0], free_in_head_size);
			if (bytes <= 0) return bytes;
			assert((size_t)bytes <= free_in_head_size);
			transfer->tail_end = bytes;
			return (transfer->tail_end == transfer->head_begin); // buffer has become full
		} else {
			ssize_t bytes = read_wrapper(sockfd, &transfer->buffer[transfer->head_end], free_in_tail_size);
			if (bytes <= 0) return bytes;
			assert((size_t)bytes <= free_in_tail_size);
			transfer->head_end += bytes;
			transfer->tail_end = transfer->head_end;
			return (transfer->head_begin == 0 && transfer->head_end == transfer->buffer_size); // buffer has become full
		}
	}
}

static inline void reset_ptrs(transfer_struct *transfer) {
	transfer->head_begin = 0;
	transfer->head_end = 0;
	transfer->tail_end = 0;
}

/* return:
	< 0 -- -errno
	= 0 -- success
	= 1 -- success, buffer has become empty
*/
static int write_data(int sockfd, transfer_struct *transfer) {
	assert(transfer->head_begin < transfer->head_end); // buffer is not empty
	ssize_t bytes = write_wrapper(sockfd, &transfer->buffer[transfer->head_begin],
			transfer->head_end - transfer->head_begin);
	if (bytes <= 0) return bytes;
	assert((size_t)bytes <= transfer->head_end - transfer->head_begin);
	transfer->head_begin += bytes;
	if (transfer->head_begin < transfer->head_end) { // not all head was writed
		return 0;
	} else {
		assert(transfer->head_begin == transfer->head_end); // all head was writed
		if (transfer->tail_end < transfer->head_end) { // tail exists
			transfer->head_begin = 0;
			transfer->head_end = transfer->tail_end;
			assert(transfer->head_begin < transfer->head_end);
			ssize_t bytes = write_wrapper(sockfd, &transfer->buffer[transfer->head_begin],
					transfer->head_end - transfer->head_begin);
			if (bytes <= 0) return bytes;
			assert((size_t)bytes <= transfer->head_end - transfer->head_begin);
			transfer->head_begin += bytes;
			if (transfer->head_begin < transfer->head_end) return 0;
			else {reset_ptrs(transfer); return 1;} // buffer has become full
		} else { // tail doesn't exist
			assert(transfer->tail_end == transfer->head_end);
			reset_ptrs(transfer); return 1; // buffer has become full
		}
	}
}

static void read_cb(evutil_socket_t sockfd, short ev_flag, void *arg) {
	assert(ev_flag == EV_READ);
	(void)ev_flag;
	transfer_struct *transfer = (transfer_struct *)arg;
	assert(transfer->fd == sockfd);
	assert(is_not_full(transfer));
	
	{
		int ret = read_data(sockfd, transfer);
		if (ret < 0) {destruct(transfer); return;}
	}
	
	if (!transfer->event_write_active && is_not_empty(transfer)) {
		int ret = write_data(transfer->reverse_transfer->fd, transfer);
		if (ret < 0) {
			destruct(transfer); return;
		} else if (ret == 0) {
			if (event_add(transfer->event_write, NULL)) {everror("event_add"); destruct(transfer); return;}
			transfer->event_write_active = true;
		}
	}
	
	if (is_full(transfer)) {
		transfer->event_read_active = false;
		if (event_del(transfer->event_read)) {everror("event_del"); destruct(transfer); return;}
	}
}

static void write_cb(evutil_socket_t sockfd, short ev_flag, void *arg) {
	assert(ev_flag == EV_WRITE);
	(void)ev_flag;
	transfer_struct *transfer = (transfer_struct *)arg;
	assert(transfer->reverse_transfer->fd == sockfd);
	assert(is_not_empty(transfer));
	
	{
		int ret = write_data(sockfd, transfer);
		if (ret < 0) {destruct(transfer); return;}
	}
	
	if (!transfer->event_read_active && is_not_full(transfer)) {
		int ret = read_data(transfer->reverse_transfer->fd, transfer);
		if (ret < 0) {
			destruct(transfer); return;
		} else if (ret == 0) {
			if (event_add(transfer->event_read, NULL)) {everror("event_add"); destruct(transfer); return;}
			transfer->event_read_active = true;
		}
	}
	
	if (is_empty(transfer)) {
		transfer->event_write_active = false;
		if (event_del(transfer->event_write)) {everror("event_del"); destruct(transfer); return;}
	}
}

void transfer_construct_and_run(struct event_base *base, size_t buffer_size, int fd0, int fd1) {
	assert(buffer_size > 0 && buffer_size < SSIZE_MAX);
	transfer_struct *transfer0 = malloc(sizeof(transfer_struct) + buffer_size);
	if (transfer0 == NULL) {perror("malloc"); goto close_all;}
	transfer0->fd = fd0;
	transfer0->buffer_size = buffer_size;
	transfer0->head_begin = 0;
	transfer0->head_end = 0;
	transfer0->tail_end = 0;
	transfer0->event_write_active = false;
	
	transfer_struct *transfer1 = malloc(sizeof(transfer_struct) + buffer_size);
	if (transfer1 == NULL) {perror("malloc"); goto free_transfer0;}
	transfer1->fd = fd1;
	transfer1->buffer_size = buffer_size;
	transfer1->head_begin = 0;
	transfer1->head_end = 0;
	transfer1->tail_end = 0;
	transfer1->event_write_active = false;
	
	transfer0->reverse_transfer = transfer1;
	transfer1->reverse_transfer = transfer0;
	
	struct event *event_read0 = event_new(base, fd0, EV_READ|EV_PERSIST, read_cb, transfer0);
	if (event_read0 == NULL) {everror("event_new"); goto free_transfer1;}
	transfer0->event_read = event_read0;
	
	struct event *event_write0 = event_new(base, fd1, EV_WRITE|EV_PERSIST, write_cb, transfer0);
	if (event_write0 == NULL) {everror("event_new"); goto free_event_read0;}
	transfer0->event_write = event_write0;
	
	struct event *event_read1 = event_new(base, fd1, EV_READ|EV_PERSIST, read_cb, transfer1);
	if (event_read1 == NULL) {everror("event_new"); goto free_event_write0;}
	transfer1->event_read = event_read1;
	
	struct event *event_write1 = event_new(base, fd0, EV_WRITE|EV_PERSIST, write_cb, transfer1);
	if (event_write1 == NULL) {everror("event_new"); goto free_event_read1;}
	transfer1->event_write = event_write1;
	
	if (event_add(event_read0, NULL)) {everror("event_add"); goto free_event_write1;}
	transfer0->event_read_active = true;
	
	if (event_add(event_read1, NULL)) {everror("event_add"); goto del_event_read0;}
	transfer1->event_read_active = true;
	
	return;
	
//del_event_read1:
//	if (event_del(event_read1)) everror("event_del");
del_event_read0:
	if (event_del(event_read0)) everror("event_del");
free_event_write1:
	event_free(event_write1);
free_event_read1:
	event_free(event_read1);
free_event_write0:
	event_free(event_write0);
free_event_read0:
	event_free(event_read0);
free_transfer1:
	free(transfer1);
free_transfer0:
	free(transfer0);
close_all:
	if (close(fd0)) perror("close");
	if (close(fd1)) perror("close");
}

bool transfer_events_filter(const struct event *event) {
	event_callback_fn cb = event_get_callback(event);
	return (cb == read_cb || cb == write_cb);
}

void transfer_destruct(struct event *event) {
	event_callback_fn cb = event_get_callback(event);
	transfer_struct *transfer = (transfer_struct *)event_get_callback_arg(event);
	assert(transfer != NULL);
	assert(event == transfer->event_read || event == transfer->event_write);
	assert((cb == read_cb && transfer->event_read_active) || (cb == write_cb && transfer->event_write_active));
	
	if (cb == read_cb) {
		if (transfer->event_write_active) {
			transfer->event_read_active = false;
			transfer->event_read = NULL;
			return;
		} else {
			if (transfer->event_write != NULL) event_free(transfer->event_write);
		}
	} else {
		assert(cb == write_cb);
		if (transfer->event_read_active) {
			transfer->event_write_active = false;
			transfer->event_write = NULL;
			return;
		} else {
			if (transfer->event_read != NULL) event_free(transfer->event_read);
		}
	}
	
	if (close(transfer->fd)) perror("close");
	free(transfer);
}

