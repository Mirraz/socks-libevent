#include <event2/event.h>
#include <event2/dns.h>
#include <event2/util.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <unistd.h>

#include "handle_client.h"
#include "transfer.h"
#include "socks_proto.h"
#include "task.h"
#include "common.h"
#include "set.h"

typedef struct {
	client_handler_common_struct *common;
	union {
		struct event *read;
		struct event *write;
		struct event *connect_write;
		struct {
			bool setting_up;
			struct evdns_getaddrinfo_request *ev;
		} getaddrinfo;
	} events;
	socks5_arg_struct socks5_arg;
} client_data_struct;

static void destruct_no_close(client_data_struct *client_data) {
	free(client_data);
}

static void destruct(client_data_struct *client_data) {
	int client_sockfd = get_client_sockfd(&client_data->socks5_arg);
	if (close(client_sockfd)) perror("close");
	int connect_sockfd = get_connect_sockfd(&client_data->socks5_arg);
	if (connect_sockfd >= 0) {
		if (close(connect_sockfd)) perror("close");
	}
	destruct_no_close(client_data);
}

static void sock5_proto_wrapper(client_data_struct *client_data);

static void client_read_cb(evutil_socket_t sockfd, short ev_flag, void *arg) {
	assert(ev_flag == EV_READ);
	(void)ev_flag;
	client_data_struct *client_data = (client_data_struct *)arg;
	assert(get_client_sockfd(&client_data->socks5_arg) == sockfd);
	task_struct *task = get_task(&client_data->socks5_arg);
	assert(task->type == TASK_READ);
	read_task_struct *tsk = &task->data.read_task;
	assert(tsk->fd == sockfd);
	(void)sockfd;
	if (continue_read_task(tsk) <= 0) {
		struct event *event = client_data->events.read;
		if (event_del(event)) {everror("event_del"); event_free(event); destruct(client_data); return;} // TODO: don't del
		event_free(event);
		sock5_proto_wrapper(client_data);
	}
}

static void client_write_cb(evutil_socket_t sockfd, short ev_flag, void *arg) {
	assert(ev_flag == EV_WRITE);
	(void)ev_flag;
	client_data_struct *client_data = (client_data_struct *)arg;
	assert(get_client_sockfd(&client_data->socks5_arg) == sockfd);
	task_struct *task = get_task(&client_data->socks5_arg);
	assert(task->type == TASK_WRITE);
	write_task_struct *tsk = &task->data.write_task;
	assert(tsk->fd == sockfd);
	(void)sockfd;
	if (continue_write_task(tsk) <= 0) {
		struct event *event = client_data->events.write;
		if (event_del(event)) {everror("event_del"); event_free(event); destruct(client_data); return;}
		event_free(event);
		sock5_proto_wrapper(client_data);
	}
}

static void connect_write_cb(evutil_socket_t sockfd, short ev_flag, void *arg) {
	assert(ev_flag == EV_WRITE);
	(void)ev_flag;
	client_data_struct *client_data = (client_data_struct *)arg;
	assert(get_connect_sockfd(&client_data->socks5_arg) == sockfd);
	task_struct *task = get_task(&client_data->socks5_arg);
	assert(task->type == TASK_CONNECT);
	connect_task_struct *tsk = &task->data.connect_task;
	assert(tsk->sockfd == sockfd);
	(void)sockfd;
	if (continue_connect_task(tsk) <= 0) {
		struct event *event = client_data->events.connect_write;
		if (event_del(event)) {everror("event_del"); event_free(event); destruct(client_data); return;}
		event_free(event);
		sock5_proto_wrapper(client_data);
	}
}

static void getaddrinfo_cb(int result, struct evutil_addrinfo *res, void *arg) {
	if (result == DNS_ERR_CANCEL) {evutil_freeaddrinfo(res); return;}
	client_data_struct *client_data = (client_data_struct *)arg;
	task_struct *task = get_task(&client_data->socks5_arg);
	assert(task->type == TASK_GETADDRINFO);
	getaddrinfo_task_struct *tsk = &task->data.getaddrinfo_task;
	tsk->ret = result;
	*(tsk->res) = res;
	if (!client_data->events.getaddrinfo.setting_up) {
		assert(set_remove(&client_data->common->dns_requests, client_data));
		sock5_proto_wrapper(client_data);
	}
}

/* return:
	-1 -- error (internal, not task error)
	 0 -- task already completed (with success or error)
	 1 -- task sheduled
*/
static int shedule_task(client_data_struct *client_data) {
	task_struct *task = get_task(&client_data->socks5_arg);
	switch (task->type) {
		case TASK_READ: {
			read_task_struct *tsk = &task->data.read_task;
			if (continue_read_task(tsk) <= 0) return 0;
			struct event *event = event_new(client_data->common->base, tsk->fd, EV_READ|EV_PERSIST, client_read_cb, client_data);
			if (event == NULL) {everror("event_new"); return -1;}
			client_data->events.read = event;
			if (event_add(event, NULL)) {everror("event_add"); event_free(event); return -1;}
			return 1;
		}
		case TASK_WRITE: {
			write_task_struct *tsk = &task->data.write_task;
			if (continue_write_task(tsk) <= 0) return 0;
			struct event *event = event_new(client_data->common->base, tsk->fd, EV_WRITE|EV_PERSIST, client_write_cb, client_data);
			if (event == NULL) {everror("event_new"); return -1;}
			client_data->events.write = event;
			if (event_add(event, NULL)) {everror("event_add"); event_free(event); return -1;}
			return 1;
		}
		case TASK_GETADDRINFO: {
			getaddrinfo_task_struct *tsk = &task->data.getaddrinfo_task;
			client_data->events.getaddrinfo.setting_up = true;
			struct evdns_getaddrinfo_request *event = evdns_getaddrinfo(client_data->common->dns_base,
				tsk->node, tsk->service, tsk->hints, getaddrinfo_cb, client_data);
			client_data->events.getaddrinfo.setting_up = false;
			if (event == NULL) return 0;
			client_data->events.getaddrinfo.ev = event;
			assert(!set_contains(&client_data->common->dns_requests, client_data));
			if (set_add_new(&client_data->common->dns_requests, client_data)) {
				evdns_getaddrinfo_cancel(event);
				return -1;
			}
			return 1;
		}
		case TASK_CONNECT: {
			connect_task_struct *tsk = &task->data.connect_task;
			if (first_try_connect_task(tsk) <= 0) return 0;
			struct event *event = event_new(client_data->common->base, tsk->sockfd, EV_WRITE|EV_PERSIST, connect_write_cb, client_data);
			if (event == NULL) {everror("event_new"); return -1;}
			client_data->events.connect_write = event;
			if (event_add(event, NULL)) {everror("event_add"); event_free(event); return -1;}
			return 1;
		}
		default:
			assert(0);
			return -1;
	}
}

static void sock5_proto_wrapper(client_data_struct *client_data) {
	while (true) {
		int res = socks5(&client_data->socks5_arg);
		switch (res) {
			case SOCKS5_RES_TASK: {
				int shedule_res = shedule_task(client_data);
				if (shedule_res < 0) {destruct(client_data); return;}
				if (shedule_res > 0) return;
				break; // continue loop
			}
			case SOCKS5_RES_ERROR:
			case SOCKS5_RES_WRONG_DATA:
			case SOCKS5_RES_REFUSED:
			case SOCKS5_RES_HANGUP: {
				destruct(client_data);
				return;
			}
			case SOCKS5_RES_DONE: {
				int client_sockfd = get_client_sockfd(&client_data->socks5_arg);
				int connect_sockfd = get_connect_sockfd(&client_data->socks5_arg);
				assert(connect_sockfd >= 0);
				struct event_base *base = client_data->common->base;
				size_t transfer_buffer_size = client_data->common->transfer_buffer_size;
				destruct_no_close(client_data);
				transfer_construct_and_run(base, transfer_buffer_size, client_sockfd, connect_sockfd);
				return;
			}
			case SOCKS5_RES_AGAIN:
				break; // continue loop
			default:
				assert(0);
				destruct(client_data); return;
		}
	}
}

void client_handler_construct_and_run(client_handler_common_struct *common, int client_sockfd) {
	client_data_struct *client_data = malloc(sizeof(client_data_struct));
	if (client_data == NULL) {
		perror("malloc");
		if (close(client_sockfd)) perror("close");
		return;
	}
	client_data->common = common;
	
	socks5_init(&client_data->socks5_arg, client_sockfd);
	int shedule_res = shedule_task(client_data);
	if (shedule_res < 0) {destruct(client_data); return;}
	if (shedule_res > 0) return;
	sock5_proto_wrapper(client_data);
}

bool client_handler_events_filter(const struct event *event) {
	event_callback_fn cb = event_get_callback(event);
	return (cb == client_read_cb || cb == client_write_cb || cb == connect_write_cb);
}

void client_handler_destruct(struct event *event) {
	client_data_struct *client_data = (client_data_struct *)event_get_callback_arg(event);
	assert(client_data != NULL);
	destruct(client_data);
}

void client_handler_destruct_dns_req(client_handler_dns_req_struct *dns_req) {
	client_data_struct *client_data = (client_data_struct *)dns_req;
	destruct(client_data);
}

