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

typedef struct {
	socks5_arg_struct socks5_arg;
	client_handler_common_struct *common;
	struct event *client_read_event;
	struct event *client_write_event;
	struct event *connect_write_event;
	struct evdns_getaddrinfo_request *getaddrinfo_request;
	bool client_write_event_active;
	bool getaddrinfo_request_setting_up;
} client_data_struct;

static void destruct_impl(client_data_struct *client_data, bool close_flag) {
	if (event_del(client_data->client_read_event)) everror("event_del");
	event_free(client_data->client_read_event);
	if (client_data->client_write_event_active)
		if (event_del(client_data->client_write_event)) everror("event_del");
	event_free(client_data->client_write_event);
	if (client_data->connect_write_event != NULL) {
		if (event_del(client_data->connect_write_event)) everror("event_del");
		event_free(client_data->connect_write_event);
	}
	if (client_data->getaddrinfo_request != NULL) {
		evdns_getaddrinfo_cancel(client_data->getaddrinfo_request);
	}
	
	if (close_flag) socks5_close_all(&client_data->socks5_arg);
	
	free(client_data);
}

static void destruct_no_close(client_data_struct *client_data) {
	destruct_impl(client_data, false);
}

static void destruct(client_data_struct *client_data) {
	destruct_impl(client_data, true);
}

static void sock5_proto_wrapper(client_data_struct *client_data);

static void client_read_cb(evutil_socket_t sockfd, short ev_flag, void *arg) {
	assert(ev_flag == EV_READ);
	(void)ev_flag;
	
	client_data_struct *client_data = (client_data_struct *)arg;
	assert(get_client_sockfd(&client_data->socks5_arg) == sockfd);
	
	task_struct *task = get_task(&client_data->socks5_arg);
	if (task->type != TASK_READ) {destruct(client_data); return;}		// HANGUP or unexpected data
	read_task_struct *tsk = &task->data.read_task;
	assert(tsk->fd == sockfd);
	(void)sockfd;
	
	if (continue_read_task(tsk) <= 0) sock5_proto_wrapper(client_data);
}

static void client_write_cb(evutil_socket_t sockfd, short ev_flag, void *arg) {
	assert(ev_flag == EV_WRITE);
	(void)ev_flag;
	
	client_data_struct *client_data = (client_data_struct *)arg;
	assert(get_client_sockfd(&client_data->socks5_arg) == sockfd);
	assert(client_data->client_write_event_active);
	
	task_struct *task = get_task(&client_data->socks5_arg);
	assert(task->type == TASK_WRITE);
	write_task_struct *tsk = &task->data.write_task;
	assert(tsk->fd == sockfd);
	(void)sockfd;
	
	if (continue_write_task(tsk) <= 0) {
		bool err = false;
		if (event_del(client_data->client_write_event)) {everror("event_del"); err = true;}
		client_data->client_write_event_active = false;
		if (err) destruct(client_data);
		else sock5_proto_wrapper(client_data);
	}
}

static void connect_write_cb(evutil_socket_t sockfd, short ev_flag, void *arg) {
	assert(ev_flag == EV_WRITE);
	(void)ev_flag;
	
	client_data_struct *client_data = (client_data_struct *)arg;
	assert(get_connect_sockfd(&client_data->socks5_arg) == sockfd);
	assert(client_data->connect_write_event != NULL);
	
	task_struct *task = get_task(&client_data->socks5_arg);
	assert(task->type == TASK_CONNECT);
	connect_task_struct *tsk = &task->data.connect_task;
	assert(tsk->sockfd == sockfd);
	(void)sockfd;
	
	if (continue_connect_task(tsk) <= 0) {
		bool err = false;
		if (event_del(client_data->connect_write_event)) {everror("event_del"); err = true;}
		event_free(client_data->connect_write_event);
		client_data->connect_write_event = NULL;
		if (err) destruct(client_data);
		else sock5_proto_wrapper(client_data);
	}
}

static void getaddrinfo_cb(int result, struct evutil_addrinfo *res, void *arg) {
	assert(result == 0 || res == NULL);
	
	if (result == DNS_ERR_CANCEL) return;
	
	client_data_struct *client_data = (client_data_struct *)arg;
	assert(client_data->getaddrinfo_request != NULL);
	
	task_struct *task = get_task(&client_data->socks5_arg);
	assert(task->type == TASK_GETADDRINFO);
	getaddrinfo_task_struct *tsk = &task->data.getaddrinfo_task;
	
	tsk->ret = result;
	*(tsk->res) = res;
	
	if (client_data->getaddrinfo_request_setting_up) return;
	client_data->getaddrinfo_request = NULL;
	
	sock5_proto_wrapper(client_data);
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
			return 1;
		}
		case TASK_WRITE: {
			assert(!client_data->client_write_event_active);
			write_task_struct *tsk = &task->data.write_task;
			if (continue_write_task(tsk) <= 0) return 0;
			if (event_add(client_data->client_write_event, NULL)) {everror("event_add"); return -1;}
			return 1;
		}
		case TASK_GETADDRINFO: {
			assert(client_data->getaddrinfo_request == NULL);
			getaddrinfo_task_struct *tsk = &task->data.getaddrinfo_task;
			client_data->getaddrinfo_request_setting_up = true;
			struct evdns_getaddrinfo_request *req = evdns_getaddrinfo(client_data->common->dns_base,
				tsk->node, tsk->service, tsk->hints, getaddrinfo_cb, client_data);
			client_data->getaddrinfo_request_setting_up = false;
			if (req == NULL) return 0;
			client_data->getaddrinfo_request = req;
			return 1;
		}
		case TASK_CONNECT: {
			assert(client_data->connect_write_event == NULL);
			connect_task_struct *tsk = &task->data.connect_task;
			if (first_try_connect_task(tsk) <= 0) return 0;
			struct event *event = event_new(client_data->common->base, tsk->sockfd, EV_WRITE|EV_PERSIST, connect_write_cb, client_data);
			if (event == NULL) {everror("event_new"); return -1;}
			if (event_add(event, NULL)) {everror("event_add"); event_free(event); return -1;}
			client_data->connect_write_event = event;
			return 1;
		}
		default:
			assert(0);
			return -1;
	}
}

static void pass_control_to_transfer(client_data_struct *client_data) {
	int client_sockfd = get_client_sockfd(&client_data->socks5_arg);
	int connect_sockfd = get_connect_sockfd(&client_data->socks5_arg);
	assert(connect_sockfd >= 0);
	struct event_base *base = client_data->common->base;
	size_t transfer_buffer_size = client_data->common->transfer_buffer_size;
	destruct_no_close(client_data);
	transfer_construct_and_run(base, transfer_buffer_size, client_sockfd, connect_sockfd);
}

static void sock5_proto_wrapper(client_data_struct *client_data) {
	while (true) {
		socks5_result_type res = socks5(&client_data->socks5_arg);
		switch (res) {
			case SOCKS5_RES_TASK: {
				int shedule_res = shedule_task(client_data);
				if (shedule_res < 0) {destruct(client_data); return;}
				if (shedule_res > 0) return;
				break; // continue loop
			}
			case SOCKS5_RES_ERROR: {
				destruct(client_data);
				return;
			}
			case SOCKS5_RES_DONE: {
				pass_control_to_transfer(client_data);
				return;
			}
			default:
				assert(0);
				destruct(client_data); return;
		}
	}
}

void client_handler_construct_and_run(client_handler_common_struct *common, int client_sockfd) {
	client_data_struct *client_data = malloc(sizeof(client_data_struct));
	if (client_data == NULL) {perror("malloc"); goto close_client_sockfd;}
	client_data->common = common;
	
	struct event *event_read = event_new(client_data->common->base, client_sockfd, EV_READ|EV_PERSIST, client_read_cb, client_data);
	if (event_read == NULL) {everror("event_new"); goto free_client_data;}
	client_data->client_read_event = event_read;
	
	struct event *event_write = event_new(client_data->common->base, client_sockfd, EV_WRITE|EV_PERSIST, client_write_cb, client_data);
	if (event_write == NULL) {everror("event_new"); goto free_event_read;}
	client_data->client_write_event = event_write;
	client_data->client_write_event_active = false;
	
	client_data->connect_write_event = NULL;
	client_data->getaddrinfo_request = NULL;
	
	if (event_add(event_read, NULL)) {everror("event_add"); goto free_event_write;}
	
	socks5_init(&client_data->socks5_arg, client_sockfd);
	sock5_proto_wrapper(client_data);
	return;

free_event_write:
	event_free(event_write);
free_event_read:
	event_free(event_read);
free_client_data:
	free(client_data);
close_client_sockfd:
	if (close(client_sockfd)) perror("close");
}

bool client_handler_events_filter(const struct event *event) {
	event_callback_fn cb = event_get_callback(event);
	return (cb == client_read_cb);
}

void client_handler_destruct(struct event *event) {
	client_data_struct *client_data = (client_data_struct *)event_get_callback_arg(event);
	assert(client_data != NULL);
	destruct(client_data);
}

