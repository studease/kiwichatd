/*
 * kcd_channel.c
 *
 *  Created on: 2017年12月1日
 *      Author: Tony Lau
 */

#include "kcd_core.h"

stu_hash_t          kcd_channels;

extern kcd_cycle_t *kcd_cycle;
extern stu_fd_t     kcd_epfd;

static stu_connection_t *kcd_channel_timer_push_user;
static stu_connection_t *kcd_channel_timer_push_stat;

static stu_str_t    KCD_UPSTREAM_STAT = stu_string("stat");

static stu_int32_t  kcd_channel_init(kcd_channel_t *ch, stu_str_t *id);
static void         kcd_channel_remove_exactly(kcd_channel_t *ch, kcd_user_t *user);

static void         kcd_channel_slow_write_handler(stu_event_t *ev);
static void         kcd_channel_push_user_handler(stu_event_t *ev);
static void         kcd_channel_push_stat_handler(stu_event_t *ev);

static void         kcd_channel_push_user(stu_str_t *id, void *value);

static stu_int32_t  kcd_channel_push_stat_generate_request(stu_connection_t *pc);
static stu_int32_t  kcd_channel_push_stat_analyze_response(stu_connection_t *pc);
static void         kcd_channel_push_stat_finalize_handler(stu_connection_t *c, stu_int32_t rc);


stu_int32_t
kcd_channel_init_hash() {
	if (stu_hash_init(&kcd_channels, KCD_CHANNEL_LIST_DEFAULT_SIZE, NULL, STU_HASH_FLAGS_LOWCASE|STU_HASH_FLAGS_REPLACE) == STU_ERROR) {
		stu_log_error(0, "Failed to init channle hash.");
		return STU_ERROR;
	}

	return STU_OK;
}


static stu_int32_t
kcd_channel_init(kcd_channel_t *ch, stu_str_t *id) {
	if (ch->id.data == NULL) {
		ch->id.data = kcd_channels.hooks.malloc_fn(KCD_CHANNEL_ID_MAX_LEN + 1);
		if (ch->id.data == NULL) {
			stu_log_error(0, "Failed to malloc channel id.");
			return STU_ERROR;
		}
	}

	if (id && id->len) {
		stu_strncpy(ch->id.data, id->data, id->len);
		ch->id.len = id->len;
	}

	if (stu_hash_init(&ch->userlist, KCD_USER_LIST_DEFAULT_SIZE, &kcd_channels.hooks, STU_HASH_FLAGS_LOWCASE) == STU_ERROR) {
		stu_log_error(0, "Failed to init userlist.");
		return STU_ERROR;
	}

	if (kcd_cycle->conf.push_history) {
		ch->record = TRUE;
	}

	return STU_OK;
}

stu_int32_t
kcd_channel_insert(stu_str_t *id, kcd_user_t *user) {
	kcd_channel_t *ch;
	stu_uint32_t   hk;
	stu_int32_t    rc;

	stu_mutex_lock(&kcd_channels.lock);

	hk = stu_hash_key(id->data, id->len, kcd_channels.flags);

	ch = stu_hash_find_locked(&kcd_channels, hk, id->data, id->len);
	if (ch == NULL) {
		ch = kcd_channels.hooks.malloc_fn(sizeof(kcd_channel_t));
		if (ch == NULL) {
			stu_log_error(0, "Failed to calloc channel.");
			goto failed;
		}

		if (kcd_channel_init(ch, id) == STU_ERROR) {
			stu_log_error(0, "Failed to init channel: id=\"%s\".", id->data);
			goto failed;
		}

		if (stu_hash_insert_locked(&kcd_channels, id, ch) == STU_ERROR) {
			stu_log_error(0, "Failed to insert channel: id=\"%s\".", id->data);
			goto failed;
		}

		stu_log_debug(5, "new channel inserted: id=\"%s\", total=%d.", id->data, kcd_channels.length);
	}

	rc = kcd_channel_insert_locked(ch, user);

failed:

	stu_mutex_unlock(&kcd_channels.lock);

	return rc;
}

stu_int32_t
kcd_channel_insert_locked(kcd_channel_t *ch, kcd_user_t *user) {
	if (stu_hash_insert_locked(&ch->userlist, &user->id, user) == STU_ERROR) {
		stu_log_error(0, "Failed to insert user: id=\"%s\", ch=\"%s\".", user->id.data, ch->id.data);
		return STU_ERROR;
	}

	user->channel = ch;
	stu_log_debug(5, "user inserted into channel: id=\"%s\", ch=\"%s\", total=%d.", user->id.data, ch->id.data, ch->userlist.length);

	return STU_OK;
}


void
kcd_channel_remove(kcd_channel_t *ch, kcd_user_t *user) {
	stu_mutex_lock(&ch->userlist.lock);
	kcd_channel_remove_locked(ch, user);
	stu_mutex_unlock(&ch->userlist.lock);
}

void
kcd_channel_remove_locked(kcd_channel_t *ch, kcd_user_t *user) {
	stu_uint32_t  hk;

	kcd_channel_remove_exactly(ch, user);

	if (ch->userlist.length == 0) {
		stu_mutex_lock(&kcd_channels.lock);

		stu_hash_destroy_locked(&ch->userlist);

		hk = stu_hash_key(ch->id.data, ch->id.len, kcd_channels.flags);
		stu_hash_remove_locked(&kcd_channels, hk, ch->id.data, ch->id.len);

		stu_log_debug(5, "removed channel: id=\"%s\", total=%d.", ch->id.data, kcd_channels.length);

		if (ch->record) {
			stu_mq_destory(&ch->id);
		}

		kcd_channels.hooks.free_fn(ch->id.data);
		kcd_channels.hooks.free_fn(ch);

		stu_mutex_unlock(&kcd_channels.lock);
	}
}

static void
kcd_channel_remove_exactly(kcd_channel_t *ch, kcd_user_t *user) {
	stu_hash_t     *hash;
	stu_hash_elt_t *e;
	stu_uint32_t    hk, i;

	hash = &ch->userlist;
	hk = stu_hash_key(user->id.data, user->id.len, hash->flags);
	i = hk % hash->size;

	for (e = hash->buckets[i]; e; e = e->next) {
		if (e->key_hash != hk || e->key.len != user->id.len || e->value != user) {
			continue;
		}

		if (stu_strncmp(e->key.data, user->id.data, user->id.len) == 0) {
			stu_queue_remove(&e->queue);

			if (e->prev) {
				e->prev->next = e->next;
			} else {
				hash->buckets[i] = e->next;
			}
			if (e->next) {
				e->next->prev = e->prev;
			}

			hash->hooks.free_fn(e->key.data);
			hash->hooks.free_fn(e);

			hash->length--;

			stu_log_debug(5, "user removed from channel: id=\"%s\", ch=\"%s\", total=%d.", user->id.data, ch->id.data, ch->userlist.length);

			break;
		}
	}
}


void
kcd_channel_broadcast(kcd_channel_t *ch, u_char *data, size_t len, off_t off) {
	stu_list_elt_t        *elts;
	stu_hash_elt_t        *e;
	stu_queue_t           *q;
	kcd_user_t            *user;
	stu_connection_t      *c;
	u_char                 tmp[KCD_REQUEST_DEFAULT_SIZE];
	stu_websocket_frame_t  f;
	stu_socket_t           fd;
	stu_int32_t            n;
	size_t                 size;

	stu_log_debug(3, "broadcasting in channel \"%s\".", ch->id.data);

	elts = &ch->userlist.keys->elts;
	stu_memzero(tmp, KCD_REQUEST_DEFAULT_SIZE);

	f.fin = TRUE;
	f.opcode = STU_WEBSOCKET_OPCODE_BINARY;
	f.mask = FALSE;
	f.payload_data.start = tmp;
	f.payload_data.end = tmp + KCD_REQUEST_DEFAULT_SIZE;
	f.payload_data.size = KCD_REQUEST_DEFAULT_SIZE;

	f.payload_data.pos = data;
	f.payload_data.last = data + len;
	f.payload_data.last = stu_websocket_encode_frame(&f, f.payload_data.start);

	size = f.payload_data.last - f.payload_data.start;

	for (q = stu_queue_head(&elts->queue); q != NULL && q != stu_queue_sentinel(&elts->queue); q = stu_queue_next(q)) {
		e = stu_queue_data(q, stu_hash_elt_t, queue);

		user = (kcd_user_t *) e->value;
		if (user->slow) {
			continue;
		}

		c = user->connection;
		if (c == NULL || c->timedout || c->error || c->close || c->destroyed) {
			continue;
		}

		fd = stu_atomic_fetch_add(&c->fd, 0);

		n = send(fd, f.payload_data.start, size, 0);
		if (n == -1) {
			//stu_log_error(stu_errno, "Failed to broadcast in channel \"%s\": , fd=%d.", ch->id.data, fd);

			if (kcd_cycle->conf.mode == STU_MQ_MODE_STRICT) {
				// TODO: atomic set
				c->write.handler = kcd_channel_slow_write_handler;

				if (stu_event_add(&c->write, STU_WRITE_EVENT, STU_CLEAR_EVENT) == STU_ERROR) {
					c->error = TRUE;
					continue;
				}

				user->slow = TRUE;
			}
		}

		if (off >= 0) {
			stu_atomic_test_set(&user->current, off + (n == -1 ? 0 : len + 4));
		}
	}
}

static void
kcd_channel_slow_write_handler(stu_event_t *ev) {
	kcd_user_t            *user;
	kcd_channel_t         *ch;
	stu_connection_t      *c;
	u_char                 tmp[KCD_REQUEST_DEFAULT_SIZE];
	stu_websocket_frame_t  f;
	stu_int32_t            i, n;
	size_t                 size;
	off_t                  off;

	c = ev->data;
	user = c->data;
	ch = user->channel;
	off = user->current;

	stu_memzero(tmp, KCD_REQUEST_DEFAULT_SIZE);

	f.fin = TRUE;
	f.opcode = STU_WEBSOCKET_OPCODE_BINARY;
	f.mask = FALSE;
	f.payload_data.start = tmp;
	f.payload_data.pos = f.payload_data.last = f.payload_data.start + 10;
	f.payload_data.end = tmp + KCD_REQUEST_DEFAULT_SIZE;
	f.payload_data.size = KCD_REQUEST_DEFAULT_SIZE;

	for (i = 0; i < 5; i++) {
		f.payload_data.last = stu_mq_read(&ch->id, f.payload_data.pos, &off, FALSE);

		size = f.payload_data.last - f.payload_data.pos;
		if (size == 0) {
			user->slow = FALSE;
			stu_event_del(ev, STU_WRITE_EVENT, 0);
			break;
		}

		f.payload_data.last = stu_websocket_encode_frame(&f, f.payload_data.start);
		size = f.payload_data.last - f.payload_data.start;

		n = send(c->fd, f.payload_data.start, size, 0);
		if (n == -1) {
			//stu_log_error(stu_errno, "Failed to broadcast in channel \"%s\": , fd=%d.", ch->id.data, fd);
			break;
		}

		user->current = off;
	}
}


stu_int32_t
kcd_channel_add_push_user_timer(stu_msec_t timer) {
	stu_connection_t *c;

	c = kcd_channel_timer_push_user;

	if (c == NULL) {
		c = stu_connection_get((stu_socket_t) STU_SOCKET_INVALID);
		if (c == NULL) {
			stu_log_error(0, "Failed to get connection for pushing user.");
			return STU_ERROR;
		}

		c->write.handler = kcd_channel_push_user_handler;

		kcd_channel_timer_push_user = c;
	}

	stu_timer_add_locked(&c->write, timer);

	return STU_OK;
}

stu_int32_t
kcd_channel_add_push_stat_timer(stu_msec_t timer) {
	stu_connection_t *c;

	c = kcd_channel_timer_push_stat;

	if (c == NULL) {
		c = stu_connection_get((stu_socket_t) STU_SOCKET_INVALID);
		if (c == NULL) {
			stu_log_error(0, "Failed to get connection for pushing stat.");
			return STU_ERROR;
		}

		c->read.epfd = kcd_epfd;
		c->write.epfd = kcd_epfd;

		c->write.handler = kcd_channel_push_stat_handler;

		kcd_channel_timer_push_stat = c;
	}

	stu_timer_add_locked(&c->write, timer);

	return STU_OK;
}

void
kcd_channel_push_user_handler(stu_event_t *ev) {
	stu_connection_t *c;

	c = kcd_channel_timer_push_user;

	stu_hash_foreach(&kcd_channels, kcd_channel_push_user);

	stu_timer_add_locked(&c->write, kcd_cycle->conf.push_user_interval);
}

static void
kcd_channel_push_user(stu_str_t *id, void *value) {
	stu_json_t            *jo, *jo_raw, *jo_chan, *jo_cid, *jo_state, *jo_total;
	kcd_channel_t         *ch;
	u_char                 tmp[KCD_REQUEST_DEFAULT_SIZE];
	stu_websocket_frame_t  f;
	size_t                 size;

	ch = value;

	stu_mutex_lock(&ch->userlist.lock);

	f.fin = TRUE;
	f.opcode = STU_WEBSOCKET_OPCODE_BINARY;
	f.mask = FALSE;
	f.payload_data.start = tmp;
	f.payload_data.pos = f.payload_data.last = f.payload_data.start;
	f.payload_data.end = tmp + KCD_REQUEST_DEFAULT_SIZE;
	f.payload_data.size = KCD_REQUEST_DEFAULT_SIZE;

	jo = stu_json_create_object(NULL);

	jo_raw = stu_json_create_string(&KCD_PROTOCOL_RAW, KCD_PROTOCOL_RAW_USERS.data, KCD_PROTOCOL_RAW_USERS.len);
	jo_chan = stu_json_create_object(&KCD_PROTOCOL_CHANNEL);

	jo_cid = stu_json_create_string(&KCD_PROTOCOL_ID, id->data, id->len);
	jo_state = stu_json_create_number(&KCD_PROTOCOL_STATE, (stu_double_t) ch->state);
	jo_total = stu_json_create_number(&KCD_PROTOCOL_TOTAL, (stu_double_t) ch->userlist.length);

	stu_json_add_item_to_object(jo_chan, jo_cid);
	stu_json_add_item_to_object(jo_chan, jo_state);
	stu_json_add_item_to_object(jo_chan, jo_total);

	stu_json_add_item_to_object(jo, jo_raw);
	stu_json_add_item_to_object(jo, jo_chan);

	f.payload_data.last = stu_json_stringify(jo, f.payload_data.start);
	size = f.payload_data.last - f.payload_data.start;

	stu_json_delete(jo);

	kcd_channel_broadcast(ch, f.payload_data.start, size, -1);

	stu_mutex_unlock(&ch->userlist.lock);
}

void
kcd_channel_push_stat_handler(stu_event_t *ev) {
	stu_connection_t *c;

	c = kcd_channel_timer_push_stat;

	if (stu_upstream_create(c, KCD_UPSTREAM_STAT.data, KCD_UPSTREAM_STAT.len) == STU_ERROR) {
		stu_log_error(0, "Failed to create http upstream \"%s\".", KCD_UPSTREAM_STAT.data);
		return;
	}

	c->upstream->read_event_handler = stu_http_upstream_read_handler;
	c->upstream->write_event_handler = stu_http_upstream_write_handler;

	c->upstream->create_request_pt = stu_http_upstream_create_request;
	c->upstream->reinit_request_pt = stu_http_upstream_reinit_request;
	c->upstream->generate_request_pt = kcd_channel_push_stat_generate_request;
	c->upstream->process_response_pt = stu_http_upstream_process_response;
	c->upstream->analyze_response_pt = kcd_channel_push_stat_analyze_response;
	c->upstream->finalize_handler_pt = kcd_channel_push_stat_finalize_handler;
	c->upstream->cleanup_pt = stu_http_upstream_cleanup;

	if (stu_upstream_connect(c->upstream->peer) != STU_OK) {
		stu_log_error(0, "Failed to connect http upstream \"%s\".", KCD_UPSTREAM_STAT.data);
	}
}

static stu_int32_t
kcd_channel_push_stat_generate_request(stu_connection_t *pc) {
	stu_json_t         *jo, *jo_chan, *jo_state, *jo_total;
	stu_list_elt_t     *elts;
	stu_hash_elt_t     *e;
	stu_queue_t        *q;
	kcd_channel_t      *ch;
	stu_upstream_t     *u;
	stu_connection_t   *c;
	stu_http_request_t *pr;
	stu_buf_t          *body;
	stu_int32_t         total;

	u = pc->upstream;
	c = u->connection;

	total = 0;

	/* create stat request */
	pc->request = (void *) u->create_request_pt(pc);
	if (pc->request == NULL) {
		stu_log_error(0, "Failed to create stat request.");
		u->cleanup_pt(c);
		return STU_ERROR;
	}

	pr = pc->request;
	pr->uri = u->server->target;

	/* create request body */
	if (pc->buffer.start == NULL) {
		pc->buffer.start = (u_char *) stu_pcalloc(pc->pool, STU_HTTP_REQUEST_LARGE_SIZE);
		pc->buffer.pos = pc->buffer.last = pc->buffer.start;
		pc->buffer.end = pc->buffer.start + STU_HTTP_REQUEST_LARGE_SIZE;
		pc->buffer.size = STU_HTTP_REQUEST_LARGE_SIZE;
	}
	pc->buffer.pos = pc->buffer.last = pc->buffer.start;

	pr->request_body = (stu_http_request_body_t *) pc->buffer.last;
	pc->buffer.last += sizeof(stu_http_request_body_t);

	pr->request_body->bufs = (stu_chain_t *) pc->buffer.last;
	pc->buffer.last += sizeof(stu_chain_t);

	pr->request_body->bufs->buf = (stu_buf_t *) pc->buffer.last;
	pc->buffer.last += sizeof(stu_buf_t);

	body = pr->request_body->bufs->buf;
	body->start = body->pos = pc->buffer.last;

	/* generate request body */
	jo = stu_json_create_object(NULL);

	stu_mutex_lock(&kcd_channels.lock);

	elts = &kcd_channels.keys->elts;
	for (q = stu_queue_head(&elts->queue); q != NULL && q != stu_queue_sentinel(&elts->queue); q = stu_queue_next(q)) {
		e = stu_queue_data(q, stu_hash_elt_t, queue);
		ch = (kcd_channel_t *) e->value;

		stu_mutex_lock(&ch->userlist.lock);

		jo_chan = stu_json_create_object(&e->key);

		jo_state = stu_json_create_number(&KCD_PROTOCOL_STATE, (stu_double_t) ch->state);
		jo_total = stu_json_create_number(&KCD_PROTOCOL_TOTAL, (stu_double_t) ch->userlist.length);

		stu_json_add_item_to_object(jo_chan, jo_state);
		stu_json_add_item_to_object(jo_chan, jo_total);

		stu_json_add_item_to_object(jo, jo_chan);

		total += ch->userlist.length;

		stu_mutex_unlock(&ch->userlist.lock);
	}

	stu_mutex_unlock(&kcd_channels.lock);

	pc->buffer.last = stu_json_stringify(jo, pc->buffer.last);
	stu_json_delete(jo);

	body->last = body->end = pc->buffer.last;
	body->size = body->end - body->start;

	pr->headers_out.content_length_n = body->size;

	return stu_http_upstream_generate_request(pc);
}

static stu_int32_t
kcd_channel_push_stat_analyze_response(stu_connection_t *pc) {
	stu_http_request_t *pr;
	stu_upstream_t     *u;

	pr = (stu_http_request_t *) pc->request;
	u = pc->upstream;

	if (pr->headers_out.status != STU_HTTP_OK) {
		stu_log_error(0, "Bad push channel stat response: status=%d.", pr->headers_out.status);
		return STU_ERROR;
	}

	stu_log_debug(4, "kcd push stat done.");

	u->finalize_handler_pt(u->connection, pr->headers_out.status);

	return STU_OK;
}

static void
kcd_channel_push_stat_finalize_handler(stu_connection_t *c, stu_int32_t rc) {
	c->upstream->cleanup_pt(c);

	stu_timer_add_locked(&c->write, kcd_cycle->conf.push_stat_interval);
}
