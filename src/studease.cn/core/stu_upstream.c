/*
 * stu_upstream.c
 *
 *  Created on: 2017骞�11鏈�20鏃�
 *      Author: Tony Lau
 */

#include "../stu_config.h"
#include "stu_core.h"

stu_hash_t  stu_upstreams;

static stu_int32_t  stu_upstream_init(stu_connection_t *c, stu_upstream_server_t *s);
static stu_int32_t  stu_upstream_next(stu_connection_t *c);


stu_int32_t
stu_upstream_init_hash() {
	if (stu_hash_init(&stu_upstreams, STU_UPSTREAM_MAXIMUM, NULL, STU_HASH_FLAGS_LOWCASE) == STU_ERROR) {
		stu_log_error(0, "Failed to init upstream hash.");
		return STU_ERROR;
	}

	return STU_OK;
}


void
stu_upstream_read_handler(stu_event_t *ev) {
	stu_connection_t      *pc;
	stu_upstream_t        *u;
	stu_upstream_server_t *s;
	stu_int32_t            n;

	pc = ev->data;
	u = pc->upstream;
	s = u->server;

	stu_mutex_lock(&pc->lock);

	if (u == NULL || u->peer == NULL
			|| u->peer->timedout || u->peer->close || u->peer->error || u->peer->destroyed) {
		goto done;
	}

	pc->idle = FALSE;

	if (pc->buffer.start == NULL) {
		pc->buffer.start = (u_char *) stu_pcalloc(pc->pool, STU_UPSTREAM_BUFFER_DEFAULT_SIZE);
		pc->buffer.pos = pc->buffer.last = pc->buffer.start;
		pc->buffer.end = pc->buffer.start + STU_UPSTREAM_BUFFER_DEFAULT_SIZE;
		pc->buffer.size = STU_UPSTREAM_BUFFER_DEFAULT_SIZE;
	}

	if (pc->buffer.end == pc->buffer.last) {
		pc->buffer.pos = pc->buffer.last = pc->buffer.start;
		stu_memzero(pc->buffer.start, pc->buffer.size);
	}

	n = pc->recv(pc, pc->buffer.start, pc->buffer.size);
	if (n == STU_AGAIN) {
		goto done;
	}

	if (n == STU_ERROR) {
		pc->error = TRUE;
		goto failed;
	}

	if (n == 0) {
		stu_log_error(0, "upstream peer prematurely closed connection.");
		pc->close = TRUE;
		goto failed;
	}

	pc->buffer.last += n;
	stu_log_debug(4, "upstream recv from %s: fd=%d, bytes=%d.", s->name.data, pc->fd, n);

	u->process_response_pt(pc);

	goto done;

failed:

	stu_atomic_fetch_add(&s->fails, 1);
	u->cleanup_pt(u->connection);

done:

	stu_mutex_unlock(&pc->lock);
}

void
stu_upstream_write_handler(stu_event_t *ev) {
	stu_connection_t      *pc;
	stu_upstream_t        *u;
	stu_upstream_server_t *s;
	stu_int32_t            n;

	pc = ev->data;
	u = pc->upstream;
	s = u->server;

	stu_mutex_lock(&pc->lock);

	if (u == NULL || u->peer == NULL
			|| u->peer->timedout || u->peer->close || u->peer->error || u->peer->destroyed) {
		goto done;
	}

	if (u->generate_request_pt(pc) == STU_ERROR) {
		stu_log_error(0, "Failed to generate request of upstream %s, fd=%d.", s->name.data, pc->fd);
		goto failed;
	}

	n = pc->send(pc, pc->buffer.pos, pc->buffer.last - pc->buffer.pos);
	if (n == -1) {
		pc->error = TRUE;
		stu_log_error(stu_errno, "Failed to send upstream request, u->fd=%d.", pc->fd);
		goto failed;
	}

	stu_log_debug(4, "sent to upstream %s: u->fd=%d, bytes=%d.", s->name.data, pc->fd, n);

	stu_event_del(pc->write, STU_WRITE_EVENT, 0);

	goto done;

failed:

	stu_atomic_fetch_add(&s->fails, 1);
	u->cleanup_pt(u->connection);

done:

	stu_mutex_unlock(&pc->lock);
}


stu_int32_t
stu_upstream_create(stu_connection_t *c, u_char *name, size_t len) {
	stu_list_t            *l;
	stu_upstream_server_t *s;
	stu_queue_t           *q;
	stu_uint32_t           hk;

	hk = stu_hash_key(name, len, STU_HASH_FLAGS_LOWCASE);
	l = stu_hash_find(&stu_upstreams, hk, name, len);
	if (l == NULL || l->length == 0) {
		stu_log_error(0, "Upstream servers not found: \"%s\".", name);
		return STU_ERROR;
	}

	stu_mutex_lock(&l->lock);

	if (l->current == NULL) {
		q = stu_queue_head(&l->elts.queue);
		l->current = stu_queue_data(q, stu_list_elt_t, queue);
	}

	s = (stu_upstream_server_t *) l->current->value;
	while (s->down || s->count++ >= s->weight) {
		s->count = 0;

		q = stu_queue_next(&l->current->queue);
		if (q == stu_queue_sentinel(&l->elts.queue)) {
			q = stu_queue_head(&l->elts.queue);
			l->current = stu_queue_data(q, stu_list_elt_t, queue);
		}

		s = (stu_upstream_server_t *) l->current->value;
	}

	stu_mutex_unlock(&l->lock);

	stu_upstream_init(c, s);

	return STU_OK;
}

static stu_int32_t
stu_upstream_init(stu_connection_t *c, stu_upstream_server_t *s) {
	stu_upstream_t   *u;
	stu_connection_t *pc;
	stu_socket_t      fd;

	u = c->upstream;
	if (u == NULL) {
		u = stu_pcalloc(c->pool, sizeof(stu_upstream_t));
		if (u == NULL) {
			stu_log_error(0, "Failed to pcalloc upstream for fd=%d.", c->fd);
			return STU_ERROR;
		}

		c->upstream = u;
		u->connection = c;
		u->cleanup_pt = stu_upstream_cleanup;
	}

	pc = u->peer;
	if (pc == NULL) {
		pc = stu_connection_get(STU_SOCKET_INVALID);
		if (pc == NULL) {
			stu_log_error(0, "Failed to get connection for upstream %s, fd=%d.", s->name.data, c->fd);
			return STU_ERROR;
		}

		pc->upstream = u;
		u->peer = pc;
	}

	if (u->server != s) {
		if (u->server && pc->fd != STU_SOCKET_INVALID) {
			stu_event_del(pc->read, STU_READ_EVENT, STU_CLOSE_EVENT);
			stu_event_del(pc->write, STU_WRITE_EVENT, 0);
		}

		u->server = s;
	}

	if (pc->fd == STU_SOCKET_INVALID) {
		fd = stu_socket(s->addr.sockaddr.sin_family, SOCK_STREAM, 0);
		if (fd == (stu_socket_t) STU_SOCKET_INVALID) {
			stu_log_error(stu_errno, "Failed to create socket for upstream %s, fd=%d.", s->name.data, c->fd);
			return STU_ERROR;
		}

		if (stu_nonblocking(fd) == -1) {
			stu_log_error(stu_errno, "fcntl(O_NONBLOCK) failed while setting upstream %s, fd=%d.", s->name.data, c->fd);
			return STU_ERROR;
		}

		pc->fd = fd;
		pc->read->evfd = c->read->evfd;
		pc->write->evfd = c->write->evfd;

		if (stu_event_add_conn(pc) == STU_ERROR) {
			stu_log_error(0, "Failed to add read event of upstream %s, fd=%d.", s->name.data, c->fd);
			return STU_ERROR;
		}
	}

	return STU_OK;
}

stu_int32_t
stu_upstream_connect(stu_connection_t *pc) {
	stu_connection_t      *c;
	stu_upstream_t        *u;
	stu_upstream_server_t *s;
	int                    rc;
	stu_err_t              err;

	u = pc->upstream;
	s = u->server;
	c = u->connection;

	pc->read->handler = u->read_event_handler;
	pc->write->handler = u->write_event_handler;

	rc = connect(pc->fd, (const struct sockaddr *) &s->addr.sockaddr, s->addr.socklen);
	if (rc == -1) {
		err = stu_errno;
		if (err != STU_EINPROGRESS
#if (STU_WIN32)
				/* Winsock returns WSAEWOULDBLOCK (STU_EAGAIN) */
				&& err != STU_EAGAIN
#endif
				) {
			if (err == STU_ECONNREFUSED
#if (STU_LINUX)
					/*
					 * Linux returns EAGAIN instead of ECONNREFUSED
					 * for unix sockets if listen queue is full
					 */
					|| err == STU_EAGAIN
#endif
					|| err == STU_ECONNRESET
					|| err == STU_ENETDOWN
					|| err == STU_ENETUNREACH
					|| err == STU_EHOSTDOWN
					|| err == STU_EHOSTUNREACH) {

			} else {

			}
			stu_log_error(err, "Failed to connect to upstream %s, fd=%d.", s->name.data, pc->fd);

			return stu_upstream_next(c);
		}
	}

	pc->idle = FALSE;

	return STU_OK;
}

static stu_int32_t
stu_upstream_next(stu_connection_t *c) {
	stu_list_t            *l;
	stu_upstream_t        *u;
	stu_upstream_server_t *s, *old;
	stu_queue_t           *q;
	stu_uint32_t           hk;

	u = c->upstream;
	old = u->server;

	stu_atomic_fetch_add(&old->fails, 1);

	hk = stu_hash_key(old->name.data, old->name.len, STU_HASH_FLAGS_LOWCASE);
	l = stu_hash_find(&stu_upstreams, hk, old->name.data, old->name.len);
	if (l == NULL || l->length == 0) {
		stu_log_error(0, "Upstream servers not found.");
		return STU_ERROR;
	}

	stu_mutex_lock(&l->lock);

	if (l->current == NULL || stu_queue_next(&l->current->queue) == stu_queue_sentinel(&l->elts.queue)) {
		q = stu_queue_head(&l->elts.queue);
	} else {
		q = stu_queue_head(&l->current->queue);
	}
	l->current = stu_queue_data(q, stu_list_elt_t, queue);

	s = (stu_upstream_server_t *) l->current->value;
	while (s->down || s->count++ >= s->weight) {
		s->count = 0;

		q = stu_queue_next(&l->current->queue);
		if (q == stu_queue_sentinel(&l->elts.queue)) {
			q = stu_queue_head(&l->elts.queue);
			l->current = stu_queue_data(q, stu_list_elt_t, queue);
		}

		s = (stu_upstream_server_t *) l->current->value;
	}

	c->upstream->server = s;

	stu_mutex_unlock(&l->lock);

	stu_upstream_init(c, s);

	return stu_upstream_connect(c);
}


void *
stu_upstream_create_request(stu_connection_t *pc) {
	/* void */
	return NULL;
}

stu_int32_t
stu_upstream_reinit_request(stu_connection_t *pc) {
	/* void */
	return STU_OK;
}

stu_int32_t
stu_upstream_generate_request(stu_connection_t *pc) {
	stu_connection_t *c;
	stu_upstream_t   *u;

	u = pc->upstream;
	c = u->connection;

	pc->buffer.pos = c->buffer.pos;
	pc->buffer.last = c->buffer.last;

	return STU_OK;
}

stu_int32_t
stu_upstream_process_response(stu_connection_t *pc) {
	stu_upstream_t *u;

	u = pc->upstream;

	if (u->analyze_response_pt(pc) == STU_ERROR) {
		stu_log_error(0, "Failed to analyze upstream response.");
		u->finalize_handler_pt(u->connection, STU_ERROR);
		return STU_ERROR;
	}

	return STU_OK;
}

stu_int32_t
stu_upstream_analyze_response(stu_connection_t *pc) {
	stu_upstream_t *u;

	u = pc->upstream;

	u->finalize_handler_pt(u->connection, STU_OK);

	return STU_OK;
}

void
stu_upstream_finalize_handler(stu_connection_t *c, stu_int32_t rc) {
	stu_upstream_t *u;
	stu_int32_t     n;

	u = c->upstream;

	n = c->send(c, c->buffer.start, c->buffer.last - c->buffer.start);
	if (n == -1) {
		c->error = TRUE;

		stu_log_error(stu_errno, "Failed to send data: fd=%d.", c->fd);
		goto failed;
	}

	stu_log_debug(4, "sent: fd=%d, bytes=%d.", c->fd, n);

	return;

failed:

	u->cleanup_pt(c);
}

void
stu_upstream_cleanup(stu_connection_t *c) {
	stu_upstream_t   *u;
	stu_connection_t *pc;

	if (c->upstream == NULL) {
		return;
	}

	u = c->upstream;
	pc = u->peer;

	if (pc) {
		stu_log_debug(4, "cleaning up upstream: fd=%d.", pc->fd);
		u->peer = NULL;
		stu_connection_close(pc);
	}
}
