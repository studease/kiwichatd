/*
 * stu_websocket_request.c
 *
 *  Created on: 2017年11月27日
 *      Author: Tony Lau
 */

#include "stu_websocket.h"

static stu_int32_t   stu_websocket_process_request_frame(stu_websocket_request_t *r);
static stu_uint32_t  stu_websocket_read_request_buffer(stu_websocket_request_t *r);
static stu_int32_t   stu_websocket_alloc_large_buffer(stu_websocket_request_t *r);
static stu_int32_t   stu_websocket_filter_foreach_handler(stu_websocket_request_t *r, stu_str_t *pattern, stu_list_t *list);
static void          stu_websocket_run_phases(stu_websocket_request_t *r);
static void          stu_websocket_request_empty_handler(stu_websocket_request_t *r);

extern stu_hash_t  stu_websocket_filter_hash;
extern stu_list_t  stu_websocket_phases;


void
stu_websocket_request_read_handler(stu_event_t *ev) {
	stu_connection_t *c;
	stu_int32_t       n, err;

	c = (stu_connection_t *) ev->data;

	//stu_mutex_lock(&c->lock);

	if (c->buffer.start == NULL) {
		c->buffer.start = (u_char *) stu_pcalloc(c->pool, STU_WEBSOCKET_REQUEST_DEFAULT_SIZE);
		c->buffer.pos = c->buffer.last = c->buffer.start;
		c->buffer.end = c->buffer.start + STU_WEBSOCKET_REQUEST_DEFAULT_SIZE;
		c->buffer.size = STU_WEBSOCKET_REQUEST_DEFAULT_SIZE;
	}
	c->buffer.pos = c->buffer.last = c->buffer.start;
	stu_memzero(c->buffer.start, c->buffer.size);

again:

	n = recv(c->fd, c->buffer.last, c->buffer.size, 0);
	if (n == -1) {
		err = stu_errno;
		if (err == EINTR) {
			stu_log_debug(3, "recv trying again: fd=%d, errno=%d.", c->fd, err);
			goto again;
		}

		if (err == EAGAIN) {
			stu_log_debug(3, "no data received: fd=%d, errno=%d.", c->fd, err);
			goto done;
		}

		stu_log_error(err, "Failed to recv data: fd=%d.", c->fd);
		goto failed;
	}

	if (n == 0) {
		stu_log_debug(4, "websocket client has closed connection: fd=%d.", c->fd);
		goto failed;
	}

	c->buffer.last += n;
	stu_log_debug(4, "recv: fd=%d, bytes=%d.", c->fd, n);

	c->request = (void *) stu_websocket_create_request(c);
	if (c->request == NULL) {
		stu_log_error(0, "Failed to create websocket request.");
		goto failed;
	}

	//ev->handler = stu_websocket_process_request_frames;
	stu_websocket_process_request_frames(ev);

	goto done;

failed:

	stu_websocket_close_connection(c);

done:

	stu_log_debug(4, "websocket request done.");

	//stu_mutex_unlock(&c->lock);
}

stu_websocket_request_t *
stu_websocket_create_request(stu_connection_t *c) {
	stu_websocket_request_t *r;

	if (c->request == NULL) {
		r = stu_pcalloc(c->pool, sizeof(stu_websocket_request_t));
		if (r == NULL) {
			stu_log_error(0, "Failed to create websocket request.");
			return NULL;
		}

		r->write_event_handler = stu_websocket_request_write_handler;
	} else {
		r = c->request;
	}

	r->connection = c;
	r->frame_in = r->busy ? r->busy : &c->buffer;

	return r;
}

void
stu_websocket_process_request_frames(stu_event_t *ev) {
	stu_websocket_request_t *r;
	stu_connection_t        *c;
	stu_int32_t              rc, rv;
	stu_uint64_t             n;

	c = ev->data;
	r = c->request;

	stu_log_debug(4, "websocket process request frames.");

	if (ev->timedout) {
		stu_log_error(STU_ETIMEDOUT, "Failed to process request frames.");

		c->timedout = TRUE;
		stu_websocket_finalize_request(r, STU_ERROR);

		return;
	}

	rc = STU_DONE;

	for ( ;; ) {
		if (rc == STU_AGAIN) {
			if (r->frame_in->pos == r->frame_in->end) {
				rv = stu_websocket_alloc_large_buffer(r);
				if (rv == STU_ERROR) {
					stu_log_error(0, "websocket failed to alloc large buffer.");
					stu_websocket_finalize_request(r, STU_ERROR);
					return;
				}

				if (rv == STU_DECLINED) {
					stu_log_error(0, "websocket client sent too large request.");
					stu_websocket_finalize_request(r, STU_ERROR);
					return;
				}
			}

			n = stu_websocket_read_request_buffer(r);
			if (n == STU_AGAIN || n == STU_ERROR) {
				stu_log_error(0, "websocket failed to read request buffer.");
				stu_websocket_finalize_request(r, STU_ERROR);
				return;
			}
		}

		rc = stu_websocket_parse_frame(r, r->frame_in);
		if (rc == STU_OK) {
			/* a inner frame has been parsed successfully */
			continue;
		}

		if (rc == STU_DONE) {
			/* a key frame has been parsed successfully */
			stu_log_debug(4, "websocket key frame done: opcode=%d, len=%d.", r->frames_in.opcode, r->frames_in.payload_data.size);

			rc = stu_websocket_process_request_frame(r);
			if (rc != STU_OK) {
				stu_log_error(0, "websocket failed to process request frame.");
				stu_websocket_finalize_request(r, STU_ERROR);
				return;
			}

			stu_websocket_process_request(r);

			return;
		}

		if (rc == STU_AGAIN) {
			/* a websocket frame parsing is still not complete */
			continue;
		}

		stu_log_error(0, "client sent invalid websocket frame.");
		stu_websocket_finalize_request(r, STU_ERROR);

		return;
	}
}

static stu_uint32_t
stu_websocket_read_request_buffer(stu_websocket_request_t *r) {
	stu_connection_t *c;
	stu_uint32_t      n;
	stu_int32_t       err;

	c = r->connection;

	n = r->frames_in.payload_data.last - r->frames_in.payload_data.pos;
	if (n > 0) {
		/* buffer remains */
		return n;
	}

again:

	n = recv(c->fd, r->frame_in->last, r->frame_in->end - r->frame_in->last, 0);
	if (n == -1) {
		err = stu_errno;
		if (err == EINTR) {
			stu_log_debug(3, "recv trying again: fd=%d, errno=%d.", c->fd, err);
			goto again;
		}

		if (err == EAGAIN) {
			stu_log_debug(3, "no data received: fd=%d, errno=%d.", c->fd, err);
		}
	}

	if (n == 0) {
		c->close = TRUE;
		stu_log_error(0, "websocket client prematurely closed connection.");
	}

	if (n == 0 || n == STU_ERROR) {
		c->error = TRUE;
		return STU_ERROR;
	}

	r->frame_in->last += n;

	return n;
}

static stu_int32_t
stu_websocket_alloc_large_buffer(stu_websocket_request_t *r) {
	stu_connection_t *c;
	u_char           *old, *new;

	c = r->connection;

	stu_log_debug(4, "websocket alloc large buffer.");

	if (r->frames_in.fin && r->state == 0) {
		/* reuse buffer */
		r->frame_in->pos = r->frame_in->start;
		r->frame_in->last = r->frame_in->start;

		return STU_OK;
	}

	old = r->frames_in.payload_data.start;
	if (r->state != 0 && (size_t) (r->frames_in.payload_data.pos - old) >= STU_WEBSOCKET_REQUEST_LARGE_SIZE) {
		return STU_DECLINED;
	}

	if (r->busy) {
		return STU_DECLINED;
	}

	r->busy = stu_buf_create(c->pool, STU_WEBSOCKET_REQUEST_LARGE_SIZE);
	if (r->busy == NULL) {
		return STU_ERROR;
	}

	if (r->state == 0) {
		/*
		 * r->state == 0 means that a key frame was parsed successfully
		 * and we do not need to copy incomplete header line and
		 * to relocate the parser header pointers
		 */
		r->frame_in = r->busy;
		return STU_OK;
	}

	stu_log_debug(4, "websocket large frame copy: %u.", r->frame_in->pos - old);

	new = r->busy->start;
	(void) stu_memcpy(new, old, r->frame_in->pos - old);

	r->busy->pos = new + (r->frame_in->pos - old);
	r->busy->last = new + (r->frame_in->pos - old);

	r->frame_in = r->busy;

	return STU_OK;
}

static stu_int32_t
stu_websocket_process_request_frame(stu_websocket_request_t *r) {
	stu_uint64_t  size;

	if (r->frames_in.payload_len < STU_WEBSOCKET_EXTENDED_2) {
		size = r->frames_in.payload_len;
	} else {
		size = r->frames_in.extended;
	}

	if (size != r->frames_in.payload_data.size) {
		return STU_ERROR;
	}

	return STU_OK;
}

void
stu_websocket_process_request(stu_websocket_request_t *r) {
	stu_connection_t *c;
	stu_list_elt_t   *elts;
	stu_hash_elt_t   *e;
	stu_queue_t      *q;

	c = r->connection;

	if (c->read.timer_set) {
		stu_timer_del(&c->read);
	}

	// TODO: use rwlock
	stu_mutex_lock(&stu_websocket_filter_hash.lock);

	elts = &stu_websocket_filter_hash.keys->elts;

	for (q = stu_queue_head(&elts->queue); q != stu_queue_sentinel(&elts->queue); q = stu_queue_next(q)) {
		e = stu_queue_data(q, stu_hash_elt_t, queue);

		if (stu_websocket_filter_foreach_handler(r, &e->key, (stu_list_t *) e->value) == STU_OK) {
			goto done;
		}
	}

done:

	stu_mutex_unlock(&stu_websocket_filter_hash.lock);

	r->write_event_handler(r);
}

static stu_int32_t
stu_websocket_filter_foreach_handler(stu_websocket_request_t *r, stu_str_t *pattern, stu_list_t *list) {
	stu_list_elt_t         *elts, *e;
	stu_queue_t            *q;
	stu_websocket_filter_t *f;

	elts = &list->elts;

	for (q = stu_queue_tail(&elts->queue); q != stu_queue_sentinel(&elts->queue); q = stu_queue_prev(q)) {
		e = stu_queue_data(q, stu_list_elt_t, queue);
		f = (stu_websocket_filter_t *) e->value;

		if (f && f->handler && f->handler(r) == STU_OK) {
			return STU_OK;
		}
	}

	return STU_ERROR;
}

void
stu_websocket_request_write_handler(stu_websocket_request_t *r) {
	stu_connection_t *c;

	if (r == NULL) {
		stu_log_error(0, "something wrong here.");
		return;
	}

	c = r->connection;

	c->timedout = FALSE;

	stu_log_debug(4, "websocket run request.");

	stu_websocket_finalize_request(r, r->status);
}

void
stu_websocket_finalize_request(stu_websocket_request_t *r, stu_int32_t rc) {
	stu_connection_t *c;

	c = r->connection;

	stu_log_debug(4, "websocket finalize request: %d", rc);

	if (rc == STU_DONE) {
		stu_websocket_close_request(r);
		return;
	}

	if (rc == STU_OK) {
		c->error = TRUE;
	}

	if (rc == STU_DECLINED) {
		// TODO: response file system
		r->write_event_handler = stu_websocket_run_phases;
		stu_websocket_run_phases(r);
		return;
	}

	if (rc == STU_ERROR || c->error) {
		stu_websocket_close_request(r);
		return;
	}

	r->write_event_handler = stu_websocket_request_empty_handler;

	stu_websocket_close_request(r);
}

static void
stu_websocket_run_phases(stu_websocket_request_t *r) {
	stu_list_elt_t        *elts, *e;
	stu_queue_t           *q;
	stu_websocket_phase_t *ph;

	elts = &stu_websocket_phases.elts;

	for (q = stu_queue_head(&elts->queue); q != stu_queue_sentinel(&elts->queue); q = stu_queue_next(q)) {
		e = stu_queue_data(q, stu_list_elt_t, queue);
		ph = (stu_websocket_phase_t *) e->value;

		if (ph && ph->handler && ph->handler(r) == STU_OK) {
			return;
		}
	}
}

static void
stu_websocket_request_empty_handler(stu_websocket_request_t *r) {
	stu_log_debug(4, "websocket request empty handler.");
}


void
stu_websocket_free_request(stu_websocket_request_t *r) {
	r->connection->request = NULL;
}

void
stu_websocket_close_request(stu_websocket_request_t *r) {
	stu_connection_t *c;

	c = r->connection;

	stu_websocket_free_request(r);
	stu_websocket_close_connection(c);
}

void
stu_websocket_close_connection(stu_connection_t *c) {
	stu_http_close_connection(c);
}
