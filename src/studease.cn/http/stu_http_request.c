/*
 * stu_http_request.c
 *
 *  Created on: 2017骞�11鏈�22鏃�
 *      Author: Tony Lau
 */

#include "stu_http.h"

static void         stu_http_process_request_line(stu_event_t *ev);
static void         stu_http_process_request_headers(stu_event_t *ev);
static ssize_t      stu_http_read_request_header(stu_http_request_t *r);
static stu_int32_t  stu_http_alloc_large_header_buffer(stu_http_request_t *r, stu_bool_t is_request_line);
static stu_int32_t  stu_http_process_request_header(stu_http_request_t *r);
static stu_int32_t  stu_http_filter_foreach_handler(stu_http_request_t *r, stu_str_t *pattern, stu_list_t *list);
static stu_int32_t  stu_http_validate_host(stu_str_t *host, stu_pool_t *pool);
static void         stu_http_run_phases(stu_http_request_t *r);
static void         stu_http_request_empty_handler(stu_http_request_t *r);

static stu_int32_t  stu_http_process_header_line(stu_http_request_t *r, stu_table_elt_t *h, stu_uint32_t offset);
static stu_int32_t  stu_http_process_unique_header_line(stu_http_request_t *r, stu_table_elt_t *h, stu_uint32_t offset);
static stu_int32_t  stu_http_process_host(stu_http_request_t *r, stu_table_elt_t *h, stu_uint32_t offset);
static stu_int32_t  stu_http_process_content_length(stu_http_request_t *r, stu_table_elt_t *h, stu_uint32_t offset);
static stu_int32_t  stu_http_process_sec_websocket_key(stu_http_request_t *r, stu_table_elt_t *h, stu_uint32_t offset);
static stu_int32_t  stu_http_process_sec_websocket_protocol(stu_http_request_t *r, stu_table_elt_t *h, stu_uint32_t offset);
static stu_int32_t  stu_http_process_connection(stu_http_request_t *r, stu_table_elt_t *h, stu_uint32_t offset);

extern const stu_str_t   __NAME;
extern const stu_str_t   __VERSION;

extern stu_http_headers_t  stu_http_headers_in_hash;
extern stu_hash_t          stu_http_filter_hash;
extern stu_list_t          stu_http_phases;

extern stu_str_t  STU_FLASH_POLICY_FILE_REQUEST;
extern stu_str_t  STU_FLASH_POLICY_FILE;

stu_http_header_t  http_headers_in[] = {
	{ stu_string("Host"), offsetof(stu_http_headers_in_t, host), stu_http_process_host },
	{ stu_string("User-Agent"), offsetof(stu_http_headers_in_t, user_agent),  stu_http_process_header_line },
	{ stu_string("Accept"), offsetof(stu_http_headers_in_t, accept), stu_http_process_header_line },
	{ stu_string("Accept-Language"), offsetof(stu_http_headers_in_t, accept_language), stu_http_process_header_line },
#if (STU_HTTP_GZIP)
	{ stu_string("Accept-Encoding"), offsetof(stu_http_headers_in_t, accept_encoding), stu_http_process_header_line },
#endif
	{ stu_string("Content-Type"), offsetof(stu_http_headers_in_t, content_type), stu_http_process_header_line },
	{ stu_string("Content-Length"), offsetof(stu_http_headers_in_t, content_length), stu_http_process_content_length },
	{ stu_string("Sec-Websocket-Key"), offsetof(stu_http_headers_in_t, sec_websocket_key), stu_http_process_sec_websocket_key },
	{ stu_string("Sec-Websocket-Protocol"), offsetof(stu_http_headers_in_t, sec_websocket_protocol), stu_http_process_sec_websocket_protocol },
	{ stu_string("Sec-Websocket-Version"), offsetof(stu_http_headers_in_t, sec_websocket_version), stu_http_process_unique_header_line },
	{ stu_string("Sec-Websocket-Extensions"), offsetof(stu_http_headers_in_t, sec_websocket_extensions), stu_http_process_unique_header_line },
	{ stu_string("Upgrade"), offsetof(stu_http_headers_in_t, upgrade), stu_http_process_header_line },
	{ stu_string("Connection"), offsetof(stu_http_headers_in_t, connection), stu_http_process_connection },
	{ stu_null_string, 0, NULL }
};

static stu_str_t  STU_HTTP_HEADER_SEC_WEBSOCKET_ACCEPT = stu_string("Sec-WebSocket-Accept");
static stu_str_t  STU_HTTP_HEADER_SEC_WEBSOCKET_PROTOCOL = stu_string("Sec-WebSocket-Protocol");
static stu_str_t  STU_WEBSOCKET_SIGN_KEY = stu_string("258EAFA5-E914-47DA-95CA-C5AB0DC85B11");


void
stu_http_request_read_handler(stu_event_t *ev) {
	stu_connection_t *c;
	stu_int32_t       n;

	c = (stu_connection_t *) ev->data;

	//stu_mutex_lock(&c->lock);

	if (c->buffer.start == NULL) {
		c->buffer.start = (u_char *) stu_pcalloc(c->pool, STU_HTTP_REQUEST_DEFAULT_SIZE);
		c->buffer.pos = c->buffer.last = c->buffer.start;
		c->buffer.end = c->buffer.start + STU_HTTP_REQUEST_DEFAULT_SIZE;
		c->buffer.size = STU_HTTP_REQUEST_DEFAULT_SIZE;
	}

	if (c->buffer.end == c->buffer.last) {
		c->buffer.pos = c->buffer.last = c->buffer.start;
		stu_memzero(c->buffer.start, c->buffer.size);
	}

	n = c->recv(c, c->buffer.last, c->buffer.end - c->buffer.last);
	if (n == STU_AGAIN) {
		goto done;
	}

	if (n == STU_ERROR) {
		c->error = TRUE;
		goto failed;
	}

	if (n == 0) {
		stu_log_error(0, "http remote peer prematurely closed connection.");
		c->close = TRUE;
		goto failed;
	}

	c->buffer.last += n;
	stu_log_debug(4, "recv: fd=%d, bytes=%d.", c->fd, n);

	if (stu_strncmp(c->buffer.start, STU_FLASH_POLICY_FILE_REQUEST.data, STU_FLASH_POLICY_FILE_REQUEST.len) == 0) {
		n = c->send(c, STU_FLASH_POLICY_FILE.data, STU_FLASH_POLICY_FILE.len);
		if (n == -1) {
			stu_log_debug(4, "Failed to send policy file: fd=%d.", c->fd);
			goto failed;
		}

		stu_log_debug(4, "sent policy file: fd=%d, bytes=%d.", c->fd, n);

		goto done;
	}

	c->request = (void *) stu_http_create_request(c);
	if (c->request == NULL) {
		stu_log_error(0, "Failed to create http request.");
		goto failed;
	}

	//ev->handler = stu_http_process_request_line;
	stu_http_process_request_line(ev);

	goto done;

failed:

	stu_http_close_connection(c);

done:

	stu_log_debug(4, "http request done.");

	//stu_mutex_unlock(&c->lock);
}

// TODO: memory leak while request is available
stu_http_request_t *
stu_http_create_request(stu_connection_t *c) {
	stu_http_request_t *r;

	if (c->request == NULL) {
		r = stu_pcalloc(c->pool, sizeof(stu_http_request_t));
		if (r == NULL) {
			stu_log_error(0, "Failed to create http request.");
			return NULL;
		}

		r->write_event_handler = stu_http_request_write_handler;
	} else {
		r = c->request;
	}

	r->connection = c;
	r->header_in = r->busy ? r->busy : &c->buffer;

	stu_hash_init(&r->headers_in.headers, STU_HTTP_HEADER_MAX_RECORDS, NULL, STU_HASH_FLAGS_LOWCASE);
	stu_hash_init(&r->headers_out.headers, STU_HTTP_HEADER_MAX_RECORDS, NULL, STU_HASH_FLAGS_LOWCASE);

	return r;
}

static void
stu_http_process_request_line(stu_event_t *ev) {
	stu_connection_t   *c;
	stu_http_request_t *r;
	ssize_t             n;
	stu_int32_t         rc, rv;

	c = ev->data;
	r = c->request;

	stu_log_debug(4, "http process request line.");

	if (ev->timedout) {
		stu_log_error(STU_ETIMEDOUT, "Failed to process http request line.");

		c->timedout = TRUE;
		stu_http_finalize_request(r, STU_HTTP_REQUEST_TIMEOUT);

		return;
	}

	rc = STU_DONE;

	for ( ;; ) {
		if (rc == STU_AGAIN) {
			if (r->header_in->pos == r->header_in->end) {
				rv = stu_http_alloc_large_header_buffer(r, TRUE);
				if (rv == STU_ERROR) {
					stu_http_finalize_request(r, STU_HTTP_INTERNAL_SERVER_ERROR);
					return;
				}

				if (rv == STU_DECLINED) {
					stu_log_error(0, "client sent too long URI.");
					stu_http_finalize_request(r, STU_HTTP_REQUEST_URI_TOO_LARGE);
					return;
				}
			}

			n = stu_http_read_request_header(r);
			if (n == STU_AGAIN) {
				return;
			}

			if (n == STU_ERROR) {
				stu_log_error(0, "http failed to read request buffer.");
				stu_http_finalize_request(r, STU_HTTP_BAD_REQUEST);
				return;
			}
		}

		rc = stu_http_parse_request_line(r, r->header_in);
		if (rc == STU_OK) {
			if (r->host.data && r->host.len) {
				rc = stu_http_validate_host(&r->host, c->pool);
				if (rc == STU_DECLINED) {
					stu_log_error(0, "client sent invalid host in http request line.");
					stu_http_finalize_request(r, STU_HTTP_BAD_REQUEST);
					return;
				}

				if (rc == STU_ERROR) {
					stu_http_finalize_request(r, STU_HTTP_INTERNAL_SERVER_ERROR);
					return;
				}
			}

			//ev->handler = stu_http_process_request_headers;
			stu_http_process_request_headers(ev);

			return;
		}

		if (rc == STU_AGAIN) {
			stu_log_debug(4, "a header line parsing is still not complete.");
			continue;
		}

		stu_log_error(0, "Failed to process http request line: %s.", stu_http_status_text(STU_HTTP_BAD_REQUEST));
		stu_http_finalize_request(r, STU_HTTP_BAD_REQUEST);

		return;
	}
}

static void
stu_http_process_request_headers(stu_event_t *ev) {
	stu_http_request_t *r;
	stu_connection_t   *c;
	stu_http_header_t  *hh;
	stu_table_elt_t    *h;
	u_char             *p;
	stu_int32_t         rc, rv;
	ssize_t             n;

	c = ev->data;
	r = c->request;

	stu_log_debug(4, "http process request headers.");

	if (ev->timedout) {
		stu_log_error(STU_ETIMEDOUT, "Failed to process http request headers.");

		c->timedout = TRUE;
		stu_http_finalize_request(r, STU_HTTP_REQUEST_TIMEOUT);

		return;
	}

	rc = STU_DONE;

	for ( ;; ) {
		if (rc == STU_AGAIN) {
			if (r->header_in->pos == r->header_in->end) {
				rv = stu_http_alloc_large_header_buffer(r, FALSE);
				if (rv == STU_ERROR) {
					stu_log_error(0, "http failed to alloc large buffer.");
					stu_http_finalize_request(r, STU_HTTP_INTERNAL_SERVER_ERROR);
					return;
				}

				if (rv == STU_DECLINED) {
					p = r->header_name_start;
					if (p == NULL) {
						stu_log_error(0, "http client sent too large request.");
						stu_http_finalize_request(r, STU_HTTP_REQUEST_HEADER_TOO_LARGE);
						return;
					}

					stu_log_error(0, "http client sent too long header line: \"%s...\"", r->header_name_start);
					stu_http_finalize_request(r, STU_HTTP_REQUEST_HEADER_TOO_LARGE);
					return;
				}
			}

			n = stu_http_read_request_header(r);
			if (n == STU_AGAIN) {
				return;
			}

			if (n == STU_ERROR) {
				stu_log_error(0, "http failed to read request buffer.");
				stu_http_finalize_request(r, STU_HTTP_BAD_REQUEST);
				return;
			}
		}

		/* the host header could change the server configuration context */
		rc = stu_http_parse_header_line(r, r->header_in, 1);
		if (rc == STU_OK) {
			/* a header line has been parsed successfully */
			h = stu_pcalloc(c->pool, sizeof(stu_table_elt_t));
			if (h == NULL) {
				stu_http_finalize_request(r, STU_HTTP_INTERNAL_SERVER_ERROR);
				return;
			}

			h->hash = r->header_hash;

			h->key.len = r->header_name_end - r->header_name_start;
			h->key.data = r->header_name_start;
			h->key.data[h->key.len] = '\0';

			h->value.len = r->header_end - r->header_start;
			h->value.data = r->header_start;
			h->value.data[h->value.len] = '\0';

			h->lowcase_key = stu_pcalloc(c->pool, h->key.len + 1);
			if (h->lowcase_key == NULL) {
				stu_http_finalize_request(r, STU_HTTP_INTERNAL_SERVER_ERROR);
				return;
			}

			if (h->key.len == r->lowcase_index) {
				(void) stu_memcpy(h->lowcase_key, r->lowcase_header, h->key.len);
			} else {
				stu_strlow(h->lowcase_key, h->key.data, h->key.len);
			}

			stu_http_header_set(&r->headers_in.headers, &h->key, &h->value);

			hh = stu_hash_find(&stu_http_headers_in_hash, h->hash, h->key.data, h->key.len);
			if (hh && hh->handler(r, h, hh->offset) != STU_OK) {
				return;
			}

			stu_log_debug(3, "http header => \"%s: %s\".", h->key.data, h->value.data);

			continue;
		}

		if (rc == STU_DONE) {
			stu_log_debug(4, "http header parsed.");

			rc = stu_http_process_request_header(r);
			if (rc != STU_OK) {
				stu_log_error(0, "http failed to process request header.");
				stu_http_finalize_request(r, STU_HTTP_BAD_REQUEST);
				return;
			}

			stu_http_process_request(r);

			if (r->header_in->pos == r->header_in->last) {
				r->header_in->pos = r->header_in->last = r->header_in->start;
				rc = STU_AGAIN;
			}

			continue;
		}

		if (rc == STU_AGAIN) {
			stu_log_debug(4, "a header line parsing is still not complete.");
			continue;
		}

		/* rc == STU_HTTP_PARSE_INVALID_HEADER */
		stu_log_error(0, "http client sent invalid header line.");
		stu_http_finalize_request(r, STU_HTTP_BAD_REQUEST);

		return;
	}
}

static ssize_t
stu_http_read_request_header(stu_http_request_t *r) {
	stu_connection_t *c;
	ssize_t           n;

	c = r->connection;

	if (r->header_in->end == r->header_in->last) {
		r->header_in->pos = r->header_in->last = r->header_in->start;
		stu_memzero(r->header_in->start, r->header_in->size);
	}

	n = c->recv(c, r->header_in->last, r->header_in->end - r->header_in->last);
	if (n == STU_AGAIN) {
		return STU_AGAIN;
	}

	if (n == STU_ERROR) {
		c->error = TRUE;
		return STU_ERROR;
	}

	if (n == 0) {
		stu_log_error(0, "http remote peer prematurely closed connection.");
		c->close = TRUE;
		return STU_ERROR;
	}

	r->header_in->last += n;
	stu_log_debug(4, "recv: fd=%d, bytes=%d.", c->fd, n);

	return n;
}

static stu_int32_t
stu_http_alloc_large_header_buffer(stu_http_request_t *r, stu_bool_t is_request_line) {
	stu_connection_t *c;
	u_char           *old, *new;

	c = r->connection;

	stu_log_debug(4, "http alloc large header buffer.");

	if (is_request_line && r->state == 0) {
		/* the client fills up the buffer with "\r\n" */
		r->header_in->pos = r->header_in->start;
		r->header_in->last = r->header_in->start;

		return STU_OK;
	}

	old = is_request_line ? r->request_line.data : r->header_name_start;
	if (r->state != 0 && (size_t) (r->header_in->pos - old) >= STU_HTTP_REQUEST_LARGE_SIZE) {
		return STU_DECLINED;
	}

	if (r->busy) {
		return STU_DECLINED;
	}

	r->busy = stu_buf_create(c->pool, STU_HTTP_REQUEST_LARGE_SIZE);
	if (r->busy == NULL) {
		return STU_ERROR;
	}

	if (r->state == 0) {
		/*
		 * r->state == 0 means that a header line was parsed successfully
		 * and we do not need to copy incomplete header line and
		 * to relocate the parser header pointers
		 */
		r->header_in = r->busy;
		return STU_OK;
	}

	stu_log_debug(4, "http large header copy: %u.", r->header_in->pos - old);

	new = r->busy->start;
	(void) stu_memcpy(new, old, r->header_in->pos - old);

	r->busy->pos = new + (r->header_in->pos - old);
	r->busy->last = new + (r->header_in->pos - old);

	if (is_request_line) {
		r->request_line.data = new;

		if (r->schema.data) {
			r->schema.data = new + (r->schema.data - old);
		}

		if (r->host.data) {
			r->host.data = new + (r->host.data - old);
		}

		if (r->port.data) {
			r->port.data = new + (r->port.data - old);
		}

		if (r->uri.data) {
			r->uri.data = new + (r->uri.data - old);
		}

		if (r->args.data) {
			r->args.data = new + (r->args.data - old);
		}
	} else {
		r->header_name_start = new;
		r->header_name_end = new + (r->header_name_end - old);
		r->header_start = new + (r->header_start - old);
		r->header_end = new + (r->header_end - old);
	}

	r->header_in = r->busy;

	return STU_OK;
}

static stu_int32_t
stu_http_process_request_header(stu_http_request_t *r) {
	if (r->headers_in.host == NULL && r->http_version > STU_HTTP_VERSION_10) {
		stu_log_error(0, "http client sent HTTP/1.1 request without \"Host\" header.");
		stu_http_finalize_request(r, STU_HTTP_BAD_REQUEST);
		return STU_ERROR;
	}

	if (r->headers_in.content_length) {
		r->headers_in.content_length_n = strtol((const char *) r->headers_in.content_length->value.data, NULL, 10);
		if (r->headers_in.content_length_n < 0) {
			stu_log_error(0, "http client sent invalid \"Content-Length\" header.");
			stu_http_finalize_request(r, STU_HTTP_BAD_REQUEST);
			return STU_ERROR;
		}
	}

	if (r->headers_in.connection_type == STU_HTTP_CONNECTION_KEEP_ALIVE) {
		if (r->headers_in.keep_alive) {
			r->headers_in.keep_alive_n = strtol((const char *) r->headers_in.keep_alive->value.data, NULL, 10);
		}
	}

	return STU_OK;
}

void
stu_http_process_request(stu_http_request_t *r) {
	stu_connection_t *c;
	stu_list_elt_t   *elts;
	stu_hash_elt_t   *e;
	stu_queue_t      *q;

	c = r->connection;

	if (c->read->timer_set) {
		stu_timer_del(c->read);
	}

	// TODO: use rwlock
	stu_mutex_lock(&stu_http_filter_hash.lock);

	elts = &stu_http_filter_hash.keys->elts;

	for (q = stu_queue_head(&elts->queue); q != stu_queue_sentinel(&elts->queue); q = stu_queue_next(q)) {
		e = stu_queue_data(q, stu_hash_elt_t, queue);

		if (stu_http_filter_foreach_handler(r, &e->key, (stu_list_t *) e->value) == STU_OK) {
			goto done;
		}
	}

done:

	stu_mutex_unlock(&stu_http_filter_hash.lock);

	r->write_event_handler(r);
}

static stu_int32_t
stu_http_filter_foreach_handler(stu_http_request_t *r, stu_str_t *pattern, stu_list_t *list) {
	stu_list_elt_t    *elts, *e;
	stu_queue_t       *q;
	stu_http_filter_t *f;

	elts = &list->elts;

	for (q = stu_queue_tail(&elts->queue); q != stu_queue_sentinel(&elts->queue); q = stu_queue_prev(q)) {
		e = stu_queue_data(q, stu_list_elt_t, queue);
		f = (stu_http_filter_t *) e->value;

		if (f && f->handler && f->handler(r) == STU_OK) {
			return STU_OK;
		}
	}

	return STU_ERROR;
}

void
stu_http_request_write_handler(stu_http_request_t *r) {
	stu_connection_t *c;

	if (r == NULL) {
		stu_log_error(0, "something wrong here.");
		return;
	}

	c = r->connection;
	c->timedout = FALSE;

	stu_log_debug(4, "http run request: \"%s\"", r->uri.data);

	stu_http_finalize_request(r, r->headers_out.status);
}

static stu_int32_t
stu_http_validate_host(stu_str_t *host, stu_pool_t *pool) {
	u_char     *h, ch;
	size_t      i, dot_pos, host_len;
	stu_bool_t  upper_case;
	enum {
		sw_usual = 0,
		sw_literal,
		sw_rest
	} state;

	h = host->data;
	dot_pos = host->len;
	host_len = host->len;
	upper_case = FALSE;

	state = sw_usual;

	for (i = 0; i < host->len; i++) {
		ch = h[i];

		switch (ch) {
		case '.':
			if (dot_pos == i - 1) {
				return STU_DECLINED;
			}
			dot_pos = i;
			break;

		case ':':
			if (state == sw_usual) {
				host_len = i;
				state = sw_rest;
			}
			break;

		case '[':
			if (i == 0) {
				state = sw_literal;
			}
			break;

		case ']':
			if (state == sw_literal) {
				host_len = i + 1;
				state = sw_rest;
			}
			break;

		case '\0':
			return STU_DECLINED;

		default:
			if (stu_path_separator(ch)) {
				return STU_DECLINED;
			}

			if (ch >= 'A' && ch <= 'Z') {
				upper_case = TRUE;
			}

			break;
		}
	}

	if (dot_pos == host_len - 1) {
		host_len--;
	}

	if (host_len == 0) {
		return STU_DECLINED;
	}

	if (upper_case) {
		host->data = stu_pcalloc(pool, host_len + 1);
		if (host->data == NULL) {
			return STU_ERROR;
		}

		stu_strlow(host->data, h, host_len);
	}

	host->len = host_len;

	return STU_OK;
}


static stu_int32_t
stu_http_process_header_line(stu_http_request_t *r, stu_table_elt_t *h, stu_uint32_t offset) {
	stu_table_elt_t **ph;

	ph = (stu_table_elt_t **) ((char *) &r->headers_in + offset);
	if (*ph == NULL) {
		*ph = h;
	}

	return STU_OK;
}

static stu_int32_t
stu_http_process_unique_header_line(stu_http_request_t *r, stu_table_elt_t *h, stu_uint32_t offset) {
	stu_table_elt_t **ph;

	ph = (stu_table_elt_t **) ((char *) &r->headers_in + offset);
	if (*ph == NULL) {
		*ph = h;
		return STU_OK;
	}

	stu_log_error(0, "http client sent duplicate header line = > \"%s: %s\", "
			"previous value => \"%s: %s\".", h->key.data, h->value.data, (*ph)->key.data, (*ph)->value.data);

	stu_http_finalize_request(r, STU_HTTP_BAD_REQUEST);

	return STU_ERROR;
}

static stu_int32_t
stu_http_process_host(stu_http_request_t *r, stu_table_elt_t *h, stu_uint32_t offset) {
	stu_connection_t *c;
	stu_int32_t       rc;
	stu_str_t         host;

	c = r->connection;
	host = h->value;

	if (r->headers_in.host == NULL) {
		r->headers_in.host = h;
	}

	rc = stu_http_validate_host(&host, c->pool);
	if (rc == STU_DECLINED) {
		stu_log_error(0, "http client sent invalid host header.");
		stu_http_finalize_request(r, STU_HTTP_BAD_REQUEST);
		return STU_ERROR;
	}

	if (rc == STU_ERROR) {
		stu_http_finalize_request(r, STU_HTTP_INTERNAL_SERVER_ERROR);
		return STU_ERROR;
	}

	if (r->headers_in.server.len) {
		return STU_OK;
	}

	r->headers_in.server = host;

	return STU_OK;
}

static stu_int32_t
stu_http_process_content_length(stu_http_request_t *r, stu_table_elt_t *h, stu_uint32_t offset) {
	stu_uint32_t  length;

	length = atol((const char *) h->value.data);
	r->headers_in.content_length_n = length;

	return stu_http_process_unique_header_line(r, h, offset);
}

static stu_int32_t
stu_http_process_sec_websocket_key(stu_http_request_t *r, stu_table_elt_t *h, stu_uint32_t offset) {
	stu_connection_t *c;
	stu_table_elt_t  *e;
	stu_sha1_t        sha1;
	stu_str_t         sha1_signed;

	c = r->connection;

	if (stu_http_process_unique_header_line(r, h, offset) == STU_ERROR) {
		return STU_ERROR;
	}

	e = stu_pcalloc(c->pool, sizeof(stu_table_elt_t));
	if (e == NULL) {
		stu_http_finalize_request(r, STU_HTTP_INTERNAL_SERVER_ERROR);
		return STU_ERROR;
	}

	e->key.data = STU_HTTP_HEADER_SEC_WEBSOCKET_ACCEPT.data;
	e->key.len = STU_HTTP_HEADER_SEC_WEBSOCKET_ACCEPT.len;

	sha1_signed.len = SHA_DIGEST_LENGTH;
	sha1_signed.data = stu_pcalloc(c->pool, sha1_signed.len + 1);

	e->value.len = stu_base64_encoded_length(SHA_DIGEST_LENGTH);
	e->value.data = stu_pcalloc(c->pool, e->value.len + 1);

	if (sha1_signed.data == NULL || e->value.data == NULL) {
		stu_http_finalize_request(r, STU_HTTP_INTERNAL_SERVER_ERROR);
		return STU_ERROR;
	}

	stu_sha1_init(&sha1);
	stu_sha1_update(&sha1, h->value.data, h->value.len);
	stu_sha1_update(&sha1, STU_WEBSOCKET_SIGN_KEY.data, STU_WEBSOCKET_SIGN_KEY.len);
	stu_sha1_final(sha1_signed.data, &sha1);

	stu_base64_encode(&e->value, &sha1_signed);

	r->headers_out.sec_websocket_accept = e;

	stu_http_header_set(&r->headers_out.headers, &h->key, &h->value);

	return STU_OK;
}

static stu_int32_t
stu_http_process_sec_websocket_protocol(stu_http_request_t *r, stu_table_elt_t *h, stu_uint32_t offset) {
	stu_connection_t *c;
	stu_table_elt_t  *e;

	c = r->connection;

	if (stu_http_process_unique_header_line(r, h, offset) == STU_ERROR) {
		return STU_ERROR;
	}

	e = stu_pcalloc(c->pool, sizeof(stu_table_elt_t));
	if (e == NULL) {
		stu_http_finalize_request(r, STU_HTTP_INTERNAL_SERVER_ERROR);
		return STU_ERROR;
	}

	e->key.data = STU_HTTP_HEADER_SEC_WEBSOCKET_PROTOCOL.data;
	e->key.len = STU_HTTP_HEADER_SEC_WEBSOCKET_PROTOCOL.len;

	e->value.data = stu_pcalloc(c->pool, h->value.len + 1);
	e->value.len = h->value.len;

	(void) stu_memcpy(e->value.data, h->value.data, h->value.len);

	r->headers_out.sec_websocket_protocol = e;

	return STU_OK;
}

static stu_int32_t
stu_http_process_connection(stu_http_request_t *r, stu_table_elt_t *h, stu_uint32_t offset) {
	stu_http_process_unique_header_line(r, h, offset);

	if (stu_strnstr(h->value.data, "close", 5)) {
		r->headers_in.connection_type = STU_HTTP_CONNECTION_CLOSE;
	} else if (stu_strnstr(h->value.data, "keep-alive", 10)) {
		r->headers_in.connection_type = STU_HTTP_CONNECTION_KEEP_ALIVE;
	}

	return STU_OK;
}


void
stu_http_finalize_request(stu_http_request_t *r, stu_int32_t rc) {
	stu_connection_t *c;

	c = r->connection;

	stu_log_debug(4, "http finalize request: %d, \"%s\"", rc, r->uri.data);

	if (rc == STU_DONE) {
		stu_http_close_request(r);
		return;
	}

	if (rc == STU_OK) {
		c->error = TRUE;
	}

	if (rc == STU_DECLINED) {
		// TODO: response file system
		r->write_event_handler = stu_http_run_phases;
		stu_http_run_phases(r);
		return;
	}

	if (rc == STU_HTTP_REQUEST_TIMEOUT || rc == STU_ERROR || c->error) {
		stu_http_close_request(r);
		return;
	}

	if (rc == STU_HTTP_CREATED || rc == STU_HTTP_NO_CONTENT || rc >= STU_HTTP_MULTIPLE_CHOICES) {
		r->read_event_handler = stu_http_request_write_handler;
		r->write_event_handler = stu_http_request_write_handler;
		stu_http_send_special_response(r, rc);
		return;
	}

	r->write_event_handler = stu_http_request_empty_handler;

	stu_http_close_request(r);
}

static void
stu_http_run_phases(stu_http_request_t *r) {
	stu_list_elt_t   *elts, *e;
	stu_queue_t      *q;
	stu_http_phase_t *ph;

	elts = &stu_http_phases.elts;

	for (q = stu_queue_head(&elts->queue); q != stu_queue_sentinel(&elts->queue); q = stu_queue_next(q)) {
		e = stu_queue_data(q, stu_list_elt_t, queue);
		ph = (stu_http_phase_t *) e->value;

		if (ph && ph->handler && ph->handler(r) == STU_OK) {
			return;
		}
	}
}

stu_int32_t
stu_http_send_special_response(stu_http_request_t *r, stu_int32_t rc) {
	stu_connection_t *c;
	stu_table_elt_t  *swa, *swp;
	stu_buf_t         buf;
	u_char            tmp[STU_HTTP_REQUEST_DEFAULT_SIZE];
	stu_int32_t       n;

	c = r->connection;
	swa = r->headers_out.sec_websocket_accept;
	swp = r->headers_out.sec_websocket_protocol;

	buf.start = (u_char *) tmp;
	buf.pos = buf.last = buf.start;
	buf.end = (u_char *) tmp + STU_HTTP_REQUEST_DEFAULT_SIZE;
	buf.size = STU_HTTP_REQUEST_DEFAULT_SIZE;

	buf.last = stu_sprintf(buf.last, "HTTP/1.1 %d %s" CRLF, rc, stu_http_status_text(rc));
	buf.last = stu_sprintf(buf.last, "Server: %s/%s" CRLF, __NAME.data, __VERSION.data);
	if (rc == STU_HTTP_SWITCHING_PROTOCOLS) {
		buf.last = stu_sprintf(buf.last, "Connection: Upgrade" CRLF);
		buf.last = stu_sprintf(buf.last, "Upgrade: websocket" CRLF);
		buf.last = stu_sprintf(buf.last, "%s: %s" CRLF, swa->key.data, swa->value.data);
		if (swp) {
			buf.last = stu_sprintf(buf.last, "%s: %s" CRLF, swp->key.data, swp->value.data);
		}
		buf.last = stu_sprintf(buf.last, CRLF);
	} else {
		buf.last = stu_sprintf(buf.last, "Connection: close" CRLF);
		buf.last = stu_sprintf(buf.last, "Content-type: text/html" CRLF);
		buf.last = stu_sprintf(buf.last, "Content-length: %d" CRLF CRLF, __NAME.len + __VERSION.len + 2);
		buf.last = stu_sprintf(buf.last, "%s/%s\n", __NAME.data, __VERSION.data);
	}

	n = c->send(c, buf.pos, buf.last - buf.pos);
	if (n == -1) {
		stu_log_error(stu_errno, "Failed to send http response: fd=%d.", c->fd);
		stu_http_close_connection(c);
		return STU_ERROR;
	}

	stu_log_debug(4, "sent: fd=%d, bytes=%d.", c->fd, n);

	return STU_OK;
}

static void
stu_http_request_empty_handler(stu_http_request_t *r) {
	stu_log_debug(4, "http request empty handler.");
}

void
stu_http_free_request(stu_http_request_t *r) {
	stu_hash_destroy(&r->headers_in.headers, NULL);
	stu_hash_destroy(&r->headers_out.headers, NULL);

	r->connection->request = NULL;
}

void
stu_http_close_request(stu_http_request_t *r) {
	stu_connection_t *c;

	c = r->connection;

	stu_http_free_request(r);
	stu_http_close_connection(c);
}

void
stu_http_close_connection(stu_connection_t *c) {
	stu_connection_close(c);
}
