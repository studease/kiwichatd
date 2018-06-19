/*
 * stu_http_upstream.c
 *
 *  Created on: 2017骞�11鏈�27鏃�
 *      Author: Tony Lau
 */

#include "stu_http.h"

static void         stu_http_upstream_process_status_line(stu_event_t *ev);
static void         stu_http_upstream_process_response_headers(stu_event_t *ev);
static ssize_t      stu_http_upstream_read_response_header(stu_http_request_t *pr);
static stu_int32_t  stu_http_upstream_alloc_large_header_buffer(stu_http_request_t *pr, stu_bool_t is_status_line);
static stu_int32_t  stu_http_upstream_process_response_header(stu_http_request_t *pr);

static stu_int32_t  stu_http_upstream_process_header_line(stu_http_request_t *pr, stu_table_elt_t *h, stu_uint32_t offset);
static stu_int32_t  stu_http_upstream_process_unique_header_line(stu_http_request_t *p, stu_table_elt_t *h, stu_uint32_t offset);
static stu_int32_t  stu_http_upstream_process_content_length(stu_http_request_t *pr, stu_table_elt_t *h, stu_uint32_t offset);
static stu_int32_t  stu_http_upstream_process_connection(stu_http_request_t *pr, stu_table_elt_t *h, stu_uint32_t offset);

extern const stu_str_t  __NAME;
extern const stu_str_t  __VERSION;

extern stu_http_headers_t  stu_http_upstream_headers_in_hash;

stu_http_header_t  http_upstream_headers_in[] = {
	{ stu_string("Server"), offsetof(stu_http_headers_out_t, server),  stu_http_upstream_process_header_line },
	{ stu_string("Date"), offsetof(stu_http_headers_out_t, date), stu_http_upstream_process_header_line },
	{ stu_string("Content-Type"), offsetof(stu_http_headers_out_t, content_type), stu_http_upstream_process_header_line },
	{ stu_string("Content-Length"), offsetof(stu_http_headers_out_t, content_length), stu_http_upstream_process_content_length },
	{ stu_string("Connection"), offsetof(stu_http_headers_out_t, connection), stu_http_upstream_process_connection },
	{ stu_null_string, 0, NULL }
};

stu_http_method_bitmask_t  stu_http_upstream_method_mask[] = {
	{ stu_string("GET"),  STU_HTTP_GET },
	{ stu_string("HEAD"), STU_HTTP_HEAD },
	{ stu_string("POST"), STU_HTTP_POST },
	{ stu_null_string, 0 }
};


void
stu_http_upstream_read_handler(stu_event_t *ev) {
	stu_connection_t      *pc;
	stu_upstream_t        *u;
	stu_upstream_server_t *s;
	stu_int32_t            n;

	pc = ev->data;
	u = pc->upstream;
	s = u->server;

	//stu_mutex_lock(&pc->lock);

	if (pc->buffer.start == NULL) {
		pc->buffer.start = (u_char *) stu_pcalloc(pc->pool, STU_HTTP_REQUEST_DEFAULT_SIZE);
		pc->buffer.pos = pc->buffer.last = pc->buffer.start;
		pc->buffer.end = pc->buffer.start + STU_HTTP_REQUEST_DEFAULT_SIZE;
		pc->buffer.size = STU_HTTP_REQUEST_DEFAULT_SIZE;
	}

	if (pc->buffer.end == pc->buffer.last) {
		pc->buffer.pos = pc->buffer.last = pc->buffer.start;
		stu_memzero(pc->buffer.start, pc->buffer.size);
	}

	n = pc->recv(pc, pc->buffer.last, pc->buffer.size);
	if (n == STU_AGAIN) {
		goto done;
	}

	if (n == STU_ERROR) {
		pc->error = TRUE;
		goto failed;
	}

	if (n == 0) {
		stu_log_error(0, "http remote peer prematurely closed connection.");
		pc->close = TRUE;
		goto failed;
	}

	pc->buffer.last += n;
	stu_log_debug(4, "upstream recv from %s: fd=%d, bytes=%d.", s->name.data, pc->fd, n);

	pc->request = (void *) u->create_request_pt(pc);
	if (pc->request == NULL) {
		stu_log_error(0, "Failed to create http request.");
		goto failed;
	}

	//ev->handler = stu_http_upstream_process_status_line;
	stu_http_upstream_process_status_line(ev);

	goto done;

failed:

	stu_atomic_fetch_add(&s->fails, 1);
	u->cleanup_pt(u->connection);

done:

	stu_log_debug(4, "http upstream response done.");

	//stu_mutex_unlock(&pc->lock);
}

void *
stu_http_upstream_create_request(stu_connection_t *pc) {
	return stu_http_create_request(pc);
}

stu_int32_t
stu_http_upstream_reinit_request(stu_connection_t *pc) {
	pc->request = stu_http_upstream_create_request(pc);
	if (pc->request == NULL) {
		return STU_ERROR;
	}

	return STU_OK;
}

void
stu_http_upstream_write_handler(stu_event_t *ev) {
	stu_connection_t      *pc;
	stu_upstream_t        *u;
	stu_upstream_server_t *s;
	stu_int32_t            n;

	pc = (stu_connection_t *) ev->data;
	u = pc->upstream;
	s = u->server;

	//stu_mutex_lock(&pc->lock);

	stu_event_del(pc->write, STU_WRITE_EVENT, 0);

	if (u == NULL || u->peer == NULL
			|| u->peer->timedout || u->peer->close || u->peer->error || u->peer->destroyed) {
		goto done;
	}

	if (u->generate_request_pt(pc) == STU_ERROR) {
		stu_log_error(0, "Failed to generate request of http upstream %s, fd=%d.", s->name.data, pc->fd);
		goto failed;
	}

	n = pc->send(pc, pc->buffer.pos, pc->buffer.last - pc->buffer.pos);
	if (n == -1) {
		pc->error = TRUE;
		stu_log_error(stu_errno, "Failed to send http upstream request, u->fd=%d.", pc->fd);
		goto failed;
	}

	stu_log_debug(4, "sent to http upstream %s: u->fd=%d, bytes=%d.", s->name.data, pc->fd, n);

	goto done;

failed:

	stu_atomic_fetch_add(&s->fails, 1);
	u->cleanup_pt(u->connection);

done:

	stu_log_debug(4, "http upstream request done.");

	//stu_mutex_unlock(&pc->lock);
}

stu_int32_t
stu_http_upstream_generate_request(stu_connection_t *pc) {
	stu_upstream_t            *u;
	stu_connection_t          *c;
	stu_http_request_t        *pr;
	stu_http_method_bitmask_t *method;
	stu_str_t                 *method_name;

	pr = pc->request;
	u = pc->upstream;
	c = u->connection;

	if (pc->buffer.start == NULL) {
		pc->buffer.start = (u_char *) stu_pcalloc(pc->pool, STU_HTTP_REQUEST_DEFAULT_SIZE);
		pc->buffer.pos = pc->buffer.last = pc->buffer.start;
		pc->buffer.end = pc->buffer.start + STU_HTTP_REQUEST_DEFAULT_SIZE;
		pc->buffer.size = STU_HTTP_REQUEST_DEFAULT_SIZE;
	}
	pc->buffer.pos = pc->buffer.last;

	/* get method name */
	method_name = NULL;

	for (method = stu_http_upstream_method_mask; method->name.len; method++) {
		if (u->server->method == method->mask) {
			method_name = &method->name;
			break;
		}
	}

	if (method_name == NULL) {
		stu_log_error(0, "Method not supported while generating http upstream request: fd=%d, method=%hd.", c->fd, u->server->method);
		return STU_ERROR;
	}

	/* generate request */
	pc->buffer.last = stu_sprintf(pc->buffer.last, "%s %s HTTP/1.1" CRLF, method_name->data, pr->uri.data);
	pc->buffer.last = stu_sprintf(pc->buffer.last, "Host: %s" CRLF, u->server->addr.name.data);
	pc->buffer.last = stu_sprintf(pc->buffer.last, "User-Agent: %s/%s" CRLF, __NAME.data, __VERSION.data);
	pc->buffer.last = stu_sprintf(pc->buffer.last, "Accept: application/json" CRLF);
	pc->buffer.last = stu_sprintf(pc->buffer.last, "Accept-Charset: utf-8" CRLF);
	pc->buffer.last = stu_sprintf(pc->buffer.last, "Accept-Language: zh-CN,zh;q=0.8" CRLF);
	pc->buffer.last = stu_sprintf(pc->buffer.last, "Connection: keep-alive" CRLF);
	if (u->server->method == STU_HTTP_POST && pr->request_body) {
		pc->buffer.last = stu_sprintf(pc->buffer.last, "Content-Type: application/json" CRLF);
		pc->buffer.last = stu_sprintf(pc->buffer.last, "Content-Length: %d" CRLF CRLF, pr->headers_out.content_length_n);
		pc->buffer.last = stu_chain_read(pr->request_body->bufs, pc->buffer.last);
	} else {
		pc->buffer.last = stu_sprintf(pc->buffer.last, CRLF);
	}

	return STU_OK;
}

static void
stu_http_upstream_process_status_line(stu_event_t *ev) {
	stu_connection_t   *c, *pc;
	stu_http_request_t *r, *pr;
	ssize_t             n;
	stu_int32_t         rc, rv;

	pc = ev->data;
	pr = pc->request;
	c = pc->upstream->connection;
	r = c->request;

	stu_log_debug(4, "http upstream process status line.");

	if (ev->timedout) {
		stu_log_error(STU_ETIMEDOUT, "Failed to process http upstream status line.");

		pc->timedout = TRUE;
		stu_http_finalize_request(r, STU_HTTP_GATEWAY_TIMEOUT);

		return;
	}

	rc = STU_DONE;

	for ( ;; ) {
		if (rc == STU_AGAIN) {
			if (pr->header_in->pos == pr->header_in->end) {
				rv = stu_http_upstream_alloc_large_header_buffer(pr, TRUE);
				if (rv == STU_ERROR) {
					stu_http_finalize_request(r, STU_HTTP_INTERNAL_SERVER_ERROR);
					return;
				}

				if (rv == STU_DECLINED) {
					stu_log_error(0, "http upstream sent too long status.");
					stu_http_finalize_request(r, STU_HTTP_BAD_GATEWAY);
					return;
				}
			}

			n = stu_http_upstream_read_response_header(pr);
			if (n == STU_AGAIN) {
				return;
			}

			if (n == STU_ERROR) {
				stu_log_error(0, "http upstream failed to read response buffer.");
				stu_http_finalize_request(r, STU_HTTP_BAD_GATEWAY);
				return;
			}
		}

		rc = stu_http_parse_status_line(pr, pr->header_in);
		if (rc == STU_OK) {
			//ev->handler = stu_http_upstream_process_response_headers;
			stu_http_upstream_process_response_headers(ev);
			return;
		}

		if (rc == STU_AGAIN) {
			stu_log_debug(4, "a status line parsing is still incomplete.");
			continue;

		}

		stu_log_error(0, "Failed to process http status line: %s.", stu_http_status_text(STU_HTTP_BAD_GATEWAY));
		stu_http_finalize_request(r, STU_HTTP_BAD_GATEWAY);

		return;
	}
}

static void
stu_http_upstream_process_response_headers(stu_event_t *ev) {
	stu_connection_t   *c, *pc;
	stu_http_request_t *r, *pr;
	stu_http_header_t  *hh;
	stu_table_elt_t    *h;
	u_char             *p;
	stu_int32_t         rc, rv;
	ssize_t             n;

	pc = ev->data;
	pr = pc->request;
	c = pc->upstream->connection;
	r = c->request;

	stu_log_debug(4, "http upstream process response headers.");

	if (ev->timedout) {
		stu_log_error(STU_ETIMEDOUT, "Failed to process http upstream response headers.");

		pc->timedout = TRUE;
		stu_http_finalize_request(r, STU_HTTP_GATEWAY_TIMEOUT);

		return;
	}

	rc = STU_DONE;

	for ( ;; ) {
		if (rc == STU_AGAIN) {
			if (pr->header_in->pos == pr->header_in->end) {
				rv = stu_http_upstream_alloc_large_header_buffer(pr, FALSE);
				if (rv == STU_ERROR) {
					stu_http_finalize_request(pr, STU_HTTP_INTERNAL_SERVER_ERROR);
					return;
				}

				if (rv == STU_DECLINED) {
					p = pr->header_name_start;
					if (p == NULL) {
						stu_log_error(0, "http upstream sent too large request.");
						stu_http_finalize_request(r, STU_HTTP_BAD_GATEWAY);
						return;
					}

					stu_log_error(0, "http upstream sent too long header line: \"%s...\"", pr->header_name_start);
					stu_http_finalize_request(r, STU_HTTP_BAD_GATEWAY);

					return;
				}
			}

			n = stu_http_upstream_read_response_header(pr);
			if (n == STU_AGAIN) {
				return;
			}

			if (n == STU_ERROR) {
				stu_log_error(0, "http upstream failed to read response buffer.");
				stu_http_finalize_request(r, STU_HTTP_BAD_GATEWAY);
				return;
			}
		}

		/* the host header could change the server configuration context */
		rc = stu_http_parse_header_line(pr, pr->header_in, 1);
		if (rc == STU_OK) {
			/* a header line has been parsed successfully */
			h = stu_pcalloc(pc->pool, sizeof(stu_table_elt_t));
			if (h == NULL) {
				stu_http_finalize_request(r, STU_HTTP_INTERNAL_SERVER_ERROR);
				return;
			}

			h->hash = pr->header_hash;

			h->key.len = pr->header_name_end - pr->header_name_start;
			h->key.data = pr->header_name_start;
			h->key.data[h->key.len] = '\0';

			h->value.len = pr->header_end - pr->header_start;
			h->value.data = pr->header_start;
			h->value.data[h->value.len] = '\0';

			h->lowcase_key = stu_pcalloc(pc->pool, h->key.len + 1);
			if (h->lowcase_key == NULL) {
				stu_http_finalize_request(r, STU_HTTP_INTERNAL_SERVER_ERROR);
				return;
			}

			if (h->key.len == pr->lowcase_index) {
				(void) stu_memcpy(h->lowcase_key, pr->lowcase_header, h->key.len);
			} else {
				stu_strlow(h->lowcase_key, h->key.data, h->key.len);
			}

			stu_http_header_set(&pr->headers_out.headers, &h->key, &h->value);

			hh = stu_hash_find(&stu_http_upstream_headers_in_hash, h->hash, h->key.data, h->key.len);
			if (hh && hh->handler(pr, h, hh->offset) != STU_OK) {
				return;
			}

			stu_log_debug(3, "http header => \"%s: %s\"", h->key.data, h->value.data);

			continue;
		}

		if (rc == STU_DONE) {
			stu_log_debug(4, "http header parsed.");

			rc = stu_http_upstream_process_response_header(pr);
			if (rc != STU_OK) {
				return;
			}

			pc->upstream->process_response_pt(pc);

			if (pr->header_in->pos == pr->header_in->last) {
				pr->header_in->pos = pr->header_in->last = pr->header_in->start;
				rc = STU_AGAIN;
			}

			continue;
		}

		if (rc == STU_AGAIN) {
			stu_log_debug(4, "a header line parsing is still not complete.");
			continue;
		}

		/* rc == STU_HTTP_PARSE_INVALID_HEADER */
		stu_log_error(0, "http upstream sent invalid header line");
		stu_http_finalize_request(r, STU_HTTP_BAD_GATEWAY);

		return;
	}
}

static ssize_t
stu_http_upstream_read_response_header(stu_http_request_t *pr) {
	stu_connection_t      *pc;
	stu_upstream_t        *u;
	stu_upstream_server_t *s;
	ssize_t                n;

	pc = pr->connection;
	u = pc->upstream;
	s = u->server;

	n = pr->header_in->last - pr->header_in->pos;
	if (n > 0) {
		/* buffer remains */
		return n;
	}

	if (pr->header_in->end == pr->header_in->last) {
		pr->header_in->pos = pr->header_in->last = pr->header_in->start;
		stu_memzero(pr->header_in->start, pr->header_in->size);
	}

	n = pc->recv(pc, pr->header_in->last, pr->header_in->end - pr->header_in->last);
	if (n == STU_AGAIN) {
		return STU_AGAIN;
	}

	if (n == STU_ERROR) {
		pc->error = TRUE;
		return STU_ERROR;
	}

	if (n == 0) {
		stu_log_error(0, "http upstream prematurely closed connection.");
		pc->close = TRUE;
		return STU_ERROR;
	}

	pr->header_in->last += n;
	stu_log_debug(4, "upstream recv from %s: fd=%d, bytes=%d.", s->name.data, pc->fd, n);

	return n;
}

static stu_int32_t
stu_http_upstream_alloc_large_header_buffer(stu_http_request_t *pr, stu_bool_t is_status_line) {
	stu_connection_t *pc;
	u_char           *old, *new;

	pc = pr->connection;

	stu_log_debug(4, "http alloc large header buffer.");

	if (is_status_line && pr->state == 0) {
		/* the client fills up the buffer with "\r\n" */
		pr->header_in->pos = pr->header_in->start;
		pr->header_in->last = pr->header_in->start;

		return STU_OK;
	}

	old = is_status_line ? pr->headers_out.status_line.data : pr->header_name_start;
	if (pr->state != 0 && (size_t) (pr->header_in->pos - old) >= STU_HTTP_REQUEST_LARGE_SIZE) {
		return STU_DECLINED;
	}

	if (pr->busy) {
		return STU_DECLINED;
	}

	pr->busy = stu_buf_create(pc->pool, STU_HTTP_REQUEST_LARGE_SIZE);
	if (pr->busy == NULL) {
		return STU_ERROR;
	}

	if (pr->state == 0) {
		/*
		 * r->state == 0 means that a header line was parsed successfully
		 * and we do not need to copy incomplete header line and
		 * to relocate the parser header pointers
		 */
		pr->header_in = pr->busy;
		return STU_OK;
	}

	stu_log_debug(4, "http large header copy: %u.", pr->header_in->pos - old);

	new = pr->busy->start;
	(void) stu_memcpy(new, old, pr->header_in->pos - old);

	pr->busy->pos = new + (pr->header_in->pos - old);
	pr->busy->last = new + (pr->header_in->pos - old);

	if (is_status_line) {
		pr->headers_out.status_line.data = new;
	} else {
		pr->header_name_start = new;
		pr->header_name_end = new + (pr->header_name_end - old);
		pr->header_start = new + (pr->header_start - old);
		pr->header_end = new + (pr->header_end - old);
	}

	pr->header_in = pr->busy;

	return STU_OK;
}

static stu_int32_t
stu_http_upstream_process_response_header(stu_http_request_t *pr) {
	stu_connection_t   *c, *pc;
	stu_http_request_t *r;

	pc = pr->connection;
	c = pc->upstream->connection;
	r = c->request;

	if (pr->headers_out.content_length) {
		pr->headers_out.content_length_n = strtol((const char *) pr->headers_out.content_length->value.data, NULL, 10);
		if (pr->headers_out.content_length_n < 0) {
			stu_log_error(0, "http upstream sent invalid \"Content-Length\" header");
			stu_http_finalize_request(r, STU_HTTP_BAD_GATEWAY);
			return STU_ERROR;
		}
	}

	if (pr->headers_out.connection_type == STU_HTTP_CONNECTION_KEEP_ALIVE) {
		if (pr->headers_out.keep_alive) {
			pr->headers_out.keep_alive_n = strtol((const char *) pr->headers_out.keep_alive->value.data, NULL, 10);
		}
	}

	return STU_OK;
}

static stu_int32_t
stu_http_upstream_process_header_line(stu_http_request_t *pr, stu_table_elt_t *h, stu_uint32_t offset) {
	stu_table_elt_t **ph;

	ph = (stu_table_elt_t **) ((char *) &pr->headers_in + offset);
	if (*ph == NULL) {
		*ph = h;
	}

	return STU_OK;
}

static stu_int32_t
stu_http_upstream_process_unique_header_line(stu_http_request_t *pr, stu_table_elt_t *h, stu_uint32_t offset) {
	stu_table_elt_t    **ph;
	stu_connection_t    *c, *pc;
	stu_http_request_t  *r;

	pc = pr->connection;
	c = pc->upstream->connection;
	r = c->request;

	ph = (stu_table_elt_t **) ((char *) &pr->headers_in + offset);
	if (*ph == NULL) {
		*ph = h;
		return STU_OK;
	}

	stu_log_error(0, "http upstream sent duplicate header line = > \"%s: %s\", "
			"previous value => \"%s: %s\"", h->key.data, h->value.data, (*ph)->key.data, (*ph)->value.data);

	stu_http_finalize_request(r, STU_HTTP_BAD_GATEWAY);

	return STU_ERROR;
}

static stu_int32_t
stu_http_upstream_process_content_length(stu_http_request_t *pr, stu_table_elt_t *h, stu_uint32_t offset) {
	stu_uint32_t  length;

	length = atol((const char *) h->value.data);
	pr->headers_in.content_length_n = length;

	return stu_http_upstream_process_unique_header_line(pr, h, offset);
}

static stu_int32_t
stu_http_upstream_process_connection(stu_http_request_t *pr, stu_table_elt_t *h, stu_uint32_t offset) {
	stu_http_upstream_process_unique_header_line(pr, h, offset);

	if (stu_strnstr(h->value.data, "close", 5)) {
		pr->headers_in.connection_type = STU_HTTP_CONNECTION_CLOSE;
	} else if (stu_strnstr(h->value.data, "keep-alive", 10)) {
		pr->headers_in.connection_type = STU_HTTP_CONNECTION_KEEP_ALIVE;
	}

	return STU_OK;
}

stu_int32_t
stu_http_upstream_process_response(stu_connection_t *pc) {
	stu_http_request_t *pr;
	stu_upstream_t     *u;

	pr = pc->request;
	u = pc->upstream;

	if (u->analyze_response_pt(pc) == STU_ERROR) {
		stu_log_error(0, "Failed to analyze http upstream response.");
		u->finalize_handler_pt(u->connection, pr->headers_out.status);
		return STU_ERROR;
	}

	return STU_OK;
}

stu_int32_t
stu_http_upstream_analyze_response(stu_connection_t *pc) {
	stu_http_request_t *pr;
	stu_upstream_t     *u;

	pr = pc->request;
	u = pc->upstream;

	u->finalize_handler_pt(u->connection, pr->headers_out.status);

	return STU_OK;
}

void
stu_http_upstream_finalize_handler(stu_connection_t *c, stu_int32_t rc) {
	stu_http_finalize_request(c->request, rc);
	c->upstream->cleanup_pt(c);
}

void
stu_http_upstream_cleanup(stu_connection_t *c) {
	stu_upstream_t   *u;
	stu_connection_t *pc;

	if (c->upstream == NULL) {
		return;
	}

	u = c->upstream;
	pc = u->peer;

	if (pc) {
		stu_http_free_request(pc->request);
	}

	stu_upstream_cleanup(c);
}
