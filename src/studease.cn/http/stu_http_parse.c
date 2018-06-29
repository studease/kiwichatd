/*
 * stu_http_parse.c
 *
 *  Created on: 2017年11月23日
 *      Author: Tony Lau
 */

#include "stu_http.h"


stu_int32_t
stu_http_parse_request_line(stu_http_request_t *r, stu_buf_t *b) {
	u_char *p, *s, c, ch;
	enum {
		sw_start = 0,
		sw_method,
		sw_spaces_before_uri,
		sw_schema,
		sw_schema_slash,
		sw_schema_slash_slash,
		sw_host_start,
		sw_host,
		sw_port,
		sw_uri,
		sw_args,
		sw_spaces_before_ver,
		sw_http_H,
		sw_http_HT,
		sw_http_HTT,
		sw_http_HTTP,
		sw_first_major_digit,
		sw_major_digit,
		sw_first_minor_digit,
		sw_minor_digit,
		sw_spaces_after_digit,
		sw_almost_done
	} state;

	state = r->state;

	for (p = b->pos; p < b->last; p++) {
		ch = *p;

		switch (state) {
		case sw_start:
			r->request_line.data = p;
			state = sw_method;
			break;

		case sw_method:
			if (ch == ' ') {
				s = r->request_line.data;

				switch (p - s) {
				case 3:
					if (stu_strncmp(s, "GET", 3) == 0) {
						r->method = STU_HTTP_GET;
						break;
					}
					break;
				case 4:
					if (stu_strncmp(s, "POST", 4) == 0) {
						r->method = STU_HTTP_POST;
						break;
					}
					break;
				}

				*p = '\0'; // split request line
				state = sw_spaces_before_uri;
				break;
			}
			if (ch < 'A' || ch > 'Z') {
				return STU_ERROR;
			}
			break;

		case sw_spaces_before_uri:
			if (ch == '/') {
				r->uri.data = p;
				state = sw_uri;
				break;
			}

			c = (u_char) (ch | 0x20);
			if (c >= 'a' && c <= 'z') {
				r->schema.data = p;
				state = sw_schema;
				break;
			}

			switch (ch) {
			case ' ':
				break;
			default:
				return STU_ERROR;
			}
			break;

		case sw_schema:
			c = (u_char) (ch | 0x20);
			if (c >= 'a' && c <= 'z') {
				break;
			}

			switch (ch) {
			case ':':
				r->schema.len = p - r->schema.data;
				state = sw_schema_slash;
				break;
			default:
				return STU_ERROR;
			}
			break;

		case sw_schema_slash:
			switch (ch) {
			case '/':
				state = sw_schema_slash_slash;
				break;
			default:
				return STU_ERROR;
			}
			break;

		case sw_schema_slash_slash:
			switch (ch) {
			case '/':
				state = sw_host_start;
				break;
			default:
				return STU_ERROR;
			}
			break;

		case sw_host_start:
			r->host.data = p;
			state = sw_host;
			/* no break */

		case sw_host:
			c = (u_char) (ch | 0x20);
			if (c >= 'a' && c <= 'z') {
				break;
			}

			if ((ch >= '0' && ch <= '9') || ch == '.' || ch == '-') {
				break;
			}

			r->host.len = p - r->host.data;

			switch (ch) {
			case ':':
				r->port.data = p;
				state = sw_port;
				break;
			case '/':
				r->uri.data = p;
				state = sw_uri;
				break;
			default:
				return STU_ERROR;
			}
			break;

		case sw_port:
			if (ch >= '0' && ch <= '9') {
				break;
			}

			switch (ch) {
			case '/':
				r->port.len = p - r->port.data;
				r->uri.data = p;
				state = sw_uri;
				break;
			default:
				return STU_ERROR;
			}
			break;

		case sw_uri:
			if (ch == '?') {
				r->uri.len = p - r->uri.data;
				r->args.data = p + 1;
				state = sw_args;
				break;
			}
			if (ch == ' ') {
				r->uri.len = p - r->uri.data;

				*p = '\0'; // split request line
				state = sw_spaces_before_ver;
				break;
			}
			break;

		case sw_args:
			if (ch == ' ') {
				r->args.len = p - r->args.data;

				*p = '\0'; // split request line
				state = sw_spaces_before_ver;
				break;
			}
			break;

		case sw_spaces_before_ver:
			switch (ch) {
			case 'H':
				state = sw_http_H;
				break;
			default:
				return STU_ERROR;
			}
			break;

		case sw_http_H:
			switch (ch) {
			case 'T':
				state = sw_http_HT;
				break;
			default:
				return STU_ERROR;
			}
			break;

		case sw_http_HT:
			switch (ch) {
			case 'T':
				state = sw_http_HTT;
				break;
			default:
				return STU_ERROR;
			}
			break;

		case sw_http_HTT:
			switch (ch) {
			case 'P':
				state = sw_http_HTTP;
				break;
			default:
				return STU_ERROR;
			}
			break;

		case sw_http_HTTP:
			switch (ch) {
			case '/':
				state = sw_first_major_digit;
				break;
			default:
				return STU_ERROR;
			}
			break;

		case sw_first_major_digit:
			if (ch < '1' || ch > '9') {
				return STU_ERROR;
			}

			r->http_major = ch - '0';
			state = sw_major_digit;
			break;

		case sw_major_digit:
			if (ch == '.') {
				state = sw_first_minor_digit;
				break;
			}

			if (ch < '0' || ch > '9') {
				return STU_ERROR;
			}

			if (r->http_major > 99) {
				return STU_ERROR;
			}

			r->http_major = r->http_major * 10 + ch - '0';
			break;

		case sw_first_minor_digit:
			if (ch < '0' || ch > '9') {
				return STU_ERROR;
			}

			r->http_minor = ch - '0';
			state = sw_minor_digit;
			break;

		case sw_minor_digit:
			if (ch == CR) {
				*p = '\0'; // split request line
				state = sw_almost_done;
				break;
			}

			if (ch == LF) {
				goto done;
			}

			if (ch == ' ') {
				state = sw_spaces_after_digit;
				break;
			}

			if (ch < '0' || ch > '9') {
				return STU_ERROR;
			}

			if (r->http_minor > 99) {
				return STU_ERROR;
			}

			r->http_minor = r->http_minor * 10 + ch - '0';
			break;

		case sw_spaces_after_digit:
			switch (ch) {
			case ' ':
				break;
			case CR:
				*p = '\0'; // split request line
				state = sw_almost_done;
				break;
			case LF:
				goto done;
			default:
				return STU_ERROR;
			}
			break;

		case sw_almost_done:
			switch (ch) {
			case LF:
				goto done;
			default:
				return STU_ERROR;
			}
			break;
		}
	}

	b->pos = p;
	r->state = state;

	return STU_AGAIN;

done:

	b->pos = p + 1;
	r->http_version = r->http_major * 1000 + r->http_minor;
	r->state = sw_start;

	return STU_OK;
}

stu_int32_t
stu_http_parse_header_line(stu_http_request_t *r, stu_buf_t *b, stu_uint32_t allow_underscores) {
	u_char       *p, c, ch;
	stu_uint32_t  hash, i;
	enum {
		sw_start = 0,
		sw_name,
		sw_space_before_value,
		sw_value,
		sw_space_after_value,
		sw_ignore_line,
		sw_almost_done,
		sw_header_almost_done,
		sw_header_done
	} state;

	/* the last '\0' is not needed because string is zero terminated */
	static u_char  lowcase[] =
			"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
			"\0\0\0\0\0\0\0\0\0\0\0\0\0-\0\0" "0123456789\0\0\0\0\0\0"
			"\0abcdefghijklmnopqrstuvwxyz\0\0\0\0\0"
			"\0abcdefghijklmnopqrstuvwxyz\0\0\0\0\0"
			"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
			"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
			"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
			"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

	state = r->state;
	hash = r->header_hash;
	i = r->lowcase_index;

	for (p = b->pos; p < b->last; p++) {
		ch = *p;

		switch (state) {

		/* first char */
		case sw_start:
			r->header_name_start = p;
			r->invalid_header = FALSE;

			switch (ch) {
			case CR:
				r->header_end = p;
				state = sw_header_almost_done;
				break;
			case LF:
				r->header_end = p++;
				state = sw_header_done;
				goto header_done;
			default:
				state = sw_name;

				c = lowcase[ch];
				if (c) {
					hash = stu_hash(0, c);
					r->lowcase_header[0] = c;
					i = 1;
					break;
				}

				if (ch == '_') {
					if (allow_underscores) {
						hash = stu_hash(0, ch);
						r->lowcase_header[0] = ch;
						i = 1;
					} else {
						r->invalid_header = TRUE;
					}
					break;
				}

				if (ch == '\0') {
					return STU_ERROR;
				}

				r->invalid_header = TRUE;
				break;
			}
			break;

		/* header name */
		case sw_name:
			c = lowcase[ch];
			if (c) {
				hash = stu_hash(hash, c);
				r->lowcase_header[i++] = c;
				i &= (STU_HTTP_HEADER_MAX_LEN - 1);
				break;
			}

			if (ch == '_') {
				if (allow_underscores) {
					hash = stu_hash(hash, ch);
					r->lowcase_header[i++] = ch;
					i &= (STU_HTTP_HEADER_MAX_LEN - 1);
				} else {
					r->invalid_header = TRUE;
				}
				break;
			}

			if (ch == ':') {
				r->header_name_end = p;

				*p = '\0'; // split header line
				state = sw_space_before_value;
				break;
			}

			if (ch == CR) {
				r->header_name_end = p;
				r->header_start = p;
				r->header_end = p;
				state = sw_almost_done;
				break;
			}

			if (ch == LF) {
				r->header_name_end = p;
				r->header_start = p;
				r->header_end = p;
				goto done;
			}

			/* IIS may send the duplicate "HTTP/1.1 ..." lines */
			if (ch == '/'
					&& p - r->header_name_start == 4
					&& stu_strncmp(r->header_name_start, "HTTP", 4) == 0) {
				state = sw_ignore_line;
				break;
			}

			if (ch == '\0') {
				return STU_ERROR;
			}

			r->invalid_header = TRUE;
			break;

		/* space* before header value */
		case sw_space_before_value:
			switch (ch) {
			case ' ':
				break;
			case CR:
				r->header_start = p;
				r->header_end = p;
				state = sw_almost_done;
				break;
			case LF:
				r->header_start = p;
				r->header_end = p;
				goto done;
			case '\0':
				return STU_ERROR;
			default:
				r->header_start = p;
				state = sw_value;
				break;
			}
			break;

		/* header value */
		case sw_value:
			switch (ch) {
			case ' ':
				r->header_end = p;
				state = sw_space_after_value;
				break;
			case CR:
				r->header_end = p;

				*p = '\0'; // split header line
				state = sw_almost_done;
				break;
			case LF:
				r->header_end = p;
				goto done;
			case '\0':
				return STU_ERROR;
			}
			break;

		/* space* before end of header line */
		case sw_space_after_value:
			switch (ch) {
			case ' ':
				break;
			case CR:
				state = sw_almost_done;
				break;
			case LF:
				goto done;
			case '\0':
				return STU_ERROR;
			default:
				state = sw_value;
				break;
			}
			break;

		/* ignore header line */
		case sw_ignore_line:
			switch (ch) {
			case LF:
				state = sw_start;
				break;
			default:
				break;
			}
			break;

		/* end of header line */
		case sw_almost_done:
			switch (ch) {
			case LF:
				goto done;
			case CR:
				break;
			default:
				return STU_ERROR;
			}
			break;

		/* end of header */
		case sw_header_almost_done:
			switch (ch) {
			case LF:
				p++;
				state = sw_header_done;
				goto header_done;
			default:
				return STU_ERROR;
			}
			break;

		case sw_header_done:
			goto header_done;
		}
	}

	b->pos = p;
	r->state = state;
	r->header_hash = hash;
	r->lowcase_index = i;

	return STU_AGAIN;

done:

	b->pos = p + 1;
	r->state = sw_start;
	r->header_hash = hash;
	r->lowcase_index = i;

	return STU_OK;

header_done:

	b->pos = p;

	return STU_DONE;
}

stu_int32_t
stu_http_parse_uri(stu_http_request_t *r) {
	return STU_OK;
}


stu_int32_t
stu_http_parse_status_line(stu_http_request_t *r, stu_buf_t *b) {
	u_char *p, *s, *v, ch;
	enum {
		sw_start = 0,
		sw_version,
		sw_spaces_before_status,
		sw_status,
		sw_spaces_before_explain,
		sw_explain,
		sw_almost_done
	} state;

	state = r->state;

	for (p = b->pos; p < b->last; p++) {
		ch = *p;

		switch (state) {
		case sw_start:
			r->headers_out.status_line.data = v = p;
			state = sw_version;
			break;

		case sw_version:
			if (ch == ' ') {
				if (stu_strncmp(v, "HTTP/1.1", 8) == 0) {
					r->http_version = STU_HTTP_VERSION_11;
					state = sw_spaces_before_status;
					break;
				}
				if (stu_strncmp(v, "HTTP/1.0", 8) == 0) {
					r->http_version = STU_HTTP_VERSION_10;
					state = sw_spaces_before_status;
					break;
				}
				return STU_ERROR;
				break;
			}
			break;

		case sw_spaces_before_status:
			s = p;
			state = sw_status;
			break;

		case sw_status:
			if (ch == ' ') {
				r->headers_out.status = atol((const char *) s);
				state = sw_spaces_before_explain;
				break;
			}
			if (p - s >= 3) {
				return STU_ERROR;
				break;
			}
			break;

		case sw_spaces_before_explain:
			state = sw_explain;
			break;

		case sw_explain:
			if (ch == CR) {
				state = sw_almost_done;
				break;
			}
			break;

		case sw_almost_done:
			switch (ch) {
			case LF:
				goto done;
			default:
				return STU_ERROR;
			}
			break;
		}
	}

	b->pos = p;
	r->state = state;

	return STU_AGAIN;

done:

	b->pos = p + 1;
	r->state = sw_start;

	return STU_OK;
}


stu_int32_t
stu_http_arg(stu_http_request_t *r, u_char *name, size_t len, stu_str_t *value) {
	u_char *p, *last;

	if (r->args.len == 0) {
		return STU_DECLINED;
	}

	last = r->args.data + r->args.len;

	for (p = r->args.data; p < last; p++) {
		p = stu_strnstr(p, (char *) name, len - 1);
		if (p == NULL) {
			return STU_DECLINED;
		}

		if ((p == r->args.data || *(p - 1) == '&') && *(p + len) == '=') {
			value->data = p + len + 1;

			p = stu_strlchr(p, last, '&');
			if (p == NULL) {
				p = r->args.data + r->args.len;
			}

			value->len = p - value->data;

			return STU_OK;
		}
	}

	return STU_DECLINED;
}

void
stu_http_split_args(stu_http_request_t *r, stu_str_t *uri, stu_str_t *args) {

}
