/*
 * stu_http_header.h
 *
 *  Created on: 2017年11月21日
 *      Author: Tony Lau
 */

#ifndef STUDEASE_CN_HTTP_STU_HTTP_HEADER_H_
#define STUDEASE_CN_HTTP_STU_HTTP_HEADER_H_

#include "stu_http.h"

#define STU_HTTP_HEADER_MAX_RECORDS  32
#define STU_HTTP_HEADER_MAX_LEN      32

#define stu_http_headers_t stu_hash_t

typedef stu_int32_t  (*stu_http_header_handler_pt)(stu_http_request_t *r, stu_table_elt_t *h, stu_uint32_t offset);

typedef struct {
	stu_str_t                   name;
	stu_uint32_t                offset;
	stu_http_header_handler_pt  handler;
} stu_http_header_t;

typedef struct {
	stu_http_headers_t  headers;

	stu_str_t           server;
	stu_int32_t         content_length_n;
	stu_uint8_t         connection_type;
	time_t              keep_alive_n;

	stu_table_elt_t    *host;
	stu_table_elt_t    *user_agent;

	stu_table_elt_t    *accept;
	stu_table_elt_t    *accept_language;
#if (STU_HTTP_GZIP)
	stu_table_elt_t    *accept_encoding;
#endif

	stu_table_elt_t    *content_type;
	stu_table_elt_t    *content_length;

	stu_table_elt_t    *sec_websocket_key;
	stu_table_elt_t    *sec_websocket_protocol;
	stu_table_elt_t    *sec_websocket_version;
	stu_table_elt_t    *sec_websocket_extensions;
	stu_table_elt_t    *upgrade;

	stu_table_elt_t    *connection;
	stu_table_elt_t    *keep_alive;
} stu_http_headers_in_t;

typedef struct {
	stu_http_headers_t  headers;

	stu_int32_t         status;
	stu_str_t           status_line;
	stu_int32_t         content_length_n;
	stu_uint8_t         connection_type;
	time_t              keep_alive_n;

	stu_table_elt_t    *server;
	stu_table_elt_t    *date;

	stu_table_elt_t    *content_type;
	stu_table_elt_t    *content_length;
	stu_table_elt_t    *content_encoding;

	stu_table_elt_t    *sec_websocket_accept;
	stu_table_elt_t    *sec_websocket_protocol;
	stu_table_elt_t    *sec_websocket_extensions;
	stu_table_elt_t    *upgrade;

	stu_table_elt_t    *connection;
	stu_table_elt_t    *keep_alive;
} stu_http_headers_out_t;

stu_int32_t  stu_http_header_init_hash();

void         stu_http_header_set(stu_http_headers_t *h, stu_str_t *key, stu_str_t *value);
stu_str_t   *stu_http_header_get(stu_http_headers_t *h, stu_str_t *key);
void         stu_http_header_del(stu_http_headers_t *h, stu_str_t *key);

#endif /* STUDEASE_CN_HTTP_STU_HTTP_HEADER_H_ */
