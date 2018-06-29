/*
 * stu_http_request.h
 *
 *  Created on: 2017年11月22日
 *      Author: Tony Lau
 */

#ifndef STUDEASE_CN_HTTP_STU_HTTP_REQUEST_H_
#define STUDEASE_CN_HTTP_STU_HTTP_REQUEST_H_

#include "stu_http.h"

#define STU_HTTP_REQUEST_DEFAULT_SIZE   1024
#define STU_HTTP_REQUEST_LARGE_SIZE     4096

#define STU_HTTP_UNKNOWN                0x0001
#define STU_HTTP_GET                    0x0002
#define STU_HTTP_HEAD                   0x0004
#define STU_HTTP_POST                   0x0008
#define STU_HTTP_PUT                    0x0010
#define STU_HTTP_DELETE                 0x0020
#define STU_HTTP_MKCOL                  0x0040
#define STU_HTTP_COPY                   0x0080
#define STU_HTTP_MOVE                   0x0100
#define STU_HTTP_OPTIONS                0x0200
#define STU_HTTP_PROPFIND               0x0400
#define STU_HTTP_PROPPATCH              0x0800
#define STU_HTTP_LOCK                   0x1000
#define STU_HTTP_UNLOCK                 0x2000
#define STU_HTTP_PATCH                  0x4000
#define STU_HTTP_TRACE                  0x8000

#define STU_HTTP_CONNECTION_CLOSE       1
#define STU_HTTP_CONNECTION_KEEP_ALIVE  2

typedef void (*stu_http_event_handler_pt)(stu_http_request_t *r);

typedef struct {
	stu_str_t                  name;
	stu_uint16_t               mask;
} stu_http_method_bitmask_t;

struct stu_http_request_s {
	stu_connection_t          *connection;

	stu_http_event_handler_pt  read_event_handler;
	stu_http_event_handler_pt  write_event_handler;

	stu_uint16_t               method;
	stu_uint16_t               http_version;

	stu_str_t                  request_line;
	stu_str_t                  schema;
	stu_str_t                  host;
	stu_str_t                  port;
	stu_str_t                  uri;
	stu_str_t                  args;

	stu_buf_t                 *header_in;
	stu_buf_t                 *busy;

	stu_http_headers_in_t      headers_in;
	stu_http_headers_out_t     headers_out;
	stu_buf_t                  request_body;
	stu_buf_t                  response_body;

	// used for parsing http headers.
	uint8_t                    state;
	stu_uint32_t               header_hash;
	stu_uint32_t               lowcase_index;
	u_char                     lowcase_header[STU_HTTP_HEADER_MAX_LEN];

	stu_bool_t                 invalid_header;

	stu_uint16_t               http_major;
	stu_uint16_t               http_minor;

	u_char                    *header_name_start;
	u_char                    *header_name_end;
	u_char                    *header_start;
	u_char                    *header_end;
};

void  stu_http_request_read_handler(stu_event_t *ev);
void  stu_http_request_write_handler(stu_http_request_t *r);

stu_http_request_t *
             stu_http_create_request(stu_connection_t *c);
void         stu_http_process_request(stu_http_request_t *r);
void         stu_http_finalize_request(stu_http_request_t *r, stu_int32_t rc);
stu_int32_t  stu_http_send_special_response(stu_http_request_t *r, stu_int32_t rc);

void  stu_http_free_request(stu_http_request_t *r);
void  stu_http_close_request(stu_http_request_t *r);
void  stu_http_close_connection(stu_connection_t *c);

#endif /* STUDEASE_CN_HTTP_STU_HTTP_REQUEST_H_ */
