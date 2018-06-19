/*
 * stu_upstream.h
 *
 *  Created on: 2017骞�11鏈�20鏃�
 *      Author: Tony Lau
 */

#ifndef STUDEASE_CN_CORE_STU_UPSTREAM_H_
#define STUDEASE_CN_CORE_STU_UPSTREAM_H_

#include "../stu_config.h"
#include "stu_core.h"

#define STU_UPSTREAM_MAXIMUM             32
#define STU_UPSTREAM_DEFAULT_TIMEOUT     3

#define STU_UPSTREAM_BUFFER_DEFAULT_SIZE 1024

typedef void (*stu_upstream_handler_pt)(stu_event_t *ev);

typedef struct {
	stu_str_t     protocol;

	// used for http
	stu_uint16_t  method;
	stu_str_t     target;

	stu_str_t     name;
	stu_addr_t    addr;
	uint16_t      port;

	stu_uint32_t  weight;
	time_t        timeout;
	stu_uint32_t  max_fails;

	stu_uint32_t  count;
	stu_uint32_t  fails;

	unsigned      backup:1;
	unsigned      down:1;
} stu_upstream_server_t;

struct stu_upstream_s {
	stu_upstream_handler_pt    read_event_handler;
	stu_upstream_handler_pt    write_event_handler;

	stu_upstream_server_t     *server;
	stu_connection_t          *connection;
	stu_connection_t          *peer;

	void                    *(*create_request_pt)(stu_connection_t *pc);
	stu_int32_t              (*reinit_request_pt)(stu_connection_t *pc);
	stu_int32_t              (*generate_request_pt)(stu_connection_t *pc);
	stu_int32_t              (*process_response_pt)(stu_connection_t *pc);
	stu_int32_t              (*analyze_response_pt)(stu_connection_t *pc);
	void                     (*finalize_handler_pt)(stu_connection_t *c, stu_int32_t rc);
	void                     (*cleanup_pt)(stu_connection_t *c);
};

stu_int32_t  stu_upstream_init_hash();

void         stu_upstream_read_handler(stu_event_t *ev);
void         stu_upstream_write_handler(stu_event_t *ev);

stu_int32_t  stu_upstream_create(stu_connection_t *c, u_char *name, size_t len);
stu_int32_t  stu_upstream_connect(stu_connection_t *pc);

void        *stu_upstream_create_request(stu_connection_t *pc);
stu_int32_t  stu_upstream_reinit_request(stu_connection_t *pc);
stu_int32_t  stu_upstream_generate_request(stu_connection_t *pc);
stu_int32_t  stu_upstream_process_response(stu_connection_t *pc);
stu_int32_t  stu_upstream_analyze_response(stu_connection_t *pc);
void         stu_upstream_finalize_handler(stu_connection_t *c, stu_int32_t rc);
void         stu_upstream_cleanup(stu_connection_t *c);

#endif /* STUDEASE_CN_CORE_STU_UPSTREAM_H_ */
