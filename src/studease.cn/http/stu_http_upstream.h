/*
 * stu_http_upstream.h
 *
 *  Created on: 2017年11月27日
 *      Author: Tony Lau
 */

#ifndef STUDEASE_CN_HTTP_STU_HTTP_UPSTREAM_H_
#define STUDEASE_CN_HTTP_STU_HTTP_UPSTREAM_H_

#include "stu_http.h"

void         stu_http_upstream_read_handler(stu_event_t *ev);
void         stu_http_upstream_write_handler(stu_event_t *ev);

void        *stu_http_upstream_create_request(stu_connection_t *pc);
stu_int32_t  stu_http_upstream_reinit_request(stu_connection_t *pc);
stu_int32_t  stu_http_upstream_generate_request(stu_connection_t *pc);
stu_int32_t  stu_http_upstream_process_response(stu_connection_t *pc);
stu_int32_t  stu_http_upstream_analyze_response(stu_connection_t *pc);
void         stu_http_upstream_finalize_handler(stu_connection_t *c, stu_int32_t rc);
void         stu_http_upstream_cleanup(stu_connection_t *c);

#endif /* STUDEASE_CN_HTTP_STU_HTTP_UPSTREAM_H_ */
