/*
 * stu_http_parse.h
 *
 *  Created on: 2017年11月23日
 *      Author: Tony Lau
 */

#ifndef STUDEASE_CN_HTTP_STU_HTTP_PARSE_H_
#define STUDEASE_CN_HTTP_STU_HTTP_PARSE_H_

#include "stu_http.h"

stu_int32_t  stu_http_parse_request_line(stu_http_request_t *r, stu_buf_t *b);
stu_int32_t  stu_http_parse_header_line(stu_http_request_t *r, stu_buf_t *b, stu_uint32_t allow_underscores);
stu_int32_t  stu_http_parse_uri(stu_http_request_t *r);

stu_int32_t  stu_http_parse_status_line(stu_http_request_t *r, stu_buf_t *b);

stu_int32_t  stu_http_arg(stu_http_request_t *r, u_char *name, size_t len, stu_str_t *value);
void         stu_http_split_args(stu_http_request_t *r, stu_str_t *uri, stu_str_t *args);

#endif /* STUDEASE_CN_HTTP_STU_HTTP_PARSE_H_ */
