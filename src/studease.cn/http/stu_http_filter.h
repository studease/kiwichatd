/*
 * stu_http_filter.h
 *
 *  Created on: 2017年11月24日
 *      Author: Tony Lau
 */

#ifndef STUDEASE_CN_HTTP_STU_HTTP_FILTER_H_
#define STUDEASE_CN_HTTP_STU_HTTP_FILTER_H_

#include "stu_http.h"

#define STU_HTTP_FILTER_MAX_RECORDS  32

typedef stu_int32_t (*stu_http_filter_handler_pt)(stu_http_request_t *r);

struct stu_http_filter_s {
	stu_str_t                   pattern;
	stu_http_filter_handler_pt  handler;
};

stu_int32_t  stu_http_filter_init_hash();

stu_int32_t  stu_http_filter_add(stu_str_t *pattern, stu_http_filter_handler_pt handler);
stu_int32_t  stu_http_filter_del(stu_str_t *pattern, stu_http_filter_handler_pt handler);

#endif /* STUDEASE_CN_HTTP_STU_HTTP_FILTER_H_ */
