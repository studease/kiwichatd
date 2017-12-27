/*
 * stu_websocket_filter.h
 *
 *  Created on: 2017年11月29日
 *      Author: Tony Lau
 */

#ifndef STUDEASE_CN_WEBSOCKET_STU_WEBSOCKET_FILTER_H_
#define STUDEASE_CN_WEBSOCKET_STU_WEBSOCKET_FILTER_H_

#include "stu_websocket.h"

#define STU_WEBSOCKET_FILTER_MAX_RECORDS  32

typedef stu_int32_t (*stu_websocket_filter_handler_pt)(stu_websocket_request_t *r);

struct stu_websocket_filter_s {
	stu_str_t                        pattern;
	stu_websocket_filter_handler_pt  handler;
};

stu_int32_t  stu_websocket_filter_init_hash();

stu_int32_t  stu_websocket_filter_add(stu_str_t *pattern, stu_websocket_filter_handler_pt handler);
stu_int32_t  stu_websocket_filter_del(stu_str_t *pattern, stu_websocket_filter_handler_pt handler);

stu_int32_t  stu_websocket_filter_upgrade_handler(stu_http_request_t *r);

#endif /* STUDEASE_CN_WEBSOCKET_STU_WEBSOCKET_FILTER_H_ */
