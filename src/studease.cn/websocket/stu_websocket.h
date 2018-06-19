/*
 * stu_websocket.h
 *
 *  Created on: 2017年11月24日
 *      Author: Tony Lau
 */

#ifndef STUDEASE_CN_WEBSOCKET_STU_WEBSOCKET_H_
#define STUDEASE_CN_WEBSOCKET_STU_WEBSOCKET_H_

#include "../http/stu_http.h"

typedef struct stu_websocket_request_s stu_websocket_request_t;
typedef struct stu_websocket_filter_s  stu_websocket_filter_t;
typedef struct stu_websocket_phase_s   stu_websocket_phase_t;

#include "stu_websocket_frame.h"
#include "stu_websocket_filter.h"
#include "stu_websocket_phase.h"
#include "stu_websocket_request.h"

stu_int32_t  stu_websocket_init();
stu_bool_t   stu_websocket_is_upgrade_request(stu_http_request_t *r);

#endif /* STUDEASE_CN_WEBSOCKET_STU_WEBSOCKET_H_ */
