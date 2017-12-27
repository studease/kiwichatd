/*
 * stu_websocket_phase.h
 *
 *  Created on: 2017年11月28日
 *      Author: Tony Lau
 */

#ifndef STUDEASE_CN_WEBSOCKET_STU_WEBSOCKET_PHASE_H_
#define STUDEASE_CN_WEBSOCKET_STU_WEBSOCKET_PHASE_H_

#include "stu_websocket.h"

typedef stu_int32_t (*stu_websocket_phase_handler_pt)(stu_websocket_request_t *r);

struct stu_websocket_phase_s {
	stu_websocket_phase_handler_pt  handler;
};

stu_int32_t  stu_websocket_phase_init();

stu_int32_t  stu_websocket_phase_upgrade_handler(stu_http_request_t *r);

#endif /* STUDEASE_CN_WEBSOCKET_STU_WEBSOCKET_PHASE_H_ */
