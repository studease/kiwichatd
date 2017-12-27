/*
 * stu_http_phase.h
 *
 *  Created on: 2017年11月27日
 *      Author: Tony Lau
 */

#ifndef STUDEASE_CN_HTTP_STU_HTTP_PHASE_H_
#define STUDEASE_CN_HTTP_STU_HTTP_PHASE_H_

#include "stu_http.h"

typedef stu_int32_t (*stu_http_phase_handler_pt)(stu_http_request_t *r);

struct stu_http_phase_s {
	stu_http_phase_handler_pt  handler;
};

stu_int32_t  stu_http_phase_init();

#endif /* STUDEASE_CN_HTTP_STU_HTTP_PHASE_H_ */
