/*
 * stu_http.h
 *
 *  Created on: 2017年11月21日
 *      Author: Tony Lau
 */

#ifndef STUDEASE_CN_HTTP_STU_HTTP_H_
#define STUDEASE_CN_HTTP_STU_HTTP_H_

#include "../stu_config.h"
#include "../core/stu_core.h"

#define STU_HTTP_VERSION_10  1000
#define STU_HTTP_VERSION_11  1001
#define STU_HTTP_VERSION_20  2000

typedef struct stu_http_request_s stu_http_request_t;
typedef struct stu_http_filter_s  stu_http_filter_t;
typedef struct stu_http_phase_s   stu_http_phase_t;

#include "stu_http_status.h"
#include "stu_http_header.h"
#include "stu_http_filter.h"
#include "stu_http_phase.h"
#include "stu_http_request.h"
#include "stu_http_parse.h"
#include "stu_http_upstream.h"

stu_int32_t  stu_http_init();
stu_int32_t  stu_http_listen(stu_fd_t epfd, uint16_t port);

#endif /* STUDEASE_CN_HTTP_STU_HTTP_H_ */
