/*
 * stu_inet.h
 *
 *  Created on: 2017年11月15日
 *      Author: Tony Lau
 */

#ifndef STUDEASE_CN_CORE_STU_INET_H_
#define STUDEASE_CN_CORE_STU_INET_H_

#include "../stu_config.h"
#include "stu_core.h"

typedef struct {
	struct sockaddr_in  sockaddr;
	socklen_t           socklen;
	stu_str_t           name;
} stu_addr_t;

#endif /* STUDEASE_CN_CORE_STU_INET_H_ */
