/*
 * stu_connection.h
 *
 *  Created on: 2017年11月16日
 *      Author: Tony Lau
 */

#ifndef STUDEASE_CN_CORE_STU_CONNECTION_H_
#define STUDEASE_CN_CORE_STU_CONNECTION_H_

#include "../stu_config.h"
#include "stu_core.h"

#define STU_CONNECTION_POOL_DEFAULT_SIZE   4096

typedef struct {
	stu_mutex_t     lock;
	stu_pool_t     *pool;

	stu_socket_t    fd;
	stu_buf_t       buffer;
	void           *request;
	void           *data;
	stu_event_t     read;
	stu_event_t     write;
	stu_upstream_t *upstream;

	unsigned        idle:1;
	unsigned        timedout:1;
	unsigned        error:1;
	unsigned        close:1;
	unsigned        destroyed:1;
} stu_connection_t;

stu_connection_t *stu_connection_get(stu_socket_t s);
void              stu_connection_close(stu_connection_t *c);

#endif /* STUDEASE_CN_CORE_STU_CONNECTION_H_ */
