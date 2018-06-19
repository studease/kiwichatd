/*
 * stu_connection.h
 *
 *  Created on: 2017骞�11鏈�16鏃�
 *      Author: Tony Lau
 */

#ifndef STUDEASE_CN_CORE_STU_CONNECTION_H_
#define STUDEASE_CN_CORE_STU_CONNECTION_H_

#include "../stu_config.h"
#include "stu_core.h"

#define STU_CONNECTION_POOL_DEFAULT_SIZE  4096

struct stu_connection_s {
	stu_mutex_t      lock;
	stu_queue_t      queue;
	stu_pool_t      *pool;

	stu_socket_t     fd;
	stu_buf_t        buffer;

	stu_event_t     *read;
	stu_event_t     *write;
	stu_recv_pt      recv;
	stu_send_pt      send;

	void            *request;
	void            *data;
	stu_upstream_t  *upstream;

	struct sockaddr *sockaddr;
	socklen_t        socklen;
	stu_str_t        addr_text;

	unsigned         idle:1;
	unsigned         timedout:1;
	unsigned         error:1;
	unsigned         close:1;
	unsigned         destroyed:1;
};

stu_int32_t       stu_connection_init();

stu_int32_t       stu_connect(stu_connection_t *c, stu_addr_t *addr);

stu_connection_t *stu_connection_get(stu_socket_t s);
void              stu_connection_close(stu_connection_t *c);
void              stu_connection_free(stu_connection_t *c);

#endif /* STUDEASE_CN_CORE_STU_CONNECTION_H_ */
