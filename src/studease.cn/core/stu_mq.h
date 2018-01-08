/*
 * stu_mq.h
 *
 *  Created on: 2017年12月29日
 *      Author: Tony Lau
 */

#ifndef STUDEASE_CN_CORE_STU_MQ_H_
#define STUDEASE_CN_CORE_STU_MQ_H_

#include "../stu_config.h"
#include "stu_core.h"

#define STU_MQ_MODE_SMOOTH        0x00
#define STU_MQ_MODE_STRICT        0x01

#define STU_MQ_PAGE_DEFAULT_SIZE  4096

typedef struct {
	stu_queue_t        queue;
	off_t              offset; // file offset of start

	u_char            *start;
	u_char            *pos;    // save at
	u_char            *last;   // push at
	u_char            *end;
} stu_mq_page_t;

typedef struct {
	stu_rbtree_node_t  node;
	stu_int32_t        count;
} stu_mq_node_t;

typedef struct {
	stu_rwlock_t       lock;
	stu_queue_t        queue;
	stu_file_t         file;
	stu_uint8_t        mode;
	size_t             size;      // page size
	stu_uint32_t       message_n; // since the server started

	stu_rbtree_t       tree;      // offset of failed message
	stu_rbtree_node_t  sentinel;

	unsigned           destroyed:1;
} stu_mq_t;

stu_int32_t  stu_mq_init(stu_str_t *path, stu_uint32_t size);

off_t        stu_mq_push(stu_str_t *name, u_char *data, size_t len, stu_uint8_t mode);
u_char      *stu_mq_read(stu_str_t *name, u_char *dst, off_t *offset, stu_bool_t reverse);

void         stu_mq_destory(stu_str_t *name);

#endif /* STUDEASE_CN_CORE_STU_MQ_H_ */
