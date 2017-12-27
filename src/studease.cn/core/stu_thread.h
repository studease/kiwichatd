/*
 * stu_thread.h
 *
 *  Created on: 2017年11月16日
 *      Author: Tony Lau
 */

#ifndef STUDEASE_CN_CORE_STU_THREAD_H_
#define STUDEASE_CN_CORE_STU_THREAD_H_

#include "../stu_config.h"
#include "stu_core.h"

#define STU_THREAD_MAXIMUM            64
#define STU_THREAD_DEFAULT_STACKSIZE  524288

typedef pthread_t       stu_tid_t;
typedef pthread_key_t   stu_thread_key_t;
typedef pthread_cond_t  stu_thread_cond_t;

#define stu_thread_key_create(key)    pthread_key_create(key, NULL)

typedef struct {
	stu_tid_t          id;
	stu_thread_cond_t  cond;
	stu_fd_t           epfd;
	stu_uint32_t       state;
} stu_thread_t;

stu_int32_t stu_thread_init(size_t stacksize);
stu_int32_t stu_thread_create(stu_tid_t *tid, stu_fd_t *epfd, void *(*func)(void *arg), void *arg);

stu_int32_t stu_thread_cond_init(stu_thread_cond_t *cond);

#endif /* STUDEASE_CN_CORE_STU_THREAD_H_ */
