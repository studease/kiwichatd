/*
 * stu_thread.c
 *
 *  Created on: 2017年11月16日
 *      Author: Tony Lau
 */

#include "../stu_config.h"
#include "stu_core.h"

stu_thread_t           stu_threads[STU_THREAD_MAXIMUM];
stu_int32_t            stu_thread_n;
stu_thread_key_t       stu_thread_key;

static pthread_attr_t  stu_thread_attr;


stu_int32_t
stu_thread_init(size_t stacksize) {
	int  err;

	err = pthread_attr_init(&stu_thread_attr);
	if (err != 0) {
		stu_log_error(err, "pthread_attr_init() failed");
		return STU_ERROR;
	}

	err = pthread_attr_setstacksize(&stu_thread_attr, stacksize);

	if (err != 0) {
		stu_log_error(err, "pthread_attr_setstacksize() failed");
		return STU_ERROR;
	}

	return STU_OK;
}

stu_int32_t
stu_thread_create(stu_tid_t *tid, stu_fd_t *epfd, void *(*func)(void *arg), void *arg) {
	int  err;

	if (stu_thread_n >= STU_THREAD_MAXIMUM) {
		stu_log_error(0, "no more than %d threads can be created", STU_THREAD_MAXIMUM);
		return STU_ERROR;
	}

	err = pthread_create(tid, &stu_thread_attr, func, arg);
	if (err != 0) {
		stu_log_error(err, "pthread_create() failed");
		return STU_ERROR;
	}

	if (epfd != NULL) {
		*epfd = stu_event_create();
		if (*epfd == -1) {
			stu_log_error(0, "Failed to create thread event.");
			return STU_ERROR;
		}
	}

	stu_log_debug(2, "thread %p is created.", tid);

	stu_thread_n++;

	return STU_OK;
}

stu_int32_t
stu_thread_cond_init(stu_thread_cond_t *cond) {
	stu_int32_t  err;

	err = pthread_cond_init(cond, NULL);
	if (err != STU_OK) {
		stu_log_error(err, "pthread_cond_init() failed");
		return STU_ERROR;
	}

	return STU_OK;
}
