/*
 * stu_mutex.h
 *
 *  Created on: 2017年11月15日
 *      Author: Tony Lau
 */

#ifndef STUDEASE_CN_CORE_STU_MUTEX_H_
#define STUDEASE_CN_CORE_STU_MUTEX_H_

#include "../stu_config.h"
#include "stu_core.h"

#define stu_mutex_t          pthread_mutex_t
#define stu_mutexattr_t      pthread_mutexattr_t

#define stu_mutex_init       pthread_mutex_init
#define stu_mutex_destroy    pthread_mutex_destroy
#define stu_mutex_trylock    pthread_mutex_trylock
#define stu_mutex_lock       pthread_mutex_lock
#define stu_mutex_timedlock  pthread_mutex_timedlock
#define stu_mutex_unlock     pthread_mutex_unlock

#endif /* STUDEASE_CN_CORE_STU_MUTEX_H_ */
