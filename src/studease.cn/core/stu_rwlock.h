/*
 * stu_rwlock.h
 *
 *  Created on: 2017年11月24日
 *      Author: Tony Lau
 */

#ifndef STUDEASE_CN_CORE_STU_RWLOCK_H_
#define STUDEASE_CN_CORE_STU_RWLOCK_H_

#include "../stu_config.h"
#include "stu_core.h"

#define stu_rwlock_t            pthread_rwlock_t
#define stu_rwlockattr_t        pthread_rwlockattr_t

#define stu_rwlock_init         pthread_rwlock_init
#define stu_rwlock_destroy      pthread_rwlock_destroy
#define stu_rwlock_rdlock       pthread_rwlock_rdlock
#define stu_rwlock_tryrdlock    pthread_rwlock_tryrdlock
#define stu_rwlock_timedrdlock  pthread_rwlock_timedrdlock
#define stu_rwlock_wrlock       pthread_rwlock_wrlock
#define stu_rwlock_trywrlock    pthread_rwlock_trywrlock
#define stu_rwlock_timedwrlock  pthread_rwlock_timedwrlock
#define stu_rwlock_unlock       pthread_rwlock_unlock

#endif /* STUDEASE_CN_CORE_STU_RWLOCK_H_ */
