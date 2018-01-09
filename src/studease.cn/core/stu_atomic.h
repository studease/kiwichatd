/*
 * stu_atomic.h
 *
 *  Created on: 2017年11月15日
 *      Author: Tony Lau
 */

#ifndef STUDEASE_CN_CORE_STU_ATOMIC_H_
#define STUDEASE_CN_CORE_STU_ATOMIC_H_

#include "../stu_config.h"
#include "stu_core.h"

typedef volatile stu_uint32_t  stu_atomic_t;

#define STU_SMP_LOCK  "lock;"

#define stu_memory_barrier() __sync_synchronize()

#if ( __i386__ || __i386 || __amd64__ || __amd64 )
#define stu_cpu_pause()      __asm__ ("pause")
#else
#define stu_cpu_pause()
#endif

#define stu_atomic_release(ptr)                   \
	__sync_lock_release(ptr)

#define stu_atomic_test_set(ptr, val)             \
	__sync_lock_test_and_set(ptr, val)

#define stu_atomic_cmp_set(ptr, old, val)         \
	__sync_bool_compare_and_swap(ptr, old, val)

#define stu_atomic_fetch_add(ptr, val)            \
	__sync_fetch_and_add(ptr, val)

#define stu_atomic_fetch_sub(ptr, val)            \
	__sync_fetch_and_sub(ptr, val)

#endif /* STUDEASE_CN_CORE_STU_ATOMIC_H_ */
