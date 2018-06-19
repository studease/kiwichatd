/*
 * stu_atomic.h
 *
 *  Created on: 2018Äê3ÔÂ30ÈÕ
 *      Author: Tony Lau
 */

#ifndef STUDEASE_CN_CORE_WIN32_STU_ATOMIC_H_
#define STUDEASE_CN_CORE_WIN32_STU_ATOMIC_H_

#include "../../stu_config.h"
#include "../stu_core.h"

typedef volatile stu_uint32_t  stu_atomic_t;

#define stu_memory_barrier()

#if defined( __BORLANDC__ ) || ( __WATCOMC__ < 1230 )

/*
 * Borland C++ 5.5 (tasm32) and Open Watcom C prior to 1.3
 * do not understand the "pause" instruction
 */

#define stu_cpu_pause()
#else
#define stu_cpu_pause()      __asm { pause }
#endif

#if defined( __WATCOMC__ ) || defined( __BORLANDC__ ) || defined(__GNUC__) || ( _MSC_VER >= 1300 )

/* the new SDK headers */

#define stu_atomic_cmp_set(lock, old, set)  \
    ((stu_atomic_uint_t) InterlockedCompareExchange((long *) lock, set, old) == old)

#else

/* the old MS VC6.0SP2 SDK headers */

#define stu_atomic_cmp_set(lock, old, set)  \
    (InterlockedCompareExchange((void **) lock, (void *) set, (void *) old) == (void *) old)

#endif

#define stu_atomic_fetch_add(p, add) InterlockedExchangeAdd((long *) p, add)

#endif /* STUDEASE_CN_CORE_WIN32_STU_ATOMIC_H_ */
