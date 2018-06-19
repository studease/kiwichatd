/*
 * stu_times.h
 *
 *  Created on: 2018Äê4ÔÂ26ÈÕ
 *      Author: Tony Lau
 */

#ifndef STUDEASE_CN_CORE_STU_TIMES_H_
#define STUDEASE_CN_CORE_STU_TIMES_H_

#include "../stu_config.h"
#include "stu_core.h"

typedef stu_rbtree_key_t      stu_msec_t;
typedef stu_rbtree_key_int_t  stu_msec_int_t;

typedef struct {
	time_t        sec;
	stu_uint32_t  msec;
	stu_int32_t   gmtoff;
} stu_time_t;

void    stu_time_init(void);
void    stu_time_update(void);
u_char *stu_http_time(u_char *buf, time_t t);
u_char *stu_http_cookie_time(u_char *buf, time_t t);

void    stu_gmtime(time_t t, stu_tm_t *tp);

time_t  stu_next_time(time_t when);
#define stu_next_time_n     "mktime()"


extern volatile stu_time_t  *stu_cached_time;

#define stu_time()           stu_cached_time->sec
#define stu_timeofday()     (stu_time_t *) stu_cached_time

extern volatile stu_str_t    stu_cached_log_time;
extern volatile stu_str_t    stu_cached_http_time;
extern volatile stu_str_t    stu_cached_http_log_time;

/*
 * milliseconds elapsed since epoch and truncated to stu_msec_t,
 * used in event timers
 */
extern volatile stu_msec_t   stu_current_msec;

#endif /* STUDEASE_CN_CORE_STU_TIMES_H_ */
