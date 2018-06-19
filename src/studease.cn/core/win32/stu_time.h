/*
 * stu_time.h
 *
 *  Created on: 2018Äê4ÔÂ26ÈÕ
 *      Author: Tony Lau
 */

#ifndef STUDEASE_CN_CORE_WIN32_STU_TIME_H_
#define STUDEASE_CN_CORE_WIN32_STU_TIME_H_

#include "../../stu_config.h"
#include "../stu_core.h"

typedef SYSTEMTIME            stu_tm_t;
typedef FILETIME              stu_mtime_t;

#define stu_tm_sec            wSecond
#define stu_tm_min            wMinute
#define stu_tm_hour           wHour
#define stu_tm_mday           wDay
#define stu_tm_mon            wMonth
#define stu_tm_year           wYear
#define stu_tm_wday           wDayOfWeek

#define stu_tm_sec_t          u_short
#define stu_tm_min_t          u_short
#define stu_tm_hour_t         u_short
#define stu_tm_mday_t         u_short
#define stu_tm_mon_t          u_short
#define stu_tm_year_t         u_short
#define stu_tm_wday_t         u_short

#define stu_msleep            Sleep

#define STU_HAVE_GETTIMEZONE  1

#define stu_timezone_update()

stu_int32_t  stu_gettimezone(void);
void         stu_libc_localtime(time_t s, struct tm *tm);
void         stu_libc_gmtime(time_t s, struct tm *tm);
void         stu_gettimeofday(struct timeval *tp);

#endif /* STUDEASE_CN_CORE_WIN32_STU_TIME_H_ */
