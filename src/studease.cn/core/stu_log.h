/*
 * stu_log.h
 *
 *  Created on: 2017年11月15日
 *      Author: Tony Lau
 */

#ifndef STUDEASE_CN_CORE_STU_LOG_H_
#define STUDEASE_CN_CORE_STU_LOG_H_

#include "../stu_config.h"
#include "stu_core.h"

#define STU_LOG_RECORD_MAX_LEN  1024

static const stu_str_t STU_LOG_PREFIX = stu_string("[L O G]");
static const stu_str_t STU_DEBUG_PREFIX = stu_string("[DEBUG]");
static const stu_str_t STU_ERROR_PREFIX = stu_string("[ERROR]");

#define STU_LOG_FILE_LINE                  "[" __FILE__ ":%d] " LFHT
#define stu_log(fmt, args...)              __stu_log(STU_LOG_FILE_LINE fmt "\n", __LINE__, ##args)
#define stu_log_debug(level, fmt, args...) __stu_log_debug(level, STU_LOG_FILE_LINE fmt "\n", __LINE__, ##args)
#define stu_log_error(errno, fmt, args...) __stu_log_error(errno, STU_LOG_FILE_LINE fmt, __LINE__, ##args)

stu_int32_t  stu_log_init(stu_file_t *file);

void __stu_log(const char *fmt, ...);
void __stu_log_debug(stu_int32_t level, const char *fmt, ...);
void __stu_log_error(stu_int32_t err, const char *fmt, ...);

#endif /* STUDEASE_CN_CORE_STU_LOG_H_ */
