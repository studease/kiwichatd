/*
 * stu_hardware.h
 *
 *  Created on: 2017年12月26日
 *      Author: Tony Lau
 */

#ifndef STUDEASE_CN_UTILS_STU_HARDWARE_H_
#define STUDEASE_CN_UTILS_STU_HARDWARE_H_

#include "stu_utils.h"

u_char *stu_hardware_get_cpuid(u_char *dst);
u_char *stu_hardware_get_serial(u_char *dst);
u_char *stu_hardware_get_macaddr(u_char *dst);

void    stu_hardware_get_cpuidex(stu_int32_t dst[4], stu_uint32_t level, stu_uint32_t count);

#endif /* STUDEASE_CN_UTILS_STU_HARDWARE_H_ */
