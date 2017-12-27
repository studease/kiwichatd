/*
 * stu_alloc.h
 *
 *  Created on: 2017年11月15日
 *      Author: Tony Lau
 */

#ifndef STUDEASE_CN_CORE_STU_ALLOC_H_
#define STUDEASE_CN_CORE_STU_ALLOC_H_

#include "../stu_config.h"
#include "stu_core.h"

void *stu_alloc(size_t size);
void *stu_calloc(size_t size);

#define stu_free  free

#endif /* STUDEASE_CN_CORE_STU_ALLOC_H_ */
