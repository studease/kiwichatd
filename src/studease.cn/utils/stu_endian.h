/*
 * stu_endian.h
 *
 *  Created on: 2018骞�1鏈�17鏃�
 *      Author: Tony Lau
 */

#ifndef STUDEASE_CN_UTILS_STU_ENDIAN_H_
#define STUDEASE_CN_UTILS_STU_ENDIAN_H_

#include "stu_utils.h"

static stu_inline stu_uint16_t
stu_endian_16(stu_uint16_t n) {
	return (n << 8) | (n >> 8);
}

static stu_inline stu_uint32_t
stu_endian_32(stu_uint32_t n) {
	return (n << 24) | ((n << 8) & 0xFF0000) | ((n >> 8) & 0xFF00) | (n >> 24);
}

static stu_inline stu_uint64_t
stu_endian_64(stu_uint64_t n) {
	return (stu_uint64_t) stu_endian_32((stu_uint32_t) n) << 32 | stu_endian_32((stu_uint32_t) (n >> 32));
}

#endif /* STUDEASE_CN_UTILS_STU_ENDIAN_H_ */
