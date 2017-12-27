/*
 * stu_base64.h
 *
 *  Created on: 2017年11月15日
 *      Author: Tony Lau
 */

#ifndef STUDEASE_CN_CORE_STU_BASE64_H_
#define STUDEASE_CN_CORE_STU_BASE64_H_

#include "../stu_config.h"
#include "stu_core.h"

#define stu_base64_encoded_length(len)  (((len + 2) / 3) * 4)
#define stu_base64_decoded_length(len)  (((len + 3) / 4) * 3)

void         stu_base64_encode(stu_str_t *dst, stu_str_t *src);
stu_int32_t  stu_base64_decode(stu_str_t *dst, stu_str_t *src);

#endif /* STUDEASE_CN_CORE_STU_BASE64_H_ */
