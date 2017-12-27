/*
 * stu_md5.h
 *
 *  Created on: 2017年11月15日
 *      Author: Tony Lau
 */

#ifndef STUDEASE_CN_CORE_STU_MD5_H_
#define STUDEASE_CN_CORE_STU_MD5_H_

#include "../stu_config.h"
#include "stu_core.h"

#if (STU_HAVE_OPENSSL_MD5_H)
#include <openssl/md5.h>
#else
#include <md5.h>
#endif

typedef MD5_CTX  stu_md5_t;

#define stu_md5_init    MD5_Init
#define stu_md5_update  MD5_Update
#define stu_md5_final   MD5_Final

#endif /* STUDEASE_CN_CORE_STU_MD5_H_ */
