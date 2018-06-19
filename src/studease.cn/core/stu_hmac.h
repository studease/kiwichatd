/*
 * stu_sha256.h
 *
 *  Created on: 2018年1月18日
 *      Author: Tony Lau
 */

#ifndef STUDEASE_CN_CORE_STU_HMAC_H_
#define STUDEASE_CN_CORE_STU_HMAC_H_

#include "../stu_config.h"
#include "stu_core.h"

#if (STU_HAVE_OPENSSL_HMAC_H)
#include <openssl/hmac.h>
#include <openssl/sha.h>
#else
#include <hmac.h>
#include <sha.h>
#endif

typedef HMAC_CTX  stu_hmac_t;

stu_hmac_t *stu_hmac_create();
void        stu_hmac_free(stu_hmac_t *hmac);

#define stu_hmac_init    HMAC_Init_ex
#define stu_hmac_update  HMAC_Update
#define stu_hmac_final   HMAC_Final

#endif /* STUDEASE_CN_CORE_STU_HMAC_H_ */
