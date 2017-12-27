/*
 * stu_rsa.h
 *
 *  Created on: 2017年12月26日
 *      Author: Tony Lau
 */

#ifndef STUDEASE_CN_CORE_STU_RSA_H_
#define STUDEASE_CN_CORE_STU_RSA_H_

#include "../stu_config.h"
#include "stu_core.h"

#if (STU_HAVE_OPENSSL_RSA_H)
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#else
#include <bn.h>
#include <pem.h>
#include <rand.h>
#include <rsa.h>
#endif

typedef EVP_MD_CTX  stu_pem_t;

#define stu_pem_init    PEM_SignInit
#define stu_pem_update  PEM_SignUpdate
#define stu_pem_final   PEM_SignFinal

#endif /* STUDEASE_CN_CORE_STU_RSA_H_ */
