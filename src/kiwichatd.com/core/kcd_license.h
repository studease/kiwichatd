/*
 * kcd_license.h
 *
 *  Created on: 2017年12月27日
 *      Author: Tony Lau
 */

#ifndef KIWICHATD_COM_CORE_KCD_LICENSE_H_
#define KIWICHATD_COM_CORE_KCD_LICENSE_H_

#include "kcd_core.h"

#define KCD_LICENSE_LENGTH  24

#define KCD_LICENSE_SOURCE_DEFAULT_SIZE  18 + 24
#define KCD_LICENSE_ENCRYPT_MAX_SIZE     1024
#define KCD_LICENSE_REQUEST_MAX_SIZE     1024
#define KCD_LICENSE_RESPONSE_MAX_SIZE    1024

kcd_edition_t  kcd_license_check(stu_str_t *key, stu_str_t *response);

#endif /* KIWICHATD_COM_CORE_KCD_LICENSE_H_ */
