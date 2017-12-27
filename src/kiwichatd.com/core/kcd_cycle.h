/*
 * kcd_cycle.h
 *
 *  Created on: 2017年11月17日
 *      Author: Tony Lau
 */

#ifndef KIWICHATD_COM_CORE_KCD_CYCLE_H_
#define KIWICHATD_COM_CORE_KCD_CYCLE_H_

#include "kcd_core.h"

#define KCD_CYCLE_DEFAULT_SIZE 4096

typedef struct {
	stu_pool_t   *pool;
	kcd_conf_t    conf;
	stu_uint32_t  auto_user_id;
} kcd_cycle_t;

stu_int32_t  kcd_cycle_init();

stu_int32_t  kcd_cycle_create_pidfile(stu_file_t *pid);
void         kcd_cycle_delete_pidfile(stu_file_t *pid);

#endif /* KIWICHATD_COM_CORE_KCD_CYCLE_H_ */
