/*
 * kcd_process.h
 *
 *  Created on: 2017年12月5日
 *      Author: Tony Lau
 */

#ifndef KIWICHATD_COM_CORE_KCD_PROCESS_H_
#define KIWICHATD_COM_CORE_KCD_PROCESS_H_

#include "kcd_core.h"

void  kcd_process_master_cycle();
void  kcd_process_worker_cycle(stu_int32_t threads, void *data);

#endif /* KIWICHATD_COM_CORE_KCD_PROCESS_H_ */
