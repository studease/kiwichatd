/*
 * stu_http_phase.c
 *
 *  Created on: 2017年11月27日
 *      Author: Tony Lau
 */

#include "stu_http.h"

stu_list_t  stu_http_phases;


stu_int32_t
stu_http_phase_init() {
	stu_list_init(&stu_http_phases, NULL);
	return STU_OK;
}
