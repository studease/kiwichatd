/*
 * stu_flash.c
 *
 *  Created on: 2017年11月22日
 *      Author: Tony Lau
 */

#include "../stu_config.h"
#include "stu_core.h"

stu_str_t  STU_FLASH_POLICY_FILE_REQUEST = stu_string(
		"<policy-file-request/>\0"
	);

stu_str_t  STU_FLASH_POLICY_FILE = stu_string(
		"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
		"<cross-domain-policy>"
			"<allow-access-from domain=\"*\" to-ports=\"*\" />"
		"</cross-domain-policy>\0"
	);


