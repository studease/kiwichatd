/*
 * stu_files.h
 *
 *  Created on: 2018Äê4ÔÂ26ÈÕ
 *      Author: Tony Lau
 */

#ifndef STUDEASE_CN_CORE_STU_FILES_H_
#define STUDEASE_CN_CORE_STU_FILES_H_

#include "../stu_config.h"
#include "stu_core.h"

#define STU_MAX_PATH_LEVEL  3

typedef stu_msec_t (*stu_path_manager_pt)(void *data);
typedef stu_msec_t (*stu_path_purger_pt)(void *data);
typedef void       (*stu_path_loader_pt)(void *data);

struct stu_file_s {
	stu_fd_t             fd;
	stu_str_t            name;
	stu_file_info_t      info;

	void               (*flush)(stu_file_t *file);
	void                *data;

	off_t                offset;
	off_t                sys_offset;
};

stu_int32_t  stu_create_path(stu_file_t *file);
stu_err_t    stu_create_full_path(u_char *dir, stu_uint16_t access);

#endif /* STUDEASE_CN_CORE_STU_FILES_H_ */
