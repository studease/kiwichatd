/*
 * stu_files.c
 *
 *  Created on: 2018Äê4ÔÂ26ÈÕ
 *      Author: Tony Lau
 */

#include "../stu_config.h"
#include "stu_core.h"


stu_int32_t
stu_create_path(stu_file_t *file) {
	u_char    *p;
	stu_err_t  err;

	p = file->name.data;

	for ( /* void */ ; *p; p++) {
		if (*p != '/') {
			continue;
		}

		*p = '\0';

		if (stu_dir_create(file->name.data, 0700) == STU_FILE_ERROR) {
			err = stu_errno;
			if (err != STU_EEXIST) {
				stu_log_error(err, stu_dir_create_n " \"%s\" failed", file->name.data);
				return STU_ERROR;
			}
		}

		*p = '/';
	}

	return STU_OK;
}


stu_err_t
stu_create_full_path(u_char *dir, stu_uint16_t access) {
	u_char    *p, ch;
	stu_err_t  err;

	err = 0;

#if (STU_WIN32)
	p = dir + 3;
#else
	p = dir + 1;
#endif

	for ( /* void */ ; *p; p++) {
		ch = *p;
		if (ch != '/') {
			continue;
		}

		*p = '\0';

		if (stu_dir_create(dir, access) == STU_FILE_ERROR) {
			err = stu_errno;

			switch (err) {
			case STU_EEXIST:
				err = 0;
				/* no break */
			case STU_EACCES:
				break;

			default:
				return err;
			}
		}

		*p = '/';
	}

	return err;
}
