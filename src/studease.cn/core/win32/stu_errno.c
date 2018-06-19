/*
 * stu_errno.c
 *
 *  Created on: 2018Äê3ÔÂ30ÈÕ
 *      Author: Tony Lau
 */

#include "../../stu_config.h"
#include "../stu_core.h"


u_char *
stu_strerror(stu_err_t err, u_char *explain, size_t size) {
	u_int          len;
	static u_long  lang = MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US);

	if (size == 0) {
		return explain;
	}

	len = FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, err, lang, (char *) explain, size, NULL);

	if (len == 0 && lang && GetLastError() == ERROR_RESOURCE_LANG_NOT_FOUND) {
		/*
		 * Try to use English messages first and fallback to a language,
		 * based on locale: non-English Windows have no English messages
		 * at all.  This way allows to use English messages at least on
		 * Windows with MUI.
		 */

		lang = 0;

		len = FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, err, lang, (char *) explain, size, NULL);
	}

	if (len == 0) {
		return stu_sprintf(explain, "FormatMessage() error:(%d)", GetLastError());
	}

	/* remove ".\r\n\0" */
	while (explain[len] == '\0' || explain[len] == CR || explain[len] == LF || explain[len] == '.') {
		--len;
	}

	return &explain[++len];
}

stu_int32_t
stu_strerror_init(void) {
	return STU_OK;
}
