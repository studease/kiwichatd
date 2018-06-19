/*
 * stu_time.c
 *
 *  Created on: 2018Äê4ÔÂ26ÈÕ
 *      Author: Tony Lau
 */

#include "../../stu_config.h"
#include "../stu_core.h"


/*
 * FreeBSD does not test /etc/localtime change, however, we can workaround it
 * by calling tzset() with TZ and then without TZ to update timezone.
 * The trick should work since FreeBSD 2.1.0.
 *
 * Linux does not test /etc/localtime change in localtime(),
 * but may stat("/etc/localtime") several times in every strftime(),
 * therefore we use it to update timezone.
 *
 * Solaris does not test /etc/TIMEZONE change too and no workaround available.
 */

void
stu_timezone_update(void) {
#if (STU_FREEBSD)
	if (getenv("TZ")) {
		return;
	}

	putenv("TZ=UTC");

	tzset();

	unsetenv("TZ");

	tzset();

#elif (STU_LINUX)
	time_t      s;
	struct tm  *t;
	char        buf[4];

	s = time(0);

	t = localtime(&s);

	strftime(buf, 4, "%H", t);

#endif
}


void
stu_localtime(time_t s, stu_tm_t *tm) {
#if (STU_HAVE_LOCALTIME_R)
	(void) localtime_r(&s, tm);

#else
	stu_tm_t  *t;

	t = localtime(&s);
	*tm = *t;

#endif

	tm->stu_tm_mon++;
	tm->stu_tm_year += 1900;
}


void
stu_libc_localtime(time_t s, struct tm *tm) {
#if (STU_HAVE_LOCALTIME_R)
	(void) localtime_r(&s, tm);

#else
	struct tm  *t;

	t = localtime(&s);
	*tm = *t;

#endif
}


void
stu_libc_gmtime(time_t s, struct tm *tm) {
#if (STU_HAVE_LOCALTIME_R)
	(void) gmtime_r(&s, tm);

#else
	struct tm  *t;

	t = gmtime(&s);
	*tm = *t;

#endif
}
