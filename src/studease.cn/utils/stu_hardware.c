/*
 * stu_hardware.c
 *
 *  Created on: 2017骞�12鏈�26鏃�
 *      Author: Tony Lau
 */

#if defined(__GNUC__)
#include <cpuid.h>
#elif defined(_MSC_VER)
	#if _MSC_VER >= 1400  // VC2005+ supports __cpuid
		#include <intrin.h>
	#endif
#endif

#include "stu_utils.h"


u_char *
stu_hardware_get_cpuid(u_char *dst) {
	stu_uint32_t  tmp[4];

#if defined(__GNUC__)
	__cpuid(1, tmp[0], tmp[1], tmp[2], tmp[3]);
#elif defined(_MSC_VER)
	#if _MSC_VER >= 1400
		__cpuid(tmp, 1);
	#else
		stu_hardware_get_cpuidex(tmp, 1, 0);
	#endif
#endif

	return stu_sprintf(dst, "%08X%08X", tmp[3], tmp[0]);
}

void
stu_hardware_get_cpuidex(stu_int32_t dst[4], stu_uint32_t level, stu_uint32_t count) {
#if defined(__GNUC__)
	__cpuid_count(level, count, dst[0], dst[1], dst[2], dst[3]);
#elif defined(_MSC_VER)
	#if defined(_WIN64) || _MSC_VER >= 1600 // VC2008 SP1+ supports __cpuidex
		__cpuidex(dst, level, count);
	#else
		if (dst == NULL) return;

		_asm {
			// load
			mov edi, dst;
			mov eax, level;
			mov ecx, count;

			cpuid;

			// save
			mov    [edi],    eax;
			mov    [edi+4],  ebx;
			mov    [edi+8],  ecx;
			mov    [edi+12], edx;
		}
	#endif
#endif
}


u_char *
stu_hardware_get_serial(u_char *dst) {
	u_char      *pos, ch;
	stu_file_t   file;
	u_char       cmd[STU_MAX_PATH];
	u_char       tmp[128];
	stu_int32_t  n;

	pos = tmp;
	stu_memzero(cmd, STU_MAX_PATH);
	stu_memzero(tmp, 128);
	stu_memzero(&file, sizeof(stu_file_t));

	stu_str_set(&file.name, "serial.out");
	stu_sprintf(cmd, "dmidecode -s system-serial-number > %s", file.name.data);

	if (system((const char *) cmd) == -1) {
		stu_log_error(stu_errno, "Failed to execute command \"dmidecode\".");
		goto failed;
	}

	file.fd = stu_file_open(file.name.data, STU_FILE_RDONLY, 0, STU_FILE_DEFAULT_ACCESS);
	if (file.fd == STU_FILE_INVALID) {
		stu_log_error(stu_errno, "Failed to " stu_file_open_n " temp file \"%s\".", file.name.data);
		goto failed;
	}

	n = stu_file_read(&file, tmp, 128, 0);
	if (n == STU_ERROR) {
		stu_log_error(stu_errno, "Failed to read temp file \"%s\".", file.name.data);
	}

	for (pos = stu_strlchr(pos, pos + n, '-') + 1; *pos; pos++) {
		ch = stu_toupper(*pos);

		if ((ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'F')) {
			*dst++ = ch;
		}
	}

	stu_file_close(file.fd);
	stu_file_delete(file.name.data);

failed:

	return dst;
}


#if (STU_LINUX)

u_char *
stu_hardware_get_macaddr(u_char *dst) {
	u_char       *p;
	struct ifreq *ifr, buf[INET_ADDRSTRLEN];
	struct ifconf ifc;
	stu_socket_t  fd;
	stu_int32_t   i;

	p = NULL;

	fd = stu_socket(AF_INET, SOCK_DGRAM, 0);
	if (fd == -1) {
		stu_log_error(stu_errno, "Failed to create socket for macaddr detection.");
		return NULL;
	}

	ifc.ifc_len = sizeof(buf);
	ifc.ifc_buf = (caddr_t) buf;

	if (ioctl(fd, SIOCGIFCONF, &ifc) == -1) {
		stu_log_error(stu_errno, "ioctl(SIOCGIFCONF) failed.");
		goto failed;
	}

	for (i = 0; i < INET_ADDRSTRLEN; i++) {
		ifr = &buf[i];

		if (ioctl(fd, SIOCGIFFLAGS, ifr) == -1) {
			stu_log_error(stu_errno, "ioctl(SIOCGIFFLAGS) failed.");
			goto failed;
		}

		if ((ifr->ifr_flags & IFF_LOOPBACK)
				|| (ifr->ifr_flags & IFF_UP) == 0
				|| (ifr->ifr_flags & IFF_RUNNING) == 0) {
			continue;
		}

		if (ioctl(fd, SIOCGIFHWADDR, ifr) == -1) {
			stu_log_error(stu_errno, "ioctl(SIOCGIFHWADDR) failed.");
			goto failed;
		}

		p = stu_sprintf(dst, "%02X%02X%02X%02X%02X%02X",
				ifr->ifr_hwaddr.sa_data[0],
				ifr->ifr_hwaddr.sa_data[1],
				ifr->ifr_hwaddr.sa_data[2],
				ifr->ifr_hwaddr.sa_data[3],
				ifr->ifr_hwaddr.sa_data[4],
				ifr->ifr_hwaddr.sa_data[5]);

		break;
	}

failed:

	stu_socket_close(fd);

	return p;
}

#elif (STU_WIN32)

u_char *
stu_hardware_get_macaddr(u_char *dst) {
	u_char           *p;
	PIP_ADAPTER_INFO  infos, info;
	ULONG             rc, size;

	p = NULL;
	infos = NULL;
	size = 0;

	GetAdaptersInfo(infos, &size);

	infos = stu_calloc(size);
	if (infos == NULL) {
		stu_log_error(stu_errno, "Failed to calloc IP_ADAPTER_INFO buffer.");
		return NULL;
	}

	rc = GetAdaptersInfo(infos, &size);
	if (rc) {
		stu_log_error(stu_errno, "Failed to GetAdaptersInfo().");
		goto failed;
	}

	for (info = infos; info; info = info->Next) {
		p = stu_sprintf(dst, "%02X:%02X:%02X:%02X:%02X:%02X",
				info->Address[0],
				info->Address[1],
				info->Address[2],
				info->Address[3],
				info->Address[4],
				info->Address[5]);

		break;
	}

failed:

	stu_free(infos);

	return p;
}

#endif
