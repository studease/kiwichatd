/*
 * stu_hardware.c
 *
 *  Created on: 2017骞�12鏈�26鏃�
 *      Author: Tony Lau
 */

#include "stu_utils.h"


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

		p = stu_sprintf(dst, "%02X:%02X:%02X:%02X:%02X:%02X",
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
