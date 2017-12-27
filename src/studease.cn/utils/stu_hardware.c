/*
 * stu_hardware.c
 *
 *  Created on: 2017年12月26日
 *      Author: Tony Lau
 */

#include "stu_hardware.h"


u_char *
stu_hardware_get_hwaddr(u_char *dst) {
	u_char       *p;
	struct ifreq *ifr;
	struct ifreq  buf[INET_ADDRSTRLEN];
	struct ifconf ifc;
	stu_socket_t  fd;
	stu_int32_t   i;

	p = NULL;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
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

	stu_close_socket(fd);

	return p;
}
