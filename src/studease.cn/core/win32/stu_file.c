/*
 * stu_file.c
 *
 *  Created on: 2018Äê3ÔÂ30ÈÕ
 *      Author: Tony Lau
 */

#include "../../stu_config.h"
#include "../stu_core.h"

#define STU_UTF16_BUFLEN  256

static stu_int32_t  stu_win32_check_filename(u_char *name, u_short *u, size_t len);
static u_short     *stu_utf8_to_utf16(u_short *utf16, u_char *utf8, size_t *len);


/* FILE_FLAG_BACKUP_SEMANTICS allows to obtain a handle to a directory */
stu_fd_t
stu_file_open(u_char *name, u_long mode, u_long create, u_long access) {
	u_short   *u;
	u_short    utf16[STU_UTF16_BUFLEN];
	stu_fd_t   fd;
	stu_err_t  err;
	size_t     len;

	fd = INVALID_HANDLE_VALUE;
	len = STU_UTF16_BUFLEN;

	u = stu_utf8_to_utf16(utf16, name, &len);
	if (u == NULL) {
		return INVALID_HANDLE_VALUE;
	}

	if (create == STU_FILE_OPEN && stu_win32_check_filename(name, u, len) != STU_OK) {
		goto failed;
	}

	fd = CreateFileW(u, mode, FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
			NULL, create, FILE_FLAG_BACKUP_SEMANTICS, NULL);

failed:

	if (u != utf16) {
		err = stu_errno;
		stu_free(u);
		stu_set_errno(err);
	}

	return fd;
}

ssize_t
stu_file_read(stu_file_t *file, u_char *buf, size_t size,  stu_off_t offset) {
	OVERLAPPED *povlp, ovlp;
	u_long      n;
	stu_err_t   err;

	ovlp.Internal = 0;
	ovlp.InternalHigh = 0;
	ovlp.Offset = (DWORD) offset;
	ovlp.OffsetHigh = (DWORD) (offset >> 32);
	ovlp.hEvent = NULL;

	povlp = &ovlp;

	if (ReadFile(file->fd, buf, size, &n, povlp) == 0) {
		err = stu_errno;
		if (err == ERROR_HANDLE_EOF) {
			return 0;
		}

		stu_log_error(err, "ReadFile() \"%s\" failed", file->name.data);
		return STU_ERROR;
	}

	file->offset += n;

	return n;
}

ssize_t
stu_file_write(stu_file_t *file, u_char *buf, size_t size,  stu_off_t offset) {
	OVERLAPPED *povlp, ovlp;
	u_long      n;

	ovlp.Internal = 0;
	ovlp.InternalHigh = 0;
	ovlp.Offset = (DWORD) offset;
	ovlp.OffsetHigh = (DWORD) (offset >> 32);
	ovlp.hEvent = NULL;

	povlp = &ovlp;

	if (WriteFile(file->fd, buf, size, &n, povlp) == 0) {
		stu_log_error(stu_errno, "WriteFile() \"%s\" failed", file->name.data);
		return STU_ERROR;
	}

	if (n != size) {
		stu_log_error(0, "WriteFile() \"%s\" has written only %ul of %uz", file->name.data, n, size);
		return STU_ERROR;
	}

	file->offset += n;

	return n;
}


ssize_t
stu_read_fd(stu_fd_t fd, void *buf, size_t size) {
	u_long  n;

	if (ReadFile(fd, buf, size, &n, NULL) != 0) {
		return (size_t) n;
	}

	return -1;
}

ssize_t
stu_write_fd(stu_fd_t fd, void *buf, size_t size) {
	u_long  n;

	if (WriteFile(fd, buf, size, &n, NULL) != 0) {
		return (size_t) n;
	}

	return -1;
}


stu_int32_t
stu_file_set_time(u_char *name, stu_fd_t fd, time_t s) {
	uint64_t  intervals;
	FILETIME  ft;

	/* 116444736000000000 is commented in src/os/win32/stu_time.c */
	intervals = s * 10000000 + 116444736000000000;

	ft.dwLowDateTime = (DWORD) intervals;
	ft.dwHighDateTime = (DWORD) (intervals >> 32);

	if (SetFileTime(fd, NULL, NULL, &ft) != 0) {
		return STU_OK;
	}

	return STU_ERROR;
}

stu_int32_t
stu_file_info(u_char *file, stu_file_info_t *sb) {
	u_short                   *u;
	u_short                    utf16[STU_UTF16_BUFLEN];
	size_t                     len;
	long                       rc;
	stu_err_t                  err;
	WIN32_FILE_ATTRIBUTE_DATA  fa;

	len = STU_UTF16_BUFLEN;
	rc = STU_FILE_ERROR;

	u = stu_utf8_to_utf16(utf16, file, &len);
	if (u == NULL) {
		return STU_FILE_ERROR;
	}

	if (stu_win32_check_filename(file, u, len) != STU_OK) {
		goto failed;
	}

	rc = GetFileAttributesExW(u, GetFileExInfoStandard, &fa);

	sb->dwFileAttributes = fa.dwFileAttributes;
	sb->ftCreationTime = fa.ftCreationTime;
	sb->ftLastAccessTime = fa.ftLastAccessTime;
	sb->ftLastWriteTime = fa.ftLastWriteTime;
	sb->nFileSizeHigh = fa.nFileSizeHigh;
	sb->nFileSizeLow = fa.nFileSizeLow;

failed:

	if (u != utf16) {
		err = stu_errno;
		stu_free(u);
		stu_set_errno(err);
	}

    return rc;
}


u_char *
stu_realpath(u_char *path, u_char *resolved) {
	/* STUB */
	return path;
}


stu_int32_t
stu_dir_open(stu_str_t *name, stu_dir_t *dir) {
	stu_strncpy(name->data + name->len, STU_DIR_MASK, STU_DIR_MASK_LEN + 1);

	dir->dir = FindFirstFile((const char *) name->data, &dir->finddata);

	name->data[name->len] = '\0';

	if (dir->dir == INVALID_HANDLE_VALUE) {
		return STU_ERROR;
	}

	dir->valid_info = 1;
	dir->ready = 1;

	return STU_OK;
}

stu_int32_t
stu_dir_read(stu_dir_t *dir) {
	if (dir->ready) {
		dir->ready = 0;
		return STU_OK;
	}

	if (FindNextFile(dir->dir, &dir->finddata) != 0) {
		dir->type = 1;
		return STU_OK;
	}

	return STU_ERROR;
}

stu_int32_t
stu_dir_close(stu_dir_t *dir) {
	if (FindClose(dir->dir) == 0) {
		return STU_ERROR;
	}

	return STU_OK;
}


stu_int32_t
stu_de_info(u_char *name, stu_dir_t *dir) {
	return STU_OK;
}

stu_int32_t
stu_de_link_info(u_char *name, stu_dir_t *dir) {
	return STU_OK;
}


stu_int32_t
stu_read_ahead(stu_fd_t fd, size_t n) {
	return ~STU_FILE_ERROR;
}

size_t
stu_fs_bsize(u_char *name) {
	u_char  root[4];
	u_long  sc, bs, nfree, ncl;

	if (name[2] == ':') {
		stu_strncpy(root, name, 4);
		name = root;
	}

	if (GetDiskFreeSpace((const char *) name, &sc, &bs, &nfree, &ncl) == 0) {
		return 512;
	}

	return sc * bs;
}


static stu_int32_t
stu_win32_check_filename(u_char *name, u_short *u, size_t len) {
	u_char     *p, ch;
	u_short    *lu;
	u_long      n;
	stu_err_t   err;
	enum {
		sw_start = 0,
		sw_normal,
		sw_after_slash,
		sw_after_colon,
		sw_after_dot
	} state;

	/* check for NTFS streams (":"), trailing dots and spaces */

	lu = NULL;
	state = sw_start;

	for (p = name; *p; p++) {
		ch = *p;

		switch (state) {
		case sw_start:
			/*
			 * skip till first "/" to allow paths starting with drive and
			 * relative path, like "c:html/"
			 */
			if (ch == '/' || ch == '\\') {
				state = sw_after_slash;
			}
			break;

		case sw_normal:
			if (ch == ':') {
				state = sw_after_colon;
				break;
			}

			if (ch == '.' || ch == ' ') {
				state = sw_after_dot;
				break;
			}

			if (ch == '/' || ch == '\\') {
				state = sw_after_slash;
				break;
			}
			break;

		case sw_after_slash:
			if (ch == '/' || ch == '\\') {
				break;
			}

			if (ch == '.') {
				break;
			}

			if (ch == ':') {
				state = sw_after_colon;
				break;
			}

			state = sw_normal;
			break;

		case sw_after_colon:
			if (ch == '/' || ch == '\\') {
				state = sw_after_slash;
				break;
			}

			goto invalid;

		case sw_after_dot:
			if (ch == '/' || ch == '\\') {
				goto invalid;
			}

			if (ch == ':') {
				goto invalid;
			}

			if (ch == '.' || ch == ' ') {
				break;
			}

			state = sw_normal;
			break;
		}
	}

	if (state == sw_after_dot) {
		goto invalid;
	}

	/* check if long name match */
	lu = malloc(len * 2);
	if (lu == NULL) {
		return STU_ERROR;
	}

	n = GetLongPathNameW(u, lu, len);

	if (n == 0) {
		goto failed;
	}

	if (n != len - 1 || _wcsicmp(u, lu) != 0) {
		goto invalid;
	}

	stu_free(lu);

	return STU_OK;

invalid:

	stu_set_errno(STU_ENOENT);

failed:

	if (lu) {
		err = stu_errno;
		stu_free(lu);
		stu_set_errno(err);
	}

	return STU_ERROR;
}


static u_short *
stu_utf8_to_utf16(u_short *utf16, u_char *utf8, size_t *len) {
	u_char    *p;
	u_short   *u, *last;
	uint32_t   n;

	p = utf8;
	u = utf16;
	last = utf16 + *len;

	while (u < last) {
		if (*p < 0x80) {
			*u++ = (u_short) *p;

			if (*p == 0) {
				*len = u - utf16;
				return utf16;
			}

			p++;

			continue;
		}

		if (u + 1 == last) {
			*len = u - utf16;
			break;
		}

		n = stu_utf8_decode(&p, 4);
		if (n > 0x10ffff) {
			stu_set_errno(STU_EILSEQ);
			return NULL;
		}

		if (n > 0xffff) {
			n -= 0x10000;
			*u++ = (u_short) (0xd800 + (n >> 10));
			*u++ = (u_short) (0xdc00 + (n & 0x03ff));
			continue;
		}

		*u++ = (u_short) n;
	}

	/* the given buffer is not enough, allocate a new one */
	u = malloc(((p - utf8) + stu_strlen(p) + 1) * sizeof(u_short));
	if (u == NULL) {
		return NULL;
	}

	(void) stu_memcpy(u, utf16, *len * 2);

	utf16 = u;
	u += *len;

	for ( ;; ) {
		if (*p < 0x80) {
			*u++ = (u_short) *p;

			if (*p == 0) {
				*len = u - utf16;
				return utf16;
			}

			p++;

			continue;
		}

		n = stu_utf8_decode(&p, 4);

		if (n > 0x10ffff) {
			stu_free(utf16);
			stu_set_errno(STU_EILSEQ);
			return NULL;
		}

		if (n > 0xffff) {
			n -= 0x10000;
			*u++ = (u_short) (0xd800 + (n >> 10));
			*u++ = (u_short) (0xdc00 + (n & 0x03ff));
			continue;
		}

		*u++ = (u_short) n;
	}

	/* unreachable */
	return NULL;
}
