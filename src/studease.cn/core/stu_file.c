/*
 * stu_file.c
 *
 *  Created on: 2017年11月15日
 *      Author: Tony Lau
 */

#include "../stu_config.h"
#include "stu_core.h"


ssize_t
stu_file_read(stu_file_t *file, u_char *buf, size_t size, off_t offset) {
	ssize_t  n;

	n = pread(file->fd, buf, size, offset);
	if (n == -1) {
		stu_log_error(stu_errno, "pread() \"%s\" failed.", file->name.data);
		return STU_ERROR;
	}

	stu_atomic_fetch_add(&file->offset, n); // file->offset += n;

	return n;
}

ssize_t
stu_file_write(stu_file_t *file, u_char *buf, size_t size, off_t offset) {
	ssize_t  n, written;

	written = 0;

	for ( ;; ) {
		n = pwrite(file->fd, buf + written, size, offset);
		if (n == -1) {
			stu_log_error(stu_errno, "pwrite() \"%s\" failed.", file->name.data);
			return STU_ERROR;
		}

		stu_atomic_fetch_add(&file->offset, n); // file->offset += n;
		written += n;

		if ((size_t) n == size) {
			break;
		}

		offset += n;
		size -= n;
	}

	return written;
}


stu_int32_t
stu_file_set_time(u_char *name, stu_fd_t fd, time_t s) {
	struct timeval  tv[2];

	tv[0].tv_sec = s;
	tv[0].tv_usec = 0;
	tv[1].tv_sec = s;
	tv[1].tv_usec = 0;

	if (utimes((char *) name, tv) != -1) {
		return STU_OK;
	}

	return STU_ERROR;
}


stu_int32_t
stu_dir_open(u_char *name, stu_dir_t *dir) {
	dir->dir = opendir((const char *) name);

	if (dir->dir == NULL) {
		return STU_ERROR;
	}

	dir->valid_info = 0;

	return STU_OK;
}

stu_int32_t
stu_dir_read(stu_dir_t *dir) {
	dir->de = readdir(dir->dir);

	if (dir->de) {
#if (STU_HAVE_D_TYPE)
		dir->type = dir->de->d_type;
#else
		dir->type = 0;
#endif
		return STU_OK;
	}

	return STU_ERROR;
}


stu_int32_t
stu_create_path(stu_file_t *file) {
	u_char      *pos, *last;
	stu_int32_t  err;

	last = file->name.data + file->name.len;

	for (pos = file->name.data; (pos = stu_strlchr(pos, last, '/')); pos++) {
		*pos = '\0';

		if (stu_dir_create(file->name.data, STU_FILE_DEFAULT_ACCESS) == STU_ERROR) {
			err = stu_errno;
			if (err != STU_EEXIST) {
				stu_log_error(err, "Failed to " stu_dir_create_n " \"%s\".", file->name.data);
				*pos = '/';
				return STU_ERROR;
			}
		}

		*pos = '/';
	}

	return STU_OK;
}

stu_int32_t
stu_create_full_path(u_char *dir, stu_uint16_t access) {
	u_char      *p, ch;
	stu_int32_t  err;

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

		if (stu_dir_create(dir, access) == STU_ERROR) {
			err = stu_errno;

			switch (err) {
			case STU_EEXIST:
				err = 0;
				/* no break */
			case STU_EACCES:
				break;

			default:
				stu_log_error(err, "Failed to " stu_dir_create_n " \"%s\".", dir);
				*p = '/';
				return err;
			}
		}

		*p = '/';
	}

	return err;
}


stu_int32_t
stu_trylock_fd(stu_fd_t fd) {
	struct flock  fl;

	stu_memzero(&fl, sizeof(struct flock));
	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_SET;

	if (fcntl(fd, F_SETLK, &fl) == -1) {
		stu_log_error(stu_errno, "fcntl() \"%d\" failed.", fd);
		return STU_ERROR;
	}

	return STU_OK;
}

stu_int32_t
stu_lock_fd(stu_fd_t fd) {
	struct flock  fl;

	stu_memzero(&fl, sizeof(struct flock));
	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_SET;

	if (fcntl(fd, F_SETLKW, &fl) == -1) {
		stu_log_error(stu_errno, "fcntl() \"%d\" failed.", fd);
		return STU_ERROR;
	}

	return STU_OK;
}

stu_int32_t
stu_unlock_fd(stu_fd_t fd) {
	struct flock  fl;

	stu_memzero(&fl, sizeof(struct flock));
	fl.l_type = F_UNLCK;
	fl.l_whence = SEEK_SET;

	if (fcntl(fd, F_SETLK, &fl) == -1) {
		stu_log_error(stu_errno, "fcntl() \"%d\" failed.", fd);
		return STU_ERROR;
	}

	return STU_OK;
}
