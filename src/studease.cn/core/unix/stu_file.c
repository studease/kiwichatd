/*
 * stu_file.c
 *
 *  Created on: 2017骞�11鏈�15鏃�
 *      Author: Tony Lau
 */

#include "../../stu_config.h"
#include "../stu_core.h"


ssize_t
stu_file_read(stu_file_t *file, u_char *buf, size_t size, stu_off_t offset) {
	ssize_t  n;

	stu_log_debug(2, "read file: fd=%d, %zu, %zu", file->fd, size, offset);

#if (STU_HAVE_PREAD)

	n = pread(file->fd, buf, size, offset);
	if (n == -1) {
		stu_log_error(stu_errno, "pread() \"%s\" failed", file->name.data);
		return STU_ERROR;
	}

#else

	if (file->sys_offset != offset) {
		if (lseek(file->fd, offset, SEEK_SET) == -1) {
			stu_log_error(stu_errno, "lseek() \"%s\" failed", file->name.data);
			return STU_ERROR;
		}

		file->sys_offset = offset;
	}

	n = read(file->fd, buf, size);
	if (n == -1) {
		stu_log_error(stu_errno, "read() \"%s\" failed", file->name.data);
		return STU_ERROR;
	}

	file->sys_offset += n;

#endif

	file->offset += n;

	return n;
}

ssize_t
stu_file_write(stu_file_t *file, u_char *buf, size_t size, stu_off_t offset) {
	ssize_t    n, written;
	stu_err_t  err;

	stu_log_debug(2, "write: %d, %p, %uz, %O", file->fd, buf, size, offset);

	written = 0;

#if (STU_HAVE_PWRITE)

	for ( ;; ) {
		n = pwrite(file->fd, buf + written, size, offset);
		if (n == -1) {
			err = stu_errno;

			if (err == STU_EINTR) {
				stu_log_error(err, "pwrite() was interrupted");
				continue;
			}

			stu_log_error(err, "pwrite() \"%s\" failed", file->name.data);
			return STU_ERROR;
		}

		file->offset += n;
		written += n;

		if ((size_t) n == size) {
			return written;
		}

		offset += n;
		size -= n;
	}

#else

	if (file->sys_offset != offset) {
		if (lseek(file->fd, offset, SEEK_SET) == -1) {
			stu_log_error(stu_errno, "lseek() \"%s\" failed", file->name.data);
			return STU_ERROR;
		}

		file->sys_offset = offset;
	}

	for ( ;; ) {
		n = write(file->fd, buf + written, size);
		if (n == -1) {
			err = stu_errno;

			if (err == STU_EINTR) {
				stu_log_error(err, "write() was interrupted");
				continue;
			}

			stu_log_error(err, "write() \"%s\" failed", file->name.data);
			return STU_ERROR;
		}

		file->sys_offset += n;
		file->offset += n;
		written += n;

		if ((size_t) n == size) {
			return written;
		}

		size -= n;
	}

#endif

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
stu_dir_open(stu_str_t *name, stu_dir_t *dir) {
	dir->dir = opendir((const char *) name->data);

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


#if (STU_HAVE_POSIX_FADVISE) && !(STU_HAVE_F_READAHEAD)

stu_int_t
stu_read_ahead(stu_fd_t fd, size_t n) {
	int  err;

	err = posix_fadvise(fd, 0, 0, POSIX_FADV_SEQUENTIAL);
	if (err == 0) {
		return 0;
	}

	stu_set_errno(err);

	return STU_FILE_ERROR;
}

#endif


#if (STU_HAVE_STATFS)

size_t
stu_fs_bsize(u_char *name) {
	struct statfs  fs;

	if (statfs((char *) name, &fs) == -1) {
		return 512;
	}

	if ((fs.f_bsize % 512) != 0) {
		return 512;
	}

	return (size_t) fs.f_bsize;
}

#elif (STU_HAVE_STATVFS)

size_t
stu_fs_bsize(u_char *name) {
	struct statvfs  fs;

	if (statvfs((char *) name, &fs) == -1) {
		return 512;
	}

	if ((fs.f_frsize % 512) != 0) {
		return 512;
	}

	return (size_t) fs.f_frsize;
}

#else

size_t
stu_fs_bsize(u_char *name) {
	return 512;
}

#endif
