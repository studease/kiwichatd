/*
 * stu_file.h
 *
 *  Created on: 2018Äê3ÔÂ30ÈÕ
 *      Author: Tony Lau
 */

#ifndef STUDEASE_CN_CORE_WIN32_STU_FILE_H_
#define STUDEASE_CN_CORE_WIN32_STU_FILE_H_

#include "../../stu_config.h"
#include "../stu_core.h"

#define STU_FILE_INVALID            INVALID_HANDLE_VALUE
#define STU_FILE_ERROR              0

typedef HANDLE                      stu_fd_t;
typedef BY_HANDLE_FILE_INFORMATION  stu_file_info_t;

typedef struct {
	HANDLE                          dir;
	WIN32_FIND_DATA                 finddata;

	unsigned                        valid_info:1;
	unsigned                        type:1;
	unsigned                        ready:1;
} stu_dir_t;

/* INVALID_FILE_ATTRIBUTES is specified but not defined at least in MSVC6SP2 */
#ifndef INVALID_FILE_ATTRIBUTES
#define INVALID_FILE_ATTRIBUTES     0xffffffff
#endif

/* INVALID_SET_FILE_POINTER is not defined at least in MSVC6SP2 */
#ifndef INVALID_SET_FILE_POINTER
#define INVALID_SET_FILE_POINTER    0xffffffff
#endif

#define STU_FILE_RDONLY             GENERIC_READ
#define STU_FILE_WRONLY             GENERIC_WRITE
#define STU_FILE_RDWR               GENERIC_READ|GENERIC_WRITE
#define STU_FILE_CREATE_OR_OPEN     OPEN_ALWAYS
#define STU_FILE_OPEN               OPEN_EXISTING
#define STU_FILE_TRUNCATE           CREATE_ALWAYS
#define STU_FILE_APPEND             FILE_APPEND_DATA|SYNCHRONIZE
#define STU_FILE_NONBLOCK           0

#define STU_FILE_DEFAULT_ACCESS     0
#define STU_FILE_OWNER_ACCESS       0

stu_fd_t stu_file_open(u_char *name, u_long mode, u_long create, u_long access);
#define  stu_file_open_n           "CreateFile()"

#define  stu_file_close             CloseHandle
#define stu_file_close_n           "CloseHandle()"

#define stu_file_delete(name)       DeleteFile((const char *) name)
#define stu_file_delete_n          "DeleteFile()"

ssize_t stu_file_read(stu_file_t *file, u_char *buf, size_t size,  stu_off_t offset);
#define stu_read_file_n            "ReadFile()"

ssize_t stu_file_write(stu_file_t *file, u_char *buf, size_t size,  stu_off_t offset);

ssize_t stu_read_fd(stu_fd_t fd, void *buf, size_t size);
#define stu_read_fd_n              "ReadFile()"

ssize_t stu_write_fd(stu_fd_t fd, void *buf, size_t size);
#define stu_write_fd_n             "WriteFile()"

#define stu_linefeed(p)            *p++ = CR; *p++ = LF;
#define STU_LINEFEED_SIZE           2
#define STU_LINEFEED                CRLF

#define stu_file_rename(o, n)       MoveFile((const char *) o, (const char *) n)
#define stu_file_rename_n          "MoveFile()"

stu_int32_t stu_file_set_time(u_char *name, stu_fd_t fd, time_t s);
#define stu_file_set_time_n        "SetFileTime()"

stu_int32_t stu_file_info(u_char *filename, stu_file_info_t *fi);
#define stu_file_info_n            "GetFileAttributesEx()"

#define stu_fd_info(fd, fi)         GetFileInformationByHandle(fd, fi)
#define stu_fd_info_n              "GetFileInformationByHandle()"

#define stu_link_info(name, fi)     stu_file_info(name, fi)
#define stu_link_info_n            "GetFileAttributesEx()"

#define stu_is_dir(fi)                                                         \
	(((fi)->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
#define stu_is_file(fi)                                                        \
	(((fi)->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
#define stu_is_link(fi)             0
#define stu_is_exec(fi)             0

#define stu_file_access(fi)         0
#define stu_file_size(fi)                                                      \
	(((off_t) (fi)->nFileSizeHigh << 32) | (fi)->nFileSizeLow)
#define stu_file_fs_size(fi)        stu_file_size(fi)
/* 116444736000000000 is commented in src/os/win32/stu_time.c */
#define stu_file_mtime(fi)                                                     \
	(time_t) (((((unsigned __int64)                                            \
                                   (fi)->ftLastWriteTime.dwHighDateTime << 32) \
                                 | (fi)->ftLastWriteTime.dwLowDateTime)        \
                                 - 116444736000000000) / 10000000)
#define stu_file_uniq(fi)        (*(stu_file_uniq_t *) &(fi)->nFileIndexHigh)


u_char *stu_realpath(u_char *path, u_char *resolved);
#define stu_realpath_n             ""
#define stu_getcwd(buf, size)       GetCurrentDirectory(size, (char *) buf)
#define stu_getcwd_n               "GetCurrentDirectory()"
#define stu_path_separator(c)       ((c) == '/' || (c) == '\\')

#define STU_HAVE_MAX_PATH           1
#define STU_MAX_PATH                MAX_PATH

#define STU_DIR_MASK               (u_char *) "/*"
#define STU_DIR_MASK_LEN            2

stu_int32_t stu_dir_open(stu_str_t *name, stu_dir_t *dir);
#define stu_dir_open_n             "FindFirstFile()"

stu_int32_t stu_dir_read(stu_dir_t *dir);
#define stu_dir_read_n             "FindNextFile()"

stu_int32_t stu_dir_close(stu_dir_t *dir);
#define stu_dir_close_n            "FindClose()"

#define stu_dir_create(name, access) CreateDirectory((const char *) name, NULL)
#define stu_dir_create_n            "CreateDirectory()"

#define stu_dir_delete(name)        RemoveDirectory((const char *) name)
#define stu_dir_delete_n           "RemoveDirectory()"

#define stu_dir_access(a)          (a)


#define stu_de_name(dir)          ((u_char *) (dir)->finddata.cFileName)
#define stu_de_namelen(dir)         stu_strlen((dir)->finddata.cFileName)

stu_int32_t stu_de_info(u_char *name, stu_dir_t *dir);
#define stu_de_info_n              "dummy()"

stu_int32_t stu_de_link_info(u_char *name, stu_dir_t *dir);
#define stu_de_link_info_n         "dummy()"

#define stu_de_is_dir(dir)                                                     \
	(((dir)->finddata.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
#define stu_de_is_file(dir)                                                    \
	(((dir)->finddata.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
#define stu_de_is_link(dir)         0
#define stu_de_access(dir)          0
#define stu_de_size(dir)                                                       \
  (((off_t) (dir)->finddata.nFileSizeHigh << 32) | (dir)->finddata.nFileSizeLow)
#define stu_de_fs_size(dir)         stu_de_size(dir)

/* 116444736000000000 is commented in src/os/win32/stu_time.c */
#define stu_de_mtime(dir)                                                      \
	(time_t) (((((unsigned __int64)                                            \
                     (dir)->finddata.ftLastWriteTime.dwHighDateTime << 32)     \
                   | (dir)->finddata.ftLastWriteTime.dwLowDateTime)            \
                   - 116444736000000000) / 10000000)


stu_int32_t  stu_read_ahead(stu_fd_t fd, size_t n);
#define stu_read_ahead_n           "stu_read_ahead_n"

size_t  stu_fs_bsize(u_char *name);


#define stu_stdout                  GetStdHandle(STD_OUTPUT_HANDLE)
#define stu_stderr                  GetStdHandle(STD_ERROR_HANDLE)
#define stu_set_stderr(fd)          SetStdHandle(STD_ERROR_HANDLE, fd)
#define stu_set_stderr_n           "SetStdHandle(STD_ERROR_HANDLE)"

#endif /* STUDEASE_CN_CORE_WIN32_STU_FILE_H_ */
