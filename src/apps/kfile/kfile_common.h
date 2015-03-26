#ifndef _KFILE_COMMON_H_
#define _KFILE_COMMON_H_


#define KFILE_MAGIC			("KFILE")
#define KFILE_MAX_RES_NAME_LENGTH	(256ull) /* 255 byte + 1 zero byte */
#define KFILE_MAX_PASSWORD_LENGTH	(256ull) /* 2048 bit */
#define KFILE_SIZE_MAX			(256ull) /* 256 byte */


typedef int kfile_fd_t;
typedef kfile_fd_t kfile_read_fd_t;
typedef kfile_fd_t kfile_write_fd_t;

#endif /* _KFILE_COMMON_H_ */
