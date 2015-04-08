#ifndef _KFILE_FS_LAYOUT_H_
#define _KFILE_FS_LAYOUT_H_

#include <stdint.h>
#include <sys/stat.h>

typedef enum kfile_layout_t {
	KFILE_LAYOUT_NONE		= 0,
	KFILE_LAYOUT_UUID_UINT64	= 1,
	KFILE_LAYOUT_MAX
} kfile_layout_t;

int uuid_create_file(uint64_t uuid, mode_t mode);
int uuid_open_file_ro(uint64_t uuid);
int uuid_close_file(int fd);

#endif /* _KFILE_FS_LAYOUT_H_ */
