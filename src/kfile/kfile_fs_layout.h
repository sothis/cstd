#ifndef _KFILE_FS_LAYOUT_H_
#define _KFILE_FS_LAYOUT_H_

#include <stdint.h>

typedef enum kfile_layout_t {
	KFILE_LAYOUT_NONE		= 0,
	KFILE_LAYOUT_UUID_UINT64	= 1,
	KFILE_LAYOUT_MAX
} kfile_layout_t;

#endif /* _KFILE_FS_LAYOUT_H_ */
