#ifndef _KFILE_FS_LAYOUT_DESC_H
#define _KFILE_FS_LAYOUT_DESC_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

typedef enum kfile_layout_t {
	KFILE_LAYOUT_NONE		= 0,
	KFILE_LAYOUT_UUID_UINT64	= 1,
	KFILE_LAYOUT_MAX
} kfile_layout_t;

#define _CODE_SEGMENT
#define _DATA_SEGMENT
#define externally_visible externally_visible
#define section_alignment aligned(32)
#define section_start(_name) __start_##_name
#define section_end(_name) __stop_##_name

#define section_prologue(_name, _item_type)				\
	extern const _item_type section_start(_name)[];			\
	extern const _item_type section_end(_name)[];

#define section_items(_name, _item_type)				\
	(((void*)section_end(_name)-(void*)section_start(_name))	\
	/ sizeof(_item_type))

#define foreach_section_item(_item_type, _var, _section)		\
	const _item_type* _var = section_start(_section);		\
	for (size_t i = 0; i < section_items(_section, _item_type); ++i)


typedef int (*open_file_ro_fn)(uint64_t uuid);
typedef int (*create_file_fn)(uint64_t uuid, mode_t mode);
typedef int (*close_file_fn)(int fd);

struct kfile_fsl_desc {
	const create_file_fn	create_file;
	const open_file_ro_fn	open_file_ro;
	const close_file_fn	close_file;

	const char*		name;
	const uint32_t		id;
} __attribute__((section_alignment));


#define _kfile_fsl_entry_					\
	__attribute__((section(_DATA_SEGMENT "__kfile_fsl"),	\
	used, section_alignment, externally_visible)) const

#define kfile_fsl_start(_id, _name)			\
	_kfile_fsl_entry_ struct kfile_fsl_desc 	\
	__kfile_fsl_##_id = {				\
		.id		= KFILE_LAYOUT_##_id,	\
		.name		= _name,

#define kfile_fsl_end					\
	};

section_prologue(__kfile_fsl, struct kfile_fsl_desc);

static inline const struct kfile_fsl_desc* kfile_get_fsl_by_id
(enum kfile_layout_t id)
{
	foreach_section_item(struct kfile_fsl_desc, fsls, __kfile_fsl) {
		if (id == fsls[i].id)
			return &fsls[i];
	}
	return 0;
}

#endif /* _KFILE_FS_LAYOUT_DESC_H */
