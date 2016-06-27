#if 0
#include "kfile_fs_layout_desc.h"





const struct kfile_fsl_desc* layout = 0;

#include "stdio.h"
__attribute__((constructor)) void startup_(void)
{
	printf("------------- start ----------\n");

	printf("layout0: %u\n", KFILE_LAYOUT_UUID_UINT64);
	layout = kfile_get_fsl_by_id(KFILE_LAYOUT_UUID_UINT64);
	if (!layout) {
		printf("unable to find layout.\n");
		return;
	}

}
#endif
