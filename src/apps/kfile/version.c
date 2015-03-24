#include "kfile_version.h"
#include <string.h>

/* index must match enum kfile_version_t */
static const char* _kfile_version_strings[] = {
	"0.1",
	"1.0"
};

const char* kfile_version_string(kfile_version_t version)
{
	/* check for version < KFILE_VERSION_MAX here? */
	return _kfile_version_strings[version];
}

int kfile_determine_version(const char* version_string)
{
	int ver;

	for(ver = 0; ver < KFILE_VERSION_MAX; ver++) {
		if (!strcmp(version_string, _kfile_version_strings[ver]))
			return ver;
	}

	return -1;
}
