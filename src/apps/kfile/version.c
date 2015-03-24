#include "kfile_version.h"
#include <string.h>

static const char* _kfile_version_strings[] = {
	"0.1",
	"1.0"
};

int kfile_determine_version(const char* version_string)
{
	int ver;

	for(ver = 0; ver < KFILE_VERSION_MAX; ver++) {
		if (!strcmp(version_string, _kfile_version_strings[ver]))
			return ver;
	}

	return -1;
}
