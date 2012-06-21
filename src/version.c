#include "cstd.h"

#include <string.h>
#include <stdio.h>

static char __cstd_extra_ver[256];
static char __cstd_git_ver[256];
static const char* const __cstd_version_string = VERSION;
static const char* const __cstd_builddate_string = __DATE__;
static const char* const __cstd_buildtime_string = __TIME__;
#ifdef NDEBUG
static const int _debug_build = 0;
#else
static const int _debug_build = 1;
#endif

const char* cstd_version_string(void)
{
	return __cstd_version_string;
}

uint32_t cstd_version(const char** extra, const char** git)
{
	uint32_t maj = 0, min = 0, plev = 0;
	const char* s = __cstd_version_string;

	const char* e = 0, *g = 0;
	while (*s) {
		if (*s == '-')
			e = s+1;
		if (*s == '+')
			g = s+1;
		s++;
	}

	if (git) {
		memset(__cstd_git_ver, 0, 256);
		if (g)
			strncpy(__cstd_git_ver, g, 255);
		*git = __cstd_git_ver;
	}
	if (extra) {
		memset(__cstd_extra_ver, 0, 256);
		if (e)
			strncpy(__cstd_extra_ver, e, 255);
		char* ms = __cstd_extra_ver;
		while (*ms) {
			if (*ms == '+') {
				*ms = 0;
				break;
			}
			ms++;
		}
		*extra = __cstd_extra_ver;
	}

	sscanf(__cstd_version_string, "%u.%u.%u", &maj, &min, &plev);
	return (maj*10000) + (min*100) + plev;
}

uint32_t cstd_version_major(void)
{
	uint32_t v = cstd_version(0, 0);
	return v/10000;
}

uint32_t cstd_version_minor(void)
{
	uint32_t v = cstd_version(0, 0);
	return (v % 10000) / 100;
}

uint32_t cstd_version_patchlevel(void)
{
	uint32_t v = cstd_version(0, 0);
	return v % 100;
}

void cstd_eprint_version(void)
{
	eprintf(LOG_DEBUG, "cstd %s, %s %s%s",
		__cstd_version_string,
		__cstd_builddate_string,
		__cstd_buildtime_string,
		_debug_build ? " (debug build)" : "");
}
