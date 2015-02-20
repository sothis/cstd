#include "dir.h"
#include "cstd.h"
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>

/* TODO: make both thread local */
static DIR* cwd_ds;
static int cwd_fd;

int dir_save_cwd(void)
{
	cwd_ds = opendir(".");
	if (!cwd_ds)
		return -1;

	cwd_fd = dirfd(cwd_ds);
	if (cwd_fd < 0) {
		/* ignore possible errors */
		closedir(cwd_ds);
		return -1;
	}
	return 0;
}

int dir_restore_cwd(void)
{
	if (fchdir(cwd_fd)) {
		/* ignore possible errors */
		closedir(cwd_ds);
		return -1;
	}

	if (closedir(cwd_ds))
		return -1;

	return 0;
}
