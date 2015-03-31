#include "cstd.h"
#include "kfile.h"
#include "xio.h"
#include "dir.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sys/stat.h>


int mkdirp(const char* path)
{
	char* p, *tok;
	int e, r = 0;

	if (!path || !strlen(path))
		return -1;

	p = xstrdup(path);

	if (dir_save_cwd())
		pdie("dir_save_cwd()");

	tok = strtok(p, "/");
	while (tok) {
		e = mkdir(tok, 0755);
		if (e && (errno != EEXIST)) {
			r = -1;
			goto out;
		}
		if (chdir(tok)) {
			r = -1;
			goto out;
		}
		tok = strtok(0, "/");
	}
	r = 0;
out:
	if (dir_restore_cwd())
		pdie("dir_restore_cwd()");
	free(p);
	return r;
}

const char* kfile_get_resource_name(kfile_read_fd_t fd)
{
	kfile_t* kf;

	if (fd < 0)
		return 0;

	kf = file_get_userdata(fd);
	if (!kf)
		return 0;

	if (!strlen(kf->resourcename))
		return 0;

	return kf->resourcename;
}


