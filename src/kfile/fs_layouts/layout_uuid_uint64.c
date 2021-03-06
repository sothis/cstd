#include "kfile_fs_layout.h"
#include "cstd.h"
#include "dir.h"
#include <stdio.h>
#include <dirent.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <inttypes.h>
#include <fcntl.h>

static int mkdir_recursive(const char* path)
{
	char* p, *tok;
	int e, r = 0;

	if (!path || !strlen(path))
		return -1;

	p = xstrdup(path);

	if (dir_save_cwd()) {
		r = -1;
		goto out;
	}

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
	dir_restore_cwd();
	free(p);
	return r;
}

/*
	uuid max:  18446744073709551615		[20]
	compl max: 1844/6744/0737/0955/1615	[24]
	fpath max: 1844/6744/0737/0955		[19]
	fname max: 1615				[4]
*/
static void uuid_to_path
(uint64_t uuid, char* compl/*[25]*/, char* fpath/*[20]*/, char* fname/*[5]*/)
{
	int i, j;
	char uuid_ascii[21];
	char cpath[25];
	char path[20];
	char name[5];

	snprintf(uuid_ascii, 21, "%020" PRIu64, uuid);
	memset(cpath, 0, 25);
	memset(path, 0, 20);
	memset(name, 0, 5);

	for (j = 0, i = 0; i <= 16; i += 4, j += 5) {
		if (i < 16) {
			path[j] = uuid_ascii[i];
			path[j+1] = uuid_ascii[i+1];
			path[j+2] = uuid_ascii[i+2];
			path[j+3] = uuid_ascii[i+3];
			if (i < 12)
				path[j+4] = '/';
		} else {
			name[0] = uuid_ascii[i];
			name[1] = uuid_ascii[i+1];
			name[2] = uuid_ascii[i+2];
			name[3] = uuid_ascii[i+3];
		}

		cpath[j] = uuid_ascii[i];
		cpath[j+1] = uuid_ascii[i+1];
		cpath[j+2] = uuid_ascii[i+2];
		cpath[j+3] = uuid_ascii[i+3];
		if (i < 16)
			cpath[j+4] = '/';
	}

	if (compl)
		strcpy(compl, cpath);
	if (fpath)
		strcpy(fpath, path);
	if (fname)
		strcpy(fname, name);

	return;
}

static int uuid_create_file(uint64_t uuid, mode_t mode)
{
	int r = -1;
	char path[20];
	char filename[5];

	uuid_to_path(uuid, 0, path, filename);

	if (mkdir_recursive(path)) {
		r = -1;
		goto out;
	}

	r = file_create_rw_with_hidden_tmp(filename, path, mode);

out:
	return r;
}

static int uuid_open_file_ro(uint64_t uuid)
{
	int r = -1;
	char path[20];
	char filename[5];
	DIR* path_ds = 0;
	int path_fd = -1;

	uuid_to_path(uuid, 0, path, filename);

	path_ds = opendir(path);
	if (!path_ds) {
		r = -1;
		goto out;
	}

	path_fd = dirfd(path_ds);
	if (path_fd < 0) {
		r = -1;
		goto out;
	}

	r = openat(path_fd, filename, O_RDONLY | O_NOATIME);
	if (r >= 0) {
		file_register_fd(r, path, filename);
	}

out:
	if (path_ds)
		closedir(path_ds);
	return r;
}

static int uuid_close_file(int fd)
{
	return file_sync_and_close(fd);
}


kfile_fsl_start(UUID_UINT64, "64 bit UUID tree layout")
	.create_file	= &uuid_create_file,
	.open_file_ro	= &uuid_open_file_ro,
	.close_file	= &uuid_close_file,
kfile_fsl_end
