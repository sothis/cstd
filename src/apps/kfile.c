#include "cstd.h"
#include "kfile.h"
#include "xio.h"
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
	int e;

	if (!path || !strlen(path))
		return -1;

	p = xstrdup(path);

	tok = strtok(p, "/");

	while (tok) {
		e = mkdir(tok, 0755);
		if (e && (errno != EEXIST)) {
			free(p);
			return -1;
		}
		if (chdir(tok)) {
			free(p);
			return -1;
		}
		tok = strtok(0, "/");
	}
	free(p);
	return 0;
}

int mkpath(uint64_t uuid, char* filename, char* pathname)
{
	int i, j;
	char uuid_ascii[20];
	char cpath[40];
	char path[20];
	char fname[5];
	char* cwd = 0;

	if (!filename || !pathname)
		return -1;

	memset(fname, 0, 5);
	memset(path, 0, 20);
	memset(cpath, 0, 40);
	memset(uuid_ascii, 0, 20);
	snprintf(uuid_ascii, 21, "%020" PRIu64 "", uuid);

	for (j = 0, i = 0; i <= 16; i += 4, j += 5) {
		if (i < 16) {
			path[j] = uuid_ascii[i];
			path[j+1] = uuid_ascii[i+1];
			path[j+2] = uuid_ascii[i+2];
			path[j+3] = uuid_ascii[i+3];
			if (i < 12)
				path[j+4] = '/';
		} else {
			fname[0] = uuid_ascii[i];
			fname[1] = uuid_ascii[i+1];
			fname[2] = uuid_ascii[i+2];
			fname[3] = uuid_ascii[i+3];
		}

		cpath[j] = uuid_ascii[i];
		cpath[j+1] = uuid_ascii[i+1];
		cpath[j+2] = uuid_ascii[i+2];
		cpath[j+3] = uuid_ascii[i+3];
		if (i < 16)
			cpath[j+4] = '/';
	}

	cwd = get_current_dir_name();
	if (!cwd) {
		err("could not get current working directory");
		return -1;
	}

	if (mkdirp(path)) {
		err("could not create whole path '%s'", path);
		chdir(cwd), free(cwd);
		return -1;
	}

	chdir(cwd), free(cwd);
	strcpy(filename, fname);
	strcpy(pathname, path);

	return 0;
}

int _kfile_write_header(int fd)
{
	kfile_header_t header;

	memset(&header, 0, sizeof(kfile_header_t));
	strcpy(header.magic, KFILE_MAGIC);
	strcpy(header.version, KFILE_VERSION);
	header.hashfunction = HASHSUM_SKEIN_512;


	return xwrite(fd, &header, sizeof(kfile_header_t));
}

int kfile_create(uint64_t uuid, const char* pass)
{
	int fd;
	char path[20];
	char fname[5];
	kfile_t* kf;

	if (mkpath(uuid, fname, path)) {
		err("error creating path for given uuid ('%" PRIu64 "')", uuid);
		return -1;
	}

	fd = file_create_rw_with_hidden_tmp(fname, path, 0400);
	if (fd < 0)
		err("error creating file '%s' in directory '%s'", fname, path);

	_kfile_write_header(fd);

	return fd;
}

int kfile_close(int fd)
{
	return file_sync_and_close(fd);
}
