#include "cstd.h"

#include <sys/stat.h> // umask()

#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

	#include <stdio.h>

struct file_t {
	int		fd;
	char*		path;
	char*		name;
	char*		tmp_name;
	mode_t		mode;

	struct file_t*	next;
};

static struct file_t* last_created_file = 0;

static int _file_check_name(const char* name)
{
	const char* n = name;
	size_t s = 0;

	if (!n)
		return -1;

	while (*n) {
		s++;
		if ((*n == '/') || (s == 255))
			return -1;
		n++;
	}
	return 0;
}

static struct file_t* _file_traverse_fd(int fd, struct file_t** previous)
{
	struct file_t* res = 0;

	res = last_created_file;
	while (res) {
		if (res->fd == fd)
			break;
		if (previous)
			*previous = res;
		res = res->next;
	}

	return res;
}

int file_create(const char* name, const char* parent_dir, mode_t mode)
{
	struct file_t* file = 0;

	/* filename mustn't be longer than 254 bytes (so that the hidden
	 * temporary filename isn't longer than 255 bytes) and must not
	 * contain slashes */
	if (_file_check_name(name))
		return -1;

	file = xcalloc(1, sizeof(struct file_t));
	file->path = path_resolve_const(parent_dir ? parent_dir : ".");

	/* path doesn't exist */
	if (!file->path)
		pdie("path_resolve_const(\"%s\")", parent_dir);

	file->name = xstrdup(file->path);
	file->name = str_append(file->name, "/");
	file->name = str_append(file->name, name);

	file->tmp_name = xstrdup(file->path);
	file->tmp_name = str_append(file->tmp_name, "/.");
	file->tmp_name = str_append(file->tmp_name, name);

	file->mode = mode;

	file->fd = open(file->tmp_name, O_RDWR|O_CREAT|O_EXCL|O_SYNC, 0);
	if (file->fd < 0)
		pdie("open()");

	file->next = last_created_file;
	last_created_file = file;

	return file->fd;
}


int file_sync_and_close(int fd)
{
	int r = 0;
	struct file_t* file = 0;
	struct file_t* previous = 0;

	file = _file_traverse_fd(fd, &previous);
	if (!file) {
		/* descriptor wasn't created with file_create(), just close */
		return close(fd);
	}

	if (fsync(fd)) {
		/* log this */
		r = -1;
		goto out;
	}
	if (fchmod(fd, file->mode)) {
		/* log this */
		r = -1;
		goto out;
	}
	if (rename(file->tmp_name, file->name)) {
		/* log this */
		r = -1;
		goto out;
	}

out:
	if (r == -1) {
		unlink(file->tmp_name);
	}
	if (close(fd)) {
		/* log this */
		if (r == 0)
			unlink(file->name);
		r = -1;
	}

	/* remove file context from linked list here */

	free(file->path);
	free(file->name);
	free(file->tmp_name);
	free(file);

	return r;
}
