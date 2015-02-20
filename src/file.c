#include "cstd.h"

#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdio.h>

#include "mutex.h"


struct file_t {
	int		fd;
	char*		path;
	char*		name;
	char*		tmp_name;
	mode_t		mode;
	void*		userdata;

	struct file_t*	next;
	struct file_t*	prev;
};

struct filelist_t {
	size_t		nopen_files;
	struct file_t*	first;
	struct file_t*	last;
};

static struct filelist_t files = {
	.nopen_files	= 0,
	.first		= 0,
	.last		= 0
};

static void _file_add_to_list(struct file_t* file)
{
	if (!files.last) {
		files.first = files.last = file;
	} else {
		files.last->next = file;
		file->prev = files.last;
		files.last = file;
	}
	files.nopen_files++;
}

static void _file_remove_from_list(struct file_t* file)
{
	if(file == files.first && file == files.last) {
		files.first = 0;
		files.last = 0;
	} else if(file == files.first) {
		files.first = file->next;
		files.first->prev = 0;
	} else if (file == files.last) {
		files.last = file->prev;
		files.last->next = 0;
	} else {
		file->next->prev = file->prev;
		file->prev->next = file->next;
	}
	files.nopen_files--;
}

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

static struct file_t* _file_get_by_fd(int fd)
{
	struct file_t* res = files.first;

	while (res) {
		if (res->fd == fd)
			break;
		res = res->next;
	}
	return res;
}

void file_register_fd(int fd, char* path, char* name)
{
	struct file_t* file = 0;

	file = xcalloc(1, sizeof(struct file_t));

	file->name = xstrdup(name);
	file->path = path_resolve_const(path);
	file->fd = fd;
	_file_add_to_list(file);
}

int file_set_userdata(int fd, void* userdata)
{
	struct file_t* file = 0;

	file = _file_get_by_fd(fd);
	if (!file) {
		/* fd was not created by our API */
		err("specified filedescriptor unknown");
		return -1;
	}
	file->userdata = userdata;
	return 0;
}

void* file_get_userdata(int fd)
{
	struct file_t* file = 0;

	file = _file_get_by_fd(fd);
	if (!file) {
		/* fd was not created by our API */
		err("specified filedescriptor unknown");
		return 0;
	}
	return file->userdata;
}

int file_create_rw_with_hidden_tmp
(const char* name, const char* parent_dir, mode_t mode)
{
	int r = -1;
	struct file_t* file = 0;

	/* the filename mustn't contain slashes and mustn't be longer than
	 * 254 bytes (excluding the terminating zero byte) so that the filename
	 * of the hidden temporary file isn't longer than 255 bytes,
	 * which fits on most modern filesystems */
	if (_file_check_name(name))
		goto err;

	file = xcalloc(1, sizeof(struct file_t));
	file->path = path_resolve_const(parent_dir ? parent_dir : ".");

	/* path doesn't exist */
	if (!file->path)
		goto err;

	file->name = xstrdup(file->path);
	file->name = str_append(file->name, "/");
	file->name = str_append(file->name, name);

	file->tmp_name = xstrdup(file->path);
	file->tmp_name = str_append(file->tmp_name, "/.");
	file->tmp_name = str_append(file->tmp_name, name);

	file->mode = mode;

	file->fd = open(file->tmp_name, O_RDWR|O_CREAT|O_EXCL|O_SYNC, 0);
	if (file->fd < 0)
		goto err;

	_file_add_to_list(file);
	r = file->fd;
	goto out;
err:
	if (file) {
		if (file->path)
			free(file->path);
		if (file->name)
			free(file->name);
		if (file->tmp_name)
			free(file->tmp_name);
		free(file);
	}
out:
	return r;
}

int file_sync_and_close(int fd)
{
	int r = 0;
	struct file_t* file = 0;

	file = _file_get_by_fd(fd);
	if (!file) {
		/* fd was not created by our API */
		err("specified filedescriptor unknown");
		return -1;
	}

	if (file->tmp_name) {
		if (fsync(fd)) {
			err("error fsync'ing file descriptor %u", fd);
			r = -1;
			goto out;
		}
		if (fchmod(fd, file->mode)) {
			err("error changing file mode of descriptor %u", fd);
			r = -1;
			goto out;
		}
		if (rename(file->tmp_name, file->name)) {
			err("error renaming temporary file");
			r = -1;
			goto out;
		}
	}

out:
	if (r == -1) {
		unlink(file->tmp_name);
	}
	if (close(fd)) {
		/* log this */
		if ((r == 0) && file->tmp_name)
			unlink(file->name);
		r = -1;
	}

	_file_remove_from_list(file);

	free(file->path);
	free(file->name);
	if (file->tmp_name)
		free(file->tmp_name);
	free(file);

	return r;
}

void file_sync_and_close_all(void)
{
	struct file_t* cur = files.first;
	struct file_t* next = 0;

	while (cur) {
		/* ignoring errors in file_sync_and_close() for now */
		next = cur->next;
		file_sync_and_close(cur->fd);
		cur = next;
	}
}
