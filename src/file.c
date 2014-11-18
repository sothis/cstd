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

struct file_t* last_created_file = 0;

static int

int file_create(const char* name, const char* parent_dir, mode_t mode)
{
	struct file_t* new_file = 0;

	/* check here that 'name' doesn't have slashes and is not longer than
	 * 255 bytes (excluding the zero-terminating byte) */

	new_file = xcalloc(1, sizeof(struct file_t));
	new_file->path = path_resolve_const(parent_dir ? parent_dir : ".");

	/* path doesn't exist */
	if (!new_file->path)
		pdie("path_resolve_const(\"%s\")", parent_dir);

	new_file->name = xstrdup(new_file->path);
	new_file->name = str_append(new_file->name, "/");
	new_file->name = str_append(new_file->name, name);

	new_file->tmp_name = xstrdup(new_file->path);
	new_file->tmp_name = str_append(new_file->tmp_name, "/.");
	new_file->tmp_name = str_append(new_file->tmp_name, name);

	new_file->mode = mode;

	new_file->fd = open(new_file->tmp_name, O_RDWR|O_CREAT|O_EXCL|O_SYNC, 0);
	if (new_file->fd < 0)
		pdie("open()");

	new_file->next = last_created_file;
	last_created_file = new_file;

	if (write(new_file->fd, "hello", 5) != 5)
		pdie("write()");

	if (fsync(new_file->fd))
		pdie("fsync()");

	if (fchmod(new_file->fd, new_file->mode))
		pdie("fchmod()");

	if (rename(new_file->tmp_name, new_file->name))
		pdie("rename()");

	close(new_file->fd);

//out:
//	umask(old_umask);
	return 0;
}
