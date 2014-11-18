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
	char*		hidden_name;
	mode_t		mode;

	struct file_t*	next;
};

struct file_t* last_created_file = 0;

int file_create(const char* path, const char* name, mode_t mode)
{
//	mode_t old_umask;
//	old_umask = umask(077);
	struct file_t* new_file = 0;

	new_file = xcalloc(1, sizeof(struct file_t));

	new_file->path = path_resolve_const(path);

	/* path doesn't exist */
	if (!new_file->path)
		pdie("path_resolve_const(\"%s\")", path);

	new_file->name = xstrdup(new_file->path);
	new_file->name = str_append(new_file->name, "/");
	new_file->name = str_append(new_file->name, name);

	new_file->hidden_name = xstrdup(new_file->path);
	new_file->hidden_name = str_append(new_file->hidden_name, "/.");
	new_file->hidden_name = str_append(new_file->hidden_name, name);

	new_file->mode = mode;

	new_file->fd = open(new_file->hidden_name,
		O_RDWR|O_CREAT|O_EXCL|O_SYNC, 0);
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

	if (rename(new_file->hidden_name, new_file->name))
		pdie("rename()");

	close(new_file->fd);

//out:
//	umask(old_umask);
	return 0;
}
