#include "cstd.h"

#include <ftw.h>
#include <stdio.h>

static int _nftw_remove
(const char* fpath, const struct stat* sb, int typeflag, struct FTW* ftwbuf)
{
	int r;
	/* If the name passed to remove() is a symbolic link, the link
	 * is removed. */

	r = remove(fpath);
	if (r) {
		/* Log error here if desired, because if something wents wrong
		 * and nftw returns r, the name of the offending fpath is
		 * lost at this point. */
	}
	return r;
}

int fs_delete_deep(const char* directory)
{
	const char* p = directory;
	int flags = 0;
	int max_open_descriptors = 0;

/*
 * FTW_DEPTH	pass content of a directory to the callback before the directory
 * 		itself, useful for recursively deleting a directory, since
 * 		directories must be emtpy before we can remove them
 * FTW_MOUNT	stay within the same filesystem
 * FTW_CHDIR	chdir(dirname(fpath)) before calling the callback
 * FTW_PHYS	don't follow symbolic links */
	flags |= FTW_DEPTH;
	flags |= FTW_PHYS;
	flags |= FTW_MOUNT;

/* glibc nftw(): if max_open_descriptors is less than 1, it is set
 * internally to 1 without further notice. Lower values may slow down code,
 * higher ones may hit max open filedescriptor limit, resulting in nftw()
 * to fail. */
	max_open_descriptors = 1;

/* NOTE: glibc nftw() recurses internally and is therefore bound to
 * available stack memory. Returns -1 on error, 0 on success or any
 * non-zero value returned by the callback in case of the callback
 * failing. */
	return nftw(p, &_nftw_remove, max_open_descriptors, flags);
}
