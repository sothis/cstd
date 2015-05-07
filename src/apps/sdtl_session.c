#include "sdtl_session.h"

sdtl_session_t* sdtl_session_create(sdtl_session_opts_t* opts)
{
	sdtl_session_t* sess;
	sdtl_read_flags_t sdtlflags;

	if (!opts)
		return 0;

	if (!opts->on_event)
		return 0;

	memset(&sdtlflags, 0, sizeof(sdtl_read_flags_t));
	sdtlflags.userdata = opts->userdata;
	sdtlflags.on_event = opts->on_event;

	sess = calloc(1, sizeof(sdtl_session_t));
	if (!sess)
		return sess;

	sdtl_open_write(&sess->writefd, opts->socket,
		opts->use_write_debug_fd ? &opts->write_debug_fd : 0);

	sdtl_open_read(&sess->readfd, opts->socket,
		opts->use_read_debug_fd ? &opts->read_debug_fd : 0,
		&sdtlflags);

	return sess;
}

void sdtl_session_destroy(sdtl_session_t* sess)
{
	if (!sess)
		return;

	/* sdtl_open_write() && sdtl_open_read() doesn't allocate any
	 * memory on the heap */
	free(sess);
}
