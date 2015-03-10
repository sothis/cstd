#ifndef _SDTL_SESSION_H_
#define _SDTL_SESSION_H_

#include <stdint.h>
#include <sdtl.h>
#include "restrans_client.h"

typedef enum sdtl_session_role_t {
	SDTL_ROLE_SERVER = 0,
	SDTL_ROLE_CLIENT
} sdtl_session_role_t;

typedef struct sdtl_session_t {
	sdtl_session_role_t	role;
	int			socket;
	sdtl_read_fd_t		readfd;
	sdtl_write_fd_t		writefd;
} sdtl_session_t;

typedef struct sdtl_session_opts_t {
	sdtl_session_role_t 	role;
	int			socket;
	int			use_read_debug_fd;
	int			use_write_debug_fd;
	int			read_debug_fd;
	int			write_debug_fd;
	int (*on_event)(void* userdata, sdtl_event_t e, sdtl_data_t* data);
	void*			userdata;
	const char*		applications[];
} sdtl_session_opts_t;

sdtl_session_t* sdtl_session_create(sdtl_session_opts_t* opts);
void sdtl_session_destroy(sdtl_session_t* sess);

#endif /* _SDTL_SESSION_H_ */
