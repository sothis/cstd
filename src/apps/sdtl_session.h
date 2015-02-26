#ifndef _SDTL_SESSION_H_
#define _SDTL_SESSION_H_

#include <stdint.h>
#include <sdtl.h>

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



#endif /* _SDTL_SESSION_H_ */
