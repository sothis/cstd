#ifndef _XIO_H_
#define _XIO_H_

#include <unistd.h>

/* writes nbyte bytes from buf onto fd. returns 0 if all
 * bytes were written or -1 in case of an error with errno set
 * appropriately */
extern int xwrite(int fd, const void* buf, size_t nbyte);


#endif /* _XIO_H_ */
