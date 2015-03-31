#ifndef _KFILE_KDF_H_
#define _KFILE_KDF_H_

#include "kfile_version.h"
#include <stdint.h>

uint64_t kfile_get_iteration_count
(kfile_version_t version, uint8_t kdf_complexity);


#endif /* _KFILE_KDF_H_ */
