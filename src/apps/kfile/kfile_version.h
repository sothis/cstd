#ifndef _KFILE_VERSION_H_
#define _KFILE_VERSION_H_

#define KFILE_MAGIC		("KFILE")
#define KFILE_VERSION_LENGTH	(4)

typedef enum kfile_version_t {
	KFILE_VERSION_0_1	= 0,
	KFILE_VERSION_1_0	= 1,
	KFILE_VERSION_MAX
} kfile_version_t;

int kfile_determine_version(const char* version_string);


#endif /* _KFILE_VERSION_H_ */
