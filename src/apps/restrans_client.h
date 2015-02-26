#ifndef _RESTRANS_CLIENT_H_
#define _RESTRANS_CLIENT_H_

#include <stdint.h>

typedef struct restrans_add_param_t
{
	char		uuid[21];
	char*		rname;
	const char*	streamname;
} restrans_add_param_t;

typedef struct restrans_get_param_t
{
	uint64_t	uuid;
} restrans_get_param_t;

typedef struct restrans_del_param_t
{
	uint64_t	uuid;
} restrans_del_param_t;

typedef enum restrans_operation_t
{
	RESTRANS_OPERATION_ADD = 0,
	RESTRANS_OPERATION_DEL,
	RESTRANS_OPERATION_GET,
	RESTRANS_OPERATION_MAX
} restrans_operation_t;

typedef enum restrans_protver_t
{
	RESTRANS_PROT_0_1 = 0,
	RESTRANS_PROT_1_0,
	RESTRANS_PROT_MAX
} restrans_protver_t;

const char* const restrans_prot_versions[] = {
	"0.1",
	"1.0"
};

const char* const restrans_operations[] = {
	"add-resource",
	"delete-resource",
	"get-resource"
};

typedef struct restrans_request_opts_t
{
	restrans_protver_t	protversion;
	restrans_operation_t	operation;
} restrans_request_opts_t;

typedef struct restrans_request_t
{
	const char*		application;
	const char*		protversion;
	const char*		opstr;
	restrans_operation_t	operation;
	void*			param;
} restrans_request_t;


#endif /* _RESTRANS_CLIENT_H_ */
