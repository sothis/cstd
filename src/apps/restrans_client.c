#include "restrans_client.h"

#include <inttypes.h>
#include <stdio.h>
#include <sdtl.h>

void* restrans_new_add_param(uint64_t uuid, const char* resname)
{
	restrans_add_param_t* param;
	size_t nlen;
	char* namecpy;

	if (!resname)
		return 0;

	nlen = strlen(resname);
	if (nlen > 255)
		return 0;

	namecpy = calloc(256, sizeof(char));
	if (!namecpy)
		return 0;
	strcpy(namecpy, resname);

	param = calloc(1, sizeof(restrans_add_param_t));
	if (!param) {
		free(namecpy);
		return 0;
	}

	/* ["%020" PRIu64] for leading zeros */
	if (snprintf(param->uuid, 21, "%" PRIu64, uuid) < 0) {
		free(namecpy);
		return 0;
	}
	param->rname = namecpy;
	param->streamname = "resource-stream";
	return param;
}

void restrans_free_add_param(restrans_add_param_t* param)
{
	if (param) {
		if (param->rname)
			free(param->rname);
		free(param);
	}
}


restrans_request_t* restrans_req_new
(restrans_request_opts_t* opts, void* req_param)
{
	restrans_request_t* req;

	if (opts->protversion >= RESTRANS_PROT_MAX)
		return 0;

	if (opts->operation >= RESTRANS_OPERATION_MAX)
		return 0;

	if (!req_param)
		return 0;

	req = calloc(1, sizeof(restrans_request_t));
	if (!req)
		return req;

	req->application = "resource-transfer";
	req->protversion = restrans_prot_versions[opts->protversion];
	req->operation = opts->operation;
	req->opstr = restrans_operations[opts->operation];
	req->param = req_param;
	return req;
}

void restrans_req_free(restrans_request_t* req)
{
	if (req) {
		switch (req->operation) {
			case RESTRANS_OPERATION_ADD:
				restrans_free_add_param(req->param);
				break;
			case RESTRANS_OPERATION_DEL:
				break;
			case RESTRANS_OPERATION_GET:
				break;
			case RESTRANS_OPERATION_MAX:
			default:
				break;
		}
		free(req);
	}
}

int restrans_op_add_resource(uint64_t uuid, const char* resname)
{
	restrans_request_opts_t ropts;
	restrans_request_t* req;
	restrans_add_param_t* param;

	ropts.protversion = RESTRANS_PROT_1_0;
	ropts.operation = RESTRANS_OPERATION_ADD;

	param = restrans_new_add_param(uuid, resname);
	if (!param)
		return -1;

	req = restrans_req_new(&ropts, param);
	if (!req) {
		restrans_free_add_param(param);
		return -1;
	}
#if 0
	sdtl_write_enum(&sdtl_wfd, "application", req->application);
	sdtl_write_utf8string(&sdtl_wfd, "protocol-version", req->protversion);
	  sdtl_write_start_struct(&sdtl_wfd, "request");
	    sdtl_write_enum(&sdtl_wfd, "op", req->opstr);
	    sdtl_write_start_struct(&sdtl_wfd, "parameter");
	    sdtl_write_number(&sdtl_wfd, "uuid", param->uuid);
	    sdtl_write_utf8string(&sdtl_wfd, "resource-name", param->rname);
	    sdtl_write_enum(&sdtl_wfd, "stream-name", param->streamname);
	  sdtl_write_end_struct(&sdtl_wfd);
	sdtl_write_end_struct(&sdtl_wfd);
#endif
	return 0;
}
