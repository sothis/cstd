#include "cstd.h"

//#include <stdio.h>
//#include <stdint.h>
//#include <stdlib.h>
#include <string.h>
//#include <unistd.h>
//#include <fcntl.h>
//#include <errno.h>
//#include <inttypes.h>
//#include <ctype.h>

typedef enum entity_type {
	entity_is_string = 0,
	entity_is_numeric,
	entity_is_struct,
	dimension_entity
} entity_type_t;

typedef struct entity {
	entity_type_t		type;
	size_t			size;
	char*			name;
	void*			data;
	struct entity*	next;
} entity_t;


//static int was_first=0;

/* actions */
static int action_ignore_whitespace(sdtl_parser_t* p, int byte)
{
	/* just keep current state, do nothing */
	return 0;
}

static int action_in_identifier(sdtl_parser_t* p, int byte)
{
//	if (!was_first) {
//		printf("id: %c", byte);
//		was_first = 1;
//	} else
//		printf("%c", byte);
	p->state_lvl0 = lvl0_assignment_start;
	return 0;
}

static int action_start_assignment(sdtl_parser_t* p, int byte)
{
	p->state_lvl0 = lvl0_assignment_start;
	return 0;
}

static int action_do_assignment(sdtl_parser_t* p, int byte)
{
//	was_first = 0;
//	printf("\n");
	p->state_lvl0 = lvl0_assignment_op;
	return 0;
}

static int action_end_assignment(sdtl_parser_t* p, int byte)
{
//	was_first = 0;
//	printf("\n");
	p->state_lvl0 = lvl0_assignment_end;
	return 0;
}

static int action_introduce_binary_stream(sdtl_parser_t* p, int byte)
{
	p->state_lvl0 = lvl0_introduce_binary_stream;
	return 0;
}

static int action_introduce_struct(sdtl_parser_t* p, int byte)
{
	p->state_lvl0 = lvl0_introduce_struct;
	p->struct_nesting_level++;
	return 0;
}

static int action_terminate_struct(sdtl_parser_t* p, int byte)
{
	p->state_lvl0 = lvl0_terminate_struct;
	p->struct_nesting_level--;
	if (p->struct_nesting_level < 0)
		return -1;
	return 0;
}

static int action_introduce_string(sdtl_parser_t* p, int byte)
{
	p->state_lvl0 = lvl0_introduce_string;
	return 0;
}

static int action_in_string(sdtl_parser_t* p, int byte)
{
//	if (!was_first) {
//		printf("str: %c", byte);
//		was_first = 1;
//	} else
//		printf("%c", byte);
	p->state_lvl0 = lvl0_in_string;
	return 0;
}

static int action_escape_character(sdtl_parser_t* p, int byte)
{
	p->state_lvl0 = lvl0_escape_character;
	return 0;
}

static int action_terminate_string(sdtl_parser_t* p, int byte)
{
	p->state_lvl0 = lvl0_terminate_string;
	return 0;
}

static int action_in_number(sdtl_parser_t* p, int byte)
{
//	if (!was_first) {
//		printf("num: %c", byte);
//		was_first = 1;
//	} else
//		printf("%c", byte);
	p->state_lvl0 = lvl0_in_number;
	return 0;
}


/* state machine */
static int32_t sdtl_parse(sdtl_parser_t* p, int byte)
{
	action_t action = 0;

	switch (p->state_lvl0) {
		case lvl0_undefined:
			action = p->actions_after_undefined[byte];
			break;
		case lvl0_assignment_start:
			action = p->actions_after_assignment_start[byte];
			break;
		case lvl0_assignment_op:
			action = p->actions_after_assignment_op[byte];
			break;
		case lvl0_assignment_end:
			action = p->actions_after_assignment_end[byte];
			break;
		case lvl0_in_number:
			action = p->actions_after_in_number[byte];
			break;
		case lvl0_introduce_string:
			action = p->actions_after_introduce_string[byte];
			break;
		case lvl0_in_string:
			action = p->actions_after_in_string[byte];
			break;
		case lvl0_terminate_string:
			action = p->actions_after_terminate_string[byte];
			break;
		case lvl0_introduce_struct:
			action = p->actions_after_introduce_struct[byte];
			break;
		case lvl0_terminate_struct:
			action = p->actions_after_terminate_struct[byte];
			break;
		default:
			return -1;
	}

	if (!action) {
//		printf("unexpected byte: 0x%.2x ('%c')\n",
//			(uint8_t)byte, (uint8_t)byte);
		return -1;
	}
	if (action(p, byte))
		return -1;
	return 0;
}

/* feed statemachine, handle binary streams */
int32_t
sdtl_add_input_data(sdtl_parser_t* p, unsigned char* data, int32_t len)
{
	uint32_t idx = 0;

	if (len < 0)
		return -1;
	if (!len)
		return 0;

	for (idx = 0; idx < len; ++idx) {
		if (sdtl_parse(p, data[idx])) {
			return -1;
		}
		if (p->state_lvl0 == lvl0_introduce_binary_stream) {
			/* handover to special binary stream parser,
			 * the next required 2 bytes to follow form the
			 * chunksize of the first chunk, if this is 0 then
			 * a ';' must follow*/
		}
	}

	return 0;
}

static void _sdtl_ignore_whitespace(action_t* action_list)
{
	action_list[0x09] = &action_ignore_whitespace;
	action_list[0x0a] = &action_ignore_whitespace;
	action_list[0x0b] = &action_ignore_whitespace;
	action_list[0x0c] = &action_ignore_whitespace;
	action_list[0x0d] = &action_ignore_whitespace;
	action_list[0x20] = &action_ignore_whitespace;
}

int32_t sdtl_init(sdtl_parser_t* p)
{
	int i;
	memset(p, 0, sizeof(sdtl_parser_t));
	p->state_lvl0 = lvl0_undefined;

/* We come from 'lvl0_undefined': this will be executed on stream
 * start and after an lvl0 assignment has been terminated with ';'. */
	_sdtl_ignore_whitespace(p->actions_after_undefined);
	p->actions_after_undefined['.'] = &action_start_assignment;

/* We come from 'lvl0_assignment_start': this will be executed after
 * we found the '.' which introduces a new assignment. This in fact will
 * read all bytes until '=', which will form the identifier name. */
	for (i = 0; i < 256; ++i)
		p->actions_after_assignment_start[i] = &action_in_identifier;
	_sdtl_ignore_whitespace(p->actions_after_assignment_start);
	p->actions_after_assignment_start[0x00] = 0;
	p->actions_after_assignment_start['.'] = 0;
	p->actions_after_assignment_start['='] = &action_do_assignment;


/* We come from 'lvl0_assignment_op' or from a value-parser:
 * this will be either directly after a '=' or if a value parser
 * did finish it's work. It will put the state machine to
 * 'lvl0_undefined' again, and as such allows further assignments
 * to follow. */
	_sdtl_ignore_whitespace(p->actions_after_assignment_op);
	p->actions_after_assignment_op[';'] = &action_end_assignment;
	p->actions_after_assignment_op['\0'] = &action_introduce_binary_stream;
	p->actions_after_assignment_op['"'] = &action_introduce_string;
	p->actions_after_assignment_op['{'] = &action_introduce_struct;
	/* in order to support several num formats, add start byte here */
	p->actions_after_assignment_op['-'] = &action_in_number;
	p->actions_after_assignment_op['$'] = &action_in_number;
	p->actions_after_assignment_op['0'] = &action_in_number;
	p->actions_after_assignment_op['1'] = &action_in_number;
	p->actions_after_assignment_op['2'] = &action_in_number;
	p->actions_after_assignment_op['3'] = &action_in_number;
	p->actions_after_assignment_op['4'] = &action_in_number;
	p->actions_after_assignment_op['5'] = &action_in_number;
	p->actions_after_assignment_op['6'] = &action_in_number;
	p->actions_after_assignment_op['7'] = &action_in_number;
	p->actions_after_assignment_op['8'] = &action_in_number;
	p->actions_after_assignment_op['9'] = &action_in_number;

	_sdtl_ignore_whitespace(p->actions_after_assignment_end);
	p->actions_after_assignment_end['}'] = &action_terminate_struct;
	p->actions_after_assignment_end['.'] = &action_start_assignment;

/* We come from 'lvl0_introduce_string': start string processing */
	for (i = 0; i < 256; ++i)
		p->actions_after_introduce_string[i] = &action_in_string;
	p->actions_after_introduce_string[0x00] = 0;
	p->actions_after_introduce_string['"'] = &action_terminate_string;
	p->actions_after_introduce_string['\\'] = &action_escape_character;

/* We come from 'lvl0_in_string': proceed string processing */
	for (i = 0; i < 256; ++i)
		p->actions_after_in_string[i] = &action_in_string;
	p->actions_after_in_string[0x00] = 0;
	p->actions_after_in_string['"'] = &action_terminate_string;
	p->actions_after_in_string['\\'] = &action_escape_character;


/* We come from 'lvl0_terminate_string': allow string concatenation */
	_sdtl_ignore_whitespace(p->actions_after_terminate_string);
	p->actions_after_terminate_string['"'] = &action_introduce_string;
	p->actions_after_terminate_string[';'] = &action_end_assignment;

/* We come from 'lvl0_escape_character': only allow '\' and
 * '"' to follow a '\' */
	p->actions_after_escape_character['\\'] = &action_in_string;
	p->actions_after_escape_character['"'] = &action_in_string;


/* We come from 'lvl0_in_number': accept anything except ';' and '\0', ignore
 * whitespace */
	for (i = 0; i < 256; ++i)
		p->actions_after_in_number[i] = &action_in_number;
	_sdtl_ignore_whitespace(p->actions_after_in_number);
	p->actions_after_in_number[';'] = &action_end_assignment;
	p->actions_after_in_number['\0'] = 0;


	_sdtl_ignore_whitespace(p->actions_after_introduce_struct);
	p->actions_after_introduce_struct['}'] = &action_terminate_struct;
	p->actions_after_introduce_struct['.'] = &action_start_assignment;

	_sdtl_ignore_whitespace(p->actions_after_terminate_struct);
	p->actions_after_terminate_struct[';'] = &action_end_assignment;

	return 0;
}
