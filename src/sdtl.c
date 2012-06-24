#include "cstd.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void indent(int level)
{
	while (level) {
		printf("\t");
		level--;
	}
}

/* Find member of a structure by it's name (without dots). It doesn't
 * recurse into other structures that may be member of the given parent
 * structure. */
static entity_t*
sdtl_get_entity_flat(entity_t* parent_struct, const char* name)
{
	entity_t* e = parent_struct;

	if (!name || !*name || (*name == '.'))
		return 0;

	while (e) {
		if (!strcmp(e->name, name))
			break;
		e = e->next_entity;
	}
	return e;
}

entity_t* sdtl_get_entity_abs(sdtl_parser_t* p, const char* path)
{
	char* abspath, *component, *temp;
	entity_t* curr_entity = p->root_entity->child_entity;
	entity_t* e = 0;
	entity_t* r = 0;

	/* only allow absolute paths (starting with dot) at the moment */
	if (!path || !*path || (*path != '.'))
		return 0;

	/* special root member case */
	if (!strcmp(path, ".")) {
		return p->root_entity;
	}

	/* path mustn't end with '.', exception is a single dot for the root
	 * structure */
	if (*(strrchr(path, 0)-1) == '.')
		return 0;

	abspath = xstrdup(path);
	temp = abspath;
	while ((component = strtok(temp, "."))) {
		temp = 0;

		if (r) {
			if (r->type == entity_is_struct) {
				/* dive into structure */
				curr_entity = r->child_entity;
			} else {
				/* The last entity was not a structure, but
				 * we have still components in the path.
				 * This is exactly ENOTDIR in the context
				 * of POSIX paths. */
				r = 0;
				break;
			}
		}
		e = sdtl_get_entity_flat(curr_entity, component);
		if (!e) {
			/* no such structure member in curr_entity */
			r = 0;
			break;
		} else {
			r = e;
			continue;
		}

	}

	free(abspath);
	return r;
}

static void
print_escaped_string(size_t level, const char* name, const char* str, int w)
{
	size_t i;
	size_t l = strlen(str);
	if (w) {
		indent(level);
		printf(".%s = \"", name);
	} else
		printf(".%s=\"", name);

	for (i = 0; i < l; ++i) {
		if (str[i] == '"' || str[i] == '\\') {
			printf("%c", '\\');
		}
		printf("%c", str[i]);
	}

	if (w)
		printf("\";\n");
	else
		printf("\";");
}

static void print_entities_recursive(size_t level, entity_t* first, int w)
{
	entity_t* e = first;
	int whitespace = w;

	while (e) {
		if (e->type == entity_is_struct) {
			/* NOTE: may cause stackoverflow if nesting level
			 * is too high, use an own stack in order to
			 * be able to apply a configurable limit */
			if (whitespace)
				indent(level);
			if (!e->child_entity) {
				/* struct is empty */
				if (whitespace)
					printf(".%s = {};\n", e->name);
				else
					printf(".%s={};", e->name);
			} else {
				if (whitespace)
					printf(".%s = {\n", e->name);
				else
					printf(".%s={", e->name);
				print_entities_recursive(level+1,
					e->child_entity, whitespace);
				if (!e->struct_is_open) {
					if (whitespace) {
						indent(level);
						printf("};\n");
					} else
						printf("};");
				}
			}
		}
		else if (e->type == entity_is_null) {
			if (whitespace) {
				indent(level);
				printf(".%s = ;\n", e->name);
			} else
				printf(".%s=;", e->name);
		} else if (e->type == entity_is_string) {
			print_escaped_string(level, e->name, e->data,
				whitespace);
		} else if (e->type == entity_is_numeric) {
			if (whitespace) {
				indent(level);
				printf(".%s = %s;\n", e->name, e->data);
			} else
				printf(".%s=%s;", e->name, e->data);
		}
		e = e->next_entity;
	}
}

void print_entities(sdtl_parser_t* p, int use_whitespace)
{
	if (p->root_entity)
		print_entities_recursive(0, p->root_entity->child_entity,
			use_whitespace);
}

static void free_entities(entity_t* first)
{
	entity_t* n, *c;
	entity_t* e = first;
	int is_struct;

	while (e) {
		is_struct = (e->type == entity_is_struct);
		n = e->next_entity;
		c = e->child_entity;
		free(e->name);
		if (e->data)
			free(e->data);
		free(e);

		if (is_struct) {
			free_entities(c);
		}
		e = n;
	}
}

void sdtl_free(sdtl_parser_t* p)
{
	free_entities(p->root_entity);
	if (p->current_multibyte_token) {
		free(p->current_multibyte_token);
		p->current_multibyte_token = 0;
	}
	p->root_entity = p->curr_entity = 0;
}

/* simple fixed sized stack */
static int push_struct_entity(sdtl_parser_t* p, entity_t* first)
{
	/* full */
	if (p->stack_head == sizeof(p->nesting_stack)/sizeof(void*))
		return -1;
	p->nesting_stack[p->stack_head] = first;
	p->stack_head++;
	return 0;
}

static entity_t* pop_struct_entity(sdtl_parser_t* p)
{
	/* empty */
	if (!p->stack_head)
		return 0;
	p->stack_head--;
	return p->nesting_stack[p->stack_head];
}


/* second-level actions */
/* The first parser step ensures that we get these entities in the correct
 * order */
int action_on_stream_start(sdtl_parser_t* p, entity_t* first)
{
	p->root_entity = calloc(1, sizeof(entity_t));
	if (!p->root_entity)
		return -1;
	p->root_entity->type = entity_is_struct;
	p->root_entity->name = malloc(1);
	if (!p->root_entity->name) {
		free(p->root_entity);
		p->root_entity = 0;
		return -1;
	}
	*p->root_entity->name = 0;
	p->root_entity->struct_is_open = 1;
	p->curr_entity = p->root_entity;
	return 0;
}

int action_on_identifier(sdtl_parser_t* p, char* id)
{
	int r = 0;
	entity_t* last_entity;
	entity_t* new_entity;

	new_entity = calloc(1, sizeof(entity_t));
	if (!new_entity) {
		return -1;
	}
	new_entity->name = id;

	if (!p->stream_started) {
		p->stream_started = 1;
		r = action_on_stream_start(p, new_entity);
		if (r) {
			free(new_entity);
			return -1;
		}
	}

	if (!p->struct_nesting_level)
		p->root_entity->struct_is_open = 1;

	last_entity = p->curr_entity;
	new_entity->prev_entity = last_entity;

	if (last_entity->struct_is_open && !last_entity->child_entity) {
		last_entity->child_entity = new_entity;
	} else {
		last_entity->next_entity = new_entity;
	}

	p->curr_entity = new_entity;
	return 0;
}

void action_on_null_value(sdtl_parser_t* p)
{
	p->curr_entity->type = entity_is_null;
	p->curr_entity->data = 0;
}

int action_on_string(sdtl_parser_t* p, char* str)
{
	p->curr_entity->type = entity_is_string;
	p->curr_entity->data = str;
	return 0;
}

int action_on_numeric(sdtl_parser_t* p, char* num)
{
	p->curr_entity->type = entity_is_numeric;
	p->curr_entity->data = num;
	return 0;
}

int action_on_struct_value_start(sdtl_parser_t* p)
{
	p->curr_entity->type = entity_is_struct;
	p->curr_entity->data = 0;
	p->curr_entity->struct_is_open = 1;
	return push_struct_entity(p, p->curr_entity);
}

int action_on_struct_value_end(sdtl_parser_t* p)
{
	p->curr_entity = pop_struct_entity(p);
	if (!p->curr_entity)
		return -1;
	p->curr_entity->struct_is_open = 0;
	/* if struct is empty, convert entity type to entity_is_null */
	if (!p->curr_entity->child_entity)
		p->curr_entity->type = entity_is_null;
	return 0;
}

int action_on_value_end(sdtl_parser_t* p)
{
	if (!p->struct_nesting_level)
		p->root_entity->struct_is_open = 0;

	/* possible point for a callback in order to pass a single
	 * entity (p->curr_entity) to the application code. This
	 * callback will get called in the order how the entities
	 * appear, which allows incorporating application defined
	 * logic on special named entities. Note that passing
	 * an entity which is of type 'structure', doesn't make
	 * always sense here and should be configurable. */

	/* NOTE: do not modify p->curr_entity, return entity
	 * name as const char*, the data for strings and nums can be
	 * returned as char*: allow to free name and data in the callback,
	 * the entity itself must remain untouched in order to preserve
	 * inter-entity links */
	return 0;
}



/* first-level actions */
static int action_ignore_whitespace(sdtl_parser_t* p, int byte)
{
	/* just keep current state, do nothing */
	return 0;
}

static int action_in_identifier(sdtl_parser_t* p, int byte)
{
	char c[2] = { byte, 0x00 };

	if (!p->first_byte_of_multibyte_token) {
		p->first_byte_of_multibyte_token = 1;
		p->current_type = entity_is_identifier;
	}

	/* NOTE: this is slow; a buffer should be used here, lowering the
	 * amount of realloc's */
	p->current_multibyte_token = str_append(p->current_multibyte_token, c);

	p->has_empty_identifier = 0;
	p->state_lvl0 = lvl0_assignment_start;
	return 0;
}

static int action_start_assignment(sdtl_parser_t* p, int byte)
{
	p->has_empty_identifier = 1;
	p->state_lvl0 = lvl0_assignment_start;
	return 0;
}

static int end_multibyte_action(sdtl_parser_t* p)
{
	int r = 0;
	switch (p->current_type) {
		case entity_is_identifier:
			r = action_on_identifier(p, p->current_multibyte_token);
			break;
		case entity_is_string:
			r = action_on_string(p, p->current_multibyte_token);
			break;
		case entity_is_numeric:
			r = action_on_numeric(p, p->current_multibyte_token);
			break;
		default:
			break;
	}
	p->current_type = entity_is_unknown;
	p->first_byte_of_multibyte_token = 0;
	/* we pass this pointer to the event handlers, which has
	 * to take care of freeing this memory */
	p->current_multibyte_token = 0;
	return r;
}

static int action_do_assignment(sdtl_parser_t* p, int byte)
{
	if (p->has_empty_identifier)
		return -1;

	p->has_empty_identifier = 0;
	p->has_empty_value = 1;
	p->state_lvl0 = lvl0_assignment_op;
	return end_multibyte_action(p);
}

static int action_end_assignment(sdtl_parser_t* p, int byte)
{
	int r;
	if (p->has_empty_value) {
		action_on_null_value(p);
		p->has_empty_value = 0;
	}

	p->state_lvl0 = lvl0_assignment_end;
	r = end_multibyte_action(p);
	if (r)
		return r;
	return action_on_value_end(p);
}

static int action_start_symbolic_link(sdtl_parser_t* p, int byte)
{
#if 0
	p->has_empty_value = 0;
	p->state_lvl0 = lvl0_introduce_binary_stream;
	return 0;
#else
	return 1;
#endif
}


static int action_introduce_binary_stream(sdtl_parser_t* p, int byte)
{
	p->has_empty_value = 0;
	p->state_lvl0 = lvl0_introduce_binary_stream;
	return 0;
}

static int action_introduce_struct(sdtl_parser_t* p, int byte)
{
	p->has_empty_value = 0;
	p->state_lvl0 = lvl0_introduce_struct;
	p->struct_nesting_level++;
	return action_on_struct_value_start(p);
}

static int action_terminate_struct(sdtl_parser_t* p, int byte)
{
	p->state_lvl0 = lvl0_terminate_struct;
	p->struct_nesting_level--;
	if (p->struct_nesting_level < 0)
		return -1;
	return action_on_struct_value_end(p);
}

static int action_introduce_string(sdtl_parser_t* p, int byte)
{
	p->state_lvl0 = lvl0_introduce_string;
	return 0;
}

static int action_in_string(sdtl_parser_t* p, int byte)
{
	char c[2] = { byte, 0x00 };

	if (!p->first_byte_of_multibyte_token) {
		p->has_empty_value = 0;
		p->first_byte_of_multibyte_token = 1;
		p->current_type = entity_is_string;
	}

	/* NOTE: this is slow; a buffer should be used here, lowering the
	 * amount of realloc's */
	p->current_multibyte_token = str_append(p->current_multibyte_token, c);
	p->state_lvl0 = lvl0_in_string;
	return 0;
}

static int action_replace_escape(sdtl_parser_t* p, int byte)
{
	char b;
	char c[2] = { 0x00, 0x00 };

	switch (byte) {
		case 'b':
			b = '\b';
			break;
		case 'f':
			b = '\f';
			break;
		case 'n':
			b = '\n';
			break;
		case 'r':
			b = '\r';
			break;
		case 't':
			b = '\t';
			break;
		case 'v':
			b = '\v';
			break;
		default:
			return -1;
	}
	c[0] = b;

	/* NOTE: this is slow; a buffer should be used here, lowering the
	 * amount of realloc's */
	p->current_multibyte_token = str_append(p->current_multibyte_token, c);
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
	char c[2] = { byte, 0x00 };

	if (!p->first_byte_of_multibyte_token) {
		p->has_empty_value = 0;
		p->first_byte_of_multibyte_token = 1;
		p->current_type = entity_is_numeric;
	}

	/* NOTE: this is slow; a buffer should be used here, lowering the
	 * amount of realloc's */
	p->current_multibyte_token = str_append(p->current_multibyte_token, c);
	p->state_lvl0 = lvl0_in_number;
	return 0;
}


/* state machine */
static int32_t sdtl_parse(sdtl_parser_t* p, int byte)
{
	action_t action = 0;

	/* TODO: if something fails in here, free memory and reset
	 * parser with sdtl_init() */

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
		case lvl0_escape_character:
			action = p->actions_after_escape_character[byte];
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

	/* TODO: support size prefixed random data, which is skipped
	 * here in order to defend against known plain text attacks if
	 * the stream was transported over an encrypted serial line */
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

void sdtl_init(sdtl_parser_t* p)
{
/* NOTE: for performance reasons these tables might be written
 * statically in C */
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
	/* disallow slash so we can use it as path separator beside the dot */
	p->actions_after_assignment_start['/'] = 0;
	/* this is disallowed in order to support identifiers in arrays */
	p->actions_after_assignment_start[','] = 0;
	p->actions_after_assignment_start[']'] = 0;
	/* this is disallowed in order to support identifiers as values,
	 * TODO: define action for this instead of disallowing it */
	p->actions_after_assignment_start[';'] = 0;
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
	p->actions_after_assignment_op['.'] = &action_start_symbolic_link;
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
	/* NOTE: in SDTL it's not necessary to escape these, they are
	 * supported just for convenience reasons */
	p->actions_after_escape_character['b'] = &action_replace_escape;
	p->actions_after_escape_character['f'] = &action_replace_escape;
	p->actions_after_escape_character['n'] = &action_replace_escape;
	p->actions_after_escape_character['r'] = &action_replace_escape;
	p->actions_after_escape_character['t'] = &action_replace_escape;
	p->actions_after_escape_character['v'] = &action_replace_escape;


/* We come from 'lvl0_in_number': accept anything except ';' and '\0', ignore
 * whitespace */
	for (i = 0; i < 256; ++i)
		p->actions_after_in_number[i] = &action_in_number;
	_sdtl_ignore_whitespace(p->actions_after_in_number);
	p->actions_after_in_number[';'] = &action_end_assignment;
	/* this is disallowed in order to support numbers in arrays */
	p->actions_after_in_number[','] = 0;
	p->actions_after_in_number[']'] = 0;
	p->actions_after_in_number['\0'] = 0;

	_sdtl_ignore_whitespace(p->actions_after_introduce_struct);
	p->actions_after_introduce_struct['}'] = &action_terminate_struct;
	p->actions_after_introduce_struct['.'] = &action_start_assignment;

	_sdtl_ignore_whitespace(p->actions_after_terminate_struct);
	p->actions_after_terminate_struct[';'] = &action_end_assignment;
}

void sdtl_factory_init(sdtl_factory_t* f, output_t put_data)
{
	memset(f, 0, sizeof(sdtl_factory_t));
	f->put_data = put_data;
}


int sdtl_factory_flush(sdtl_factory_t* f)
{
	int r = 0;
	size_t len = f->next_byte;
	if (len) {
		r = f->put_data(f, f->buffer, len);
		if (!r)
			f->next_byte = 0;
	}
	return 0;
}

static int sdtl_add_byte(sdtl_factory_t* f, int c)
{
	unsigned char b = c;

	if (f->next_byte == sizeof(f->buffer)) {
		if (sdtl_factory_flush(f))
			return -1;
	}

	f->buffer[f->next_byte] = b;
	f->next_byte++;
	return 0;
}

static int sdtl_add_identifier(sdtl_factory_t* f, const char* id)
{
	int r = 0;
	size_t i, lid;

	if (!id || !*id)
		return -1;

	r = sdtl_add_byte(f, '.');
	if (r)
		return -1;

	lid = strlen(id);
	for (i = 0; i < lid; ++i) {
#if ALLOW_ESCAPES_IN_IDENTIFIER
		if (
			id[i] == '.' ||
			id[i] == ';' ||
			id[i] == '=' ||
			id[i] == ']' ||
			id[i] == ',' ||
			id[i] == '/' ||
			id[i] == '\\'

		) {
			r = sdtl_add_byte(f, '\\');
			if (r)
				break;
		}
#else
		if (
			id[i] == '.' ||
			id[i] == ';' ||
			id[i] == '=' ||
			id[i] == ']' ||
			id[i] == ',' ||
			id[i] == '/'
		)
			return -1;
#endif
		r = sdtl_add_byte(f, id[i]);
		if (r)
			break;
	}
	return r;
}

static int sdtl_add_string(sdtl_factory_t* f, const char* str)
{
	int r = 0;
	size_t i, lstr;

	if (!str || !*str) {
		return sdtl_add_byte(f, ';');
	}

	r = sdtl_add_byte(f, '"');
	if (r)
		return -1;

	lstr = strlen(str);
	for (i = 0; i < lstr; ++i) {
		if (str[i] == '"' || str[i] == '\\') {
			r = sdtl_add_byte(f, '\\');
			if (r)
				break;
		}
		r = sdtl_add_byte(f, str[i]);
		if (r)
			break;
	}

	r = sdtl_add_byte(f, '"');
	if (r)
		return -1;

	r = sdtl_add_byte(f, ';');
	if (r)
		return -1;

	return r;
}

static int sdtl_add_num(sdtl_factory_t* f, const char* num)
{
	int r = 0;
	size_t i, lnum;

	if (!num || !*num) {
		return sdtl_add_byte(f, ';');
	}

	switch (*num) {
		case '$':
		case '-':
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			break;
		default:
			return -1;
	}

	lnum = strlen(num);
	for (i = 0; i < lnum; ++i) {
#if ALLOW_ESCAPES_IN_NUMERIC
		if (
			num[i] == ';' ||
			num[i] == ',' ||
			num[i] == ']' ||
			num[i] == '\\'
		) {
			r = sdtl_add_byte(f, '\\');
			if (r)
				break;
		}
#else
		if (
			num[i] == ';' ||
			num[i] == ',' ||
			num[i] == ']'
		)
			return -1;
#endif
		r = sdtl_add_byte(f, num[i]);
		if (r)
			break;
	}

	r = sdtl_add_byte(f, ';');
	if (r)
		return -1;

	return r;
}

int
sdtl_factory_add_string(sdtl_factory_t* f, const char* key,
			const char* value)
{
	int r = 0;

	r = sdtl_add_identifier(f, key);
	if (r)
		return -1;

	r = sdtl_add_byte(f, '=');
	if (r)
		return -1;

	r = sdtl_add_string(f, value);
	if (r)
		return -1;

	return r;
}

int
sdtl_factory_add_num(sdtl_factory_t* f, const char* key,
			const char* value)
{
	int r = 0;

	r = sdtl_add_identifier(f, key);
	if (r)
		return -1;

	r = sdtl_add_byte(f, '=');
	if (r)
		return -1;

	r = sdtl_add_num(f, value);
	if (r)
		return -1;

	return r;
}

int
sdtl_factory_start_struct(sdtl_factory_t* f, const char* key)
{
	int r = 0;

	r = sdtl_add_identifier(f, key);
	if (r)
		return -1;

	r = sdtl_add_byte(f, '=');
	if (r)
		return -1;

	r = sdtl_add_byte(f, '{');
	if (r)
		return -1;

	return r;
}

int
sdtl_factory_end_struct(sdtl_factory_t* f)
{
	int r = 0;

	r = sdtl_add_byte(f, '}');
	if (r)
		return -1;

	r = sdtl_add_byte(f, ';');
	if (r)
		return -1;

	return r;
}
