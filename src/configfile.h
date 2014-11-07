#ifndef _CONFIGFILE_H
#define _CONFIGFILE_H

#if !defined(_WIN32)
	#define _POSIX_C_SOURCE	200112L
	#define _GNU_SOURCE 1
	#define _BSD_SOURCE 1
	#include <stdint.h>
	#include <string.h>
	#include <stdlib.h>
	#include <fcntl.h>
	#include <unistd.h>
#else
	#if defined(_MSC_VER)
		/* unreferenced inline removed */
		#pragma warning (disable: 4514)

		#pragma section(".CRT$XCU", read)
		#define __do_before_main(f)			\
			static void __cdecl f(void);		\
			__declspec(allocate(".CRT$XCU"))	\
			void (__cdecl *f##_)(void) = f; 	\
			static void __cdecl f(void)

		#define	_CRT_SECURE_NO_WARNINGS	1
		#pragma warning (push)
		/* nonstandard extension 'single line comment' was used */
		#pragma warning (disable: 4001)
		/* padding inserted after struct member */
		#pragma warning (disable: 4820)
			#include <stdint.h>
			#include <string.h>
			#include <stdlib.h>
			#include <fcntl.h>
			#include <io.h>
		#pragma warning (pop)

		#define O_RDONLY	_O_RDONLY
		#define O_BINARY	_O_BINARY
		#define read		_read
		#define write		_write
	#else
		#define _POSIX_C_SOURCE	200112L
		#define _GNU_SOURCE 1
		#define _BSD_SOURCE 1
		#include <stdint.h>
		#include <stdlib.h>
		#include <fcntl.h>
		#include <unistd.h>

		#define __do_before_main(f)			\
			__attribute__((constructor))		\
			static void f(void)
	#endif
	#define	O_NOATIME 0

	#define pipe(fds) _pipe(fds, 512, O_BINARY)

	__do_before_main(__disable_msvcrt_text_translation) {
		/* set stdin, stdout and stderr to binary mode, make binary
		 * mode default for all subsequent open() calls */
		_fmode = O_BINARY;
		if (_setmode(0, O_BINARY) == -1)
			return;
		if (_setmode(1, O_BINARY) == -1)
			return;
		if (_setmode(2, O_BINARY) == -1)
			return;
	}
#endif /* _WIN32 */

#if defined(__cplusplus)
//namespace sdtl {
#endif

#define uint8_max	((uint8_t)~0)
#define uint16_max	((uint16_t)~0)
#define uint32_max	((uint32_t)~0ul)
#define uint64_max	((uint64_t)~0ull)

typedef enum state_e {
	undefined,
	first_bom,
	utf8bom_intro,
	comment_intro,
	ignore_comment_byte,
	comment_outro,
	nullstring_intro,
	ign_nullstring_byte,
	escape_from_ign,
	nullstring_outro,
	identifier_intro,
	type_intro,
	type_outro,
	value_intro,
		array_intro,
		new_array_value,
		array_outro,
		neg_number_intro,
		neg_arr_number_intro,
		copy_type_byte,
		copy_unit_byte,
		copy_number_byte,
		fraction_intro,
		copy_fraction_byte,
		arr_fraction_intro,
		copy_arr_fraction_byte,
		copy_arr_number_byte,
		copy_enum_byte,
		copy_symlink_byte,
		copy_utf8string_byte,
		copy_arr_utf8string_byte,
		escape_from_copy,
		arr_escape_from_copy,
		utf8string_intro,
		utf8string_outro,
		arr_utf8string_intro,
		arr_utf8string_outro,
		octet_stream_intro,
		octet_stream_outro,
		struct_intro,
		struct_outro,
	value_outro,
	dimension_state
} state_t;

typedef enum token_type_e {
	token_is_identifier,
	token_is_utf8string,
	token_is_number,
	token_is_enum,
	token_is_symlink,
	token_is_array_number,
	token_is_array_utf8string,
	token_is_type,
	token_is_unit,
	token_is_octet_stream,
	token_is_null_value,
	token_is_structure,
	token_is_unknown
} token_type_t;

typedef enum data_type_e {
	datatype_identifier		= token_is_identifier,
	datatype_utf8string		= token_is_utf8string,
	datatype_number			= token_is_number,
	datatype_unit			= token_is_unit,
	datatype_enum			= token_is_enum,
	datatype_symlink		= token_is_symlink,
	datatype_octet_stream		= token_is_octet_stream,
	datatype_null_value		= token_is_null_value
} data_type_t;

typedef enum error_code_e {
	error_none				= 0,
	error_unknown_token_type		= 1,
	error_array_row_size_mismatch		= 2,
	error_identifier_too_long		= 3,
	error_empty_identifier			= 4,
	error_struct_nesting_too_high		= 5,
	error_illegal_struct_close		= 6,
	error_utf8string_too_long		= 7,
	error_illegal_escape_sequence		= 8,
	error_number_too_long			= 9,
	error_enum_too_long			= 10,
	error_symlink_too_long			= 11,
	error_read_complete_chunk_failed	= 12,
	error_octet_stream_out_of_sync		= 13,
	error_invalid_binstart_or_length	= 14,
	error_unexpected_input_byte		= 15,
	error_text_data_too_long		= 16,
	error_reading_from_source_fd		= 17,
	error_got_incomplete_sdtl_stream	= 18,
	error_invalid_utf8_byte			= 19,
	error_invalid_byte_order_mark		= 20,
	error_type_too_long			= 21,
	error_unit_too_long			= 22,
	error_expected_string_in_array		= 23,
	error_expected_number_in_array		= 24,
	error_illegal_value_type		= 25,
	error_scanner_callback_returned_nonzero	= 26,
	error_file_too_long			= 27,
	error_invalid_argument			= 28,
	error_too_much_array_items		= 29,

	dimension_error_code
} error_code_t;

typedef enum value_type_e {
	/* Don't interpret the string with these two types. If no type is given,
	 * the string defaults to type 'st_plain'. */
	st_plain,
	st_utf8,
	/* simple base transformations, turning the string into a number,
	 * keep these constants at this place, so that the integer
	 * representation of the enumeration constant equals to the base
	 * in which the string value should be interpreted */
	st_base02, st_base03, st_base04, st_base05, st_base06, st_base07,
	st_base08, st_base09, st_base10, st_base11, st_base12, st_base13,
	st_base14, st_base15, st_base16, st_base17, st_base18, st_base19,
	st_base20, st_base21, st_base22, st_base23, st_base24, st_base25,
	st_base26, st_base27, st_base28, st_base29, st_base30, st_base31,
	st_base32, st_base33, st_base34, st_base35, st_base36, st_base37,
	st_base38, st_base39, st_base40, st_base41, st_base42, st_base43,
	st_base44, st_base45, st_base46, st_base47, st_base48, st_base49,
	st_base50, st_base51, st_base52, st_base53, st_base54, st_base55,
	st_base56, st_base57, st_base58, st_base59, st_base60, st_base61,
	st_base62,
	/* those use their own special alphabet/encoding scheme */
	st_base63, st_base64, st_base85,
	/* IP address representations */
	st_ip_socket,
	/* date/time values according to ISO 8601 */
	st_iso8601,

	int_u8,
	int_s8,
	int_u16,
	int_s16,
	int_u32,
	int_s32,
	int_u64,
	int_s64,
	int_u128,
	int_s128,
	int_u256,
	int_s256,
	int_u512,
	int_s512,
	int_u1024,
	int_s1024,
	/* insert new types here */

	dimension_value_type,
	st_illegal
} value_type_t;

typedef enum value_unit_e {
	unit_none,
	unit_byte,
	unit_second,
	unit_yoctosecond,
	unit_gram,
	unit_yoctogram,
	/* insert new units here */

	dimension_value_unit,
	unit_illegal
} value_unit_t;

typedef enum sdtl_event_e {
	ev_assignment_start,
	ev_octet_stream_start,
	ev_octet_stream_end,
	ev_struct_start,
	ev_struct_end,
	ev_array_new_row,
	ev_array_end_row,
	ev_data,
	dimension_sdtl_event
} sdtl_event_t;

typedef struct sdtl_data_s {
	data_type_t	type;
	value_type_t	value_type;
	void*		data;
	uint16_t	length;
} sdtl_data_t;

typedef struct sdtl_read_flags_s {
	/* Per entity limits. If set to 0 a default value
	 * will be applied */
	uint16_t	max_identifier_length;	/* default: uint8_max */
	uint16_t	max_utf8string_length;	/* default: uint16_max */
	uint8_t		max_number_length;	/* default: uint8_max */
	uint16_t	max_enum_length;	/* default: uint8_max */
	uint16_t	max_symlink_length;	/* default: uint16_max */

	/* Limits total count of array items (total sum of all dimensions).
	 * If set to 0, this is unlimited (until max_text_bytes or
	 * max_file_size comes into play, if they are non-zero). */
	uint64_t	max_array_items;	/* default: 0 */

	/* Limits total count of text bytes (not counting bytes in
	 * octet streams). If set to 0, the total text data length
	 * is unlimited. */
	uint64_t	max_text_bytes;		/* default: 0 */

	/* Limits total bytes (including octet stream bytes) to be read. If
	 * set to 0, the file size is unlimited (useful for streaming over
	 * network). If this value is lower or equal than max_text_bytes, then
	 * the max_file_size limit will take precedence over max_text_bytes. */
	uint64_t	max_file_size;		/* default: 0 */

	/* Limits maximum struct nesting level. If set to 0 a default
	 * value will be applied. */
	uint64_t	max_struct_nesting;	/* default: uint8_max */

	/* A pointer which will be passed back to the user callback. Can be
	 * set to NULL. */
	void*		userdata;
	/* the user callback, which will receive all parser events */
	int		(*on_event)		/* mandatory, must be set */
			(void* userdata, sdtl_event_t e, sdtl_data_t* data);
} sdtl_read_flags_t;

typedef struct sdtl_read_fd {
	sdtl_read_flags_t	opts;
	int			byte;
	token_type_t		token_type;
	state_t			next_state;
	state_t			last_state;
	value_type_t		value_type;
	int			is_num_array;
	int			is_string_array;

	uint64_t		struct_nesting_level;
	uint64_t		array_items;
	uint64_t		array_row_size;
	uint64_t		curr_row_size;

	uint64_t		processed_bytes;
	uint64_t		text_bytes;

	void*			userdata;

	error_code_t		last_error;
	int			fd;

	uint8_t			bom_len;
	uint8_t			type_len;
	uint8_t			unit_len;
	uint16_t		str_len;
	unsigned char		bom[2];
	unsigned char		type_data[uint8_max+(uint32_t)1];
	unsigned char		unit_data[uint8_max+(uint32_t)1];
	unsigned char		str_data[uint16_max+(uint32_t)1];
} sdtl_read_fd_t;

typedef int (*action_t)(struct sdtl_read_fd* p);

typedef struct sdtl_write_fd {
	uint64_t	struct_nesting_level;
	int		fd;
	int		white;
	int		last_was_struct;
	int		octet_stream;
	int		padding0;
	uint32_t	next_byte;
	unsigned char	buffer[uint16_max+(uint32_t)1];
} sdtl_write_fd_t;

const char* const _value_types[dimension_value_type] = {
	"plain",
	"utf8",
	"base02", "base03", "base04", "base05", "base06", "base07",
	"base08", "base09", "base10", "base11", "base12", "base13",
	"base14", "base15", "base16", "base17", "base18", "base19",
	"base20", "base21", "base22", "base23", "base24", "base25",
	"base26", "base27", "base28", "base29", "base30", "base31",
	"base32", "base33", "base34", "base35", "base36", "base37",
	"base38", "base39", "base40", "base41", "base42", "base43",
	"base44", "base45", "base46", "base47", "base48", "base49",
	"base50", "base51", "base52", "base53", "base54", "base55",
	"base56", "base57", "base58", "base59", "base60", "base61",
	"base62",
	"base63", "base64", "base85",
	"ip-socket",
	"iso8601",

	"int8",
	"uint8",
	"int16",
	"uint16",
	"int32",
	"uint32",
	"int64",
	"uint64",
	"int128",
	"uint128",
	"int256",
	"uint256",
	"int512",
	"uint512",
	"int1024",
	"uint1024"
};

const char* const _value_units[dimension_value_unit] = {
	"none",
	"b", "s", "ys", "g", "yg"
};

value_type_t _get_value_type(const unsigned char* type)
{
	int i;
	for (i = 0; i < dimension_value_type; ++i) {
		if (!strcmp((const char*)type, _value_types[i]))
			return (value_type_t)i;
	}
	return st_illegal;
}

action_t _after_state[dimension_state][uint8_max+1];

int _finalize_binary_chunk
(sdtl_read_fd_t* p, unsigned char* data, uint16_t length)
{
	sdtl_data_t d;

	if (!length) {
		p->token_type = token_is_unknown;
		if (p->opts.on_event(p->userdata, ev_octet_stream_end, 0)) {
			p->last_error = error_scanner_callback_returned_nonzero;
			return -1;
		}
		return 0;
	}
	d.type = datatype_octet_stream;
	d.length = length;
	d.data = data;

	if (p->opts.on_event(p->userdata, ev_data, &d)) {
		p->last_error = error_scanner_callback_returned_nonzero;
		return -1;
	}
	return 0;
}

int _finalize_current_token
(sdtl_read_fd_t* p)
{
	sdtl_data_t data;

	/* if we hit this, the given structure is empty. just ignore and
	 * don't generate an event. */
	if (p->token_type == token_is_structure) {
		p->token_type = token_is_unknown;
		return 0;
	}

	/* handle possible second invocation through _do_value_outro()
	 * after array or (not empty) struct end, just return */
	if (p->token_type == token_is_unknown) {
		return 0;
	}

	p->str_data[p->str_len] = 0;
	p->type_data[p->type_len] = 0;
	p->unit_data[p->unit_len] = 0;

	if (p->token_type == token_is_identifier) {
		if (!p->str_len) {
			p->last_error = error_empty_identifier;
			return -1;
		}
	}

	if (p->token_type == token_is_type) {
		p->value_type = _get_value_type(p->type_data);
		if (p->value_type == st_illegal) {
			p->last_error = error_illegal_value_type;
			return -1;
		}
		return 0;
	}

	if (p->token_type == token_is_unit) {
		data.data =  p->unit_data;
		data.length = p->unit_len;
	} else {
		data.data = (p->token_type != token_is_null_value) ?
			p->str_data : 0;
		data.length = (p->token_type != token_is_null_value) ?
			p->str_len : (uint16_t)0;
	}

	if (p->token_type == token_is_array_number)
		data.type = datatype_number;
	else if (p->token_type == token_is_array_utf8string)
		data.type = datatype_utf8string;
	else
		data.type = (data_type_t)p->token_type;

	data.value_type = p->value_type;


	if (p->token_type == token_is_identifier) {
		if (p->opts.on_event(p->userdata, ev_assignment_start, &data)) {
			p->last_error = error_scanner_callback_returned_nonzero;
			return -1;
		}
	} else if (p->opts.on_event(p->userdata, ev_data, &data)) {
		p->last_error = error_scanner_callback_returned_nonzero;
		return -1;
	}

	p->type_len = 0;
	p->unit_len = 0;
	p->str_len = 0;
	/* make sure that a second call to _finalize_str_data() without
	 * token type change is a noop */
	p->token_type = token_is_unknown;
	return 0;
}

/* state transition actions */
int _do_ignore_whitespace
(sdtl_read_fd_t* p)
{
	/* just keep current state, do nothing */
	return 0;
}

int _do_comment_intro
(sdtl_read_fd_t* p)
{
	p->last_state = p->next_state;
	p->next_state = comment_intro;
	return 0;
}

int _do_ignore_comment_byte
(sdtl_read_fd_t* p)
{
	p->next_state = ignore_comment_byte;
	return 0;
}

int _do_comment_outro
(sdtl_read_fd_t* p)
{
	/* restore state to the state before the comment intro */
	p->next_state = p->last_state;
	return 0;
}

int _do_copy_utf8bom_byte
(sdtl_read_fd_t* p)
{
	if (!p->bom_len) {
		p->last_state = p->next_state;
	}
	if (p->bom_len == 2) {
		if ((p->bom[0] == 0xef) &&
		(p->bom[1] == 0xbb) &&
		(p->byte == 0xbf)) {
			p->bom_len = 0;
			if (p->last_state == utf8string_intro)
				p->next_state = copy_utf8string_byte;
			else if (p->last_state == undefined)
				p->next_state = first_bom;
			else if (p->last_state == arr_utf8string_intro)
				p->next_state = copy_arr_utf8string_byte;
			else
				return -1;
			return 0;
		}
		p->last_error = error_invalid_byte_order_mark;
		return -1;
	}

	p->bom[p->bom_len] = (unsigned char)p->byte;
	p->bom_len++;

	p->next_state = utf8bom_intro;
	return 0;
}

int _do_copy_identifier_byte
(sdtl_read_fd_t* p)
{
	if (p->str_len == p->opts.max_identifier_length) {
		p->last_error = error_identifier_too_long;
		return -1;
	}
	p->str_data[p->str_len] = (unsigned char)p->byte;
	p->str_len++;

	p->next_state = identifier_intro;
	return 0;
}

int _do_identifier_intro
(sdtl_read_fd_t* p)
{
	p->str_len = 0;
	p->token_type = token_is_identifier;
	p->next_state = identifier_intro;
	return 0;
}

int _do_value_intro
(sdtl_read_fd_t* p)
{
	/* identifier */
	if (_finalize_current_token(p))
		return -1;

	p->str_len = 0;
	p->array_items = 0;
	p->token_type = token_is_null_value;
	p->next_state = value_intro;
	return 0;
}

int _do_value_outro
(sdtl_read_fd_t* p)
{
	/* note: might be called twice after struct and array outro */
	if (_finalize_current_token(p))
		return -1;

	p->is_num_array = 0;
	p->is_string_array = 0;
	p->array_row_size = 0;
	/* the string type remain valid until semicolon */
	p->value_type = st_plain;
	p->next_state = value_outro;
	return 0;
}

int _do_octet_stream_intro
(sdtl_read_fd_t* p)
{
	p->token_type = token_is_octet_stream;
	p->next_state = octet_stream_intro;
	if (p->opts.on_event(p->userdata, ev_octet_stream_start, 0)) {
		p->last_error = error_scanner_callback_returned_nonzero;
		return -1;
	}
	return 0;
}

int _do_struct_intro
(sdtl_read_fd_t* p)
{
	if (p->struct_nesting_level == p->opts.max_struct_nesting) {
		p->last_error = error_struct_nesting_too_high;
		return -1;
	}
	p->struct_nesting_level++;
	if (p->opts.on_event(p->userdata, ev_struct_start, 0)) {
		p->last_error = error_scanner_callback_returned_nonzero;
		return -1;
	}
	p->token_type = token_is_structure;
	p->next_state = struct_intro;
	return 0;
}

int _do_struct_outro
(sdtl_read_fd_t* p)
{
	if (!p->struct_nesting_level) {
		p->last_error = error_illegal_struct_close;
		return -1;
	}
	p->struct_nesting_level--;
	if (p->opts.on_event(p->userdata, ev_struct_end, 0)) {
		p->last_error = error_scanner_callback_returned_nonzero;
		return -1;
	}
	p->next_state = struct_outro;
	return 0;
}

int _do_array_intro
(sdtl_read_fd_t* p)
{
#if 0
	if (p->type_len) {
		p->is_string_array = 1;
	}
#endif

	p->str_len = 0;
	/* an array consists of at least one null value (.a = [];) */
	if (p->opts.max_array_items &&
	(p->array_items == p->opts.max_array_items)) {
		p->last_error = error_too_much_array_items;
		return -1;
	}
	p->array_items++;

	p->curr_row_size++;
	p->token_type = token_is_null_value;
	p->next_state = array_intro;
	if (p->opts.on_event(p->userdata, ev_array_new_row, 0)) {
		p->last_error = error_scanner_callback_returned_nonzero;
		return -1;
	}
	return 0;
}

int _do_new_array_value
(sdtl_read_fd_t* p)
{
	if (_finalize_current_token(p))
		return -1;

	p->str_len = 0;

	if (p->opts.max_array_items &&
	(p->array_items == p->opts.max_array_items)) {
		p->last_error = error_too_much_array_items;
		return -1;
	}
	p->array_items++;

	if (p->array_row_size && (p->array_row_size == p->curr_row_size)) {
		p->last_error = error_array_row_size_mismatch;
		return -1;
	}
	p->curr_row_size++;
	p->token_type = token_is_null_value;
	p->next_state = new_array_value;
	return 0;
}

int _do_array_outro
(sdtl_read_fd_t* p)
{
	if (_finalize_current_token(p))
		return -1;

	if (!p->array_row_size)
		p->array_row_size = p->curr_row_size;
	else if (p->array_row_size != p->curr_row_size) {
		p->last_error = error_array_row_size_mismatch;
		return -1;
	}
	p->curr_row_size = 0;
	p->next_state = array_outro;
	if (p->opts.on_event(p->userdata, ev_array_end_row, 0)) {
		p->last_error = error_scanner_callback_returned_nonzero;
		return -1;
	}
	return 0;
}

int _do_utf8string_intro
(sdtl_read_fd_t* p)
{
	p->token_type = token_is_utf8string;
	p->next_state = utf8string_intro;
	return 0;
}

int _do_copy_utf8string_byte
(sdtl_read_fd_t* p)
{
	if (p->str_len == p->opts.max_utf8string_length) {
		p->last_error = error_utf8string_too_long;
		return -1;
	}
	p->str_data[p->str_len] = (unsigned char)p->byte;
	p->str_len++;

	p->next_state = copy_utf8string_byte;
	return 0;
}

int _do_replace_escaped_byte
(sdtl_read_fd_t* p)
{
	if (p->str_len == p->opts.max_utf8string_length) {
		p->last_error = error_utf8string_too_long;
		return -1;
	}

	switch (p->byte) {
		case 't':
			p->byte = '\t';
			break;
		case 'n':
			p->byte = '\n';
			break;
		case 'v':
			p->byte = '\v';
			break;
		case 'f':
			p->byte = '\f';
			break;
		case 'r':
			p->byte = '\r';
			break;
		case '"':
			p->byte = '"';
			break;
		case '\\':
			p->byte = '\\';
			break;
		default:
			p->last_error = error_illegal_escape_sequence;
			return -1;
	}

	p->str_data[p->str_len] = (unsigned char)p->byte;
	p->str_len++;
	p->next_state = copy_utf8string_byte;
	return 0;
}

int _do_escape_from_copy
(sdtl_read_fd_t* p)
{
	p->next_state = escape_from_copy;
	return 0;
}

int _do_utf8string_outro
(sdtl_read_fd_t* p)
{
	p->next_state = utf8string_outro;
	return 0;
}

int _do_nullstring_intro
(sdtl_read_fd_t* p)
{
	p->next_state = nullstring_intro;
	return 0;
}

int _do_ign_nullstring_byte
(sdtl_read_fd_t* p)
{
	p->next_state = ign_nullstring_byte;
	return 0;
}

int _do_ign_escaped_byte
(sdtl_read_fd_t* p)
{
	p->next_state = ign_nullstring_byte;
	return 0;
}

int _do_escape_from_ign
(sdtl_read_fd_t* p)
{
	p->next_state = escape_from_ign;
	return 0;
}

int _do_nullstring_outro
(sdtl_read_fd_t* p)
{
	p->next_state = nullstring_outro;
	return 0;
}

int _do_arr_utf8string_intro
(sdtl_read_fd_t* p)
{
	if (p->is_num_array) {
		p->last_error = error_expected_number_in_array;
		return -1;
	}
	p->is_string_array = 1;
	p->token_type = token_is_array_utf8string;
	p->next_state = arr_utf8string_intro;
	return 0;
}

int _do_copy_arr_utf8string_byte
(sdtl_read_fd_t* p)
{
	if (p->str_len == p->opts.max_utf8string_length) {
		p->last_error = error_utf8string_too_long;
		return -1;
	}
	p->str_data[p->str_len] = (unsigned char)p->byte;
	p->str_len++;

	p->next_state = copy_arr_utf8string_byte;
	return 0;
}

int _do_arr_replace_escaped_byte
(sdtl_read_fd_t* p)
{
	if (p->str_len == p->opts.max_utf8string_length) {
		p->last_error = error_utf8string_too_long;
		return -1;
	}

	switch (p->byte) {
		case 't':
			p->byte = '\t';
			break;
		case 'n':
			p->byte = '\n';
			break;
		case 'v':
			p->byte = '\v';
			break;
		case 'f':
			p->byte = '\f';
			break;
		case 'r':
			p->byte = '\r';
			break;
		case '"':
			p->byte = '"';
			break;
		case '\\':
			p->byte = '\\';
			break;
		default:
			p->last_error = error_illegal_escape_sequence;
			return -1;
	}

	p->str_data[p->str_len] = (unsigned char)p->byte;
	p->str_len++;
	p->next_state = copy_arr_utf8string_byte;
	return 0;
}

int _do_arr_escape_from_copy
(sdtl_read_fd_t* p)
{
	p->next_state = arr_escape_from_copy;
	return 0;
}

int _do_arr_utf8string_outro
(sdtl_read_fd_t* p)
{
	p->next_state = arr_utf8string_outro;
	return 0;
}

int _do_type_intro
(sdtl_read_fd_t* p)
{
	p->token_type = token_is_type;
	p->next_state = type_intro;
	return 0;
}

int _do_copy_type_byte
(sdtl_read_fd_t* p)
{
	if (p->type_len == sizeof(p->type_data)-1) {
		p->last_error = error_type_too_long;
		return -1;
	}
	p->type_data[p->type_len] = (unsigned char)p->byte;
	p->type_len++;

	p->next_state = copy_type_byte;
	return 0;
}

int _do_type_outro
(sdtl_read_fd_t* p)
{
	if (_finalize_current_token(p))
		return -1;

	p->next_state = type_outro;
	return 0;
}

int _do_copy_unit_byte
(sdtl_read_fd_t* p)
{
	if (!p->unit_len) {
		if (p->token_type == token_is_number ||
		p->token_type == token_is_utf8string) {
			if (_finalize_current_token(p))
				return -1;
		}
		p->token_type = token_is_unit;
	}
	if (p->unit_len == sizeof(p->unit_data)-1) {
		p->last_error = error_unit_too_long;
		return -1;
	}
	p->unit_data[p->unit_len] = (unsigned char)p->byte;
	p->unit_len++;

	p->next_state = copy_unit_byte;
	return 0;
}

int _do_neg_number_intro
(sdtl_read_fd_t* p)
{
	if (!p->str_len) {
		p->token_type = token_is_number;
	}
	if (p->str_len == p->opts.max_number_length) {
		p->last_error = error_number_too_long;
		return -1;
	}
	p->str_data[p->str_len] = (unsigned char)p->byte;
	p->str_len++;

	p->next_state = neg_number_intro;
	return 0;
}

int _do_copy_number_byte
(sdtl_read_fd_t* p)
{
	if (!p->str_len) {
		p->token_type = token_is_number;
	}
	if (p->str_len == p->opts.max_number_length) {
		p->last_error = error_number_too_long;
		return -1;
	}
	p->str_data[p->str_len] = (unsigned char)p->byte;
	p->str_len++;

	p->next_state = copy_number_byte;
	return 0;
}

int _do_fraction_intro
(sdtl_read_fd_t* p)
{
	if (p->str_len == p->opts.max_number_length) {
		p->last_error = error_number_too_long;
		return -1;
	}
	p->str_data[p->str_len] = (unsigned char)p->byte;
	p->str_len++;

	p->next_state = fraction_intro;
	return 0;
}

int _do_copy_fraction_byte
(sdtl_read_fd_t* p)
{
	if (p->str_len == p->opts.max_number_length) {
		p->last_error = error_number_too_long;
		return -1;
	}
	p->str_data[p->str_len] = (unsigned char)p->byte;
	p->str_len++;

	p->next_state = copy_fraction_byte;
	return 0;
}

int _do_neg_arr_number_intro
(sdtl_read_fd_t* p)
{
	if (!p->str_len) {
		if (p->is_string_array) {
			p->last_error = error_expected_string_in_array;
			return -1;
		}
		p->token_type = token_is_array_number;
		p->is_num_array = 1;
	}
	if (p->str_len == p->opts.max_number_length) {
		p->last_error = error_number_too_long;
		return -1;
	}
	p->str_data[p->str_len] = (unsigned char)p->byte;
	p->str_len++;

	p->next_state = neg_arr_number_intro;
	return 0;
}

int _do_copy_arr_number_byte
(sdtl_read_fd_t* p)
{
	if (!p->str_len) {
		if (p->is_string_array) {
			p->last_error = error_expected_string_in_array;
			return -1;
		}
		p->token_type = token_is_array_number;
		p->is_num_array = 1;
	}
	if (p->str_len == p->opts.max_number_length) {
		p->last_error = error_number_too_long;
		return -1;
	}
	p->str_data[p->str_len] = (unsigned char)p->byte;
	p->str_len++;

	p->next_state = copy_arr_number_byte;
	return 0;
}

int _do_arr_fraction_intro
(sdtl_read_fd_t* p)
{
	if (p->str_len == p->opts.max_number_length) {
		p->last_error = error_number_too_long;
		return -1;
	}
	p->str_data[p->str_len] = (unsigned char)p->byte;
	p->str_len++;

	p->next_state = arr_fraction_intro;
	return 0;
}

int _do_copy_arr_fraction_byte
(sdtl_read_fd_t* p)
{
	if (p->str_len == p->opts.max_number_length) {
		p->last_error = error_number_too_long;
		return -1;
	}
	p->str_data[p->str_len] = (unsigned char)p->byte;
	p->str_len++;

	p->next_state = copy_arr_fraction_byte;
	return 0;
}

int _do_copy_enum_byte
(sdtl_read_fd_t* p)
{
	if (!p->str_len) {
		p->token_type = token_is_enum;
	}
	if (p->str_len == p->opts.max_enum_length) {
		p->last_error = error_enum_too_long;
		return -1;
	}
	p->str_data[p->str_len] = (unsigned char)p->byte;
	p->str_len++;

	p->next_state = copy_enum_byte;
	return 0;
}

int _do_copy_symlink_byte
(sdtl_read_fd_t* p)
{
	if (!p->str_len) {
		p->token_type = token_is_symlink;
	}
	if (p->str_len == p->opts.max_symlink_length) {
		p->last_error = error_symlink_too_long;
		return -1;
	}
	p->str_data[p->str_len] = (unsigned char)p->byte;
	p->str_len++;

	p->next_state = copy_symlink_byte;
	return 0;
}

int _stream_read_complete_length
(sdtl_read_fd_t* p, void* output, int32_t length)
{
	int64_t bytes_read;
	int32_t total = 0;
	int fd = p->fd;
	unsigned char* buf = (unsigned char*)output;

	if (!length) {
		p->last_error = error_invalid_argument;
		return -1;
	}

	if (p->opts.max_file_size) {
		p->processed_bytes += (uint64_t)length;
		if (p->processed_bytes < (uint64_t)length) {
			/* modulo 2^64 overflow */
			p->last_error = error_file_too_long;
			return -1;
		}
		if (p->processed_bytes > p->opts.max_file_size) {
			p->last_error = error_file_too_long;
			return -1;
		}
	}

	do {
		bytes_read = read(fd,
		buf+total,
		(uint32_t)length-total);
		/* returning 0 is an error here */
		if (bytes_read <= 0) {
			p->last_error = error_read_complete_chunk_failed;
			return -1;
		}
		total += (int32_t)bytes_read;
	} while (total != length);
	return 0;
}

int _stream_read_one_chunk
(sdtl_read_fd_t* p, uint16_t length)
{
	if (_stream_read_complete_length(p, p->str_data, length))
		return -1;
	if (_finalize_binary_chunk(p, p->str_data, length))
		return -1;
	return 0;
}

int _stream_read_partial_chunk
(sdtl_read_fd_t* p, uint16_t length, unsigned char* prepend, uint16_t prepsize)
{
	if (prepsize)
		memcpy(p->str_data, prepend, prepsize);
	if (_stream_read_complete_length(p, p->str_data+prepsize, length))
		return -1;
	if (_finalize_binary_chunk(p, p->str_data, (uint16_t)(length+prepsize)))
		return -1;
	return 0;
}

int _stream_read_all_chunks
(sdtl_read_fd_t* p)
{
	unsigned char tmp[3];
	int r = 0;
	uint16_t chunksize = 0;

	for (;;) {
		if (_stream_read_complete_length(p, tmp, 3)) {
			return -1;
		}
		/* 0 is our sync byte right before the 2 byte large chunk
		 * size */
		if (*tmp) {
			p->last_error = error_octet_stream_out_of_sync;
			return -1;
		}
		memcpy(&chunksize, tmp+1, 2);
		if (!chunksize) {
			r = _finalize_binary_chunk(p, 0, 0);
			break;
		}
		if (_stream_read_one_chunk(p, chunksize))
			return -1;
	}
	return r;
}

/* synchronize read strategy */
int32_t _stream_synchronize
(sdtl_read_fd_t* p, unsigned char* data, int32_t length, int32_t bin_start)
{
	unsigned char tmp[2];
	uint16_t chunksize = 0;
	int32_t bytes_after_chunksize;
	int32_t chunkstart_off;
	unsigned char* chunkstart;

	next_chunk_in_buffer:
	chunkstart_off = bin_start + 2;
	chunkstart = data + bin_start + 2;
	bytes_after_chunksize = length - bin_start;
	bytes_after_chunksize -= 2;
	if (bytes_after_chunksize < 0) {
		if (bytes_after_chunksize == -1) {
			/* we need 1 byte more for chunksize */
			if(_stream_read_complete_length(p, tmp, 1))
				return -1;
			memcpy(&chunksize, data+bin_start, 1);
			memcpy((char*)&chunksize+1, tmp, 1);
		} else if (bytes_after_chunksize == -2) {
			/* we need 2 bytes more for chunksize */
			if(_stream_read_complete_length(p, tmp, 2))
				return -1;
			memcpy(&chunksize, tmp, 2);
		} else {
			p->last_error = error_invalid_binstart_or_length;
			return -1;
		}
		bytes_after_chunksize = 0;
	} else {
		memcpy(&chunksize, data+bin_start, 2);
	}

	/* most simple case with chunksize being 0 */
	if (!chunksize) {
		if (_finalize_binary_chunk(p, 0, 0))
			return -1;

		/* if the empty chunk ends with the current buffer, just
		 * continue reading text data just like nothing has happened */
		if (!bytes_after_chunksize)
			return 0;
		else {
			/* if there is still text data in the buffer, we need
			 * to adjust offsets and parse the remaining data */
			return chunkstart_off;
		}
	}

	/* chunk data is about to follow */

	/* our buffer is empty, we can proceed with reading the first chunk
	 * and do a synchronized chunk read afterwards */
	if (!bytes_after_chunksize) {
		if (_stream_read_one_chunk(p, chunksize)) {
			return -1;
		}
		if (_stream_read_all_chunks(p)) {
			return -1;
		}
		return 0;
	}
	/* the buffer end and the chunk end are the same */
	if (bytes_after_chunksize == chunksize) {
		if (_finalize_binary_chunk(p, chunkstart, chunksize))
			return -1;
		if (_stream_read_all_chunks(p))
			return -1;
		return 0;
	}
	/* the chunk needs bytes from fd, prepend the bytes we already have */
	if (chunksize > bytes_after_chunksize) {
		if (_stream_read_partial_chunk(p,
		(uint16_t)(chunksize-bytes_after_chunksize), chunkstart,
		(uint16_t)bytes_after_chunksize)) {
			return -1;
		}
		if (_stream_read_all_chunks(p)) {
			return -1;
		}
		return 0;
	}
	/* the chunk ends in the current buffer, we have at least 1 byte of
	 * the next chunk in our buffer */
	if (chunksize < bytes_after_chunksize) {
		if (_finalize_binary_chunk(p, chunkstart, chunksize))
			return -1;
		/* calculate next bin_start in buffer */
		bin_start += chunksize+2;
		/* check sync byte */
		if (data[bin_start]) {
			p->last_error = error_octet_stream_out_of_sync;
			return -1;
		}
		/* bin_start is counted from 1 */
		bin_start++;
		goto next_chunk_in_buffer;
	}
	return 0;
}

/* state machine */
int _call_action_for_new_byte
(sdtl_read_fd_t* p)
{
	action_t action;

	action = _after_state[p->next_state][p->byte];
	if (!action) {
		p->last_error = error_unexpected_input_byte;
		return -1;
	}
	return action(p);
}

int _utf8check(int b)
{
	static int _to_follow = 0;

	if (b == 0xc0 || b == 0xc1)
		goto err_out;
	if (b >= 0xf5)
		goto err_out;
	if (!_to_follow) {
		if ((b & 0xc0) == 0x80)
			goto err_out;
	}
	if (_to_follow > 0) {
		if ((b & 0xc0) != 0x80)
			goto err_out;
		_to_follow--;
		return 0;
	}
	if (b <= 0x7f)
		return 0;
	if ((b & 0xe0) == 0xc0) {
		_to_follow = 1;
		return 0;
	}
	if ((b & 0xf0) == 0xe0) {
		_to_follow = 2;
		return 0;
	}
	if ((b & 0xf8) == 0xf0) {
		_to_follow = 3;
		return 0;
	}

err_out:
	_to_follow = 0;
	return -1;
}

/* feed statemachine, handle binary stream start */
int _interpret_buffer
(sdtl_read_fd_t* p, unsigned char* data, uint16_t len, int32_t* pos)
{
	int32_t idx = 0;

	*pos = 0;
	if (p->next_state == octet_stream_intro) {
		p->next_state = octet_stream_outro;
	}

	for (idx = 0; idx < len; ++idx) {
		if (p->opts.max_text_bytes &&
		(p->text_bytes == p->opts.max_text_bytes)) {
			p->last_error = error_text_data_too_long;
			return -1;
		}
		p->text_bytes++;
		p->byte = data[idx];
		if (_utf8check(p->byte)) {
			p->last_error = error_invalid_utf8_byte;
			return -1;
		};
		if (_call_action_for_new_byte(p))
			return -1;
		if (p->next_state == octet_stream_intro) {
			/* the caller shall change read strategy to
			 * 2 byte size prefixed buffers (max 64k) */
			*pos = idx+1;
			break;
		}
	}
	return 0;
}

int sdtl_read
(sdtl_read_fd_t* p)
{
	int32_t		nb;
	int32_t		bin;
	int32_t		off;
	/* 8192 is a good value here */
	unsigned char	data[8192];
	const uint16_t	bufsize = 8192;
	int 		fd = p->fd;

	for(;;) {
		off = 0;

		nb = read(fd, data, bufsize);
		if (nb <= 0) {
			if (nb < 0) {
				p->last_error = error_reading_from_source_fd;
			} else {
				/* The file has ended or the remote side
				 * of the pipe has shutdown its corresponding
				 * write socket, indicating that it wants to
				 * quit communication. In this case we
				 * return only 0, if the current state is
				 * 'value_outro' or 'undefined' and
				 * struct_nesting_level is 0 */
				if ((p->next_state == value_outro ||
				p->next_state == undefined) &&
				(!p->struct_nesting_level)) {
					p->last_error = error_none;
					break;
				}
				/* the remote side has dropped connection
				 * due to an error on the remote side, which
				 * doesn't allow further transmission of
				 * data */
				p->last_error =
					error_got_incomplete_sdtl_stream;
				return -1;
			}
		}
		if (p->opts.max_file_size) {
			p->processed_bytes += (uint64_t)nb;
			if (p->processed_bytes < (uint64_t)nb) {
				/* modulo 2^64 overflow */
				p->last_error = error_file_too_long;
				return -1;
			}
			if (p->processed_bytes > p->opts.max_file_size) {
				p->last_error = error_file_too_long;
				return -1;
			}
		}

		process_remaining:
		if (_interpret_buffer(p, data+off, (uint16_t)(nb-off), &bin))
			return -1;
		if (bin) {
			off = _stream_synchronize(p, data, nb, bin+off);
			if (off < 0) {
				return -1;
			}
			if (off) {
				goto process_remaining;
			}
		}
	}
	return nb;
}

int sdtl_get_error
(sdtl_read_fd_t* r)
{
	return r->last_error;
}

void _ignore_whitespace_in
(action_t* tofill)
{
	tofill[/*0x09*/(int)'\t'] = &_do_ignore_whitespace;
	tofill[/*0x0a*/(int)'\n'] = &_do_ignore_whitespace;
	tofill[/*0x0b*/(int)'\v'] = &_do_ignore_whitespace;
	tofill[/*0x0c*/(int)'\f'] = &_do_ignore_whitespace;
	tofill[/*0x0d*/(int)'\r'] = &_do_ignore_whitespace;

	tofill[/*0x20*/(int)' '] = &_do_ignore_whitespace;

}

void _disallow_ascii_control_in
(action_t* tofill)
{
	int i;
	for (i = 0x00; i < 0x08; ++i)
		tofill[i] = 0;

	for (i = 0x0e; i < 0x1f; ++i)
		tofill[i] = 0;

	tofill[0x7f] = 0;
}

int sdtl_open_read
(sdtl_read_fd_t* r, int fd, sdtl_read_flags_t* options)
{
	int i;

	memset(_after_state, 0, sizeof(_after_state));

	memset(r, 0, sizeof(sdtl_read_fd_t));
	r->next_state = undefined;
	r->last_error = error_none;
	r->fd = fd;

	if (!options || !options->on_event)
		return -1;

	memcpy(&r->opts, options, sizeof(sdtl_read_flags_t));
	if (!r->opts.max_identifier_length)
		r->opts.max_identifier_length = uint8_max;
	if (!r->opts.max_number_length)
		r->opts.max_number_length = uint8_max;
	if (!r->opts.max_utf8string_length)
		r->opts.max_utf8string_length = uint16_max;
	if (!r->opts.max_enum_length)
		r->opts.max_enum_length = uint8_max;
	if (!r->opts.max_symlink_length)
		r->opts.max_symlink_length = uint16_max;
	if (!r->opts.max_struct_nesting)
		r->opts.max_struct_nesting = uint8_max;

	r->userdata = r->opts.userdata;

	/* init tables */
	/* NOTE: for performance reasons these tables might be
	 * filled statically */

	_ignore_whitespace_in(_after_state[undefined]);
	_after_state[undefined][(int)'.'] = &_do_identifier_intro;
	_after_state[undefined][(int)'#'] = &_do_comment_intro;
	_after_state[undefined][0xef] = &_do_copy_utf8bom_byte;


	_ignore_whitespace_in(_after_state[first_bom]);
	_after_state[first_bom][(int)'.'] = &_do_identifier_intro;
	_after_state[first_bom][(int)'#'] = &_do_comment_intro;


	for (i = 0; i < 256; ++i)
		_after_state[utf8bom_intro][i] = &_do_copy_utf8bom_byte;


	for (i = 0; i < 256; ++i)
		_after_state[comment_intro][i] = &_do_ignore_comment_byte;
	_disallow_ascii_control_in(_after_state[comment_intro]);
	_after_state[comment_intro][(int)'"'] = &_do_nullstring_intro;
	_after_state[comment_intro][(int)'\n'] = &_do_comment_outro;
	_after_state[comment_intro][(int)'\r'] = &_do_comment_outro;


	for (i = 0; i < 256; ++i)
		_after_state[nullstring_intro][i] = &_do_ign_nullstring_byte;
	_disallow_ascii_control_in(_after_state[nullstring_intro]);
	_after_state[nullstring_intro][(int)'"'] = &_do_nullstring_outro;
	_after_state[nullstring_intro][(int)'\\'] = &_do_escape_from_ign;


	for (i = 0; i < 256; ++i)
		_after_state[ign_nullstring_byte][i] = &_do_ign_nullstring_byte;
	_disallow_ascii_control_in(_after_state[ign_nullstring_byte]);
	_after_state[ign_nullstring_byte][(int)'"'] = &_do_nullstring_outro;
	_after_state[ign_nullstring_byte][(int)'\\'] = &_do_escape_from_ign;


	for (i = 0; i < 256; ++i)
		_after_state[escape_from_ign][i] = &_do_ign_escaped_byte;
	_disallow_ascii_control_in(_after_state[escape_from_ign]);


	for (i = 0; i < 256; ++i)
		_after_state[nullstring_outro][i] = &_do_ignore_comment_byte;
	_ignore_whitespace_in(_after_state[nullstring_outro]);
	_disallow_ascii_control_in(_after_state[nullstring_outro]);
	_after_state[nullstring_outro][(int)'"'] = &_do_nullstring_intro;
	_after_state[nullstring_outro][(int)'\n'] = &_do_comment_outro;
	_after_state[nullstring_outro][(int)'\r'] = &_do_comment_outro;


	for (i = 0; i < 256; ++i)
		_after_state[ignore_comment_byte][i] = &_do_ignore_comment_byte;
	_disallow_ascii_control_in(_after_state[ignore_comment_byte]);
	_after_state[ignore_comment_byte][(int)'"'] = &_do_nullstring_intro;
	_after_state[ignore_comment_byte][(int)'\n'] = &_do_comment_outro;
	_after_state[ignore_comment_byte][(int)'\r'] = &_do_comment_outro;


	for (i = 0; i < 256; ++i)
		_after_state[identifier_intro][i] = &_do_copy_identifier_byte;
	_ignore_whitespace_in(_after_state[identifier_intro]);
	_disallow_ascii_control_in(_after_state[identifier_intro]);
	_after_state[identifier_intro][(int)'#'] = &_do_comment_intro;
	_after_state[identifier_intro][(int)'='] = &_do_value_intro;
	_after_state[identifier_intro][(int)'.'] = 0;
	_after_state[identifier_intro][(int)'{'] = 0;
	_after_state[identifier_intro][(int)'}'] = 0;
	_after_state[identifier_intro][(int)'"'] = 0;
	_after_state[identifier_intro][(int)';'] = 0;
	_after_state[identifier_intro][(int)'/'] = 0;
	_after_state[identifier_intro][(int)']'] = 0;
	_after_state[identifier_intro][(int)'['] = 0;
	_after_state[identifier_intro][(int)','] = 0;


	for (i = 0; i < 256; ++i)
		_after_state[value_intro][i] = &_do_copy_enum_byte;
	_ignore_whitespace_in(_after_state[value_intro]);
	_disallow_ascii_control_in(_after_state[value_intro]);
	_after_state[value_intro][(int)'#'] = &_do_comment_intro;
	_after_state[value_intro][(int)';'] = &_do_value_outro;
	_after_state[value_intro][(int)'"'] = &_do_utf8string_intro;
	_after_state[value_intro][(int)'{'] = &_do_struct_intro;
#if SUPPORT_SYMLINKS
	_after_state[value_intro][(int)'.'] = &_do_copy_symlink_byte;
#else
	_after_state[value_intro][(int)'.'] = 0;
#endif
	_after_state[value_intro][(int)'<'] = &_do_type_intro;
	_after_state[value_intro][(int)'['] = &_do_array_intro;
	_after_state[value_intro][0x00] = &_do_octet_stream_intro;
	_after_state[value_intro][(int)'-'] = &_do_neg_number_intro;
	for (i = (int)'0'; i <= (int)'9'; ++i)
		_after_state[value_intro][i] = &_do_copy_number_byte;
	_after_state[value_intro][(int)'='] = 0;
	_after_state[value_intro][(int)'}'] = 0;
	_after_state[value_intro][(int)'/'] = 0;
	_after_state[value_intro][(int)']'] = 0;
	_after_state[value_intro][(int)','] = 0;


	_ignore_whitespace_in(_after_state[array_intro]);
	_after_state[array_intro][(int)'#'] = &_do_comment_intro;
	_after_state[array_intro][(int)','] = &_do_new_array_value;
	_after_state[array_intro][(int)']'] = &_do_array_outro;
	_after_state[array_intro][(int)'"'] = &_do_arr_utf8string_intro;
	_after_state[array_intro][(int)'-'] = &_do_neg_arr_number_intro;
	for (i = (int)'0'; i <= (int)'9'; ++i)
		_after_state[array_intro][i] = &_do_copy_arr_number_byte;


	_ignore_whitespace_in(_after_state[new_array_value]);
	_after_state[new_array_value][(int)'#'] = &_do_comment_intro;
	_after_state[new_array_value][(int)','] = &_do_new_array_value;
	_after_state[new_array_value][(int)']'] = &_do_array_outro;
	_after_state[new_array_value][(int)'"'] = &_do_arr_utf8string_intro;
	_after_state[new_array_value][(int)'-'] = &_do_neg_arr_number_intro;
	for (i = (int)'0'; i <= (int)'9'; ++i)
		_after_state[new_array_value][i] = &_do_copy_arr_number_byte;


	_ignore_whitespace_in(_after_state[array_outro]);
	_after_state[array_outro][(int)'#'] = &_do_comment_intro;
	_after_state[array_outro][(int)'['] = &_do_array_intro;
	_after_state[array_outro][(int)';'] = &_do_value_outro;


	_ignore_whitespace_in(_after_state[neg_number_intro]);
	_after_state[neg_number_intro][(int)'#'] = &_do_comment_intro;
	for (i = (int)'0'; i <= (int)'9'; ++i)
		_after_state[neg_number_intro][i] = &_do_copy_number_byte;


	_ignore_whitespace_in(_after_state[neg_arr_number_intro]);
	_after_state[neg_arr_number_intro][(int)'#'] = &_do_comment_intro;
	for (i = (int)'0'; i <= (int)'9'; ++i)
		_after_state[neg_arr_number_intro][i] =
			&_do_copy_arr_number_byte;


	_ignore_whitespace_in(_after_state[copy_number_byte]);
	_after_state[copy_number_byte][(int)'#'] = &_do_comment_intro;
	_after_state[copy_number_byte][(int)';'] = &_do_value_outro;
#if SUPPORT_FLOATING_POINT
	_after_state[copy_number_byte][(int)'.'] = &_do_fraction_intro;
#else
	_after_state[copy_number_byte][(int)'.'] = 0;
#endif


	for (i = (int)'0'; i <= (int)'9'; ++i)
		_after_state[copy_number_byte][i] = &_do_copy_number_byte;


	_ignore_whitespace_in(_after_state[fraction_intro]);
	_after_state[fraction_intro][(int)'#'] = &_do_comment_intro;
	for (i = (int)'0'; i <= (int)'9'; ++i)
		_after_state[fraction_intro][i] = &_do_copy_fraction_byte;


	_ignore_whitespace_in(_after_state[copy_fraction_byte]);
	_after_state[copy_fraction_byte][(int)'#'] = &_do_comment_intro;
	_after_state[copy_fraction_byte][(int)';'] = &_do_value_outro;
	for (i = (int)'0'; i <= (int)'9'; ++i)
		_after_state[copy_fraction_byte][i] = &_do_copy_fraction_byte;


	_ignore_whitespace_in(_after_state[copy_arr_number_byte]);
	_after_state[copy_arr_number_byte][(int)'#'] = &_do_comment_intro;
	_after_state[copy_arr_number_byte][(int)','] = &_do_new_array_value;
#if SUPPORT_FLOATING_POINT
	_after_state[copy_arr_number_byte][(int)'.'] =
		&_do_arr_fraction_intro;
#else
	_after_state[copy_arr_number_byte][(int)'.'] = 0;
#endif
	_after_state[copy_arr_number_byte][(int)']'] = &_do_array_outro;
	for (i = (int)'0'; i <= (int)'9'; ++i)
		_after_state[copy_arr_number_byte][i] =
			&_do_copy_arr_number_byte;


	_ignore_whitespace_in(_after_state[arr_fraction_intro]);
	_after_state[arr_fraction_intro][(int)'#'] = &_do_comment_intro;
	for (i = (int)'0'; i <= (int)'9'; ++i)
		_after_state[arr_fraction_intro][i] =
			&_do_copy_arr_fraction_byte;


	_ignore_whitespace_in(_after_state[copy_arr_fraction_byte]);
	_disallow_ascii_control_in(_after_state[copy_arr_fraction_byte]);
	_after_state[copy_arr_fraction_byte][(int)'#'] = &_do_comment_intro;
	_after_state[copy_arr_fraction_byte][(int)']'] = &_do_array_outro;
	for (i = (int)'0'; i <= (int)'9'; ++i)
		_after_state[copy_arr_fraction_byte][i] =
			&_do_copy_arr_fraction_byte;


	_ignore_whitespace_in(_after_state[type_intro]);
	_after_state[type_intro][(int)'#'] = &_do_comment_intro;
	for (i = (int)'a'; i <= (int)'z'; ++i)
		_after_state[type_intro][i] = &_do_copy_type_byte;

	_ignore_whitespace_in(_after_state[copy_type_byte]);
	_after_state[copy_type_byte][(int)'#'] = &_do_comment_intro;
	_after_state[copy_type_byte][(int)'>'] = &_do_type_outro;
	_after_state[copy_type_byte][(int)':'] = &_do_copy_type_byte;
	_after_state[copy_type_byte][(int)'_'] = &_do_copy_type_byte;
	_after_state[copy_type_byte][(int)'-'] = &_do_copy_type_byte;
	_after_state[copy_type_byte][(int)','] = &_do_copy_unit_byte;
	for (i = (int)'0'; i <= (int)'9'; ++i)
		_after_state[copy_type_byte][i] = &_do_copy_type_byte;
	for (i = (int)'a'; i <= (int)'z'; ++i)
		_after_state[copy_type_byte][i] = &_do_copy_type_byte;


	_ignore_whitespace_in(_after_state[type_outro]);
	_after_state[type_outro][(int)'#'] = &_do_comment_intro;
	_after_state[type_outro][(int)'"'] = &_do_utf8string_intro;
	_after_state[type_outro][(int)'['] = &_do_array_intro;
	_after_state[type_outro][(int)'-'] = &_do_neg_number_intro;
	for (i = (int)'0'; i <= (int)'9'; ++i)
		_after_state[type_outro][i] = &_do_copy_number_byte;

	for (i = 0; i < 256; ++i)
		_after_state[copy_unit_byte][i] = &_do_copy_unit_byte;
	_ignore_whitespace_in(_after_state[copy_unit_byte]);
	_disallow_ascii_control_in(_after_state[copy_unit_byte]);
	_after_state[copy_unit_byte][(int)'#'] = &_do_comment_intro;
	_after_state[copy_unit_byte][(int)';'] = &_do_value_outro;
	_after_state[copy_unit_byte][(int)'>'] = &_do_type_outro;
	/* disallow unit containing following */
	_after_state[copy_unit_byte][(int)'.'] = 0;
	_after_state[copy_unit_byte][(int)'{'] = 0;
	_after_state[copy_unit_byte][(int)'}'] = 0;
	_after_state[copy_unit_byte][(int)'"'] = 0;
	_after_state[copy_unit_byte][(int)'/'] = 0;
	_after_state[copy_unit_byte][(int)']'] = 0;
	_after_state[copy_unit_byte][(int)'['] = 0;
	_after_state[copy_unit_byte][(int)','] = 0;
	_after_state[copy_unit_byte][(int)'='] = 0;


	_ignore_whitespace_in(_after_state[value_outro]);
	_after_state[value_outro][(int)'#'] = &_do_comment_intro;
	_after_state[value_outro][(int)'}'] = &_do_struct_outro;
	_after_state[value_outro][(int)'.'] = &_do_identifier_intro;


	for (i = 0; i < 256; ++i)
		_after_state[utf8string_intro][i] = &_do_copy_utf8string_byte;
	_disallow_ascii_control_in(_after_state[utf8string_intro]);
	_after_state[utf8string_intro][(int)'"'] = &_do_utf8string_outro;
	_after_state[utf8string_intro][(int)'\\'] = &_do_escape_from_copy;
	_after_state[utf8string_intro][0xef] = &_do_copy_utf8bom_byte;


	for (i = 0; i < 256; ++i)
		_after_state[copy_utf8string_byte][i] =
			&_do_copy_utf8string_byte;
	_disallow_ascii_control_in(_after_state[copy_utf8string_byte]);
	_after_state[copy_utf8string_byte][(int)'"'] = &_do_utf8string_outro;
	_after_state[copy_utf8string_byte][(int)'\\'] = &_do_escape_from_copy;


	_ignore_whitespace_in(_after_state[utf8string_outro]);
	_after_state[utf8string_outro][(int)'#'] = &_do_comment_intro;
	_after_state[utf8string_outro][(int)'"'] = &_do_utf8string_intro;
	_after_state[utf8string_outro][(int)';'] = &_do_value_outro;


	_after_state[escape_from_copy][(int)'t'] = &_do_replace_escaped_byte;
	_after_state[escape_from_copy][(int)'n'] = &_do_replace_escaped_byte;
	_after_state[escape_from_copy][(int)'v'] = &_do_replace_escaped_byte;
	_after_state[escape_from_copy][(int)'f'] = &_do_replace_escaped_byte;
	_after_state[escape_from_copy][(int)'r'] = &_do_replace_escaped_byte;
	_after_state[escape_from_copy][(int)'"'] = &_do_replace_escaped_byte;
	_after_state[escape_from_copy][(int)'\\'] = &_do_replace_escaped_byte;


	for (i = 0; i < 256; ++i)
		_after_state[arr_utf8string_intro][i] =
			&_do_copy_arr_utf8string_byte;
	_disallow_ascii_control_in(_after_state[arr_utf8string_intro]);
	_after_state[arr_utf8string_intro][(int)'"'] =
		&_do_arr_utf8string_outro;
	_after_state[arr_utf8string_intro][(int)'\\'] =
		&_do_arr_escape_from_copy;
	_after_state[arr_utf8string_intro][0xef] = &_do_copy_utf8bom_byte;


	for (i = 0; i < 256; ++i)
		_after_state[copy_arr_utf8string_byte][i] =
			&_do_copy_arr_utf8string_byte;
	_disallow_ascii_control_in(_after_state[copy_arr_utf8string_byte]);
	_after_state[copy_arr_utf8string_byte][(int)'"'] =
		&_do_arr_utf8string_outro;
	_after_state[copy_arr_utf8string_byte][(int)'\\'] =
		&_do_arr_escape_from_copy;


	_ignore_whitespace_in(_after_state[arr_utf8string_outro]);
	_after_state[arr_utf8string_outro][(int)'#'] = &_do_comment_intro;
	_after_state[arr_utf8string_outro][(int)'"'] =
		&_do_arr_utf8string_intro;
	_after_state[arr_utf8string_outro][(int)','] = &_do_new_array_value;
	_after_state[arr_utf8string_outro][(int)']'] = &_do_array_outro;


	_after_state[arr_escape_from_copy][(int)'t'] =
		&_do_arr_replace_escaped_byte;
	_after_state[arr_escape_from_copy][(int)'n'] =
		&_do_arr_replace_escaped_byte;
	_after_state[arr_escape_from_copy][(int)'v'] =
		&_do_arr_replace_escaped_byte;
	_after_state[arr_escape_from_copy][(int)'f'] =
		&_do_arr_replace_escaped_byte;
	_after_state[arr_escape_from_copy][(int)'r'] =
		&_do_arr_replace_escaped_byte;
	_after_state[arr_escape_from_copy][(int)'"'] =
		&_do_arr_replace_escaped_byte;
	_after_state[arr_escape_from_copy][(int)'\\'] =
		&_do_arr_replace_escaped_byte;


	for (i = 0; i < 256; ++i)
		_after_state[copy_enum_byte][i] = &_do_copy_enum_byte;
	_ignore_whitespace_in(_after_state[copy_enum_byte]);
	_disallow_ascii_control_in(_after_state[copy_enum_byte]);
	_after_state[copy_enum_byte][(int)'#'] = &_do_comment_intro;
	_after_state[copy_enum_byte][(int)';'] = &_do_value_outro;
	_after_state[copy_enum_byte][(int)'='] = 0;
	_after_state[copy_enum_byte][(int)'.'] = 0;
	_after_state[copy_enum_byte][(int)'{'] = 0;
	_after_state[copy_enum_byte][(int)'}'] = 0;
	_after_state[copy_enum_byte][(int)'"'] = 0;
	_after_state[copy_enum_byte][(int)'/'] = 0;
	_after_state[copy_enum_byte][(int)']'] = 0;
	_after_state[copy_enum_byte][(int)'['] = 0;
	_after_state[copy_enum_byte][(int)','] = 0;


	for (i = 0; i < 256; ++i)
		_after_state[copy_symlink_byte][i] = &_do_copy_symlink_byte;
	_ignore_whitespace_in(_after_state[copy_symlink_byte]);
	_disallow_ascii_control_in(_after_state[copy_symlink_byte]);
	_after_state[copy_symlink_byte][(int)'#'] = &_do_comment_intro;
	_after_state[copy_symlink_byte][(int)';'] = &_do_value_outro;
	_after_state[copy_symlink_byte][(int)'='] = 0;
	_after_state[copy_symlink_byte][(int)'{'] = 0;
	_after_state[copy_symlink_byte][(int)'}'] = 0;
	_after_state[copy_symlink_byte][(int)'"'] = 0;
	_after_state[copy_symlink_byte][(int)'/'] = 0;
	_after_state[copy_symlink_byte][(int)']'] = 0;
	_after_state[copy_symlink_byte][(int)'['] = 0;
	_after_state[copy_symlink_byte][(int)','] = 0;


	_ignore_whitespace_in(_after_state[struct_intro]);
	_after_state[struct_intro][(int)'#'] = &_do_comment_intro;
	_after_state[struct_intro][(int)'}'] = &_do_struct_outro;
	_after_state[struct_intro][(int)'.'] = &_do_identifier_intro;


	_ignore_whitespace_in(_after_state[struct_outro]);
	_after_state[struct_outro][(int)'#'] = &_do_comment_intro;
	_after_state[struct_outro][(int)';'] = &_do_value_outro;


	_ignore_whitespace_in(_after_state[octet_stream_outro]);
	_after_state[octet_stream_outro][(int)'#'] = &_do_comment_intro;
	_after_state[octet_stream_outro][(int)';'] = &_do_value_outro;
	return 0;
}

void sdtl_open_write
(sdtl_write_fd_t* w, int fd, int with_whitespace)
{
	memset(w, 0, sizeof(sdtl_write_fd_t));
	w->fd = fd;
	w->white = with_whitespace;
}

int sdtl_flush
(sdtl_write_fd_t* w)
{
	int32_t r = 0;
	uint32_t len = w->next_byte;
	if (len) {
		r = write(w->fd, w->buffer, len);
		((uint32_t)r == len) ? (r = 0) : (r = -1);
		w->next_byte = 0;
	}
	return r;
}

int _write_byte
(sdtl_write_fd_t* c, int byte)
{
	if (c->next_byte == /*sizeof(f->buffer)*/4096) {
		if (sdtl_flush(c))
			return -1;
	}
	c->buffer[c->next_byte] = (unsigned char)byte;
	c->next_byte++;
	return 0;
}

int _write_identifier
(sdtl_write_fd_t* c, const char* id)
{
	int r = 0;
	size_t i, lid;
	uint64_t indent;

	if (!id || !*id)
		return -1;

	if (c->white) {
		for (indent = 0; indent < c->struct_nesting_level; ++indent) {
			r = _write_byte(c, '\t');
			if (r)
				return -1;
		}
	}

	r = _write_byte(c, '.');
	if (r)
		return -1;

	lid = strlen(id);
	for (i = 0; i < lid; ++i) {
		if (
			id[i] == '.' ||
			id[i] == '/' ||
			id[i] == '='
		)
			return -1;

		r = _write_byte(c, id[i]);
		if (r)
			return -1;
	}
	return r;
}

int _write_string
(sdtl_write_fd_t* c, const char* str)
{
	int r = 0;
	size_t i, lstr;

	r = _write_byte(c, '"');
	if (r)
		return -1;

	lstr = strlen(str);
	for (i = 0; i < lstr; ++i) {
		if (str[i] == '"' || str[i] == '\\') {
			r = _write_byte(c, '\\');
			if (r)
				return -1;
		}
		r = _write_byte(c, str[i]);
		if (r)
			return -1;
	}

	r = _write_byte(c, '"');
	if (r)
		return -1;
	return r;
}

int _write_num
(sdtl_write_fd_t* c, const char* num)
{
	int r = 0;
	size_t i, lnum;

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
		if (
			num[i] == ';' ||
			num[i] == '='
		)
			return -1;

		r = _write_byte(c, num[i]);
		if (r)
			return -1;
	}
	return r;
}

int _write_enum
(sdtl_write_fd_t* c, const char* surr)
{
	int r = 0;
	size_t i, lsurr;

	switch (*surr) {
		case ';':
		case '=':
		case '{':
		case '.':
		case '/':
		case '"':
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
			return -1;
		default:
			break;
	}

	lsurr = strlen(surr);
	for (i = 0; i < lsurr; ++i) {
		if (
			surr[i] == ';' ||
			surr[i] == '='
		)
			return -1;

		r = _write_byte(c, surr[i]);
		if (r)
			return -1;
	}
	return r;
}

int _write_symlink
(sdtl_write_fd_t* c, const char* link)
{
	int r = 0;
	size_t i, llink;

	if (*link != '.')
		return -1;

	llink = strlen(link);
	for (i = 0; i < llink; ++i) {
		if (
			link[i] == ';' ||
			link[i] == '='
		)
			return -1;

		r = _write_byte(c, link[i]);
		if (r)
			return -1;
	}
	return r;
}

int _write_end_assignment(sdtl_write_fd_t* c)
{
	int r = 0;

	r = _write_byte(c, ';');
	if (r)
		return -1;
	if (c->white) {
		r = _write_byte(c, '\n');
	}
	return r;
}

int _write_start_assignment(sdtl_write_fd_t* c)
{
	int r = 0;

	if (c->white) {
		r = _write_byte(c, ' ');
		if (r)
			return -1;
	}
	r = _write_byte(c, '=');
	if (r)
		return -1;

	if (c->white) {
		r = _write_byte(c, ' ');
	}
	return r;
}

int sdtl_write_utf8string
(sdtl_write_fd_t* w, const char* key, const char* value)
{
	int r = 0;

	w->last_was_struct = 0;

	r = _write_identifier(w, key);
	if (r)
		return -1;

	r = _write_start_assignment(w);
	if (r)
		return -1;

	if (!value || !*value) {
		return _write_end_assignment(w);
	}

	r = _write_string(w, value);
	if (r)
		return -1;

	r = _write_end_assignment(w);
	if (r)
		return -1;

	return r;
}

int sdtl_write_number
(sdtl_write_fd_t* w, const char* key, const char* value)
{
	int r = 0;

	w->last_was_struct = 0;

	r = _write_identifier(w, key);
	if (r)
		return -1;

	r = _write_start_assignment(w);
	if (r)
		return -1;

	if (!value || !*value)
		return _write_end_assignment(w);

	r = _write_num(w, value);
	if (r)
		return -1;

	r = _write_end_assignment(w);
	if (r)
		return -1;

	return r;
}

int sdtl_write_enum
(sdtl_write_fd_t* w, const char* key, const char* value)
{
	int r = 0;

	w->last_was_struct = 0;

	r = _write_identifier(w, key);
	if (r)
		return -1;

	r = _write_start_assignment(w);
	if (r)
		return -1;

	if (!value || !*value)
		return _write_end_assignment(w);

	r = _write_enum(w, value);
	if (r)
		return -1;

	r = _write_end_assignment(w);
	if (r)
		return -1;

	return r;
}

int sdtl_write_symlink
(sdtl_write_fd_t* w, const char* key, const char* value)
{
	int r = 0;

	w->last_was_struct = 0;

	r = _write_identifier(w, key);
	if (r)
		return -1;

	r = _write_start_assignment(w);
	if (r)
		return -1;

	if (!value || !*value)
		return _write_end_assignment(w);

	r = _write_symlink(w, value);
	if (r)
		return -1;

	r = _write_end_assignment(w);
	if (r)
		return -1;

	return r;
}

int sdtl_write_start_struct
(sdtl_write_fd_t* w, const char* key)
{
	int r = 0;

	if (w->struct_nesting_level == uint8_max)
		return -1;

	if (!w->struct_nesting_level && !w->last_was_struct && w->white) {
		r = _write_byte(w, '\n');
		if (r)
			return -1;
	}

	r = _write_identifier(w, key);
	if (r)
		return -1;
	w->struct_nesting_level++;

	r = _write_start_assignment(w);
	if (r)
		return -1;

	r = _write_byte(w, '{');
	if (r)
		return -1;

	if (w->white) {
		r = _write_byte(w, '\n');
	}

	return r;
}

int sdtl_write_end_struct
(sdtl_write_fd_t* w)
{
	int r = 0;
	uint64_t indent;

	if (!w->struct_nesting_level)
		return -1;

	w->struct_nesting_level--;

	if (w->white) {
		for (indent = 0; indent < w->struct_nesting_level; ++indent) {
			r = _write_byte(w, '\t');
			if (r)
				return -1;
		}
	}

	r = _write_byte(w, '}');
	if (r)
		return -1;

	r = _write_end_assignment(w);
	if (r)
		return -1;

	if (!w->struct_nesting_level && w->white)
		r = _write_byte(w, '\n');

	w->last_was_struct = 1;

	return r;
}

int sdtl_write_start_octet_stream
(sdtl_write_fd_t* w, const char* key)
{
	int r = 0;

	r = _write_identifier(w, key);
	if (r)
		return -1;

	r = _write_start_assignment(w);
	if (r)
		return -1;

	/* flush write buffer, since we use write calls directly when
	 * streaming the chunks onto the destination fd */
	r = sdtl_flush(w);
	if (r)
		return -1;

	w->octet_stream = 1;
	return 0;
}

int sdtl_write_end_octet_stream
(sdtl_write_fd_t* w)
{
	uint32_t zero = 0;

	if (!w->octet_stream)
		return -1;
	w->octet_stream = 0;

	if (write(w->fd, (unsigned char*)&zero, 3) != 3)
		return -1;

	if (_write_end_assignment(w))
		return -1;

	return 0;
}

int sdtl_write_chunk
(sdtl_write_fd_t* w, unsigned char* data, uint16_t len)
{
	char zero = 0;

	if (!w->octet_stream || !len || !data)
		return -1;

	/* TODO: we might want to use writev() here, but it is less
	 * portable */
	if (write(w->fd, (unsigned char*)&zero, 1) != 1)
		return -1;
	/* TODO: make this little endian _always_ */
	if (write(w->fd, (unsigned char*)&len, 2) != 2)
		return -1;
	if (write(w->fd, data, len) != len)
		return -1;
	return 0;
}

#if defined(__cplusplus)
//}
#endif

#include <limits.h>
#include <stdio.h>
#if !defined(_MSC_VER)
#include <inttypes.h>
#else
#define PRIi64	"I64i"
#define PRIu64	"I64u"
#define strtoll _strtoi64
#endif

#if defined(__cplusplus)
//namespace sdtl {
#if !defined (_MSC_VER)
#define PRIi64	"li"
#define PRIu64	"lu"
#endif
#endif

#define _CONF_MAX_STRUCT_NESTING	16
#define _CONF_MAX_FILESIZE_BYTES	16777216

typedef enum conf_array_type {
	array_contains_null,
	array_contains_long_long_int,
	array_contains_char,

	dimension_conf_array_type
} conf_array_type_t;

typedef enum conf_node_type {
	node_is_null,
	node_is_string,
	node_is_enum,
	node_is_integer,
	node_is_struct,
	node_is_array,

	dimension_conf_node_type
} conf_node_type_t;

typedef struct conf_node {
	conf_node_type_t	type;
	conf_array_type_t	array_type;
	char*			name;
	void*			value;
	uint64_t		length;
	uint64_t		items_per_row;
	int			struct_is_not_finalized;
	struct conf_node*	prev_in_scope;
	struct conf_node*	next_in_scope;
} conf_node_t;

typedef struct conf {
	int		sdtl_stream_has_started;
	conf_node_t	root;
	conf_node_t*	workspace;
	uint64_t	current_array_items;
	uint64_t	nopen_scopes;
	conf_node_t*	open_scopes[_CONF_MAX_STRUCT_NESTING+1];
} conf_t;


void _indent_with_tab(size_t level)
{
	while (level) {
		printf("\t");
		level--;
	}
}

void _print_escaped_string(size_t lvl, const char* name, const char* str, int w)
{
	size_t i;
	size_t l = strlen(str);
	if (w) {
		_indent_with_tab(lvl);
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

void _print_escaped_array_string(const char* str)
{
	size_t i;
	size_t l = strlen(str);

	printf("\"");
	for (i = 0; i < l; ++i) {
		if (str[i] == '"' || str[i] == '\\') {
			printf("%c", '\\');
		}
		printf("%c", str[i]);
	}
	printf("\"");
}

void _print_num_array(conf_node_t* n)
{
	uint64_t row, column;
	int64_t* v;
	int64_t** values = (int64_t**)n->value;

	for (row = 0; row < n->length; ++row) {
		printf("[");
		for (column = 0; column < (n->items_per_row-1); ++column) {
			v = values[row*n->items_per_row + column];

			if (v)
				printf("%" PRIi64 ",", *v);
			else
				printf(",");
		}
		v = values[row*n->items_per_row + n->items_per_row-1];
		if (v)
			printf("%" PRIi64 "", *v);

		printf("]");
	}
}

void _print_string_array(conf_node_t* n)
{
	uint64_t row, column;
	char* v;
	char** values = (char**)n->value;

	for (row = 0; row < n->length; ++row) {
		printf("[");
		for (column = 0; column < (n->items_per_row-1); ++column) {
			v = values[row*n->items_per_row + column];

			if (v)
				_print_escaped_array_string(v), printf(",");
			else
				printf(",");
		}
		v = values[row*n->items_per_row + n->items_per_row-1];
		if (v)
			_print_escaped_array_string(v);

		printf("]");
	}
}

void _print_nodes_recursive(size_t level, conf_node_t* first, int w)
{
	conf_node_t* e = first;
	int whitespace = w;
	int64_t i;

	while (e) {
		if (e->type == node_is_struct) {
			/* NOTE: may cause stackoverflow if nesting level
			 * is too high, use an own stack in order to
			 * be able to apply a configurable limit */
			if (whitespace)
				_indent_with_tab(level);
			if (!e->value) {
				/* struct is empty */
				if (whitespace)
					printf(".%s (%" PRIu64
					" members) = {};\n", e->name,
					e->length);
				else
					printf(".%s={};", e->name);
			} else {
				if (whitespace)
					printf(".%s (%" PRIu64
					" members) = {\n", e->name, e->length);
				else
					printf(".%s={", e->name);

				_print_nodes_recursive(level+1,
					(conf_node_t*)e->value, whitespace);
				if (whitespace) {
					_indent_with_tab(level);
					printf("};\n");
				} else
					printf("};");
			}
		}
		else if (e->type == node_is_null) {
			if (whitespace) {
				_indent_with_tab(level);
				printf(".%s = ;\n", e->name);
			} else
				printf(".%s=;", e->name);
		} else if (e->type == node_is_string) {
			_print_escaped_string(level, e->name,
				(const char*)e->value, whitespace);
		} else if (e->type == node_is_integer) {
			i = *(int64_t*)e->value;
			if (whitespace) {
				_indent_with_tab(level);
				printf(".%s = %" PRIi64 ";\n", e->name, i);
			} else
				printf(".%s=%" PRIi64 ";", e->name, i);
		} else if (e->type == node_is_array) {
			if (whitespace) {
				_indent_with_tab(level);
				printf(".%s (%" PRIu64 "x%" PRIu64 ") = ",
					e->name, e->items_per_row, e->length);
				if (e->array_type ==
				array_contains_long_long_int)
					_print_num_array(e);
				else
					_print_string_array(e);
				printf("; (type: %d) \n", e->array_type);
			} else
				printf(".%s=[];", e->name);
		}
		e = e->next_in_scope;
	}
}

void _print_nodes(conf_t* c, int use_whitespace)
{
	printf("root has %" PRIu64 " members\n", c->root.length);
	_print_nodes_recursive(0, (conf_node_t*)c->root.value, use_whitespace);
}

int _start_new_node(conf_t* c, const char* name, uint16_t length)
{
	conf_node_t* previous_node = c->workspace;

	c->workspace = (conf_node_t*) calloc(1, sizeof(conf_node_t));
	if (!c->workspace)
		return -1;

	c->workspace->name = (char*) malloc(length+1);
	if (!c->workspace->name)
		return -1;
	memmove(c->workspace->name, name, length+1);
	c->workspace->prev_in_scope = previous_node;

	if (previous_node->struct_is_not_finalized && !previous_node->value) {
		previous_node->value = c->workspace;
	} else {
		previous_node->next_in_scope = c->workspace;
	}

	return 0;
}

void _increase_current_struct_member_count(conf_t* c)
{
	conf_node_t* current_scope = c->open_scopes[c->nopen_scopes-1];
	current_scope->length++;
}

int _enter_scope(conf_t* c)
{
	/* full */
	if (c->nopen_scopes == sizeof(c->open_scopes)/sizeof(conf_node_t*)) {
		return -1;
	}
	c->workspace->type = node_is_struct;
	c->workspace->length = 0;
	c->workspace->struct_is_not_finalized = 1;
	c->open_scopes[c->nopen_scopes] = c->workspace;
	c->nopen_scopes++;
	return 0;
}

int _leave_scope(conf_t* c)
{
	/* empty */
	if (!c->nopen_scopes)
		return -1;
	c->nopen_scopes--;
	c->workspace = c->open_scopes[c->nopen_scopes];
	c->workspace->struct_is_not_finalized = 0;
	return 0;
}

int _add_data(conf_t* c, sdtl_data_t* data)
{
	int64_t i;
	char* end = 0;
	void* tmp;
	int64_t** ip_array;
	char** cp_array;
	void** vp_array;
	uint64_t item;

	if (c->workspace->type == node_is_array) {
		if (c->workspace->array_type == array_contains_null) {
			if (data->type == datatype_utf8string)
				c->workspace->array_type = array_contains_char;
			if (data->type == datatype_number)
				c->workspace->array_type =
					array_contains_long_long_int;
		}

		tmp = realloc(c->workspace->value,
			c->current_array_items*sizeof(void*));
		if (!tmp)
			return -1;
		c->workspace->value = tmp;
		item = c->current_array_items - 1;

		if (data->type == datatype_null_value) {
			vp_array = (void**)(c->workspace->value);
			vp_array[item] = 0;
		}

		if (data->type == datatype_utf8string) {
			cp_array = (char**)(c->workspace->value);
			cp_array[item] = (char*) malloc(data->length + 1);
			if (!cp_array[item])
				return -1;
			memmove(cp_array[item], data->data, data->length + 1);
		}

		if (data->type == datatype_number) {
			ip_array = (int64_t**)(c->workspace->value);
			ip_array[item] = (int64_t*) malloc(sizeof(int64_t));
			if (!ip_array[item])
				return -1;
			end = 0;
			i = (int64_t)strtoll((const char*)data->data, &end, 0);
			if ((!end) || (*end != 0) ||
			(i == LLONG_MIN) || (i == LLONG_MAX)) {
				return -1;
			}
			memmove(ip_array[item], &i, sizeof(int64_t));
		}

		return 0;
	}

	switch (data->type) {
		/* note: we ignore data->value_type (the type tag) here
		 * and assume following defaults:
		 * - strings are interpreted as SDTL default, which is UTF-8
		 * - integers are stored as int64_t with correspondent range
		 * limitations
		 * */
		case datatype_utf8string:
			c->workspace->type = node_is_string;
			c->workspace->length = data->length + 1;
			c->workspace->value = malloc(c->workspace->length);
			if (!c->workspace->value)
				return -1;
			memmove(c->workspace->value, data->data,
				c->workspace->length);
			break;
		case datatype_number:
			c->workspace->type = node_is_integer;
			c->workspace->length = sizeof(int64_t);
			c->workspace->value = malloc(c->workspace->length);
			if (!c->workspace->value)
				return -1;

			end = 0;
			i = (int64_t)strtoll((const char*)data->data, &end, 0);
			if ((!end) || (*end != 0) ||
			(i == LLONG_MIN) || (i == LLONG_MAX)) {
				return -1;
			}
			memmove(c->workspace->value, &i, c->workspace->length);
			break;
		case datatype_unit:
			/* note: we don't care about units for now */
			break;
		case datatype_null_value:
			c->workspace->type = node_is_null;
			c->workspace->length = 0;
			c->workspace->value = 0;
			break;
		case datatype_enum:
			c->workspace->type = node_is_enum;
			c->workspace->length = data->length + 1;
			c->workspace->value = malloc(c->workspace->length);
			if (!c->workspace->value)
				return -1;
			memmove(c->workspace->value, data->data,
				c->workspace->length);
			break;
		case datatype_symlink:
		case datatype_octet_stream:
		default:
			return -1;
	}
	return 0;
}

int _on_sdtl_event(void* userdata, sdtl_event_t e, sdtl_data_t* data)
{
	conf_t* c = (conf_t*)userdata;

	if (!c->sdtl_stream_has_started) {
		if (e != ev_assignment_start)
			return -1;
		c->root.type = node_is_struct;
		c->root.name = (char*)(const char*)"";
		c->root.value = 0;
		c->root.length = 0;
		c->root.struct_is_not_finalized = 1;
		c->root.next_in_scope = 0;
		c->root.prev_in_scope = 0;
		c->workspace = &c->root;
		c->nopen_scopes = 0;
		c->open_scopes[c->nopen_scopes] = &c->root;
		c->nopen_scopes++;
		c->sdtl_stream_has_started = 1;
	}

	switch (e) {
		case ev_assignment_start:
			c->current_array_items = 0;
			_increase_current_struct_member_count(c);
			return _start_new_node(c, (char*)data->data,
				data->length);
		case ev_data:
			if (c->workspace->type == node_is_array)
				c->current_array_items++;
			return _add_data(c, data);
		case ev_struct_start:
			return _enter_scope(c);
		case ev_struct_end:
			return _leave_scope(c);
		case ev_array_new_row:
			c->workspace->length++;
			c->workspace->type = node_is_array;
			break;
		case ev_array_end_row:
			if (!c->workspace->items_per_row) {
				c->workspace->items_per_row =
					c->current_array_items;
			}
			break;
		/* disallow octet streams in config files */
		case ev_octet_stream_start:
		case ev_octet_stream_end:
		default:
			return -1;
	}

	return 0;
}

void _free_array_values(conf_node_t* n)
{
	uint64_t row, column;
	void* v;
	void** values = (void**)n->value;

	for (row = 0; row < n->length; ++row) {
		for (column = 0; column < n->items_per_row; ++column) {
			v = values[row*n->items_per_row + column];
			if (v)
				free(v);
		}
	}
}

void _free_nodes_recursive(conf_node_t* first)
{
	conf_node_t* e = first;
	conf_node_t* n = 0;

	while (e) {
		if (e->type == node_is_struct) {
			if (e->value) {
				_free_nodes_recursive((conf_node_t*)e->value);
				free(e->value);
			}
			free(e->name);
		}
		else if (e->type == node_is_null) {
			free(e->name);
		} else if (e->type == node_is_string) {
			free(e->name);
			free(e->value);
		} else if (e->type == node_is_enum) {
			free(e->name);
			free(e->value);
		} else if (e->type == node_is_integer) {
			free(e->name);
			free(e->value);
		} else if (e->type == node_is_array) {
			_free_array_values(e);
			free(e->name);
			free(e->value);
		}
		n = e->next_in_scope;
		if (e != first) {
			free(e);
		}
		e = n;
	}
}

void conf_cleanup(conf_t* c)
{
	_free_nodes_recursive((conf_node_t*)c->root.value);
	free(c->root.value);
	memset(c, 0, sizeof(conf_t));
}

int conf_read_fd(conf_t* c, int fd)
{
	sdtl_read_fd_t rfd;
	sdtl_read_flags_t opts;

	memset(c, 0, sizeof(conf_t));
	memset(&opts, 0, sizeof(sdtl_read_flags_t));
	opts.on_event = &_on_sdtl_event;
	opts.userdata = c;
	opts.max_struct_nesting = _CONF_MAX_STRUCT_NESTING;
	opts.max_file_size = opts.max_text_bytes = _CONF_MAX_FILESIZE_BYTES;

	if (sdtl_open_read(&rfd, fd, &opts)) {
		return -1;
	}
	if (sdtl_read(&rfd)) {
		fprintf(stderr, "the parser has interrupted its work "
			"(error %d) @ '%c'\n", sdtl_get_error(&rfd), rfd.byte);
		return -1;
	}

	return 0;
}

int conf_read(conf_t* c, const char* filename)
{
	int fd;

	fd = open(filename, O_RDONLY | O_NOATIME);
	if (fd < 0)
		return -1;
	return conf_read_fd(c, fd);
}

const conf_node_t*
_get_conf_node_flat(const conf_node_t* parent_struct, const char* name)
{
	const conf_node_t* e = parent_struct;

	if (!name || !*name || (*name == '.'))
		return 0;

	while (e) {
		if (!strcmp(e->name, name))
			break;
		e = e->next_in_scope;
	}
	return e;
}

const conf_node_t* conf_get_conf_node(const conf_t* c, const char* path)
{
	char* abspath, *component, *temp;
	const conf_node_t* first = (const conf_node_t*)c->root.value;
	const conf_node_t* curr_node = first;
	const conf_node_t* e = 0;
	const conf_node_t* r = 0;

	/* only allow absolute paths (starting with dot) at the moment */
	if (!path || !*path || (*path != '.'))
		return 0;

	/* special root member case */
	if (!strcmp(path, ".")) {
		return &c->root;
	}

	/* path mustn't end with '.', exception is a single dot for the root
	 * structure */
	if (*(strrchr(path, 0)-1) == '.')
		return 0;

	abspath = strdup(path);
	if (!abspath)
		return 0;

	temp = abspath;
	while ((component = strtok(temp, "."))) {
		temp = 0;

		if (r) {
			if (r->type == node_is_struct) {
				/* dive into structure */
				curr_node = (conf_node_t*)r->value;
			} else {
				/* The current node is not a structure, but
				 * we still have components in the path.
				 * This is exactly ENOTDIR in the context
				 * of POSIX paths. */
				r = 0;
				break;
			}
		}
		e = _get_conf_node_flat(curr_node, component);
		if (!e) {
			/* no such structure member in curr_node */
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

const char* conf_get_utf8string_by_key(const conf_t* c, const char* key)
{
	const conf_node_t* key_node = 0;

	if (!c || !c->root.value)
		return 0;

	key_node = conf_get_conf_node(c, key);
	if (!key_node)
		return 0;

	if (key_node->type == node_is_string)
		return (const char*) key_node->value;
	else
		return 0;
}

const char* conf_get_enum_by_key(const conf_t* c, const char* key)
{
	const conf_node_t* key_node = 0;

	if (!c || !c->root.value)
		return 0;

	key_node = conf_get_conf_node(c, key);
	if (!key_node)
		return 0;

	if (key_node->type == node_is_enum)
		return (const char*) key_node->value;
	else
		return 0;
}

const char** conf_get_utf8string_array_by_key
(const conf_t* c, const char* key, uint64_t* rows, uint64_t* columns)
{
	const conf_node_t* key_node = 0;

	if (!c || !c->root.value)
		return 0;

	key_node = conf_get_conf_node(c, key);
	if (!key_node)
		return 0;

	if (key_node->type == node_is_array &&
	key_node->array_type == array_contains_char) {
		if (rows)
			*rows = key_node->length;
		if (columns)
			*columns = key_node->items_per_row;
		return (const char**) key_node->value;
	} else
		return 0;
}

const int64_t* conf_get_int64_by_key(const conf_t* c, const char* key)
{
	const conf_node_t* key_node = 0;

	if (!c || !c->root.value)
		return 0;

	key_node = conf_get_conf_node(c, key);
	if (!key_node)
		return 0;

	if (key_node->type == node_is_integer)
		return (int64_t*)key_node->value;
	else
		return 0;
}

const int64_t** conf_get_int64_array_by_key
(const conf_t* c, const char* key, uint64_t* rows, uint64_t* columns)
{
	const conf_node_t* key_node = 0;

	if (!c || !c->root.value)
		return 0;

	key_node = conf_get_conf_node(c, key);
	if (!key_node)
		return 0;

	if (key_node->type == node_is_array &&
	key_node->array_type == array_contains_long_long_int) {
		if (rows)
			*rows = key_node->length;
		if (columns)
			*columns = key_node->items_per_row;
		return (const int64_t**) key_node->value;
	} else
		return 0;
}

#if defined(__cplusplus)
//}
#endif

#endif /* _CONFIGFILE_H */
