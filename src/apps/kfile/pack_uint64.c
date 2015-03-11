#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include "dumphx.h"

uint8_t get_pack_size(uint64_t n)
{
	/* is there a more efficient algorithm? */
	if (n <= 0xff)
		return 1;
	if (n <= 0xffff)
		return 2;
	if (n <= 0xffffff)
		return 3;
	if (n <= 0xffffffff)
		return 4;
	if (n <= 0xffffffffff)
		return 5;
	if (n <= 0xffffffffffff)
		return 6;
	if (n <= 0xffffffffffffff)
		return 7;
	if (n <= 0xffffffffffffffff)
		return 8;
}

size_t pack_uint64(uint64_t n, unsigned char* out)
{
	uint8_t pack_size = get_pack_size(n);

	out[0] = pack_size - 1;
	memcpy(out + 1, &n, pack_size);

	return pack_size + 1;
}

uint64_t unpack_uint64(unsigned char* in)
{
	uint64_t r = 0;
	uint8_t pack_size = in[0] + 1;

	memcpy(&r, in + 1, pack_size);
	return r;
}


int main(int argc, char* argv[], char* envp[])
{
	unsigned char m[257];
	size_t n;

	uint64_t in = 43216546;
	uint64_t out;


	n = pack_uint64(in, m);
	dumphx("in", m, n);

	out = unpack_uint64(m);
	printf("out: '0x%.16lx' '%" PRIu64 "'\n", out, out);


	return 0;
}
