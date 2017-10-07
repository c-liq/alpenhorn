#include <netinet/in.h>
#include "utils.h"
#include <math.h>
#include <time.h>

void printhex(char *msg, uint8_t *data, size_t len)
{
	size_t hex_len = len * 2 + 1;
	char hex_str[hex_len];
	sodium_bin2hex(hex_str, hex_len, data, len);
	printf("%s: %s\n", msg, hex_str);
}

/*void serialize_uint32(uint8_t *out, uint32_t in) {
  uint32_t network_in = htonl(in);
	memcpy(out, &network_in, sizeof network_in);
}

uint32_t deserialize_uint32(uint8_t *in) {
  uint32_t *ptr = (uint32_t *) in;
	return ntohl(*ptr);
}*/

uint64_t sizeof_serialized_bytes(uint64_t size)
{
	return size * 2 + 1;
}

void serialize_u64(uint8_t *out, uint64_t input)
{
	out[0] = (uint8_t) (input >> 56);
	out[1] = (uint8_t) (input >> 48);
	out[2] = (uint8_t) (input >> 40);
	out[3] = (uint8_t) (input >> 32);
	out[4] = (uint8_t) (input >> 24);
	out[5] = (uint8_t) (input >> 16);
	out[6] = (uint8_t) (input >> 8);
	out[7] = (uint8_t) (input >> 0);
}

uint64_t deserialize_uint64(uint8_t *in)
{
	uint64_t *ptr = (uint64_t *) in;
	return be64toh(*ptr);
}




void get_current_time(char *out_buffer)
{
	long millisec;
	struct tm *tm_info;
	struct timeval tv;
	char buffer[50];
	gettimeofday(&tv, NULL);

	millisec = lrint(tv.tv_usec / 1000.0); // Round to nearest millisec
	if (millisec >= 1000) { // Allow for rounding up to nearest second
		millisec -= 1000;
		tv.tv_sec++;
	}

	tm_info = localtime(&tv.tv_sec);

	strftime(buffer, 26, "%Y:%m:%d %H:%M:%S", tm_info);
	sprintf(out_buffer, "%s.%03ld\n", buffer, millisec);
}



uint64_t laplace_rand(laplace_s *l)
{
	double rand = ((double)(randombytes_random() % 10000) / 10000) - 0.5;
	int sign;
	double abs;
	if (rand < 0) {
		abs = -rand;
		sign = -1;
	}
	else {
		abs = rand;
		sign = 1;
	}
	double lv = log(1 - (2 * abs));
	lv *= sign;
	lv *= l->b;
	lv = l->mu - lv;
	if (lv < 0) {
		return laplace_rand(l);
	}
	return (uint64_t) lv;
}

double get_time()
{
	struct timeval t;
	struct timezone tzp;
	gettimeofday(&t, &tzp);
	return t.tv_sec + t.tv_usec * 1e-6;
}

