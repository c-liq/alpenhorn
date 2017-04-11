//

#ifndef ALPENHORN_TEST_UTILS_H
#define ALPENHORN_TEST_UTILS_H
#include <sys/time.h>
double get_time()
{
	struct timeval t;
	struct timezone tzp;
	gettimeofday(&t, &tzp);
	return t.tv_sec + t.tv_usec * 1e-6;
}
#endif //ALPENHORN_TEST_UTILS_H
