#ifndef TIME_THIS_H
#define TIME_THIS_H 1

#include <sys/time.h>
#include <sys/resource.h>

static long time_this(void (*proc)(), unsigned count) {
	struct rusage start, end;
	getrusage(RUSAGE_SELF, &start);
	while (count--)
		proc();
	getrusage(RUSAGE_SELF, &end);
	return (end.ru_utime.tv_sec - start.ru_utime.tv_sec) * 1000000
	     + (end.ru_utime.tv_usec - start.ru_utime.tv_usec);
}

#endif
