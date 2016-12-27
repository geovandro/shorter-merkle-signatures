#ifndef __BENCH
#define __BENCH


enum BENCH {
	BENCH_MSS_SIGN,
	BENCH_HASH
};

void do_bench(enum BENCH operation);
void bench_hash();

#endif // __BENCH
