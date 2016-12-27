#ifndef __TEST
#define __TEST


enum TEST {
	TEST_MSS_SIGN,
	TEST_AES_ENC,
#ifdef SERIALIZATION
	TEST_MSS_SERIALIZATION
#endif
};

#define TEST_OK 1
#define TEST_FALSE 0

unsigned short do_test(enum TEST operation);

#endif // __TEST
