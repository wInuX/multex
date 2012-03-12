#ifndef __CHECK_H__
#include <check.h>
#include <errno.h>
#include <memory.h>
#include <string.h>
#include <alloca.h>

const char* fail_message_i(const char* zero, const char* format, ...);

void assert_fail_m(const char* message, ...);

const char* show_memory(const char* value, size_t length, char* d);



#define assert_null(V, ...) { \
	const void* _tmp_ = V; \
	if (_tmp_ != 0) { \
		assert_fail_m("<" #V "> is not NULL. (%x)%s\n", _tmp_, fail_message_i(0, ##__VA_ARGS__, 0)); \
	}\
}

#define assert_not_null(V, ...) { \
	const void* _tmp_ = V; \
	if (_tmp_ == 0) { \
		assert_fail_m("<" #V "> is NULL. (%x)%s\n", _tmp_, fail_message_i(0, ##__VA_ARGS__, 0)); \
	}\
}

#define assert_op(V, O, E, T, F, ...) { \
	T _v_ = V; \
	T _e_ = E; \
	if (!(_v_ O _e_)) { \
		assert_fail_m("<" #V "> " #O " <" #E ">. Expected " F " but was " F "\n%s", _e_, _v_, fail_message_i(0, ##__VA_ARGS__, 0)); \
	}\
}
#define assert_unsigned_op(V, O, E, ...) assert_op(V, O, E, unsigned long int, "%lu", ##__VA_ARGS__)
#define assert_signed_op(V, O, E, ...) assert_op(V, O, E, signed long int, "%ld", ##__VA_ARGS__)

#define assert_signed_eq(V, E, ...)  assert_signed_op(V, ==, E, ##__VA_ARGS__)
#define assert_unsigned_eq(V, E, ...) assert_unsigned_op(V, ==, E, ##__VA_ARGS__)

#define assert_signed_ge(V, E, ...)  assert_signed_op(V, >=, E, ##__VA_ARGS__)
#define assert_unsigned_ge(V, E, ...) assert_unsigned_op(V, >=, E, ##__VA_ARGS__)
#define assert_signed_le(V, E, ...)  assert_signed_op(V, <=, E, ##__VA_ARGS__)
#define assert_unsigned_le(V, E, ...) assert_unsigned_op(V, <=, E, ##__VA_ARGS__)
#define assert_signed_g(V, E, ...)  assert_signed_op(V, >, E, ##__VA_ARGS__)
#define assert_unsigned_g(V, E, ...) assert_unsigned_op(V, >, E, ##__VA_ARGS__)
#define assert_signed_l(V, E, ...)  assert_signed_op(V, <, E, ##__VA_ARGS__)
#define assert_unsigned_l(V, E, ...) assert_unsigned_op(V, <, E, ##__VA_ARGS__)


#define assert_signed_ne(V, E, ...)  assert_signed_op(V, !=, E, ##__VA_ARGS__)
#define assert_unsigned_ne(V, E, ...) assert_unsigned_op(V, !=, E, ##__VA_ARGS__)

#define assert_hex_eq(V, E, ...) assert_op(V, ==, E, unsigned long int, "%lx", ##__VA_ARGS__)
#define assert_ref_eq(V, E, ...) assert_op(V, ==, E, const void*, "%p", ##__VA_ARGS__)

#define assert_char_eq(V, E, ...) assert_op(V, ==, E, char, "%c", ##__VA_ARGS__)

#define assert_str_eq(V, E, ...) { \
	const char* _v_ = (V); \
	const char* _e_ = (E); \
	if (_v_ != _e_) { \
		if (_v_ == 0 || _e_ == 0) { \
            assert_fail_m("<" #V "> != <" #E ">. Expected '%s' but was '%s' %s\n", _e_, _v_, fail_message_i(0, ##__VA_ARGS__, 0)); \
		} else \
		if (strcmp(_v_, _e_ ) != 0) { \
			assert_fail_m("<" #V "> != <" #E ">. Expected '%s' but was '%s' %s\n", _e_, _v_, fail_message_i(0, ##__VA_ARGS__, 0)); \
		}\
	} \
}

#define assert_true(V, ...) { \
	int _tmp_ = (V) != 0; \
	if (_tmp_ == 0) { \
		assert_fail_m("<" #V "> is false. %s\n", fail_message_i(0, ##__VA_ARGS__, 0)); \
	}\
}

#define assert_false(V, ...) { \
	int _tmp_ = (V) != 0; \
	if (_tmp_ != 0) { \
		assert_fail_m("<" #V "> is true. %s\n", fail_message_i(0, ##__VA_ARGS__, 0)); \
	}\
}

#define assert_fail(...) { \
	assert_fail_m("Failed. %s\n", fail_message_i(0, ##__VA_ARGS__, 0)); \
}

#define assert_errno(V, ...) { \
	if ((V) == 0) { \
		assert_fail_m("syscall failed: %s. %s\n", strerror(errno), fail_message_i(0, ##__VA_ARGS__, 0)); \
	}\
}

#define assert_mem_eq(V, VL, E, EL, ...) while (1) { \
	char* s_src; \
	char* s_expected; \
	size_t vlength = (VL); \
	size_t elength = (EL); \
	const void* v = (V); \
	const void* expected = (E); \
	if (vlength == elength) { \
		if (memcmp(v, expected, vlength) == 0) { \
			break; \
		} \
	} \
	s_src = alloca(vlength * 4 + 1); \
	s_expected = alloca(elength * 4 + 1); \
	assert_fail_m("Expected [%d]%s but was [%d]%s.%s\n", \
		(int)elength, show_memory((const char*)expected, elength, s_expected), \
		(int) vlength, show_memory((const char*)v, vlength, s_src), fail_message_i(0, ##__VA_ARGS__, 0)); \
}

void install_signals(void);


void* assert_alloc(size_t length);
void assert_free(void*);

#endif