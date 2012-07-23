#include <memory.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <alloca.h>
#include <execinfo.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "trace.h"
#include "acheck.h"

struct block;
struct block {
	struct block* next;
	struct block* prev;
    size_t length;
    void* stack[20];
    int stack_size;
};

static struct block* head = 0;

void show_error(const char* message, va_list list)
{
	fprintf(stderr, "ASSERTION ERROR: ");
	vfprintf(stderr, message, list);
	printtrace(0);
 	abort();
}

static char message[1024];
const char* fail_message_i(const char* zero, const char* format, ...)
{
	va_list va_list;
	if (format == 0) {
		return "";
	}
	va_start(va_list, format);
	strcpy(message, "Message: ");
	vsnprintf(message + strlen(message), sizeof(message) - strlen(message), format, va_list);
	va_end(va_list);
	return message;
}

void assert_fail_m(const char* message, ...)
{
	va_list list;
	va_start(list, message);
	show_error(message, list);
	va_end(list);
}


const char* show_memory(const char* value, size_t length, char* d) {
	char* p = d;
	size_t i;
	for (i = 0; i < length; ++i, value++) {
		if (*value < 0x20 || (unsigned char) *value >= 0x80) {
		    *p++ = '\\';
		    *p++ = '0' + ((*value >> 6) & 0x3);
		    *p++ = '0'+ ((*value >> 3) & 0x7);
		    *p++ = '0' + (*value & 0x7);
		} else {
			*p++ = *value;
		}
	}
	*p = 0;
	return d;
}

void sighandler(int signal, siginfo_t* info, void *p)
{
	fprintf(stderr, "SIGNAL RECEIVED %d\n", signal);
	printtrace(p);
	exit(1);
}

void install_signals(void)
{
	struct sigaction action;
    int r;

	memset(&action, 0, sizeof(action));
	action.sa_sigaction = sighandler;
	sigemptyset (&action.sa_mask);
	action.sa_flags = SA_SIGINFO;

	r = sigaction(SIGABRT, &action, 0);
	r = sigaction(SIGSEGV, &action, 0);
	r = sigaction(SIGBUS, &action, 0);
	r = sigaction(SIGFPE, &action, 0);

	assert_errno(r == 0);
}

void* assert_alloc(size_t length)
{
	char* r;
	struct block *block;

	char *header;
	char *trailer;

	r = malloc(length + sizeof(struct block) + 16);
	assert_not_null(r);
	block = (struct block *)r;

	header =  r + sizeof(struct block);
	trailer = r + sizeof(struct block) + 8 + length;

    memcpy(header,  "HEADER00", 8);
    memcpy(trailer, "TRAILER0", 8);
	if (head == 0) {
		head = malloc(sizeof(struct block));
		head->next = head;
		head->prev = head;
	}
	head->prev->next = block;
	block->prev = head->prev;
	head->prev = block;
	block->next = head;

	block->length = length;

	block->stack_size = backtrace(block->stack, sizeof(block->stack) / sizeof(void*));
	return r + sizeof(struct block) + 8;
}

void assert_free(void* data) {
	struct block* p;
	if (head == 0) {
		head = malloc(sizeof(struct block));
		head->next = head;
		head->prev = head;
	}
	p = head->next;
	while (p != head) {
		char* r = (char*)p + sizeof(struct block) + 8;
		if (r == data) {
			p->next->prev = p->prev;
			p->prev->next = p->next;
			free(p);
			return;
		}
		p = p->next;
	}

	assert_fail_m("Block not allocated");

}
