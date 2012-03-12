#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <alloca.h>

#include <execinfo.h>


#include "trace.h"

static
void translate_linux(void* address, const char* symbol)
{
	/* <name>(<function>) [address] */
	char* fstart = strchr(symbol, '(');
	char* fend = strchr(symbol, ')');
	char* fname = 0;
	char* ename = 0;
	char* cmdline;
	char buf[80];
	char buf2[80];
    FILE* proc;

	if (fstart == 0 || fend == 0) {
		return;
	}
	fname = alloca(fend - fstart);
	memcpy(fname, fstart + 1, fend - fstart - 1);
	fname[fend - fstart - 1] = 0;

	ename = alloca(fstart - symbol);
	memcpy(ename, symbol, fstart - symbol);
	ename[fstart - symbol] = 0;

	cmdline = alloca(128);
	*cmdline = 0;
	sprintf(cmdline, "addr2line -f -e %s %p", ename, address);

	proc = popen(cmdline, "r");

    buf[0] = 0;
    buf2[0] = 0;
	fgets(buf2, sizeof(buf2), proc);
 	buf2[strlen(buf2) - 1] = 0;
    fgets(buf, sizeof(buf), proc);
	buf[strlen(buf) - 1] = 0;
    if (buf2[0] != '?') {
    	fname = buf2;
    }
    if (*buf == 0 || *buf == '?') {
		fprintf(stderr, "\t%s(%s) [%p]\n", ename, fname, address);
    } else {
    	fprintf(stderr, "\t%s(%s) [%p]\n", buf, buf2, address);
    }
    pclose(proc);

}

static
void translate(void* address, const char* symbol)
{
	translate_linux(address, symbol);
}

void printtrace(void* ctx)
{
    ucontext_t* context = (ucontext_t*) ctx;
	void* buf[40];
 	char**s;
	int length;
	int i;
    int skip = 0;
    void* c = 0;

	if (context != 0) {
		/*skip = 2;
		c = (void*)context->uc_mcontext.gregs[REG_EIP]; *//*TODO: crossplatform*/
		skip = 2;
		c = 0;
	}

	length = backtrace(buf, sizeof(buf) / sizeof(void*) - 1);
	if (skip > 0 && length > skip) {
		memmove(buf, buf + skip, length - skip);
		length -= skip;
	}
	if (c != 0) {
		memmove(buf + 1, buf, length * sizeof(void*));
		++length;
		buf[0] = c;
	}
	fprintf(stderr, "##Trace:");
	for (i = 0; i < length; ++i) {
		fprintf(stderr, " %p", buf[i]);
	}
	fprintf(stderr, "##\n");
	s = backtrace_symbols(buf, length);

	for (i = 0; i < length; ++i) {
    	translate(buf[i], s[i]);
	}
 	free(s);
}
