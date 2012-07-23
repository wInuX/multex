#ifndef __FALLOC_H__
#define __FALLOC_H__

#include <stddef.h>
#include <setjmp.h>

struct pool {
    void* (*alloc)(void *pool, size_t size);
    void (*free)(void *pool, void *p);
	jmp_buf *outofmemory;
};

struct fpool {
    struct pool pool;

	char* buf;
	char* s;
	char* e;
};

struct mpool {
    struct pool pool;
};

void *palloc(struct pool *pool, size_t size);
void pfree(struct pool *pool, void* p);
char *pstrdup(struct pool *pool, const char *p);
void *pmemdup(struct pool *pool, const void *p, size_t length);
char *pstrcreate(struct pool *pool, const char *p, size_t length);

struct pool *fcreate(struct fpool* pool, char* buf, size_t size, jmp_buf *outofmemory);
struct pool *mcreate(struct mpool* pool, jmp_buf *outofmemory);

#endif
