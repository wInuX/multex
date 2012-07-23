#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "falloc.h"

static void* falloc(struct fpool *pool, size_t size);
static void ffree(struct fpool *pool, void *p);

static void* mmalloc(struct mpool *pool, size_t size);
static void mmfree(struct mpool *pool, void *p);

struct pool *fcreate(struct fpool *pool, char* buf, size_t size, jmp_buf *outofmemory) {
	pool->pool.alloc = (void*)falloc;
	pool->pool.free = (void*)ffree;
	pool->pool.outofmemory = outofmemory;
	pool->buf = buf;
	pool->s = buf;
	pool->e = buf + size;
	return &pool->pool;
}

static void* falloc(struct fpool *pool, size_t size) {
	char *r = pool->s;
	if (pool->e - pool->s < size) {
		return 0;
	}
	size = (size + 15) & ~0xf;
	pool->s += size;
	return r;
}

static void ffree(struct fpool *pool, void *p) {
    // nothing to do
}

struct pool *mcreate(struct mpool *pool, jmp_buf *outofmemory) {
	pool->pool.alloc = (void*)mmalloc;
	pool->pool.free = (void*)mmfree;
	pool->pool.outofmemory = outofmemory;
	return &pool->pool;
}


void *mmalloc(struct mpool *pool, size_t size) {
    return malloc(size);
}

void mmfree(struct mpool *pool, void* p) {
    free(p);
}



void *palloc(struct pool *pool, size_t size) {
    void *r;
    r = pool->alloc(pool, size);
    if (r == 0) {
        if (pool->outofmemory != 0) {
            longjmp(*pool->outofmemory, 0);
        } else {
            fprintf(stderr, "Out of pool memory\n");
            abort();
        }
    }
}

void pfree(struct pool *pool, void* p) {
    assert(pool);
    assert(p);

    pool->free(pool, p);
}


char* pstrdup(struct pool *pool, const char* p) {
    assert(pool);
    assert(p);

    return strcpy(palloc(pool, strlen(p) + 1), p);
}

void *pmemdup(struct pool *pool, const void *p, size_t length) {
    assert(pool);
    assert(p);

    char *r = palloc(pool, length);
    memcpy(r, p, length);
    return r;
}

char *pstrcreate(struct pool *pool, const char *p, size_t length) {
    assert(pool);
    assert(p);

    char *r = palloc(pool, length + 1);
    memcpy(r, p, length);
    r[length] = 0;
    return r;
}