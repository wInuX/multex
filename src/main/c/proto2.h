#ifndef _PROTO2_INCLUDED_
#define _PROTO2_INCLUDED_

#include <setjmp.h>
#include <stdint.h>
#include <stddef.h>

#include "falloc.h"

#define PROTO_NULL 0
#define PROTO_INT 1
#define PROTO_STRING 2
#define PROTO_MAP 3
#define PROTO_LIST 4

struct lv {
    size_t length;
    void *value;
};

struct proto2;
struct pleaf;

//TODO: make names more readable

/* base API */
struct proto2 *proto2_create(struct pool *pool, jmp_buf *env);
struct proto2 *proto2_parse_bencode(struct pool *pool, jmp_buf *env, const char *buf, size_t blength);
struct proto2 *proto2_parse_json(struct pool *pool, jmp_buf *env, const char *buf, size_t blength);

int proto2_leaf_type(struct pleaf* leaf);

struct pleaf *proto2_leaf_get(struct proto2 *proto, struct pleaf *leaf, const char *name);
struct pleaf *proto2_leaf_find(struct proto2 *proto, struct pleaf *leaf, const char *name);
struct pleaf *proto2_leaf_new(struct proto2 *proto, struct pleaf *leaf, const char *name);


const char* proto2_leaf_gets(struct pleaf* leaf);
const struct lv* proto2_leaf_getb(struct pleaf *leaf);
const int32_t* proto2_leaf_geti(struct pleaf *leaf);

void proto2_leaf_puts(struct pleaf *leaf, const char *value);
void proto2_leaf_putb(struct pleaf *leaf, const void *value, size_t length);
void proto2_leaf_puti(struct pleaf *leaf, int32_t value);
void proto2_leaf_putmap(struct pleaf *leaf);
void proto2_leaf_putlist(struct pleaf *leaf);

struct pleaf* proto2_leaf_first(struct proto2 *proto, struct pleaf *leaf);
struct pleaf* proto2_leaf_next(struct pleaf *leaf);

size_t proto2_format_bencode(struct proto2 *proto, char *buf, size_t blength);
size_t proto2_format_json(struct proto2 *proto, char *buf, size_t blength);

struct pleaf* proto2_root(struct proto2 *proto);
const char* proto2_name(struct pleaf *leaf);
size_t proto2_count(struct pleaf *leaf);

void proto2_destroy(struct proto2 *proto);

/* Facade */

struct pleaf *proto2_new(struct proto2 *proto, struct pleaf *leaf, const char *name);
struct pleaf *proto2_newmap(struct proto2 *proto, struct pleaf *leaf, const char *name);
struct pleaf *proto2_newlist(struct proto2 *proto, struct pleaf *leaf, const char *name);
void proto2_news(struct proto2 *proto, struct pleaf *leaf, const char *name, const char *value);
void proto2_newb(struct proto2 *proto, struct pleaf *leaf, const char *name, const void *value, size_t length);
void proto2_newi(struct proto2 *proto, struct pleaf *leaf, const char *name, int32_t value);


struct pleaf *proto2_find(struct proto2 *proto, struct pleaf *leaf, const char *name);
struct pleaf *proto2_findmap(struct proto2 *proto, struct pleaf *leaf, const char *name);
struct pleaf *proto2_findlist(struct proto2 *proto, struct pleaf *leaf, const char *name);
const char *proto2_finds(struct proto2 *proto, struct pleaf *leaf, const char *name);
const struct lv *proto2_findb(struct proto2 *proto, struct pleaf *leaf, const char *value);
const int32_t* proto2_findi(struct proto2 *proto, struct pleaf *leaf, const char *name);


struct pleaf *proto2_get(struct proto2 *proto, struct pleaf *leaf, const char *name);
struct pleaf *proto2_getmap(struct proto2 *proto, struct pleaf *leaf, const char *name);
struct pleaf *proto2_getlist(struct proto2 *proto, struct pleaf *leaf, const char *name);
const char *proto2_gets(struct proto2 *proto, struct pleaf *leaf, const char *name);
const struct lv *proto2_getb(struct proto2 *proto, struct pleaf *leaf, const char *name);
int32_t proto2_geti(struct proto2 *proto, struct pleaf *leaf, const char *name);

const char *proto2_gets_default(struct proto2 *proto, struct pleaf *leaf, const char *name, const char* value);
int32_t proto2_geti_default(struct proto2 *proto, struct pleaf *leaf, const char *name, int32_t value);

struct pleaf *proto2_first(struct proto2 *proto, struct pleaf *leaf, const char *name);
struct pleaf *proto2_next(struct pleaf *leaf);



#endif
