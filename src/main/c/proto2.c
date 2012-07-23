#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <alloca.h>

#include "proto2.h"

struct pleaf;
struct pleaf {
    struct proto2* proto;
    struct pleaf* next;
    char* name;
    int type;
    union {
        int32_t i;
        struct lv lv;
        struct pleaf* child;
    } value;
};

struct proto2 {
    struct pool *pool;
    jmp_buf *env;

    struct pleaf* root;
    const char* message;
};

struct rcontext {
    struct proto2* proto;
    const char* p;
    const char* e;
};

struct wcontext {
    struct proto2* proto;
    char* p;
    char* e;
};

static void throw_now(struct proto2 *proto, const char *message) {
    if (proto->env) {
        proto->message = message;
        longjmp(*proto->env, 0);
    } else {
        fprintf(stderr, "%s\n", message);
        abort();
    }
}

struct proto2 *proto2_create(struct pool *pool, jmp_buf *env) {
    struct proto2 *proto = palloc(pool, sizeof(struct proto2));
    proto->env = env;
    proto->pool = pool;
    proto->root = palloc(pool, sizeof(struct pleaf));
    proto->root->proto = proto;
    proto->root->name = 0;
    proto->root->type = PROTO_MAP;
    proto->root->value.child = 0;
    proto->message = 0;

    return proto;
}

struct pleaf *proto2_leaf_get(struct proto2 *proto, struct pleaf *leaf, const char *name) {
    struct pleaf *p = proto2_leaf_find(proto, leaf, name);
    if (p == 0) {
        throw_now(proto, "Element is missing");
    }
    return p;
}

struct pleaf *proto2_leaf_find(struct proto2 *proto, struct pleaf *leaf, const char *name) {
    struct pleaf *p;

    assert(proto);
    assert(leaf);
    assert(name);

    if (leaf->type != PROTO_MAP) {
        return 0;
    }
    for (p = proto2_leaf_first(proto, leaf); p; p = proto2_leaf_next(p)) {
        if (strcmp(p->name, name) == 0) {
            return p;
        }
    }
    return 0;
}

struct pleaf *proto2_leaf_new(struct proto2 *proto, struct pleaf *leaf, const char *name) {
    struct pleaf *n;

    assert(proto);
    assert(leaf);
    assert(leaf->type == PROTO_LIST || leaf->type == PROTO_MAP);
    assert((leaf->type == PROTO_LIST && name == 0) || (leaf->type == PROTO_MAP && name != 0));

    n = palloc(proto->pool, sizeof (struct pleaf));
    assert(n);
    n->type = PROTO_NULL;
    n->proto = proto;
    n->name = (char*)name;
    n->next = leaf->value.child;
    leaf->value.child = n;
    return n;
}

int proto2_leaf_type(struct pleaf* leaf) {
    assert(leaf);

    return leaf->type;
}

const char* proto2_leaf_gets(struct pleaf *leaf) {
    assert(leaf);

    if (leaf->type == PROTO_NULL) {
        return 0;
    }
    if (leaf->type == PROTO_STRING) {
        return leaf->value.lv.value;
    }
    throw_now(leaf->proto, "Wrong leaf type. Expected string");
}

const struct lv *proto2_leaf_getb(struct pleaf *leaf) {
    assert(leaf);

    if (leaf->type == PROTO_NULL) {
        return 0;
    }
    if (leaf->type == PROTO_STRING) {
        return &leaf->value.lv;
    }
    throw_now(leaf->proto, "Wrong leaf type. Expected string");
}

const int32_t* proto2_leaf_geti(struct pleaf *leaf) {
    assert(leaf);

    if (leaf->type == PROTO_NULL) {
        return 0;
    }
    if (leaf->type == PROTO_INT) {
        return &leaf->value.i;
    }
    throw_now(leaf->proto, "Wrong leaf type. Expected int");
}

void proto2_leaf_puts(struct pleaf *leaf, const char *value) {
    assert(leaf);
    assert(leaf->type == 0);

    leaf->type = PROTO_STRING;
    leaf->value.lv.value = (char*)value;
    leaf->value.lv.length = strlen(value);
}

void proto2_leaf_putb(struct pleaf *leaf, const void *value, size_t length) {
    assert(leaf);
    assert(leaf->type == 0);

    leaf->type = PROTO_STRING;
    leaf->value.lv.value = (char*)value;
    leaf->value.lv.length = length;
}

void proto2_leaf_puti(struct pleaf *leaf, int32_t value) {
    assert(leaf);
    assert(leaf->type == 0);

    leaf->type = PROTO_INT;
    leaf->value.i = value;
}

void proto2_leaf_putmap(struct pleaf *leaf) {
    assert(leaf);
    assert(leaf->type == 0);

    leaf->type = PROTO_MAP;
    leaf->value.child = 0;
}

void proto2_leaf_putlist(struct pleaf *leaf) {
    assert(leaf);
    assert(leaf->type == 0);

    leaf->type = PROTO_LIST;
    leaf->value.child = 0;
}


struct pleaf* proto2_leaf_first(struct proto2 *proto, struct pleaf *leaf) {
    assert(proto);
    assert(leaf);

    assert (leaf->type == PROTO_MAP || leaf->type == PROTO_LIST);
    return leaf->value.child;
}

struct pleaf* proto2_leaf_next(struct pleaf *leaf) {
    assert(leaf);

    return leaf->next;
}

const char* proto2_name(struct pleaf *leaf) {
    return leaf->name;
}

size_t proto2_count(struct pleaf *leaf) {
    struct pleaf* p;
    size_t count = 0;

    assert(leaf);

    p = proto2_leaf_first(leaf->proto, leaf);
    while (p != 0) {
        ++count;
        p = proto2_leaf_next(leaf);
    }
    return count;
}

struct pleaf* proto2_root(struct proto2 *proto) {
    assert(proto);

    return proto->root;
}




struct pleaf *proto2_new(struct proto2 *proto, struct pleaf *leaf, const char *name) {
    struct pleaf *r;

    assert(proto);

    if (leaf == 0) {
        leaf = proto->root;
    }
    if (name == 0) {
        return proto2_leaf_new(proto, leaf, 0);        
    }

    const char *p;
    do {
        p = strchr(name, '.');
        char *subname;
        struct pleaf *subleaf;
        if (p) {
            subname = alloca(p - name + 1);
            strncpy(subname, name, p - name);
            subname[p - name] = 0;
            ++p;
        } else {
            subname = (char*)name;
        }
        subleaf = proto2_leaf_find(proto, leaf, subname);
        if (!subleaf) {
            subleaf = proto2_leaf_new(proto, leaf, pstrdup(proto->pool, subname));
            if (p) {
                proto2_leaf_putmap(subleaf);
            }
        }
        name = p;
        leaf = subleaf;
    } while (p);
    return leaf;
}

struct pleaf *proto2_newmap(struct proto2 *proto, struct pleaf *leaf, const char *name) {
    struct pleaf *r = proto2_new(proto, leaf, name);
    proto2_leaf_putmap(r);
    return r;
}

struct pleaf *proto2_newlist(struct proto2 *proto, struct pleaf *leaf, const char *name) {
    struct pleaf *r = proto2_new(proto, leaf, name);
    proto2_leaf_putlist(r);
    return r;
}

void proto2_news(struct proto2 *proto, struct pleaf *leaf, const char *name, const char *value) {
    struct pleaf *r = proto2_new(proto, leaf, name);
    proto2_leaf_puts(r, value);
}

void proto2_newb(struct proto2 *proto, struct pleaf *leaf, const char *name, const void *value, size_t length) {
    struct pleaf *r = proto2_new(proto, leaf, name);
    proto2_leaf_putb(r, value, length);
}

void proto2_newi(struct proto2 *proto, struct pleaf *leaf, const char *name, int32_t value) {
    struct pleaf *r = proto2_new(proto, leaf, name);
    proto2_leaf_puti(r, value);
}


struct pleaf *proto2_find(struct proto2 *proto, struct pleaf *leaf, const char *name) {
    struct pleaf *r;

    assert(proto);
    if (leaf == 0) {
        leaf = proto->root;
    }
    if (name == 0) {
        return leaf;
    }

    const char *p;
    do {
        p = strchr(name, '.');
        char *subname;
        if (p) {
            subname = alloca(p - name + 1);
            strncpy(subname, name, p - name);
            subname[p - name] = 0;
            ++p;
        } else {
            subname = (char*)name;
        }
        leaf = proto2_leaf_find(proto, leaf, subname);
        name = p;
    } while (leaf && p);
    return leaf;
}

struct pleaf *proto2_findmap(struct proto2 *proto, struct pleaf *leaf, const char *name) {
    struct pleaf *r = proto2_find(proto, leaf, name);
    if (r == 0) {
        return 0;
    }
    if (r->type != PROTO_MAP) {
        throw_now(proto, "map expected");
    }
    return r;
}

struct pleaf *proto2_findlist(struct proto2 *proto, struct pleaf *leaf, const char *name) {
    struct pleaf *r = proto2_find(proto, leaf, name);
    if (r == 0) {
        return 0;
    }
    if (r->type != PROTO_LIST) {
        throw_now(proto, "list expected");
    }
    return r;
}

const char *proto2_finds(struct proto2 *proto, struct pleaf *leaf, const char *name) {
    struct pleaf *r = proto2_find(proto, leaf, name);
    if (r == 0) {
        return 0;
    }
    if (r->type != PROTO_STRING) {
        throw_now(proto, "string expected");
    }
    return r->value.lv.value;
}

const struct lv *proto2_findb(struct proto2 *proto, struct pleaf *leaf, const char *name) {
    struct pleaf *r = proto2_find(proto, leaf, name);
    if (r == 0) {
        return 0;
    }
    if (r->type != PROTO_STRING) {
        throw_now(proto, "string expected");
    }
    return &r->value.lv;
}

const int32_t* proto2_findi(struct proto2 *proto, struct pleaf *leaf, const char *name) {
    struct pleaf *r = proto2_find(proto, leaf, name);
    if (r == 0) {
        return 0;
    }
    if (r->type != PROTO_INT) {
        throw_now(proto, "integer expected");
    }
    return &r->value.i;
}


struct pleaf *proto2_get(struct proto2 *proto, struct pleaf *leaf, const char *name) {
    struct pleaf *r = proto2_find(proto, leaf, name);
    if (r == 0) {
        throw_now(proto, "node not present");
    }
    return r;
}

const char *proto2_gets(struct proto2 *proto, struct pleaf *leaf, const char *name) {
    struct pleaf *r = proto2_get(proto, leaf, name);
    if (r->type != PROTO_STRING) {
        throw_now(proto, "expected string");
    }
    return r->value.lv.value;
}

const struct lv *proto2_getb(struct proto2 *proto, struct pleaf *leaf, const char *name) {
    struct pleaf *r = proto2_get(proto, leaf, name);
    if (r->type != PROTO_STRING) {
        throw_now(proto, "expected string");
    }
    return &r->value.lv;
}

int32_t proto2_geti(struct proto2 *proto, struct pleaf *leaf, const char *name) {
    struct pleaf *r = proto2_get(proto, leaf, name);
    if (r->type != PROTO_INT) {
        throw_now(proto, "expected string");
    }
    return r->value.i;
}

struct pleaf *proto2_getmap(struct proto2 *proto, struct pleaf *leaf, const char *name) {
    struct pleaf *r = proto2_findmap(proto, leaf, name);
    if (r == 0) {
        throw_now(proto, "node not present");
    }
    return r;
}

struct pleaf *proto2_getlist(struct proto2 *proto, struct pleaf *leaf, const char *name) {
    struct pleaf *r = proto2_findlist(proto, leaf, name);
    if (r == 0) {
        throw_now(proto, "node not present");
    }
    return r;
}


const struct lv *proto2_getb(struct proto2 *proto, struct pleaf *leaf, const char *name);
int32_t proto2_geti(struct proto2 *proto, struct pleaf *leaf, const char *name);


struct pleaf* proto2_first(struct proto2 *proto, struct pleaf *leaf, const char *name) {
    struct pleaf *r = proto2_find(proto, leaf, name);
    if (r == 0) {
        return 0;
    }
    if (r->type != PROTO_MAP && r->type != PROTO_LIST) {
        throw_now(proto, "Wrong leaf type. Expected list or map");
    }
    return proto2_leaf_first(proto, r);
}

struct pleaf* proto2_next(struct pleaf *leaf) {
    return proto2_leaf_next(leaf);
}



static
void wchar(struct wcontext *context, int ch) {
    if (context->p >= context->e) {
        throw_now(context->proto, "buffer overflow");
    }
    *context->p++ = ch;
}

static
void wmemory(struct wcontext *context, const void *m, size_t length) {
    if (context->p + length >= context->e) {
        throw_now(context->proto, "buffer overflow");
    }
    memcpy(context->p, m, length);
    context->p += length;
}

static
void winteger(struct wcontext *context, size_t value) {
    char buf[40];
    char* e = buf + sizeof(buf) - 1;
    char* p = e + 1;

    do {
        *--p = '0' + (value % 10);
        value = value / 10;
    } while (value > 0);
    if (context->p + (e - p) >= context-> e) {
        throw_now(context->proto, "buffer overflow");
    }
    memcpy(context->p, p, e - p + 1);
    context->p += e - p + 1;
}

static
void bencode_wleaf(struct wcontext* context, struct pleaf* leaf);

static
void bencode_integer(struct wcontext *context, size_t value) {
    wchar(context, 'i');
    winteger(context, value);
    wchar(context, 'e');
}

static
void bencode_wbinary(struct wcontext *context, const void *m, size_t length) {
    winteger(context, length);
    wchar(context, ':');
    wmemory(context, m, length);
}

static
void bencode_wstring(struct wcontext *context, const char *s) {
    bencode_wbinary(context, s, strlen(s));
}

static
void bencode_wmap(struct wcontext* context, struct pleaf* leaf) {
    struct pleaf *p;

    wchar(context, 'd');
    p = proto2_leaf_first(context->proto, leaf);
    while (p != 0) {
        bencode_wstring(context, p->name);
        bencode_wleaf(context, p);

        p = proto2_leaf_next(p);
    }
    wchar(context, 'e');
}

static
void bencode_wlist(struct wcontext* context, struct pleaf* leaf) {
    struct pleaf *p;

    wchar(context, 'l');
    p = proto2_leaf_first(context->proto, leaf);
    while (p != 0) {
        bencode_wleaf(context, p);

        p = proto2_leaf_next(p);
    }
    wchar(context, 'e');
}

static
void bencode_wleaf(struct wcontext* context, struct pleaf* leaf) {
    switch (leaf->type) {
        case PROTO_NULL:
            throw_now(context->proto, "bencode does not support null value");
            break;
        case PROTO_INT:
            bencode_integer(context, leaf->value.i);
            break;
        case PROTO_STRING:
            bencode_wbinary(context, leaf->value.lv.value, leaf->value.lv.length);
            break;
        case PROTO_MAP:
            bencode_wmap(context, leaf);
            break;
        case PROTO_LIST:
            bencode_wlist(context, leaf);
            break;
        default:
            assert(0);
    }
}

size_t proto2_format_bencode(struct proto2 *proto, char *buf, size_t blength) {
    struct wcontext context;

    context.proto = proto;
    context.p = buf;
    context.e = buf + blength;
    bencode_wleaf(&context, proto->root);
    return context.p - buf;
}

static
char rchar(struct rcontext* context) {
    if (context->p >= context->e) {
        throw_now(context->proto, "buffer underflow(rchar)");
    }
    ++context->p;
    return *(context->p - 1);
}

static
void rmemory(struct rcontext* context, void* out, size_t length) {
    if (context->p + length >= context->e) {
        throw_now(context->proto, "buffer underflow(rmemory)");
    }
    memcpy(out, context->p, length);
    context->p += length;
}

static
size_t rinteger(struct rcontext* context) {
    size_t value = 0;
    if (context->p == context->e) {
        throw_now(context->proto, "buffer underflow(rinteger)");
    }
    while (*context->p >= '0' && *context->p <= '9') {
        value = value * 10 + *context->p++ - '0';
        if (context->p == context->e) {
            break;
        }
    }
    return value;
}

static
size_t bencode_rinteger(struct rcontext* context) {
    size_t r;
    if (rchar(context) != 'i') {
        throw_now(context->proto, "wrong format");
    }
    r = rinteger(context);
    if (rchar(context) != 'e') {
        throw_now(context->proto, "wrong format");
    }
    return r;
}

static
void bencode_rmemory(struct rcontext* context, struct lv* lv) {
    lv->length = rinteger(context);
    if (rchar(context) != ':') {
        throw_now(context->proto, "wrong format");
    }
    if (context->p + lv->length >= context->e) {
        throw_now(context->proto, "buffer undeflow(b_rmemory)");
    }
    lv->value = pstrcreate(context->proto->pool, context->p, lv->length);
    context->p += lv->length;
}

static
char* bencode_rstring(struct rcontext* context) {
    struct lv lv;
    bencode_rmemory(context, &lv);

    return lv.value;
}

static
void bencode_rleaf(struct rcontext* context, struct pleaf *leaf);

static
void bencode_rlist(struct rcontext* context, struct pleaf *leaf) {
    if (rchar(context) != 'l') {
        throw_now(context->proto, "wrong format");
    }
    proto2_leaf_putlist(leaf);
    while (context->p < context->e) {
        if (*context->p == 'e') {
            break;
        }
        bencode_rleaf(context, proto2_leaf_new(context->proto, leaf, 0));
    }
    if (rchar(context) != 'e') {
        throw_now(context->proto, "wrong format");
    }
}

static
void bencode_rmap(struct rcontext* context, struct pleaf *leaf) {
    assert(context);
    assert(leaf);
    assert(leaf->type == 0);

    if (rchar(context) != 'd') {
        throw_now(context->proto, "wrong format");
    }
    proto2_leaf_putmap(leaf);
    while (context->p < context->e) {
        char *name;
        if (*context->p == 'e') {
            break;
        }
        name = bencode_rstring(context);
        bencode_rleaf(context, proto2_leaf_new(context->proto, leaf, name));
    }
    if (rchar(context) != 'e') {
        throw_now(context->proto, "wrong format");
    }
}

static
void bencode_rleaf(struct rcontext* context, struct pleaf *leaf) {
    assert(context);
    assert(leaf);
    assert(leaf->type == 0);

    if (context->p >= context->e) {
        throw_now(context->proto, "buffer underflow(rleaf)");
    }
    switch (*context->p) {
        case 'l':
            bencode_rlist(context, leaf);
            break;
        case 'd':
            bencode_rmap(context, leaf);
            break;
        case 'i':
            proto2_leaf_puti(leaf, (uint32_t)bencode_rinteger(context));
            break;
        default: {
            struct lv lv;
            
            bencode_rmemory(context, &lv);
            proto2_leaf_putb(leaf, lv.value, lv.length);
            break;
        }
    }
}

struct proto2 *proto2_parse_bencode(struct pool *pool, jmp_buf *env, const char *buf, size_t blength) {
    struct rcontext context;
    struct proto2 *proto;

    proto = proto2_create(pool, env);
    proto->root->type = 0; // hack
    context.proto = proto;
    context.p = buf;
    context.e = buf + blength;
    bencode_rmap(&context, proto->root);
    return proto;
}