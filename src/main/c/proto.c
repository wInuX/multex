#include <setjmp.h>
#include <stdio.h>
#include <string.h>

#include "proto.h"

struct wcontext {
    char* p;
    char* e;

    jmp_buf error;
};

struct rcontext {
    char* p;
    char* e;

    jmp_buf error;
};

static
char rchar(struct rcontext* context) {
    if (context->p == context->e) {
        longjmp(context->error, 0);
    }
    ++context->p;
    return *(context->p - 1);
}

void rmemory(struct rcontext* context, void* out, size_t length) {
    if (context->p + length >= context->e) {
        longjmp(context->error, 0);
    }
    memcpy(out, context->p, length);
    context->p += length;
}

static
ssize_t ri(struct rcontext* context) {
    ssize_t value = 0;
    if (context->p == context->e) {
        longjmp(context->error, 0);
    }
    while (*context->p >= '0' && *context->p <= '9') {
        value = value * 10 + *context->p++ - '0';
        if (context->p == context->e) {
            longjmp(context->error, 0);
        }
    }
    return value;
}

static
ssize_t rinteger(struct rcontext* context) {
    ssize_t r;
    if (rchar(context) != 'i') {
        longjmp(context->error, 0);
    }
    r = ri(context);
    if (rchar(context) != 'e') {
        longjmp(context->error, 0);
    }
    return r;
}

static
void rlv(struct rcontext* context, struct lv* lv) {
    lv->length =  ri(context);
    if (rchar(context) != ':') {
        longjmp(context->error, 0);
    }
    lv->value = context->p;
    if (context->p + lv->length >= context->e) {
        longjmp(context->error, 0);
    }
    context->p += lv->length;
}

static
void wchar(struct wcontext* context, char ch) {
    if (context->p == context->e) {
        longjmp(context->error, 0);
    }
    *context->p = ch;
    ++context->p;
}

static
void wmemory(struct wcontext* context, const void* value, ssize_t length) {
    if (context->p + length >= context->e) {
        longjmp(context->error, 0);
    }
    memcpy(context->p, value, length);
    context->p += length;
}

static
void wint(struct wcontext* context, size_t value) {
    char buf[40];
    char* e = buf + sizeof(buf) - 1;
    char* p = e + 1;

    do {
        *--p = '0' + (value % 10);
        value = value / 10;
    } while (value > 0);
    if (context->p + (e - p) >= context-> e) {
        longjmp(context->error, 0);
    }
    memcpy(context->p, p, e - p + 1);
    context->p += e - p + 1;
}

static
void winteger(struct wcontext* context, size_t value) {
    wchar(context, 'i');
    wint(context, value);
    wchar(context, 'e');
}


static
void wbstring(struct wcontext* context, const void* data, size_t length) {
    wint(context, length);
    wchar(context, ':');
    wmemory(context, data, length);
}

static
void wstring(struct wcontext* context, const char* data) {
    wbstring(context, data, strlen(data));
}

static
void wlv(struct wcontext* context, const char* name, const struct lv* lv) {
    if (lv) {
        if (lv->value) {
            wstring(context, name);
            wbstring(context, lv->value, lv->length);
        }
    }
}

static
int lv_eq(const char* name, const struct lv* lv) {
    if (strlen(name) != lv->length) {
        return 0;
    }
    return memcmp(name, lv->value, lv->length) == 0;
}


ssize_t proto_decode(struct proto* proto, const char* in, ssize_t length) {
    struct rcontext context;
    context.p = (char*)in;
    context.e = (char*)in + length;
    if (setjmp(context.error) > 0) {
        return 0;
    }
    memset(proto, 0, sizeof(struct proto));

    if (rchar(&context) == 'd') {
        struct lv name;
        while (rchar(&context) != 'e') {
            --context.p;
            rlv(&context, &name);
            if (lv_eq("type", &name)) {
                proto->type = rinteger(&context);
            }
            if (lv_eq("id", &name)) {
                rlv(&context, &proto->id);
            }
            if (lv_eq("rid", &name)) {
                rlv(&context, &proto->rid);
            }
            if (lv_eq("key", &name)) {
                rlv(&context, &proto->key);
            }
            if (lv_eq("weight", &name)) {
                proto->parameters.weight = rinteger(&context);
            }
            if (lv_eq("priority", &name)) {
                proto->parameters.priority = rinteger(&context);
            }
            if (lv_eq("hwaddr", &name)) {
                struct lv lv;
                rlv(&context, &lv);
                if (lv.length == sizeof(proto->parameters.hwaddr)) {
                    memcpy(&proto->parameters.hwaddr, lv.value, lv.length);
                }
            }
        }
    } else {
        proto->type = PROTO_DATA;
        proto->data.value = context.p;
        proto->data.length = context.e - context.p;
        context.p = context.e;
    }
    return context.p - in;
}

ssize_t proto_encode(const struct proto* proto, char* out, ssize_t length) {
    if (proto->type != PROTO_DATA) {
        struct wcontext context;
        context.p = out;
        context.e = out + length;
        if (setjmp(context.error) > 0) {
            return 0;
        }
        wchar(&context, 'd');

        wlv(&context, "id", &proto->id);
        wlv(&context, "key", &proto->key);
        wlv(&context, "rid", &proto->rid);

        wstring(&context, "type");
        winteger(&context, proto->type);

        if (proto->type == PROTO_CONFIRM) {
            wstring(&context, "weight");
            winteger(&context, proto->parameters.weight);
            wstring(&context, "priority");
            winteger(&context, proto->parameters.priority);
            wstring(&context, "hwaddr");
            wbstring(&context, &proto->parameters.hwaddr, sizeof(proto->parameters.hwaddr));
        }

        wchar(&context, 'e');
        return context.p - out;
    } else {
        *out++ = 'p';
        memcpy(out, proto->data.value, proto->data.length);
        return proto->data.length + 1;
    }
}

