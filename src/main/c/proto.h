#include <stdlib.h>
#include <stdint.h>

#define PROTO_DATA 0
#define PROTO_OFFER 1
#define PROTO_CHALLENGE 2
#define PROTO_CONFIRM 3
#define PROTO_ACCEPTED 4


struct lv {
    size_t length;
    void* value;
};

struct proto_parameters {
    struct lv hwaddr;
    size_t weight;
    size_t priority;
};

struct proto {
    int type;
    struct lv key;
    struct lv id;
    struct lv rid;
    struct lv params;
    struct lv data;

    struct proto_parameters parameters;
};


ssize_t proto_decode(struct proto* proto, const char* in, ssize_t length);

ssize_t proto_encode(const struct proto* proto, char* out, ssize_t length);

ssize_t proto_decode_param(struct proto* proto_parameters, const char* in, ssize_t length);

ssize_t proto_encode_param(const struct proto* proto_parameters, char* out, ssize_t length);