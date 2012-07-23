#include <memory.h>
#include <stdlib.h>
#include "acheck.h"
#include "proto2.h"

static
struct proto2 *parse(const char *s) {
    struct mpool *mpool = malloc(sizeof(struct mpool));
    struct pool *pool = mcreate(mpool, 0);

    return proto2_parse_bencode(pool, 0, s, strlen(s));
}

static
struct proto2 *create(void) {
    struct mpool *mpool = malloc(sizeof(struct mpool));
    struct pool *pool = mcreate(mpool, 0);

    return proto2_create(pool, 0);
}

char formatbuf[1024];

static
const char *format(struct proto2 *proto) {
    size_t size = proto2_format_bencode(proto, formatbuf, sizeof(formatbuf));
    formatbuf[size] = 0;
    return formatbuf;
}


START_TEST(test_proto2_decode_empty)
{
    struct proto2 *proto = parse("de");
    
    assert_unsigned_eq(proto2_count(proto2_root(proto)), 0);
    assert_unsigned_eq(proto2_leaf_type(proto2_root(proto)), PROTO_MAP);

}
END_TEST

START_TEST(test_proto2_decode_int)
{
    struct proto2 *proto;

    proto = parse("d1:ii10ee");

    assert_unsigned_eq(proto2_count(proto2_root(proto)), 1);
    assert_unsigned_eq(proto2_geti(proto, 0, "i"), 10);
    assert_null(proto2_findi(proto, 0, "w"));
}
END_TEST

START_TEST(test_proto2_decode_string)
{
    struct proto2 *proto;

    proto = parse("d1:s5:valuee");

    assert_unsigned_eq(proto2_count(proto2_root(proto)), 1);
    assert_str_eq(proto2_gets(proto, 0, "s"), "value");
    assert_null(proto2_finds(proto, 0, "w"));
}
END_TEST

START_TEST(test_proto2_decode_list)
{
    struct proto2 *proto;
    struct pleaf* leaf;

    proto = parse("d1:ll4:itemee");

    assert_unsigned_eq(proto2_count(proto2_root(proto)), 1);
    leaf = proto2_getlist(proto, 0, "l");
    assert_not_null(leaf);
    assert_str_eq(proto2_leaf_gets(proto2_first(proto, leaf, 0)), "item");
    assert_null(proto2_findlist(proto, 0, "w"));
}
END_TEST

START_TEST(test_proto2_decode_map)
{
    struct proto2 *proto;
    struct pleaf* leaf;

    proto = parse("d1:dd3:key5:valueee");

    assert_unsigned_eq(proto2_count(proto2_root(proto)), 1);
    leaf = proto2_getmap(proto, 0, "d");
    assert_not_null(leaf);
    assert_str_eq(proto2_name(proto2_first(proto, leaf, 0)), "key");
    assert_str_eq(proto2_leaf_gets(proto2_first(proto, leaf, 0)), "value");
    assert_str_eq(proto2_gets(proto, 0, "d.key"), "value");
    assert_null(proto2_findlist(proto, 0, "w"));
}
END_TEST

START_TEST(test_proto2_encode_empty)
{
    struct proto2 *proto = create();
    assert_str_eq(format(proto), "de");
}
END_TEST

START_TEST(test_proto2_encode_int)
{
    struct proto2 *proto = create();

    proto2_newi(proto, 0, "i", 10);

    assert_str_eq(format(proto), "d1:ii10ee");
}
END_TEST

START_TEST(test_proto2_encode_string)
{
    struct proto2 *proto = create();

    proto2_news(proto, 0, "s", "value");

    assert_str_eq(format(proto), "d1:s5:valuee");
}
END_TEST

START_TEST(test_proto2_encode_list)
{
    struct proto2 *proto = create();
    struct pleaf* leaf;

    leaf = proto2_newlist(proto, 0, "l");
    proto2_news(proto, leaf, 0, "item");

    assert_str_eq(format(proto), "d1:ll4:itemee");
}
END_TEST

START_TEST(test_proto2_encode_map)
{
    struct proto2 *proto = create();
    struct pleaf* leaf;

    proto2_news(proto, 0, "d.key", "value");

    assert_str_eq(format(proto), "d1:dd3:key5:valueee");
}
END_TEST


TCase *test_proto2_create_tests() {
    TCase *tc;

    tc = tcase_create("proto2");
    tcase_add_test(tc, test_proto2_decode_empty);
    tcase_add_test(tc, test_proto2_decode_int);
    tcase_add_test(tc, test_proto2_decode_string);
    tcase_add_test(tc, test_proto2_decode_list);
    tcase_add_test(tc, test_proto2_decode_map);

    tcase_add_test(tc, test_proto2_encode_empty);
    tcase_add_test(tc, test_proto2_encode_int);
    tcase_add_test(tc, test_proto2_encode_string);
    tcase_add_test(tc, test_proto2_encode_list);
    tcase_add_test(tc, test_proto2_encode_map);

    return tc;
}