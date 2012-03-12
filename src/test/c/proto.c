#include <memory.h>
#include "acheck.h"
#include "proto.h"

START_TEST(test_proto_encode_offer)
{
    struct proto proto;
    char buf[100];
    ssize_t length;


    memset(&proto, 0, sizeof(proto));
    proto.type = PROTO_OFFER;
    proto.key.value ="a";
    proto.key.length = 1;

    length = proto_encode(&proto, buf, sizeof(buf));

    assert_mem_eq(buf, length, "d3:key1:a4:typei1ee", 19);
}
END_TEST

START_TEST(test_proto_decode_offer)
{
    struct proto proto;
    ssize_t length;

    length = proto_decode(&proto, "d3:key1:a4:typei1ee", 19);

    assert_signed_eq(length, 19);
    assert_unsigned_eq(proto.type, PROTO_OFFER);
    assert_mem_eq(proto.key.value, proto.key.length, "a", 1);
}
END_TEST

START_TEST(test_proto_encode_challenge)
{
    struct proto proto;
    char buf[100];
    ssize_t length;


    memset(&proto, 0, sizeof(proto));
    proto.type = PROTO_CHALLENGE;
    proto.id.value ="a";
    proto.id.length = 1;

    length = proto_encode(&proto, buf, sizeof(buf));

    assert_mem_eq(buf, length, "d2:id1:a4:typei2ee", 21);
}
END_TEST

START_TEST(test_proto_decode_challenge)
{
    struct proto proto;
    ssize_t length;

    length = proto_decode(&proto, "d2:id1:a4:typei2ee", 21);

    assert_signed_eq(length, 21);
    assert_unsigned_eq(proto.type, PROTO_CHALLENGE);
    assert_mem_eq(proto.id.value, proto.id.length, "a", 1);
}
END_TEST

TCase *
test_proto_create_tests()
{
        TCase *tc;

        tc = tcase_create("proto");
        tcase_add_test(tc, test_proto_encode_offer);
        tcase_add_test(tc, test_proto_decode_offer);
        tcase_add_test(tc, test_proto_encode_challenge);
        tcase_add_test(tc, test_proto_decode_challenge);

        return tc;
}
