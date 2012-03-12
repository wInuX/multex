#include <alloca.h>

#include "acheck.h"
#include "cipher.h"

START_TEST(test_cipher_double_encode) {
    struct cipher* cipher;
    struct cipher_context* context;
    char* key;
    char ibuf[100];
    char obuf[100];
    ssize_t ilength, olength;

    cipher = cipher_bf();
    key = alloca(cipher_keysize(cipher));
    memset(key, 0, cipher_keysize(cipher));
    context = cipher_context_create(cipher, key);

    ilength = cipher_encrypt(context, "a", 1, ibuf);
    olength = cipher_encrypt(context, "a", 1, obuf);
    assert_mem_eq(ibuf, ilength, obuf, olength);
}
END_TEST

TCase *
test_cipher_create_tests()
{
        TCase *tc;

        tc = tcase_create("cipher");
        tcase_add_test(tc, test_cipher_double_encode);


        return tc;
}