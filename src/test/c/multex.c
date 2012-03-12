#include "acheck.h"

void add_test(Suite *suite, int argc, char** argv, const char* name, TCase* (*test)()) {
    int i;
    for (i = 1; i < argc; ++i) {
        char buf[1024];
        memcpy(buf, name + strlen("test_"), strlen(name) - strlen("test_") - strlen("_create_tests"));
        buf[strlen(name) - strlen("test_") - strlen("_create_tests")] = 0;
        if(strcmp(argv[i], buf) == 0) {
                suite_add_tcase(suite, test());
        }
    }
    if (argc == 1) {
            suite_add_tcase(suite, test());
    }
}

#define add(NAME) add_test(multex, argc, argv, ""#NAME,  NAME)


TCase *test_proto_create_tests();
TCase *test_cipher_create_tests();

int main(int argc, char* argv[]) {
        SRunner *runner;
        Suite *multex;
        int failed;

        install_signals();

        multex = suite_create("multex");

        add(test_proto_create_tests);
        add(test_cipher_create_tests);

        runner = srunner_create(multex);
        srunner_run_all(runner, CK_NORMAL);
        failed = srunner_ntests_failed(runner);

        srunner_free(runner);

        return (failed == 0) ? 0 : 1;
}