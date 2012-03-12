multex: 
	gcc -g -D_GNU_SOURCE -DENTRY_NAME=main -o multex ./src/main/c/*.c -I ./src/main/c -levent -lcrypto -lrt
test:
	gcc -g -D_GNU_SOURCE -DENTRY_NAME=multex_main -o tests ./src/main/c/*.c ./src/test/c/*.c -I ./src/main/c -I ./src/test/c -levent -lcrypto -lrt -lcheck
	
.PHONY: multex test
