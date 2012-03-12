#ifndef _CIPHER_H_
#define _CIPHER_H_

struct cipher;

struct digest;

struct cipher_context;

struct digest_context;


struct cipher* cipher_bf();

int cipher_keysize(struct cipher* cipher);

int cipher_blocksize(struct cipher* cipher);


struct cipher_context* cipher_context_create(struct cipher* cipher, const char* key);

const char* cipher_context_getkey(struct cipher_context* context);

ssize_t cipher_encrypt(struct cipher_context* context, const char* in, size_t length, char* out);

ssize_t cipher_decrypt(struct cipher_context* context, const char* in, size_t length, char* out);

void cipher_context_free(struct cipher_context* context);


struct digest* digest_sha();

struct digest_context* digest_context_create(struct digest* digest);

int digest_size(struct digest* digest);

void digest_sign(struct digest_context* context, const char* in, size_t length, char* digest);

void digest_context_free(struct digest_context* context);

void random_bytes(void* buf, size_t length);


#endif