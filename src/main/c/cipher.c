#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <memory.h>

#include "cipher.h"

struct cipher {
    const EVP_CIPHER *type;
};

struct cipher_context {
    struct cipher* cipher;
    char* key;
    EVP_CIPHER_CTX ectx;
    EVP_CIPHER_CTX dctx;
};

struct digest {
    const EVP_MD *type;
};

struct digest_context {
    struct digest* digest;
    EVP_MD_CTX ctx;
};

static struct cipher bf = {0};
static struct digest sha = {0};


struct cipher* cipher_bf() {
    if (bf.type == 0) {
        bf.type = EVP_bf_cbc();
    }
    return &bf;
}

int cipher_keysize(struct cipher* cipher) {
    return EVP_CIPHER_key_length(cipher->type);
}

int cipher_blocksize(struct cipher* cipher) {
    return EVP_CIPHER_block_size(cipher->type);
}

struct cipher_context* cipher_context_create(struct cipher* cipher, const char* key) {
    struct cipher_context* context = malloc(sizeof(struct cipher_context));
    int keysize;

    keysize = cipher_keysize(cipher);
    EVP_CIPHER_CTX_init(&context->ectx);
    EVP_CIPHER_CTX_init(&context->dctx);
    EVP_EncryptInit_ex(&context->ectx, cipher->type, 0, (const unsigned char*)key, 0);
    EVP_DecryptInit_ex(&context->dctx, cipher->type, 0, (const unsigned char*)key, 0);
    context->cipher = cipher;
    context->key = malloc(keysize);
    memcpy(context->key, key, keysize);
    return context;
}

ssize_t cipher_encrypt(struct cipher_context* context, const char* in, size_t ilength, char* out) {
    ssize_t total = 0;
    int olength = 0;

    EVP_EncryptInit_ex(&context->ectx, 0, 0, 0, 0);
    EVP_EncryptUpdate(&context->ectx, (unsigned char*)out, &olength, (const unsigned char*)in, ilength);
    total += olength;
    EVP_EncryptFinal_ex(&context->ectx, (unsigned char*)out + olength, &olength);
    return total + olength;
}

ssize_t cipher_decrypt(struct cipher_context* context, const char* in, size_t ilength, char* out) {
    ssize_t total = 0;
    int olength = 0;

    EVP_DecryptInit_ex(&context->dctx, 0, 0, 0, 0);
    EVP_DecryptUpdate(&context->dctx, (unsigned char*)out, &olength, (const unsigned char*)in, ilength);
    total += olength;
    EVP_DecryptFinal_ex(&context->dctx, (unsigned char*)out + olength, &olength);
    return total + olength;
}

const char* cipher_context_getkey(struct cipher_context* context) {
    return context->key;
}

void cipher_context_free(struct cipher_context* context) {
    free(context->key);
    EVP_CIPHER_CTX_cleanup(&context->ectx);
    EVP_CIPHER_CTX_cleanup(&context->dctx);
    free(context);
}



struct digest* digest_sha() {
    if (sha.type == 0) {
        sha.type = EVP_sha();
    }
    return &sha;
}

struct digest_context* digest_context_create(struct digest* digest) {
    struct digest_context* context = malloc(sizeof(struct digest_context));

    context->digest = digest;
    EVP_MD_CTX_init(&context->ctx);

    return context;
}

void digest_sign(struct digest_context* context, const char* in, size_t length, char* digest) {
    unsigned int olength = 0;

    EVP_DigestInit_ex(&context->ctx, context->digest->type, 0);
    EVP_DigestUpdate(&context->ctx, in, length);
    EVP_DigestFinal_ex(&context->ctx, (unsigned char*)digest, &olength);
}

void digest_context_free(struct digest_context* context) {
    EVP_MD_CTX_cleanup(&context->ctx);
    free(context);
}

int digest_size(struct digest* digest) {
    return EVP_MD_size(digest->type);
}

void random_bytes(void* buf, size_t length) {
    RAND_pseudo_bytes(buf, length);
}