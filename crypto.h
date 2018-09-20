#ifndef ONEPIECE_BASE_CRYPTO_H_
#define ONEPIECE_BASE_CRYPTO_H_

#include "common.h"

enum class Digest {
    MD2,
    MD5,
    SHA1,
    SHA224,
    SHA256,
    SHA384,
    SHA512,
    MDC2,
    RIPEMD160,
    BLAKE2b512,
    BLAKE2s256,
    null
};

enum class CRYPTO_FORMAT {
    FORMAT_ASN1,
    FORMAT_PEM,
    FORMAT_PKCS12,
    FORMAT_ASN1RSA,
    FORMAT_PEMRSA
};

const EVP_MD * EVP_MD_COMPUTE(const Digest digest);
BIO* bio_read_file(const char * f);
BIO* bio_write_file(const char *f);
BIO* bio_read_mm(const std::string& m);

EVP_PKEY* load_key(BIO* bio, const std::string& password, const CRYPTO_FORMAT cf);
EVP_PKEY *load_pubkey(BIO* bio,
                      const std::string& password, const CRYPTO_FORMAT cf);


#endif  // ONEPIECE_BASE_CRYPTO_H_
