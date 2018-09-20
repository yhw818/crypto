#include "crypto.h"


static int pem_p_password_cb (char *buf, int size, int rwflag, void *userdata) {
    if (!userdata) return 0;

    const char * pwd = (const char *)userdata;

    int len = strlen(pwd);
    if (len > size) len = size;
    memcpy(buf, pwd, len);
    return len;
}


const EVP_MD * EVP_MD_COMPUTE(const Digest digest) {
    switch (digest) {
#ifndef OPENSSL_NO_MD2
        case Digest::MD2:
            return EVP_md2();
#endif        
        case Digest::MD5:
            return EVP_md5();
        case Digest::SHA1:
            return EVP_sha1();
        case Digest::SHA224:
            return EVP_sha224();
        case Digest::SHA256:
            return EVP_sha256();
        case Digest::SHA384:
            return EVP_sha384();
        case Digest::SHA512:
            return EVP_sha512();
#ifndef OPENSSL_NO_MDC2
        case Digest::MDC2:
            return EVP_mdc2();            
#endif
        case Digest::RIPEMD160:
            return EVP_ripemd160();
        case Digest::BLAKE2b512:
            return EVP_blake2b512();
        case Digest::BLAKE2s256:
            return EVP_blake2s256();    
        default:
            return EVP_md_null();
    }
}

BIO* bio_read_file(const char * f) {

    if (!f) { return nullptr; }
#if 0
    BIO* bio = BIO_new(BIO_s_file());

    if (bio) {
        int code = BIO_read_filename(bio, f);  
        if (code != 1) {
            printf("read error\n");
            BIO_free(bio);
            bio = nullptr;
        }
    }
#else
    BIO * bio = BIO_new_file(f, "rb");
#endif


    return bio;
}

BIO* bio_write_file(const char *f) {
    if (!f) { return nullptr; }

    BIO* bio = BIO_new(BIO_s_file());

    if (bio) {
        BIO_write_filename(bio, (char*)f);  
    }
    return bio;
}

BIO* bio_read_mm(const std::string& m) {
    if (m.empty()) { return nullptr; }
    return BIO_new_mem_buf(m.c_str(), m.size());
}

EVP_PKEY* load_key(BIO* bio, const std::string& password, const CRYPTO_FORMAT cf) {
    EVP_PKEY *pkey = nullptr;

    switch(cf) {
        case CRYPTO_FORMAT::FORMAT_ASN1:
            pkey = d2i_PrivateKey_bio(bio, NULL);
            break;
        case CRYPTO_FORMAT::FORMAT_PEM:
            pkey = PEM_read_bio_PrivateKey(bio, NULL,
                                           (pem_password_cb*)pem_p_password_cb,
                                            (void*)password.c_str());
            break;
        default:
            break;
    }
    return pkey;
}

EVP_PKEY *load_pubkey(BIO* bio,
                      const std::string& password, const CRYPTO_FORMAT cf)
{
    
    
    EVP_PKEY * pkey = NULL;
    

    if (cf == CRYPTO_FORMAT::FORMAT_ASN1) {
        pkey = d2i_PUBKEY_bio(bio, NULL);
    } else if (cf == CRYPTO_FORMAT::FORMAT_ASN1RSA) {
        RSA *rsa;
        rsa = d2i_RSAPublicKey_bio(bio, NULL);
        if (rsa) {
            pkey = EVP_PKEY_new();
            if (pkey != NULL)
                EVP_PKEY_set1_RSA(pkey, rsa);
            RSA_free(rsa);
        } else
        pkey = NULL;   
    } else if (cf == CRYPTO_FORMAT::FORMAT_PEMRSA) {
        RSA *rsa;
        rsa = PEM_read_bio_RSAPublicKey(bio, NULL,
                                        (pem_password_cb *)pem_p_password_cb,
                                        (void*)password.c_str());
        if (rsa != NULL) {
            pkey = EVP_PKEY_new();
            if (pkey != NULL)
                EVP_PKEY_set1_RSA(pkey, rsa);
            RSA_free(rsa);
        } else
            pkey = NULL;
    } else if (cf == CRYPTO_FORMAT::FORMAT_PEM) {
        pkey = PEM_read_bio_PUBKEY(bio, NULL,
                                   (pem_password_cb *)pem_p_password_cb,
                                   (void*)password.c_str());
    }
 
    return (pkey);
}
