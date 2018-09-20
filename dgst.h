#ifndef ONEPIECE_BASE_CRYPTO_DGST_H_
#define ONEPIECE_BASE_CRYPTO_DGST_H_


#include "crypto.h"


class DgstSign {
public:
    DgstSign(const Digest digest);
    ~DgstSign() = default;

    bool sign_init_pkey_in_file(const std::string& f, const CRYPTO_FORMAT cf, const std::string& password = "");
    bool sign_init_pkey_in_mem(const std::string& m, const CRYPTO_FORMAT cf, const std::string& password = "");

    /**
     * @ret 1 for success and 0 for error
     */ 
    int sign_update(const void* d, size_t cnt);

    std::string sign_final();
private:
    bool init_pkey(std::shared_ptr<BIO> bioptr, const CRYPTO_FORMAT cf, 
                            const std::string& password);
private:
    const EVP_MD * evp_md_;
    std::shared_ptr<EVP_PKEY> pkey_;
    std::shared_ptr<EVP_MD_CTX> ctx_;
};


class DgstVerify {
public:
    DgstVerify(const Digest digest);
    ~DgstVerify() = default;

    bool verify_init_pub_in_file(const std::string& f, const CRYPTO_FORMAT cf, const std::string& password = "");
    bool verify_init_pub_in_mm(const std::string& m, const CRYPTO_FORMAT cf, const std::string& password = "");

    int verify_update(const void *d, size_t cnt);
    int verify_final(const unsigned char *sig, size_t siglen);


    int pkey_size() const { return pkey_ ? EVP_PKEY_size(pkey_.get()) : 0; }
private:
    bool init_pubkey(std::shared_ptr<BIO> bioptr, const CRYPTO_FORMAT cf, 
                const std::string& password);
private:
    const EVP_MD * evp_md_;
    std::shared_ptr<EVP_PKEY> pkey_;
    std::shared_ptr<EVP_MD_CTX> ctx_;
};




#endif  // ONEPIECE_BASE_CRYPTO_DGST_H_
