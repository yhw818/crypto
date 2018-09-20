#include "dgst.h"

#define BUFFSIZE 1024 * 8


DgstSign::DgstSign(const Digest digest) : evp_md_(nullptr) {
    evp_md_ = EVP_MD_COMPUTE(digest);
} 


bool DgstSign::init_pkey(std::shared_ptr<BIO> bioptr, const CRYPTO_FORMAT cf, 
                            const std::string& password) {
                                EVP_PKEY * signkey = load_key(bioptr.get(), password, cf);
    if (signkey == nullptr) { return false; }
    pkey_.reset(signkey, [](EVP_PKEY* pkey) { if (pkey) EVP_PKEY_free(pkey); });

    EVP_MD_CTX * ctx = EVP_MD_CTX_new();
    if (!ctx) return false;

    ctx_.reset(ctx, [](EVP_MD_CTX * ctx) { if (ctx) { EVP_MD_CTX_free(ctx);}});

    EVP_PKEY_CTX * pctx = nullptr;
    int code = EVP_DigestSignInit(ctx, &pctx, evp_md_, nullptr, signkey);

    return code == 1;
}


bool DgstSign::sign_init_pkey_in_file(const std::string& f, 
                                     const CRYPTO_FORMAT cf, 
                                     const std::string& password) {
                                         
    BIO * bio = bio_read_file(f.c_str());
    if (!bio) return false;
    std::shared_ptr<BIO> bioPtr(bio, [](BIO* b) {if (b) BIO_free(b); });

    return init_pkey(bioPtr, cf, password);   
}

bool DgstSign::sign_init_pkey_in_mem(const std::string& m, const CRYPTO_FORMAT cf, const std::string& password) {
    BIO * bio = bio_read_mm(m);
    if (!bio) return false;
    std::shared_ptr<BIO> bioPtr(bio, [](BIO* b) {if (b) BIO_free(b); });

    return init_pkey(bioPtr, cf, password);
}


int DgstSign::sign_update(const void* d, size_t cnt) {
    if (!ctx_ || !d || cnt <= 0) { return 0; }

    return EVP_DigestSignUpdate(ctx_.get(), d, cnt);
}

std::string DgstSign::sign_final() {
    size_t len = 0;
    std::string str;
    if (ctx_) { 
        int code = EVP_DigestSignFinal(ctx_.get(), nullptr, &len);
        if (code == 1) {
            unsigned char * buf = (unsigned char *)malloc(len);
            if (buf) {
                code = EVP_DigestSignFinal(ctx_.get(), buf, &len);
                if (code == 1) {
                    str = std::string((const char*)buf, len);
                }
                free(buf);
            }
        }
    }
    return str;
}

DgstVerify::DgstVerify(const Digest digest) : evp_md_(nullptr) {
    evp_md_ = EVP_MD_COMPUTE(digest);
} 

bool DgstVerify::init_pubkey(std::shared_ptr<BIO> bioptr, const CRYPTO_FORMAT cf, 
                const std::string& password) {
    EVP_PKEY * signkey = load_pubkey(bioptr.get(), password, cf);
    if (signkey == nullptr) { return false; }
    pkey_.reset(signkey, [](EVP_PKEY* pkey) { if (pkey) EVP_PKEY_free(pkey); });

    EVP_MD_CTX * ctx = EVP_MD_CTX_new();
    if (!ctx) return false;

    ctx_.reset(ctx, [](EVP_MD_CTX * ctx) {if (ctx) { EVP_MD_CTX_free(ctx);}});

    EVP_PKEY_CTX * pctx = nullptr;
    int code = EVP_DigestVerifyInit(ctx, &pctx, evp_md_, nullptr, signkey);

    return code == 1;
}

bool DgstVerify::verify_init_pub_in_file(const std::string& f, const CRYPTO_FORMAT cf, const std::string& password) {
    BIO * bio = bio_read_file(f.c_str());
    if (!bio) return false;
    std::shared_ptr<BIO> bioPtr(bio, [](BIO* b) {if (b) { BIO_free(b); } });

    return init_pubkey(bioPtr, cf, password);   
}
bool DgstVerify::verify_init_pub_in_mm(const std::string& m, const CRYPTO_FORMAT cf, const std::string& password) {
    BIO * bio = bio_read_mm(m);
    if (!bio) return false;
    std::shared_ptr<BIO> bioPtr(bio, [](BIO* b) {if (b) BIO_free(b); });

    return init_pubkey(bioPtr, cf, password);
}

int DgstVerify::verify_update(const void *d, size_t cnt) {
    if (!ctx_ || !d || cnt <= 0) { return 0; }
    return EVP_DigestVerifyUpdate(ctx_.get(), d, cnt);
}

int DgstVerify::verify_final(const unsigned char *sig, size_t siglen) {
    if (!ctx_ || !sig || siglen <= 0) { return 0; }

    return EVP_DigestVerifyFinal(ctx_.get(), sig, (unsigned int)siglen);
}

int main(int argc, char ** argv) {
    // sign
    {
        printf("start sign---\n");
        std::shared_ptr<DgstSign> sign (new DgstSign(Digest::SHA256));

        bool ret = sign->sign_init_pkey_in_file("private.pem", CRYPTO_FORMAT::FORMAT_PEM, "23003625");
        if (!ret) {
            printf("sign init error\n");
            return 0;
        }

        BIO * bio = bio_read_file("public.pem");
        if (!bio) { printf("public bio error\n"); return 0; }
        std::shared_ptr<BIO> bioPtr(bio, [](BIO * bio) { if (bio) { BIO_free(bio);}});

        char buf[1024 * 8] {'\0'};

        int i ;
        int len = 0;
        for (;;) {
            i = BIO_read(bio, buf, 1024*8);
            if (i < 0) { return 0;}
            if (i == 0) {
                break;
            }
            len += i;
        }
        int code = sign->sign_update((const void*)buf, len);
        if (code != 1) {
            printf("update error\n");
            return 0;
        }

        std::string output = sign->sign_final();

        if (output.empty()) { printf("final error\n");}

        BIO * w = BIO_new(BIO_s_file());
        if (!w) { return 0; }

        char f[64] {"sign.256"};
        BIO_write_filename(w, f);

        BIO_write(w, output.c_str(), output.size());

        BIO_flush(w);

        BIO_free(w);
        printf("end sign-> check sign.256\n");
    }

    // verify
    {
        std::shared_ptr< DgstVerify> verify (new DgstVerify(Digest::SHA256));

        bool isok = verify->verify_init_pub_in_file("public.pem", CRYPTO_FORMAT::FORMAT_PEM, "23003625");

        if (!isok) { printf("verify init error\n"); return 0; }
    
        char buf[1024 * 8] {'\0'};
        {
            BIO * bio = bio_read_file("public.pem");

            int i;
            int len = 0;
            for (;;) {
                i = BIO_read(bio, buf, 1024*8);
                if (i < 0) {
                    printf("public.pem read error\n");
                    return 0;
                }
                if (i == 0) {
                    break;
                }
                len += i;
            }
            BIO_free(bio);
            int code = verify->verify_update(buf, len);
            if (code != 1) {
                printf("verify update error\n");
                return 0;
            }
        }    

        {
            unsigned char * sigbuf = nullptr;
            BIO * pbio = bio_read_file("sign.256");

            if (!pbio) { return 0; }
            std::shared_ptr<BIO> pbioPtr(pbio, [](BIO* bio) { if (bio) { BIO_free(bio);} });

            int siglen = verify->pkey_size();
            sigbuf = (unsigned char*)malloc(siglen);
            siglen = BIO_read(pbio, sigbuf, siglen);
            if (siglen <= 0) {
                free(sigbuf);
                printf("read signature file error\n");
                return 0;
            }
            int code = verify->verify_final((const unsigned char *)sigbuf, siglen);

            if (code == 1) {
                printf("Verified OK\n");
            } else {
                printf("Verify failed %s\n", ERR_error_string(ERR_get_error(), nullptr));
            }
            free(sigbuf);
        }
    }
    return 0;
}
