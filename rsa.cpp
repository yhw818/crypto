#include "common.h"

static int pem_parse_password_cb (char *buf, int size, int rwflag, void *userdata) {
    if (!userdata) return 0;

    const char * pwd = (const char *)userdata;

    int len = strlen(pwd);

    if (len > size) len = size;

    memcpy(buf, pwd, len);
    return len;
}

// @brief public key encryption
// @ret encrypted data
std::string encrypt (const char * pub, const unsigned char * from) {

    std::shared_ptr <BIO> bio (BIO_new(BIO_s_file()), [](BIO * bio) { BIO_free(bio);});

    if (!bio) {
        printf("can't create BIO to read file\n");
        return "";
    }

    if (BIO_read_filename(bio.get(), pub) == 0) {
        printf("bio read file error\n");
        return "";
    }

    
    std::shared_ptr<RSA> rsaPtr (PEM_read_bio_RSAPublicKey(bio.get(), NULL, 
                                nullptr, nullptr),
                                [](RSA*rsa) { RSA_free(rsa);});

    
    if (!rsaPtr) {
        BIO_seek(bio.get(), 0);
        rsaPtr.reset(PEM_read_bio_RSA_PUBKEY(bio.get(), nullptr, nullptr, nullptr),
        [](RSA*rsa) { RSA_free(rsa);}
        );
        if (!rsaPtr) {
            printf("bad pubkey\n");
            return "";
        }
    }

    RSA * rsa = rsaPtr.get();
    //const unsigned char * from = (const unsigned char * )"1234567890";
    unsigned char * to = (unsigned char*)malloc(RSA_size(rsa) * sizeof(unsigned char));
    if (!to) {
        printf("bad malloc to\n");
        return "";
    }

    if (-1 == RSA_public_encrypt(strlen((const char*)from), from, to, rsa, RSA_PKCS1_PADDING)) {
        printf("bad RSA public encrypt\n");
        return "";
    }
    std::string str((const char*)to, RSA_size(rsa));
    free(to);
    return str;
} 

/**
 * @brief rsa private decryption
 */ 
unsigned char * decrypt(const std::string& from, const char * pri, const char * password) {
    std::shared_ptr <BIO> bio (BIO_new(BIO_s_file()), [](BIO * bio) { BIO_free(bio);});

    if (!bio) {
        printf("can't create BIO to read file\n");
        return nullptr;
    }

    if (BIO_read_filename(bio.get(), pri) == 0) {
        printf("bio read file error\n");
        return nullptr;
    }


    std::shared_ptr<RSA> rsaPtr (
        PEM_read_bio_RSAPrivateKey(bio.get(), nullptr, pem_parse_password_cb, (void*)password),
        [](RSA * rsa) { if (rsa) RSA_free(rsa); }
    );
    
    if (!rsaPtr) {
        printf("bad privateKey\n");
        return nullptr;
    }

    RSA * rsa = rsaPtr.get();

    unsigned char * to = (unsigned char *) malloc(RSA_size(rsa) * sizeof(unsigned char));

    memset(to, '\0', RSA_size(rsa) * sizeof(unsigned char));
    if (-1 == RSA_private_decrypt(from.size(), (unsigned char*)from.c_str(), to, rsa, RSA_PKCS1_PADDING)) {
        printf("bad rsa dec\n");
        char buf[2048] {'\0'};

        ERR_error_string(ERR_get_error(), buf);
        if (to) { free(to); }
        return nullptr;
    }
    return to;
}

int main(int argc, char ** argv) {
    if (argc < 3) {
        printf("rsa public.pem private.pem password\n");
        return 0;
    }

    const unsigned char * from = (const unsigned char * )"1234567890HelloSSL";
    auto to = encrypt(argv[1], from);

    auto dec = decrypt(to, argv[2], argv[3]);

    if (dec) { 
        printf("%s\n", dec); 
        free(dec);
    }
    return 0;
}
