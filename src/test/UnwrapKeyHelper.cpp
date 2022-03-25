#include "UnwrapKeyHelper.h"
#include "libp11sgx.h"
#include "config.h"

#include <vector>
#include <string>
#include <cstring>

std::vector<CK_BYTE> UnwrapKeyHelper::getDigest(std::vector<CK_BYTE>& data)
{
    const EVP_MD* evpMd = EVP_sha384();
    std::vector<CK_BYTE> digest;
    digest.resize(EVP_MD_size(evpMd));
    unsigned int outLen = digest.size();

    EVP_MD_CTX* curCTX = EVP_MD_CTX_new();
    if (nullptr == curCTX ||
        !EVP_DigestInit_ex(curCTX, evpMd, nullptr) ||
        !EVP_DigestUpdate(curCTX, (unsigned char*) data.data(), data.size()) ||
        !EVP_DigestFinal_ex(curCTX, &digest[0], &outLen))
    {
        EVP_MD_CTX_free(curCTX);
        CPPUNIT_ASSERT(0);
    }

    digest.resize(outLen);
    if (curCTX)
    {
        EVP_MD_CTX_free(curCTX);
    }
    return digest;
}

static RSA* getRSAPublicKey()
{
    RSA* rsa_pub = RSA_new();
    if (!rsa_pub)
    {
        CPPUNIT_ASSERT(0);
    };

    std::string unWrapPubKeyCTK = PUBLIC_KEY;
    if (unWrapPubKeyCTK.empty())
    {
        CPPUNIT_ASSERT(0);
    }

    FILE* fp = fopen(unWrapPubKeyCTK.c_str(), "r");
    if (!fp)
    {
        CPPUNIT_ASSERT(0);
    }

    if(!rsa_pub || PEM_read_RSAPublicKey(fp, &rsa_pub, nullptr, nullptr) == nullptr)
    {
        if (fp)
        {
            fclose(fp);
        }
        CPPUNIT_ASSERT(0);
    }

    if (fp)
    {
        fclose(fp);
    }

    return rsa_pub;
}

static RSA* getRSAPrivateKey()
{
    RSA* rsa_priv = RSA_new();
    if (!rsa_priv)
    {
        CPPUNIT_ASSERT(0);
    };

    std::string unWrapPrivKeyCTK = PRIVATE_KEY;
    if (unWrapPrivKeyCTK.empty())
    {
        CPPUNIT_ASSERT(0);
    }

    FILE* fp = fopen(unWrapPrivKeyCTK.c_str(), "r");
    if (!fp)
    {
        CPPUNIT_ASSERT(0);
    }

    if(!rsa_priv || PEM_read_RSAPrivateKey(fp, &rsa_priv, nullptr, nullptr) == nullptr)
    {
        if (fp)
        {
            fclose(fp);
        }
        CPPUNIT_ASSERT(0);
    }

    if (fp)
    {
        fclose(fp);
    }

    return rsa_priv;
}

static RSA* getRSAKey()
{
    ERR_load_BIO_strings();
    unsigned long e = RSA_F4;
    size_t modulusSize = 3072;

    BIGNUM* bne = BN_new();
    if (!bne)
    {
        CPPUNIT_ASSERT(0);
    }

    if (BN_set_word(bne,e) != 1)
    {
        CPPUNIT_ASSERT(0);
    }

    RSA* rsa = RSA_new();
    if (!rsa)
    {
        CPPUNIT_ASSERT(0);
    }

    if (!bne || RSA_generate_key_ex(rsa, modulusSize, bne, nullptr) != 1)
    {
        RSA_free(rsa);
        CPPUNIT_ASSERT(0);
    }

    if (!rsa)
    {
        CPPUNIT_ASSERT(0);
    }

    return rsa;
}

static void freeRSAKey(RSA* rsa_pub, RSA* rsa_priv)
{
    if (rsa_pub)
    {
        RSA_free(rsa_pub);
        rsa_pub = nullptr;
    }

    if (rsa_priv)
    {
        RSA_free(rsa_priv);
        rsa_priv = nullptr;
    }
}

void UnwrapKeyHelper::getUnwrapParams(CK_MECHANISM&         mech,
                                      std::vector<CK_BYTE>& encData,
                                      std::vector<CK_BYTE>& wrappedKey,
                                      bool                  useLocalPublicKey,
                                      bool                  useLocalPrivateKey)
{
    int padding, type = 0;
    std::vector<CK_BYTE> digest, mod, exp, signature;
    const EVP_MD* hash = nullptr;
    RSA *rsa_pub = nullptr, *rsa_priv = nullptr;
    bool useConfStrings = !useLocalPublicKey && !useLocalPrivateKey;

    if (useConfStrings)
    {
        rsa_pub = getRSAPublicKey();
        if (!rsa_pub)
        {
            CPPUNIT_ASSERT(0);
        }

        rsa_priv = getRSAPrivateKey();
        if (!rsa_priv)
        {
            freeRSAKey(rsa_pub, rsa_priv);
            CPPUNIT_ASSERT(0);
        }
    }
    else
    {
        RSA* rsa = getRSAKey();
        if (!rsa)
        {
            CPPUNIT_ASSERT(0);
        }

        if (useLocalPublicKey)
        {
            rsa_pub = rsa;
        }
        else
        {
            rsa_pub = getRSAPublicKey();
            if (!rsa_pub)
            {
                freeRSAKey(rsa_pub, rsa_priv);
                CPPUNIT_ASSERT(0);
            }
        }

        if (useLocalPrivateKey)
        {
            rsa_priv = rsa;
        }
        else
        {
            rsa_priv = getRSAPrivateKey();
            if (!rsa_priv)
            {
                freeRSAKey(rsa_pub, rsa_priv);
                CPPUNIT_ASSERT(0);
            }
        }
    }

    hash = EVP_sha384();
    digest = getDigest(encData);

    const BIGNUM* bn_n = nullptr;
	const BIGNUM* bn_e = nullptr;
	RSA_get0_key(rsa_pub, &bn_n, &bn_e, nullptr);
    if (!bn_n || !bn_e || !rsa_pub)
    {
        freeRSAKey(rsa_pub, rsa_priv);
        CPPUNIT_ASSERT(0);
    }

    CK_ULONG modulusLen = BN_num_bytes(bn_n);
    CK_ULONG exponentLen = BN_num_bytes(bn_e);
    mod.resize(modulusLen);
    exp.resize(exponentLen);

    BN_bn2bin(bn_n, mod.data());
    BN_bn2bin(bn_e, exp.data());

    // Compute signature
    signature.resize(modulusLen);

    std::vector<CK_BYTE> em;
    em.resize(modulusLen);
    size_t sLen = ((CK_RSA_PKCS_PSS_PARAMS*)mech.pParameter)->sLen;

    if (!rsa_priv)
    {
        freeRSAKey(rsa_pub, rsa_priv);
        CPPUNIT_ASSERT(0);
    }

    int result = (RSA_padding_add_PKCS1_PSS(rsa_priv, &em[0], &digest[0],
                                            hash, sLen) == 1);
    if (!result || !rsa_priv)
    {
        freeRSAKey(rsa_pub, rsa_priv);
        CPPUNIT_ASSERT(0);
    }
    else
    {
        if (!rsa_priv)
        {
            freeRSAKey(rsa_pub, rsa_priv);
            CPPUNIT_ASSERT(0);
        }

        result = RSA_private_encrypt(em.size(), &em[0], &signature[0],
                            rsa_priv, RSA_NO_PADDING);
        if (result >= 0)
        {
            signature.resize(result);
        }
        else
        {
            freeRSAKey(rsa_pub, rsa_priv);
            CPPUNIT_ASSERT(0);
        }
    }

    CK_ULONG signatureLen  = signature.size();
    CK_ULONG wrappedKeyLen = encData.size();
    CK_ULONG paramsLen     = sizeof(CK_UNWRAP_KEY_PARAMS);
    CK_ULONG totalLen      = paramsLen + modulusLen + exponentLen + signatureLen + wrappedKeyLen;

    CK_UNWRAP_KEY_PARAMS params;
    params.modulusLen    = modulusLen;
    params.exponentLen   = exponentLen;
    params.signatureLen  = signatureLen;
    params.wrappedKeyLen = wrappedKeyLen;
    params.pMechanism    = &mech;

    wrappedKey.resize(totalLen);

    CK_ULONG offset = 0;
    memcpy(wrappedKey.data() + offset, &params, paramsLen);
    offset += paramsLen;
    memcpy(wrappedKey.data() + offset, mod.data(), modulusLen);
    offset += modulusLen;
    memcpy(wrappedKey.data() + offset, exp.data(), exponentLen);
    offset += exponentLen;
    memcpy(wrappedKey.data() + offset, signature.data(), signatureLen);
    offset += signatureLen;
    memcpy(wrappedKey.data() + offset, encData.data(), wrappedKeyLen);

    freeRSAKey(rsa_pub, rsa_priv);
    return;
}