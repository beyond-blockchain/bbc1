/**
  Copyright (c) 2017 beyond-blockchain.org.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

#include <stdio.h>
#include <stdbool.h>
#include <strings.h>

#include "libbbcsig.h"
#include <string.h>
#include <time.h>

#ifndef _WIN32
#include <strings.h>
#endif

#include <openssl/ec.h>      // for EC_GROUP_new_by_curve_name, EC_GROUP_free, EC_KEY_new, EC_KEY_set_group, EC_KEY_generate_key, EC_KEY_free
#include <openssl/ecdsa.h>   // for ECDSA_do_sign, ECDSA_do_verify
#include <openssl/bn.h>
#include <openssl/obj_mac.h> // for NID_secp192k1
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/stack.h>
#include <openssl/x509_vfy.h>

#include <crypto/ec/ec_lcl.h>

#define CURVE_TYPE_SECP256  1
#define CURVE_TYPE_P256     2

#define macro_init_EC_GROUP(X)                                     \
    EC_GROUP *ecgroup;                                             \
    if (X == CURVE_TYPE_SECP256) {                                 \
        ecgroup = EC_GROUP_new_by_curve_name(NID_secp256k1);       \
    } else if (X == CURVE_TYPE_P256) {                             \
        ecgroup = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);    \
    } else {                                                       \
        return false;          \
    }                          \
    if (NULL == ecgroup) {     \
        EC_KEY_free(eckey);    \
        return false;          \
    }                          \
    if (EC_KEY_set_group(eckey, ecgroup) != 1) { \
        EC_GROUP_free(ecgroup);                  \
        EC_KEY_free(eckey);                      \
        return false;                            \
    }

#define macro_init_EC_KEY(X)              \
    EC_KEY *eckey = EC_KEY_new();         \
    if (NULL == eckey) return false;      \
    macro_init_EC_GROUP(X)

#define macro_free_EC_KEY   \
    EC_GROUP_free(ecgroup); \
    EC_KEY_free(eckey)




static inline const BIGNUM * _get_naive_privateKey_from_eckey(EC_KEY *eckey, int *privkey_len, uint8_t *privkey)
{
    const BIGNUM *private_key = EC_KEY_get0_private_key(eckey);
    *privkey_len = BN_num_bytes(private_key);
    BN_bn2bin(private_key, privkey);
    return private_key;
}

static inline void _get_naive_pubicKey_from_eckey(EC_KEY *eckey, EC_GROUP *ecgroup, const uint8_t pubkey_type, int *pubkey_len, uint8_t *pubkey)
{
    BN_CTX *ctx = BN_CTX_new();
    const EC_POINT *pubkey_point = EC_KEY_get0_public_key(eckey);
    if (pubkey_type == 0) {
        *pubkey_len = 65;
        EC_POINT_point2oct(ecgroup, pubkey_point, POINT_CONVERSION_UNCOMPRESSED, pubkey, *pubkey_len, ctx);
    } else {
        *pubkey_len = 33;
        EC_POINT_point2oct(ecgroup, pubkey_point, POINT_CONVERSION_COMPRESSED, pubkey, *pubkey_len, ctx);
    }
    EC_POINT_free((EC_POINT *)pubkey_point);
    BN_CTX_free(ctx);
}

static inline void _calculate_publicKey_from_bignum_privateKey(EC_GROUP *ecgroup, const BIGNUM *private_key,
                                                               const uint8_t pubkey_type, int *pubkey_len, uint8_t *pubkey)
{
    EC_POINT *pubkey_point = EC_POINT_new(ecgroup);
    BN_CTX *ctx = BN_CTX_new();
    EC_POINT_mul(ecgroup, pubkey_point, private_key, NULL, NULL, ctx);

    if (pubkey_type == 0) {
        *pubkey_len = 65;
        EC_POINT_point2oct(ecgroup, pubkey_point, POINT_CONVERSION_UNCOMPRESSED, pubkey, *pubkey_len, ctx);
    } else {
        *pubkey_len = 33;
        EC_POINT_point2oct(ecgroup, pubkey_point, POINT_CONVERSION_COMPRESSED, pubkey, *pubkey_len, ctx);
    }

    BN_free((BIGNUM *)private_key);
    EC_POINT_free(pubkey_point);
    BN_CTX_free(ctx);
}

static inline void _build_eckey(EC_KEY *eckey, EC_GROUP *ecgroup, int privkey_len, uint8_t *privkey)
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *private_key = BN_bin2bn(privkey, privkey_len, NULL);
    EC_KEY_set_private_key(eckey, private_key);

    EC_POINT *pubkey_point = EC_POINT_new(ecgroup);
    EC_POINT_mul(ecgroup, pubkey_point, private_key, NULL, NULL, ctx);
    EC_KEY_set_public_key(eckey, pubkey_point);

    BN_free(private_key);
    EC_POINT_free(pubkey_point);
    BN_CTX_free(ctx);
}

static inline void _build_eckey_pub(EC_KEY *eckey, EC_GROUP *ecgroup, int point_len, uint8_t *point)
{
    BN_CTX *ctx = BN_CTX_new();
    EC_POINT *pubkey_point = EC_POINT_new(ecgroup);
    EC_POINT_oct2point(ecgroup, pubkey_point, point, point_len, ctx);
    EC_KEY_set_public_key(eckey, pubkey_point);
    EC_POINT_free(pubkey_point);
    BN_CTX_free(ctx);
}

static inline EVP_PKEY * _read_privateKey_pem(const char *pem)
{
    BIO* bo = BIO_new( BIO_s_mem() );
    BIO_write(bo, pem, strlen(pem));
    EVP_PKEY *privateKey = NULL;
    if (PEM_read_bio_PrivateKey( bo, &privateKey, 0, 0 ) == NULL) {
        privateKey = NULL;
    }
    BIO_free(bo);
    return privateKey;
}



VS_DLL_EXPORT
bool VS_STDCALL sign(const int curvetype, int privkey_len, uint8_t *privkey, int hash_len, uint8_t *hash,
                     uint8_t *sig_r, uint8_t *sig_t, uint32_t *sig_r_len, uint32_t *sig_s_len)
{
    macro_init_EC_KEY(curvetype);

    BIGNUM *private_key = BN_bin2bn(privkey, privkey_len, NULL);
    EC_KEY_set_private_key(eckey, private_key);
    BN_free(private_key);

    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *kinv = NULL, *rp = NULL;
    bool flag = ECDSA_sign_setup(eckey, ctx, &kinv, &rp);
    BN_CTX_free(ctx);
    if (! flag) goto FIN;

    ECDSA_SIG *signature = ECDSA_do_sign_ex(hash, hash_len, kinv, rp, eckey);
    BN_bn2bin(signature->r, sig_r);
    BN_bn2bin(signature->s, sig_t);

    *sig_r_len = (uint32_t) BN_num_bytes(signature->r);
    *sig_s_len = (uint32_t) BN_num_bytes(signature->s);
    ECDSA_SIG_free(signature);

  FIN:
    macro_free_EC_KEY;
    return flag;
}

VS_DLL_EXPORT
int VS_STDCALL verify(const int curvetype, int point_len, const uint8_t *point,
                      int hash_len,uint8_t *hash, int sig_len, const uint8_t *sig)
{
    macro_init_EC_KEY(curvetype);

    EC_POINT *pubkey_point = EC_POINT_new(ecgroup);
    BN_CTX *ctx = BN_CTX_new();
    EC_POINT_oct2point(ecgroup, pubkey_point, point, point_len, ctx);
    BN_CTX_free(ctx);

    EC_KEY_set_public_key(eckey, pubkey_point);
    EC_POINT_free(pubkey_point);

    ECDSA_SIG *signature = ECDSA_SIG_new();
    int numlen = (int)(sig_len/2);
    signature->r = BN_bin2bn(sig, numlen, NULL);
    signature->s = BN_bin2bn(&sig[numlen], numlen, NULL);

    int verify_status = ECDSA_do_verify(hash, hash_len, signature, eckey);

    ECDSA_SIG_free(signature);
    macro_free_EC_KEY;

    return verify_status;
}

VS_DLL_EXPORT
bool VS_STDCALL generate_keypair(const int curvetype, const uint8_t pubkey_type, int *pubkey_len, uint8_t *pubkey,
                      int *privkey_len, uint8_t *privkey)
{
    macro_init_EC_KEY(curvetype);

    EC_KEY_generate_key(eckey);
    const BIGNUM *private_key = _get_naive_privateKey_from_eckey(eckey, privkey_len, privkey);

    _get_naive_pubicKey_from_eckey(eckey, ecgroup, pubkey_type, pubkey_len, pubkey);

    BN_free((BIGNUM *)private_key);
    EC_GROUP_free(ecgroup);
    return true;
}

VS_DLL_EXPORT
bool VS_STDCALL get_public_key_uncompressed(const int curvetype, int privkey_len, uint8_t *privkey, int *pubkey_len, uint8_t *pubkey)
{
    macro_init_EC_KEY(curvetype);

    const BIGNUM *private_key = BN_bin2bn(privkey, privkey_len, NULL);
    _calculate_publicKey_from_bignum_privateKey(ecgroup, private_key, 0, pubkey_len, pubkey);

    macro_free_EC_KEY;
    return true;
}

VS_DLL_EXPORT
bool VS_STDCALL get_public_key_compressed(const int curvetype, int privkey_len, uint8_t *privkey, int *pubkey_len, uint8_t *pubkey)
{
    macro_init_EC_KEY(curvetype);

    const BIGNUM *private_key = BN_bin2bn(privkey, privkey_len, NULL);
    _calculate_publicKey_from_bignum_privateKey(ecgroup, private_key, 1, pubkey_len, pubkey);

    macro_free_EC_KEY;
    return true;
}

VS_DLL_EXPORT
bool VS_STDCALL convert_from_der(long der_len, const unsigned char *der, const uint8_t pubkey_type,
                                 int *pubkey_len, uint8_t *pubkey, int *privkey_len, uint8_t *privkey)
{
    EC_KEY *eckey = d2i_ECPrivateKey(NULL, &der, der_len); // bug in memory allocation?
    if (eckey == NULL) return false;
    EC_GROUP *ecgroup = eckey->group;

    const BIGNUM *private_key = _get_naive_privateKey_from_eckey(eckey, privkey_len, privkey);

    _calculate_publicKey_from_bignum_privateKey(ecgroup, private_key, pubkey_type, pubkey_len, pubkey);

    EC_GROUP_free(ecgroup);
    return true;
}


VS_DLL_EXPORT
bool VS_STDCALL convert_from_pem(const char *pem, const uint8_t pubkey_type,
                                 int *pubkey_len, uint8_t *pubkey, int *privkey_len, uint8_t *privkey)
{
    EVP_PKEY *privateKey =  _read_privateKey_pem(pem);

    EC_KEY *eckey = EVP_PKEY_get1_EC_KEY(privateKey);
    EC_GROUP *ecgroup = eckey->group;
    //macro_init_EC_GROUP(curvetype);
    const BIGNUM *private_key = _get_naive_privateKey_from_eckey(eckey, privkey_len, privkey);

    _calculate_publicKey_from_bignum_privateKey(ecgroup, private_key, pubkey_type, pubkey_len, pubkey);

    macro_free_EC_KEY;
    return true;
}


static int cert_verify_callback(int ok, X509_STORE_CTX *ctx)
{
    /* Tolerate self-signed certificate */
    if (X509_STORE_CTX_get_error(ctx) == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) {
        return 1;
    }

    /* Otherwise don't override */
    return ok;
}


VS_DLL_EXPORT
bool VS_STDCALL read_x509(const char *pubkey_x509, const uint8_t pubkey_type,  int *pubkey_len, uint8_t *pubkey)
{
    BIO *bio = BIO_new(BIO_s_mem());
    BIO_write(bio, pubkey_x509, strlen(pubkey_x509));
    X509 *x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (x509 == NULL) {
        BIO_free(bio);
        return false;
    }
    BIO_free(bio);

    EVP_PKEY *public_key = X509_get_pubkey(x509);
    EC_KEY *eckey = EVP_PKEY_get1_EC_KEY(public_key);
    EC_GROUP *ecgroup = eckey->group;

    _get_naive_pubicKey_from_eckey(eckey, ecgroup, pubkey_type, pubkey_len, pubkey);

    EVP_PKEY_free(public_key);
    macro_free_EC_KEY;
    return true;
}


VS_DLL_EXPORT
int VS_STDCALL verify_x509(const char *pubkey_x509, const char *privkey_pem)
{
    int result;
    BIO *bio = BIO_new(BIO_s_mem());
    BIO_write(bio, pubkey_x509, strlen(pubkey_x509));
    X509 *x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (x509 == NULL) {
        BIO_free(bio);
        return EBADCERT;
    }

    X509_STORE *cert_store = NULL;
    X509_STORE_CTX *store_ctx = NULL;
    STACK_OF(X509) *stack_of_x509 = NULL;    // no need because of treating self-signed cert only
    time_t check_time;
    int store_ctx_error;
    int store_ctx_error_depth;

    if( (cert_store= X509_STORE_new()) == NULL) {
        result = EFAULURE;
        goto FIN;
    }
    if( (store_ctx= X509_STORE_CTX_new()) == NULL) {
        result = EFAULURE;
        X509_STORE_free(cert_store);
        goto FIN;
    }

    X509_STORE_set_verify_cb_func(cert_store, cert_verify_callback);
    if( !X509_STORE_CTX_init(store_ctx, cert_store, NULL, stack_of_x509) ) {
        result = EFAULURE;
        goto FIN2;
    }

    X509_STORE_CTX_set_cert(store_ctx, x509);
    time(&check_time);

    X509_STORE_CTX_set_time(store_ctx, 0, check_time);
    X509_STORE_CTX_set_flags(store_ctx, X509_V_FLAG_USE_CHECK_TIME);

    result = X509_verify_cert(store_ctx);
    if (result < 1) {
        result = EINVALIDCERT;
        store_ctx_error = X509_STORE_CTX_get_error(store_ctx);
        store_ctx_error_depth = X509_STORE_CTX_get_error_depth(store_ctx);
        printf("Error %d at %d depth: %s\n", store_ctx_error, store_ctx_error_depth, X509_verify_cert_error_string(store_ctx_error));
        goto FIN2;
    }

    if (privkey_pem != NULL && strlen(privkey_pem) > 0) {
        EVP_PKEY *privateKey =  _read_privateKey_pem(privkey_pem);
        result = EBADKEYPAIR;
        if (privateKey) {
            result = X509_check_private_key(x509, privateKey);
            if (result == 0) result = EBADKEYPAIR;
        }
        EVP_PKEY_free(privateKey);
    }

  FIN2:
    X509_STORE_CTX_free(store_ctx);
    X509_STORE_free(cert_store);

  FIN:
    X509_free(x509);
    BIO_free(bio);

    if (result > 0) return 1;
    return result;
}


VS_DLL_EXPORT
int VS_STDCALL output_der(const int curvetype, int privkey_len, uint8_t *privkey, uint8_t *der_out)
{
    macro_init_EC_KEY(curvetype);

    _build_eckey(eckey, ecgroup, privkey_len, privkey);

    int der_len = i2d_ECPrivateKey(eckey, &der_out);

    macro_free_EC_KEY;
    return der_len;
}

VS_DLL_EXPORT
int VS_STDCALL output_pem(const int curvetype, int privkey_len, uint8_t *privkey, uint8_t *pem_out)
{
    macro_init_EC_KEY(curvetype);

    _build_eckey(eckey, ecgroup, privkey_len, privkey);

    BIO *out = BIO_new(BIO_s_mem());
    BUF_MEM *buf = BUF_MEM_new();
    memset(pem_out, 0, 512);
    PEM_write_bio_ECPrivateKey(out, eckey, NULL, NULL, 0, NULL, NULL);
    BIO_get_mem_ptr(out, &buf);

	int len = buf->length;
    memcpy(pem_out, buf->data, len);

    BIO_free_all(out);
    macro_free_EC_KEY;
    return len;
}

VS_DLL_EXPORT
int VS_STDCALL output_public_key_der(const int curvetype, int point_len, uint8_t *point, uint8_t *der_out)
{
    macro_init_EC_KEY(curvetype);

    _build_eckey_pub(eckey, ecgroup, point_len, point);

    int der_len = i2d_EC_PUBKEY(eckey, &der_out);

    macro_free_EC_KEY;
    return der_len;
}

VS_DLL_EXPORT
int VS_STDCALL output_public_key_pem(const int curvetype, int point_len, uint8_t *point, uint8_t *pem_out)
{
    macro_init_EC_KEY(curvetype);

    _build_eckey_pub(eckey, ecgroup, point_len, point);

    BIO *out = BIO_new(BIO_s_mem());
    BUF_MEM *buf = BUF_MEM_new();
    memset(pem_out, 0, 512);

    PEM_write_bio_EC_PUBKEY(out, eckey);
    BIO_get_mem_ptr(out, &buf);

	int len = buf->length;
    memcpy(pem_out, buf->data, len);

    BIO_free_all(out);
    macro_free_EC_KEY;
    return len;
}
