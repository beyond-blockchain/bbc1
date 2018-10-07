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


bool _init_EC_KEY(int curvetype, EC_KEY *eckey, EC_GROUP *ecgroup)
{
    if (NULL == eckey) {
        return false;
    }

    if (curvetype == CURVE_TYPE_SECP256) {
        ecgroup = EC_GROUP_new_by_curve_name(NID_secp256k1);
    } else if (curvetype == CURVE_TYPE_P256) {
        ecgroup = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    } else {
        return false;
    }
    if (NULL == ecgroup) {
        EC_KEY_free(eckey);
        return false;
    }
    if (EC_KEY_set_group(eckey, ecgroup) != 1) {
        EC_GROUP_free(ecgroup);
        EC_KEY_free(eckey);
        return false;
    }
    return true;
}


VS_DLL_EXPORT
bool VS_STDCALL sign(int curvetype, int privkey_len, uint8_t *privkey, int hash_len, uint8_t *hash, uint8_t *sig_r, uint8_t *sig_t, uint32_t *sig_r_len, uint32_t *sig_s_len)
{
    BN_CTX *ctx = BN_CTX_new();
    EC_KEY *eckey = EC_KEY_new();
    EC_GROUP *ecgroup;

    if (NULL == eckey) {
        return false;
    }

    if (curvetype == CURVE_TYPE_SECP256) {
        ecgroup = EC_GROUP_new_by_curve_name(NID_secp256k1);
    } else if (curvetype == CURVE_TYPE_P256) {
        ecgroup = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    } else {
        return false;
    }
    if (NULL == ecgroup) {
        EC_KEY_free(eckey);
        return false;
    }
    if (EC_KEY_set_group(eckey, ecgroup) != 1) {
        EC_GROUP_free(ecgroup);
        EC_KEY_free(eckey);
        return false;
    }

    BIGNUM *private_key = BN_bin2bn(privkey, privkey_len, NULL);
    EC_KEY_set_private_key(eckey, private_key);

    ECDSA_SIG *signature = ECDSA_do_sign(hash, hash_len, eckey);
    BN_bn2bin(signature->r, sig_r);
    BN_bn2bin(signature->s, sig_t);

    *sig_r_len = (uint32_t) BN_num_bytes(signature->r);
    *sig_s_len = (uint32_t) BN_num_bytes(signature->s);

    EC_GROUP_free(ecgroup);
    EC_KEY_free(eckey);
    ECDSA_SIG_free(signature);
    BN_free(private_key);
    BN_CTX_free(ctx);

    return true;
}

VS_DLL_EXPORT
int VS_STDCALL verify(int curvetype, int point_len, const uint8_t *point,
           int hash_len,uint8_t *hash,
           int sig_len, const uint8_t *sig)
{
    BN_CTX *ctx = BN_CTX_new();
    EC_KEY *eckey = EC_KEY_new();
    if (NULL == eckey) {
        return false;
    }

    EC_GROUP *ecgroup;
    if (curvetype == CURVE_TYPE_SECP256) {
        ecgroup = EC_GROUP_new_by_curve_name(NID_secp256k1);
    } else if (curvetype == CURVE_TYPE_P256) {
        ecgroup = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    } else {
        return false;
    }
    if (NULL == ecgroup) {
        EC_KEY_free(eckey);
        return false;
    }
    if (EC_KEY_set_group(eckey, ecgroup) != 1) {
        EC_GROUP_free(ecgroup);
        EC_KEY_free(eckey);
        return false;
    }

    EC_POINT *pubkey_point = EC_POINT_new(ecgroup);
    EC_POINT_oct2point(ecgroup, pubkey_point, point, point_len, ctx);

    EC_KEY_set_public_key(eckey, pubkey_point);

    ECDSA_SIG *signature = ECDSA_SIG_new();
    int numlen = (int)(sig_len/2);
    signature->r = BN_bin2bn(sig, numlen, NULL);
    signature->s = BN_bin2bn(&sig[numlen], numlen, NULL);

    int verify_status = ECDSA_do_verify(hash, hash_len, signature, eckey);

    ECDSA_SIG_free(signature);
    EC_POINT_free(pubkey_point);
    EC_KEY_free(eckey);
    BN_CTX_free(ctx);

    return verify_status;
}

VS_DLL_EXPORT
bool VS_STDCALL generate_keypair(int curvetype, uint8_t pubkey_type, int *pubkey_len, uint8_t *pubkey,
                      int *privkey_len, uint8_t *privkey)
{
    BN_CTX *ctx = BN_CTX_new();
    EC_KEY *eckey = EC_KEY_new();
    if (NULL == eckey) {
        return false;
    }

    EC_GROUP *ecgroup;
    if (curvetype == CURVE_TYPE_SECP256) {
        ecgroup = EC_GROUP_new_by_curve_name(NID_secp256k1);
    } else if (curvetype == CURVE_TYPE_P256) {
        ecgroup = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    } else {
        return false;
    }
    if (NULL == ecgroup) {
        EC_KEY_free(eckey);
        return false;
    }
    if (EC_KEY_set_group(eckey, ecgroup) != 1) {
        EC_GROUP_free(ecgroup);
        EC_KEY_free(eckey);
        return false;
    }

    EC_KEY_generate_key(eckey);

    const BIGNUM *private_key = EC_KEY_get0_private_key(eckey);
    *privkey_len = BN_num_bytes(private_key);
    BN_bn2bin(private_key, privkey);

    const EC_POINT *pubkey_point = EC_KEY_get0_public_key(eckey);
    if (pubkey_type == 0) {
        *pubkey_len = 65;
        EC_POINT_point2oct(ecgroup, pubkey_point, POINT_CONVERSION_UNCOMPRESSED, pubkey, *pubkey_len, ctx);
    } else {
        *pubkey_len = 33;
        EC_POINT_point2oct(ecgroup, pubkey_point, POINT_CONVERSION_COMPRESSED, pubkey, *pubkey_len, ctx);
    }

    BN_free((BIGNUM *)private_key);
    EC_POINT_free((EC_POINT *)pubkey_point);
    EC_GROUP_free(ecgroup);
    //EC_KEY_free(eckey);
    BN_CTX_free(ctx);
    return true;
}

VS_DLL_EXPORT
bool VS_STDCALL get_public_key_uncompressed(int curvetype, int privkey_len, uint8_t *privkey, int *pubkey_len, uint8_t *pubkey)
{
    BN_CTX *ctx = BN_CTX_new();
    EC_KEY *eckey = EC_KEY_new();
    if (NULL == eckey) {
        return false;
    }
    EC_GROUP *ecgroup;
    if (curvetype == CURVE_TYPE_SECP256) {
        ecgroup = EC_GROUP_new_by_curve_name(NID_secp256k1);
    } else if (curvetype == CURVE_TYPE_P256) {
        ecgroup = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    } else {
        return false;
    }
    if (NULL == ecgroup) {
        EC_KEY_free(eckey);
        return false;
    }
    if (EC_KEY_set_group(eckey, ecgroup) != 1) {
        EC_GROUP_free(ecgroup);
        EC_KEY_free(eckey);
        return false;
    }

    BIGNUM *private_key = BN_bin2bn(privkey, privkey_len, NULL);
    EC_KEY_set_private_key(eckey, private_key);

    EC_POINT *pubkey_point = EC_POINT_new(ecgroup);
    EC_POINT_mul(ecgroup, pubkey_point, private_key, NULL, NULL, ctx);
    *pubkey_len = 65;
    EC_POINT_point2oct(ecgroup, pubkey_point, POINT_CONVERSION_UNCOMPRESSED, pubkey, *pubkey_len, ctx);

    BN_free((BIGNUM *)private_key);
    EC_POINT_free(pubkey_point);
    EC_GROUP_free(ecgroup);
    //EC_KEY_free(eckey);
    BN_CTX_free(ctx);
    return true;
}

VS_DLL_EXPORT
bool VS_STDCALL get_public_key_compressed(int curvetype, int privkey_len, uint8_t *privkey, int *pubkey_len, uint8_t *pubkey)
{
    BN_CTX *ctx = BN_CTX_new();
    EC_KEY *eckey = EC_KEY_new();
    if (NULL == eckey) {
        return false;
    }

    EC_GROUP *ecgroup;
    if (curvetype == CURVE_TYPE_SECP256) {
        ecgroup = EC_GROUP_new_by_curve_name(NID_secp256k1);
    } else if (curvetype == CURVE_TYPE_P256) {
        ecgroup = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    } else {
        return false;
    }
    if (NULL == ecgroup) {
        EC_KEY_free(eckey);
        return false;
    }
    if (EC_KEY_set_group(eckey, ecgroup) != 1) {
        EC_GROUP_free(ecgroup);
        EC_KEY_free(eckey);
        return false;
    }

    BIGNUM *private_key = BN_bin2bn(privkey, privkey_len, NULL);
    EC_KEY_set_private_key(eckey, private_key);

    EC_POINT *pubkey_point = EC_POINT_new(ecgroup);
    EC_POINT_mul(ecgroup, pubkey_point, private_key, NULL, NULL, ctx);
    *pubkey_len = 33;
    EC_POINT_point2oct(ecgroup, pubkey_point, POINT_CONVERSION_COMPRESSED, pubkey, *pubkey_len, ctx);

    BN_free((BIGNUM *)private_key);
    EC_POINT_free(pubkey_point);
    EC_GROUP_free(ecgroup);
    //EC_KEY_free(eckey);
    BN_CTX_free(ctx);
    return true;
}

VS_DLL_EXPORT
bool VS_STDCALL convert_from_der(int curvetype, long der_len, const unsigned char *der,
                      uint8_t pubkey_type,
                      int *pubkey_len, uint8_t *pubkey,
                      int *privkey_len, uint8_t *privkey)
{
    BN_CTX *ctx = BN_CTX_new();
    EC_KEY *eckey = EC_KEY_new();
    if (NULL == eckey) {
        return false;
    }

    EC_GROUP *ecgroup;
    if (curvetype == CURVE_TYPE_SECP256) {
        ecgroup = EC_GROUP_new_by_curve_name(NID_secp256k1);
    } else if (curvetype == CURVE_TYPE_P256) {
        ecgroup = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    } else {
        return false;
    }
    if (NULL == ecgroup) {
        EC_KEY_free(eckey);
        return false;
    }
    if (EC_KEY_set_group(eckey, ecgroup) != 1) {
        EC_GROUP_free(ecgroup);
        EC_KEY_free(eckey);
        return false;
    }

    if (!d2i_ECPrivateKey(&eckey, &der, der_len)) {
        EC_GROUP_free(ecgroup);
        EC_KEY_free(eckey);
        return false;
    }

    const BIGNUM *private_key = EC_KEY_get0_private_key(eckey);
    *privkey_len = BN_num_bytes(private_key);
    BN_bn2bin(private_key, privkey);

    EC_POINT *pubkey_point = EC_POINT_new(ecgroup);
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
    EC_GROUP_free(ecgroup);
    //EC_KEY_free(eckey);
    BN_CTX_free(ctx);
    return true;
}

VS_DLL_EXPORT
bool VS_STDCALL convert_from_pem(int curvetype, const char *pem,
                      uint8_t pubkey_type,
                      int *pubkey_len, uint8_t *pubkey,
                      int *privkey_len, uint8_t *privkey)
{
    BIO* bo = BIO_new( BIO_s_mem() );
    BIO_write(bo, pem, strlen(pem));
    EVP_PKEY *privateKey = NULL;
    if (PEM_read_bio_PrivateKey( bo, &privateKey, 0, 0 ) == NULL) {
        BIO_free(bo);
        return false;
    }
    BIO_free(bo);

    BN_CTX *ctx = BN_CTX_new();
    EC_KEY *eckey = EC_KEY_new();
    if (NULL == eckey) {
        return false;
    }

    EC_GROUP *ecgroup;
    if (curvetype == CURVE_TYPE_SECP256) {
        ecgroup = EC_GROUP_new_by_curve_name(NID_secp256k1);
    } else if (curvetype == CURVE_TYPE_P256) {
        ecgroup = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    } else {
        return false;
    }
    if (NULL == ecgroup) {
        EC_KEY_free(eckey);
        return false;
    }
    if (EC_KEY_set_group(eckey, ecgroup) != 1) {
        EC_GROUP_free(ecgroup);
        EC_KEY_free(eckey);
        return false;
    }

    eckey = EVP_PKEY_get1_EC_KEY(privateKey);
    const BIGNUM *private_key = EC_KEY_get0_private_key(eckey);
    *privkey_len = BN_num_bytes(private_key);
    BN_bn2bin(private_key, privkey);

    EC_POINT *pubkey_point = EC_POINT_new(ecgroup);
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
    EC_GROUP_free(ecgroup);
    //EC_KEY_free(eckey);
    BN_CTX_free(ctx);
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
int VS_STDCALL read_x509(int curvetype, const char *pubkey_x509, const char *privkey_pem,
        uint8_t pubkey_type, int *pubkey_len, uint8_t *pubkey, int *privkey_len, uint8_t *privkey)
{
    BIO *bio = NULL;
    X509 *x509 = NULL;
    EVP_PKEY *privateKey = NULL;

    bio = BIO_new(BIO_s_mem());
    BIO_write(bio, privkey_pem, strlen(privkey_pem));
    if (PEM_read_bio_PrivateKey( bio, &privateKey, 0, 0 ) == NULL) {
        BIO_free(bio);
        return EBADPRIVATEKEY;
    }
    BIO_free(bio);

    bio = BIO_new(BIO_s_mem());
    BIO_write(bio, pubkey_x509, strlen(pubkey_x509));
    x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (x509 == NULL) {
        BIO_free(bio);
        pubkey = NULL;
        return EBADCERT;
    }

    int result = X509_check_private_key(x509, privateKey);
    if (result == 0) {
        result = EBADKEYPAIR;
        goto FIN;
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

    EC_KEY *eckey_priv = EVP_PKEY_get1_EC_KEY(privateKey);
    const BIGNUM *private_key = EC_KEY_get0_private_key(eckey_priv);
    *privkey_len = BN_num_bytes(private_key);
    BN_bn2bin(private_key, privkey);

    EVP_PKEY *publicKey = X509_get_pubkey(x509);
    EC_KEY *eckey_pub = EVP_PKEY_get1_EC_KEY(publicKey);
    const EC_POINT *pubkey_point = EC_KEY_get0_public_key(eckey_pub);
    EC_GROUP *ecgroup;
    if (curvetype == CURVE_TYPE_SECP256) {
        ecgroup = EC_GROUP_new_by_curve_name(NID_secp256k1);
    } else if (curvetype == CURVE_TYPE_P256) {
        ecgroup = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    } else {
        return false;
    }
    BN_CTX *ctx = BN_CTX_new();
    if (pubkey_type == 0) {
        *pubkey_len = 65;
        EC_POINT_point2oct(ecgroup, pubkey_point, POINT_CONVERSION_UNCOMPRESSED, pubkey, *pubkey_len, ctx);
    } else {
        *pubkey_len = 33;
        EC_POINT_point2oct(ecgroup, pubkey_point, POINT_CONVERSION_COMPRESSED, pubkey, *pubkey_len, ctx);
    }
    BN_CTX_free(ctx);

    //sk_X509_pop_free(stack_of_x509, X509_free);  // no need because of treating self-signed cert only
  FIN2:
    X509_STORE_CTX_free(store_ctx);
    X509_STORE_free(cert_store);

  FIN:
    X509_free(x509);
    EVP_PKEY_free(privateKey);
    BIO_free(bio);

    if (result > 0) return 0;
    return result;
}


VS_DLL_EXPORT
int VS_STDCALL output_der(int curvetype, int privkey_len, uint8_t *privkey, uint8_t *der_out)
{
    BN_CTX *ctx = BN_CTX_new();
    EC_KEY *eckey = EC_KEY_new();
    if (NULL == eckey) {
        return 0;
    }

    EC_GROUP *ecgroup;
    if (curvetype == CURVE_TYPE_SECP256) {
        ecgroup = EC_GROUP_new_by_curve_name(NID_secp256k1);
    } else if (curvetype == CURVE_TYPE_P256) {
        ecgroup = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    } else {
        return false;
    }
    if (NULL == ecgroup) {
        EC_KEY_free(eckey);
        return 0;
    }
    if (EC_KEY_set_group(eckey, ecgroup) != 1) {
        EC_GROUP_free(ecgroup);
        EC_KEY_free(eckey);
        return 0;
    }

    BIGNUM *private_key = BN_bin2bn(privkey, privkey_len, NULL);
    EC_KEY_set_private_key(eckey, private_key);

    EC_POINT *pubkey_point = EC_POINT_new(ecgroup);
    EC_POINT_mul(ecgroup, pubkey_point, private_key, NULL, NULL, ctx);
    EC_KEY_set_public_key(eckey, pubkey_point);

    int der_len = i2d_ECPrivateKey(eckey, &der_out);

    BN_free(private_key);
    EC_POINT_free(pubkey_point);
    EC_GROUP_free(ecgroup);
    EC_KEY_free(eckey);
    BN_CTX_free(ctx);
    return der_len;
}

VS_DLL_EXPORT
int VS_STDCALL output_pem(int curvetype, int privkey_len, uint8_t *privkey, uint8_t *pem_out)
{
    BN_CTX *ctx = BN_CTX_new();
    EC_KEY *eckey = EC_KEY_new();
    if (NULL == eckey) {
        return 0;
    }

    EC_GROUP *ecgroup;
    if (curvetype == CURVE_TYPE_SECP256) {
        ecgroup = EC_GROUP_new_by_curve_name(NID_secp256k1);
    } else if (curvetype == CURVE_TYPE_P256) {
        ecgroup = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    } else {
        return false;
    }
    if (NULL == ecgroup) {
        EC_KEY_free(eckey);
        return 0;
    }
    if (EC_KEY_set_group(eckey, ecgroup) != 1) {
        EC_GROUP_free(ecgroup);
        EC_KEY_free(eckey);
        return 0;
    }

    BIGNUM *private_key = BN_bin2bn(privkey, privkey_len, NULL);
    EC_KEY_set_private_key(eckey, private_key);
    EC_POINT *pubkey_point = EC_POINT_new(ecgroup);
    EC_POINT_mul(ecgroup, pubkey_point, private_key, NULL, NULL, ctx);
    EC_KEY_set_public_key(eckey, pubkey_point);

    BIO *out = BIO_new(BIO_s_mem());
    BUF_MEM *buf = BUF_MEM_new();
    memset(pem_out, 0, 224);

    PEM_write_bio_ECPrivateKey(out, eckey, NULL, NULL, 0, NULL, NULL);
    BIO_get_mem_ptr(out, &buf);

	int len = buf->length;
    memcpy(pem_out, buf->data, len);

    BIO_free_all(out);
    BN_free(private_key);
    EC_POINT_free(pubkey_point);
    EC_GROUP_free(ecgroup);
    EC_KEY_free(eckey);
    BN_CTX_free(ctx);
    return len;
}

VS_DLL_EXPORT
int VS_STDCALL output_public_key_der(int curvetype, int point_len, uint8_t *point, uint8_t *der_out)
{
    BN_CTX *ctx = BN_CTX_new();
    EC_KEY *eckey = EC_KEY_new();
    if (NULL == eckey) {
        return 0;
    }

    EC_GROUP *ecgroup;
    if (curvetype == CURVE_TYPE_SECP256) {
        ecgroup = EC_GROUP_new_by_curve_name(NID_secp256k1);
    } else if (curvetype == CURVE_TYPE_P256) {
        ecgroup = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    } else {
        return false;
    }
    if (NULL == ecgroup) {
        EC_KEY_free(eckey);
        return 0;
    }
    if (EC_KEY_set_group(eckey, ecgroup) != 1) {
        EC_GROUP_free(ecgroup);
        EC_KEY_free(eckey);
        return 0;
    }

    EC_POINT *pubkey_point = EC_POINT_new(ecgroup);
    EC_POINT_oct2point(ecgroup, pubkey_point, point, point_len, ctx);
    EC_KEY_set_public_key(eckey, pubkey_point);

    int der_len = i2d_EC_PUBKEY(eckey, &der_out);

    EC_POINT_free(pubkey_point);
    EC_GROUP_free(ecgroup);
    EC_KEY_free(eckey);
    BN_CTX_free(ctx);
    return der_len;
}

VS_DLL_EXPORT
int VS_STDCALL output_public_key_pem(int curvetype, int point_len, uint8_t *point, uint8_t *pem_out)
{
    BN_CTX *ctx = BN_CTX_new();
    EC_KEY *eckey = EC_KEY_new();
    if (NULL == eckey) {
        return 0;
    }

    EC_GROUP *ecgroup;
    if (curvetype == CURVE_TYPE_SECP256) {
        ecgroup = EC_GROUP_new_by_curve_name(NID_secp256k1);
    } else if (curvetype == CURVE_TYPE_P256) {
        ecgroup = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    } else {
        return false;
    }
    if (NULL == ecgroup) {
        EC_KEY_free(eckey);
        return 0;
    }
    if (EC_KEY_set_group(eckey, ecgroup) != 1) {
        EC_GROUP_free(ecgroup);
        EC_KEY_free(eckey);
        return 0;
    }

    EC_POINT *pubkey_point = EC_POINT_new(ecgroup);
    EC_POINT_oct2point(ecgroup, pubkey_point, point, point_len, ctx);
    EC_KEY_set_public_key(eckey, pubkey_point);

    BIO *out = BIO_new(BIO_s_mem());
    BUF_MEM *buf = BUF_MEM_new();
    memset(pem_out, 0, 512);

    PEM_write_bio_EC_PUBKEY(out, eckey);
    BIO_get_mem_ptr(out, &buf);

	int len = buf->length;
    memcpy(pem_out, buf->data, len);

    BIO_free_all(out);
    EC_POINT_free(pubkey_point);
    EC_GROUP_free(ecgroup);
    EC_KEY_free(eckey);
    BN_CTX_free(ctx);
    return len;
}
