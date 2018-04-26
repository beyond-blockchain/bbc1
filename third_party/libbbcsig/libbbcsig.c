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


#include <crypto/ec/ec_lcl.h>

VS_DLL_EXPORT
bool VS_STDCALL sign(int privkey_len, uint8_t *privkey, int hash_len, uint8_t *hash, uint8_t *sig_r, uint8_t *sig_t, uint32_t *sig_r_len, uint32_t *sig_s_len)
{
    BN_CTX *ctx = BN_CTX_new();
    EC_KEY *eckey = EC_KEY_new();
    if (NULL == eckey) {
        return false;
    }
    EC_GROUP *ecgroup = EC_GROUP_new_by_curve_name(NID_secp256k1);
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
int VS_STDCALL verify(int point_len, const uint8_t *point,
           int hash_len,uint8_t *hash,
           int sig_len, const uint8_t *sig)
{
    BN_CTX *ctx = BN_CTX_new();
    EC_KEY *eckey = EC_KEY_new();
    if (NULL == eckey) {
        return false;
    }
    EC_GROUP *ecgroup = EC_GROUP_new_by_curve_name(NID_secp256k1);
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
bool VS_STDCALL generate_keypair(uint8_t pubkey_type, int *pubkey_len, uint8_t *pubkey,
                      int *privkey_len, uint8_t *privkey)
{
    BN_CTX *ctx = BN_CTX_new();
    EC_KEY *eckey = EC_KEY_new();
    if (NULL == eckey) {
        return false;
    }
    EC_GROUP *ecgroup = EC_GROUP_new_by_curve_name(NID_secp256k1);
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
bool VS_STDCALL get_public_key_uncompressed(int privkey_len, uint8_t *privkey, int *pubkey_len, uint8_t *pubkey)
{
    BN_CTX *ctx = BN_CTX_new();
    EC_KEY *eckey = EC_KEY_new();
    if (NULL == eckey) {
        return false;
    }
    EC_GROUP *ecgroup = EC_GROUP_new_by_curve_name(NID_secp256k1);
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
bool VS_STDCALL get_public_key_compressed(int privkey_len, uint8_t *privkey, int *pubkey_len, uint8_t *pubkey)
{
    BN_CTX *ctx = BN_CTX_new();
    EC_KEY *eckey = EC_KEY_new();
    if (NULL == eckey) {
        return false;
    }
    EC_GROUP *ecgroup = EC_GROUP_new_by_curve_name(NID_secp256k1);
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
bool VS_STDCALL convert_from_der(long der_len, const unsigned char *der,
                      uint8_t pubkey_type,
                      int *pubkey_len, uint8_t *pubkey,
                      int *privkey_len, uint8_t *privkey)
{
    BN_CTX *ctx = BN_CTX_new();
    EC_KEY *eckey = EC_KEY_new();
    if (NULL == eckey) {
        return false;
    }
    EC_GROUP *ecgroup = EC_GROUP_new_by_curve_name(NID_secp256k1);
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
bool VS_STDCALL convert_from_pem(const char *pem,
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
    EC_GROUP *ecgroup = EC_GROUP_new_by_curve_name(NID_secp256k1);
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

VS_DLL_EXPORT
int VS_STDCALL output_der(int privkey_len, uint8_t *privkey, uint8_t *der_out)
{
    BN_CTX *ctx = BN_CTX_new();
    EC_KEY *eckey = EC_KEY_new();
    if (NULL == eckey) {
        return 0;
    }
    EC_GROUP *ecgroup = EC_GROUP_new_by_curve_name(NID_secp256k1);
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
int VS_STDCALL output_pem(int privkey_len, uint8_t *privkey, uint8_t *pem_out)
{
    BN_CTX *ctx = BN_CTX_new();
    EC_KEY *eckey = EC_KEY_new();
    if (NULL == eckey) {
        return 0;
    }
    EC_GROUP *ecgroup = EC_GROUP_new_by_curve_name(NID_secp256k1);
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
