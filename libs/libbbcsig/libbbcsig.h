#ifndef LIBBBCSIG_H
#define LIBBBCSIG_H

#include <stdbool.h>

#ifdef _WIN32
#define VS_DLL_EXPORT __declspec(dllexport)
#define VS_STDCALL __stdcall
#else
#define VS_DLL_EXPORT 
#define VS_STDCALL 
#endif

//#ifdef _WIN32
/**
 *
 */
typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
//#else
//#endif


#define EFAULURE         -1
#define EBADPRIVATEKEY   -2
#define EBADCERT         -3
#define EBADKEYPAIR      -4
#define EINVALIDCERT     -5


/**
 * 
 *
 * @param [in] curvetype
 * @param [in] privkey_len
 * @param [in] privkey
 * @param [in] hash_len
 * @param [in] hash
 * @param [out] sig_r
 * @param [out] sig_s
 * @param [out] sig_r_len
 * @param [out] sig_s_len
 * @return bool 
 */
VS_DLL_EXPORT
bool VS_STDCALL sign(const int curvetype, int privkey_len, uint8_t *privkey, int hash_len, uint8_t *hash, uint8_t *sig_r, uint8_t *sig_t, uint32_t *sig_r_len, uint32_t *sig_s_len);

/**
 *
 *
 * @param [in] curvetype
 * @param [in] point_len
 * @param [in] point
 * @param [in] hash_len
 * @param [in] hash
 * @param [in] sig_len
 * @param [in] sig
 * @return int 
 */
VS_DLL_EXPORT
int VS_STDCALL verify(const int curvetype, int point_len, const uint8_t *point,
	int hash_len, uint8_t *hash,
	int sig_len, const uint8_t *sig);

/**
 *
 *
 * @param [in] curvetype
 * @param [in] compression
 * @param [out] pubkey_len
 * @param [out] pubkey
 * @param [out] privkey_len
 * @param [out] privkey
 * @return bool 
 */
VS_DLL_EXPORT
bool VS_STDCALL generate_keypair(const int curvetype, const uint8_t compression, int *pubkey_len, uint8_t *pubkey,
	int *privkey_len, uint8_t *privkey);

/**
 *
 * 
 * @param [in] curvetype
 * @param [in] privkey_len
 * @param [in] privkey
 * @param [out] pubkey_len
 * @param [out] pubkey
 * @return bool 
 */
VS_DLL_EXPORT
bool VS_STDCALL get_public_key_uncompressed(const int curvetype, int privkey_len, uint8_t *privkey, int *pubkey_len, uint8_t *pubkey);

/**
 *
 *
 * @param [in] curvetype
 * @param [in] privkey_len
 * @param [in] privkey
 * @param [out] pubkey_len
 * @param [out] pubkey
 * @return bool
 */
VS_DLL_EXPORT
bool VS_STDCALL get_public_key_compressed(const int curvetype, int privkey_len, uint8_t *privkey, int *pubkey_len, uint8_t *pubkey);

/**
 *
 * 
 * @param [in] der_len
 * @param [in] der
 * @param [in] compression
 * @param [out] pubkey_len
 * @param [out] pubkey
 * @param [out] privkey_len
 * @return bool 
 */
VS_DLL_EXPORT
bool VS_STDCALL convert_from_der(long der_len, const unsigned char *der, const uint8_t compression,
	                             int *pubkey_len, uint8_t *pubkey, int *privkey_len, uint8_t *privkey);

/**
 *
 *
 * @param [in] pem
 * @param [in] compression
 * @param [out] pubkey_len
 * @param [out] pubkey
 * @param [out] privkey_len
 *@return bool
 */
VS_DLL_EXPORT
bool VS_STDCALL convert_from_pem(const char *pem, const uint8_t compression,
                                 int *pubkey_len, uint8_t *pubkey, int *privkey_len, uint8_t *privkey);

/**
 *
 * @param pubkey_x509
 * @param compression
 * @param pubkey_len
 * @param pubkey
 * @return
 */
VS_DLL_EXPORT
bool VS_STDCALL read_x509(const char *pubkey_x509, const uint8_t compression, int *pubkey_len, uint8_t *pubkey);

/**
 *
 * @param pubkey_x509
 * @param privkey_pem
 * @return
 */
VS_DLL_EXPORT
int VS_STDCALL verify_x509(const char *pubkey_x509, const char *privkey_pem);

/**
 *
 *
 * @param [in] curvetype
 * @param [in] privkey_len
 * @param [in] privkey
 * @param [out] der_out
 * @return int 
 */
VS_DLL_EXPORT
int VS_STDCALL output_der(const int curvetype, int privkey_len, uint8_t *privkey, uint8_t *der_out);

/**
 *
 *
 * @param [in] curvetype
 * @param [in] privkey_len
 * @param [in] privkey
 * @param [out] pem_out
 * @return int
 */
VS_DLL_EXPORT
int VS_STDCALL output_pem(const int curvetype, int privkey_len, uint8_t *privkey, uint8_t *pem_out);


VS_DLL_EXPORT
int VS_STDCALL output_public_key_der(const int curvetype, int point_len, uint8_t *point, uint8_t *der_out);

VS_DLL_EXPORT
int VS_STDCALL output_public_key_pem(const int curvetype, int point_len, uint8_t *point, uint8_t *pem_out);

#endif
