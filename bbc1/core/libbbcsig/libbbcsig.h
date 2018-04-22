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

/**
 * 
 *
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
bool VS_STDCALL sign(int privkey_len, uint8_t *privkey, int hash_len, uint8_t *hash, uint8_t *sig_r, uint8_t *sig_t, uint32_t *sig_r_len, uint32_t *sig_s_len);

/**
 *
 *
 * @param [in] point_len
 * @param [in] point
 * @param [in] hash_len
 * @param [in] hash
 * @param [in] sig_len
 * @param [in] sig
 * @return int 
 */
VS_DLL_EXPORT
int VS_STDCALL verify(int point_len, const uint8_t *point,
	int hash_len, uint8_t *hash,
	int sig_len, const uint8_t *sig);

/**
 *
 *
 * @param [in] pubkey_type
 * @param [out] pubkey_len
 * @param [out] pubkey
 * @param [out] privkey_len
 * @param [out] privkey
 * @return bool 
 */
VS_DLL_EXPORT
bool VS_STDCALL generate_keypair(uint8_t pubkey_type, int *pubkey_len, uint8_t *pubkey,
	int *privkey_len, uint8_t *privkey);

/**
 *
 * 
 * @param [in] privkey_len
 * @param [in] privkey
 * @param [out] pubkey_len
 * @param [out] pubkey
 * @return bool 
 */
VS_DLL_EXPORT
bool VS_STDCALL get_public_key_uncompressed(int privkey_len, uint8_t *privkey, int *pubkey_len, uint8_t *pubkey);

/**
 *
 *
 * @param [in] privkey_len
 * @param [in] privkey
 * @param [out] pubkey_len
 * @param [out] pubkey
 * @return bool
 */
VS_DLL_EXPORT
bool VS_STDCALL get_public_key_compressed(int privkey_len, uint8_t *privkey, int *pubkey_len, uint8_t *pubkey);

/**
 *
 * 
 * @param [in] der_len
 * @param [in] der
 * @param [in] pubkey_type
 * @param [out] pubkey_len
 * @param [out] pubkey
 * @param [out] privkey_len
 * @return bool 
 */
VS_DLL_EXPORT
bool VS_STDCALL convert_from_der(long der_len, const unsigned char *der,
	uint8_t pubkey_type,
	int *pubkey_len, uint8_t *pubkey,
	int *privkey_len, uint8_t *privkey);

/**
 *
 *
 * @param [in] pem
 * @param [in] pubkey_type
 * @param [out] pubkey_len
 * @param [out] pubkey
 * @param [out] privkey_len
 *@return bool
 */
VS_DLL_EXPORT
bool VS_STDCALL convert_from_pem(const char *pem,
	uint8_t pubkey_type,
	int *pubkey_len, uint8_t *pubkey,
	int *privkey_len, uint8_t *privkey);

/**
 *
 *
 * @param [in] privkey_len
 * @param [in] privkey
 * @param [out] der_out
 * @return int 
 */
VS_DLL_EXPORT
int VS_STDCALL output_der(int privkey_len, uint8_t *privkey, uint8_t *der_out);

/**
 *
 *
 * @param [in] privkey_len
 * @param [in] privkey
 * @param [out] pem_out
 * @return int
 */
VS_DLL_EXPORT
int VS_STDCALL output_pem(int privkey_len, uint8_t *privkey, uint8_t *pem_out);

#endif
