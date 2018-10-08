import platform
import binascii
import os
from ctypes import *

if platform.system() == "Windows":
    lib = windll.LoadLibrary("libbbcsig.dll")
elif platform.system() == "Darwin":
    lib = cdll.LoadLibrary("libbbcsig.dylib")
else:
    lib = cdll.LoadLibrary("libbbcsig.so")

CURVETYPE = 2  # CURVE_TYPE_P256 in libbbcsig.h

POINT_CONVERSION_COMPRESSED = 2     # same as enum point_conversion_form_t in openssl/crypto/ec.h
POINT_CONVERSION_UNCOMPRESSED = 4   # same as enum point_conversion_form_t in openssl/crypto/ec.h

test_digest = binascii.a2b_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
privkey_len = c_int32(32)
privkey     = (c_byte * privkey_len.value)()
pubkey_len  = c_int32(65)
pubkey      = (c_byte * pubkey_len.value)()

signature = (c_byte * 64)()

print("# -- generate_keypair()")
lib.generate_keypair(CURVETYPE, POINT_CONVERSION_UNCOMPRESSED, byref(pubkey_len), pubkey, byref(privkey_len), privkey)
print("private_key:", binascii.b2a_hex(privkey), ", len=", privkey_len.value)
print("public_key:", binascii.b2a_hex(pubkey), ", len=", pubkey_len.value)

print("# -- sign()")
sig_r = (c_byte * 32)()
sig_s = (c_byte * 32)()
sig_r_len = (c_byte * 4)()  # Adjust size according to the expected size of sig_r and sig_s. Default:uint32.
sig_s_len = (c_byte * 4)()
ret = lib.sign(CURVETYPE, privkey_len, privkey, len(test_digest), test_digest, sig_r, sig_s, sig_r_len, sig_s_len)
print("sign:", ret)
assert ret == 1

sig_r_len = int.from_bytes(bytes(sig_r_len), "little")
sig_s_len = int.from_bytes(bytes(sig_s_len), "little")
sig_r = binascii.a2b_hex("00" * (32 - sig_r_len) + bytes(sig_r)[:sig_r_len].hex())
sig_s = binascii.a2b_hex("00" * (32 - sig_s_len) + bytes(sig_s)[:sig_s_len].hex())
signature = bytes(bytearray(sig_r)+bytearray(sig_s))
print(binascii.b2a_hex(signature))

print("# -- output_der()")
der_data = (c_byte * 512)()     # 256 -> 512
der_len = lib.output_der(CURVETYPE, privkey_len, privkey, byref(der_data))
print("DER: len=", der_len, "  dat=", binascii.b2a_hex(bytearray(der_data)[:der_len]))
assert der_len > 0

print("\n# -- clear private key")
privkey = (c_byte * privkey_len.value)()
print("private_key:", binascii.b2a_hex(privkey), ", len=", privkey_len.value)

print("# -- convert_from_der()")
pubkey_len = c_int32(33)
pubkey = (c_byte * pubkey_len.value)()
lib.convert_from_der(der_len, byref(der_data), POINT_CONVERSION_COMPRESSED, byref(pubkey_len), pubkey, byref(privkey_len), privkey)
print("private_key:", binascii.b2a_hex(privkey), ", len=", privkey_len.value)
print("public_key:", binascii.b2a_hex(pubkey), ", len=", pubkey_len.value)
assert privkey_len.value > 0
assert pubkey_len.value > 0

print("# -- sign()")
sig_r = (c_byte * 32)()
sig_s = (c_byte * 32)()
sig_r_len = (c_byte * 4)()  # Adjust size according to the expected size of sig_r and sig_s. Default:uint32.
sig_s_len = (c_byte * 4)()
ret = lib.sign(CURVETYPE, privkey_len, privkey, len(test_digest), test_digest, sig_r, sig_s, sig_r_len, sig_s_len)
print("sign:", ret)
assert ret == 1

sig_r_len = int.from_bytes(bytes(sig_r_len), "little")
sig_s_len = int.from_bytes(bytes(sig_s_len), "little")
sig_r = binascii.a2b_hex("00" * (32 - sig_r_len) + bytes(sig_r)[:sig_r_len].hex())
sig_s = binascii.a2b_hex("00" * (32 - sig_s_len) + bytes(sig_s)[:sig_s_len].hex())
signature = bytes(bytearray(sig_r)+bytearray(sig_s))
print(binascii.b2a_hex(signature))

print("\n# -- get compressed pubkey")
pubkey = (c_byte * 33)()
lib.get_public_key_compressed(CURVETYPE, privkey_len, privkey, byref(pubkey_len), pubkey)
print("public_key:", binascii.b2a_hex(pubkey), ", len=", pubkey_len.value)

print("# -- verify with compressed pubkey")
res = lib.verify(CURVETYPE, pubkey_len, pubkey, len(test_digest), test_digest, len(signature), signature)
print("result:", res)
assert res == 1

print("# -- output_public_key_der()")
der_data = (c_byte * 512)()     # 256 -> 512
der_len = lib.output_public_key_der(CURVETYPE, pubkey_len, pubkey, byref(der_data))
print("DER: len=", der_len, "  dat=", binascii.b2a_hex(bytearray(der_data)[:der_len]))
assert der_len > 0


print("\n# -- get uncompressed pubkey")
pubkey_len = c_int32(65)
pubkey = (c_byte * pubkey_len.value)()
lib.get_public_key_uncompressed(CURVETYPE, privkey_len, privkey, byref(pubkey_len), pubkey)
print("public_key:", binascii.b2a_hex(pubkey), ", len=", pubkey_len.value)

print("# -- verify with uncompressed pubkey")
res = lib.verify(CURVETYPE, pubkey_len, pubkey, len(test_digest), test_digest, len(signature), signature)
print("result:", res)
assert res == 1

print("# -- output_pem()")
pem = (c_char * 512)()      # 256 -> 512
length = lib.output_pem(CURVETYPE, privkey_len, privkey, byref(pem))
print("PEM: len=", length, " dat=", pem.value)
assert length > 0

print("# -- output_public_key_pem()")
pem = (c_char * 512)()      # 256 -> 512
length = lib.output_public_key_pem(CURVETYPE, pubkey_len, pubkey, byref(pem))
print("PEM: len=", length, " dat=", pem.value)
assert length > 0

print("# -- output_public_key_der()")
der_data = (c_byte * 512)()     # 256 -> 512
der_len = lib.output_public_key_der(CURVETYPE, pubkey_len, pubkey, byref(der_data))
print("DER: len=", der_len, "  dat=", binascii.b2a_hex(bytearray(der_data)[:der_len]))
assert der_len > 0

print("# -- output_der()")
der_data = (c_byte * 512)()     # 256 -> 512
der_len = lib.output_der(CURVETYPE, privkey_len, privkey, byref(der_data))
print("DER: len=", der_len, "  dat=", binascii.b2a_hex(bytearray(der_data)[:der_len]))
assert der_len > 0


print("******** successfully finished ********")
