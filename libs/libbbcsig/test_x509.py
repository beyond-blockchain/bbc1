import platform
import os
from ctypes import *
import binascii

if platform.system() == "Windows":
    lib = windll.LoadLibrary("libbbcsig.dll")
elif platform.system() == "Darwin":
    lib = cdll.LoadLibrary("libbbcsig.dylib")
else:
    lib = cdll.LoadLibrary("libbbcsig.so")

CURVETYPE = 2  # CURVE_TYPE_P256 in libbbcsig.h

POINT_CONVERSION_COMPRESSED = 2     # same as enum point_conversion_form_t in openssl/crypto/ec.h
POINT_CONVERSION_UNCOMPRESSED = 4   # same as enum point_conversion_form_t in openssl/crypto/ec.h

with open("private.key", "r") as f:
    private_key = f.read()

with open("self-signed.pem", "r") as f:
    pubkey_cert = f.read()

with open("private_expired.key", "r") as f:
    private_key2 = f.read()

with open("self-signed_expired.pem", "r") as f:
    pubkey_cert2 = f.read()


privkey_len = c_int32(32)
privkey     = (c_byte * privkey_len.value)()
pubkey_len  = c_int32(65)
pubkey      = (c_byte * pubkey_len.value)()

print("######### read private key only")
ret = lib.convert_from_pem(create_string_buffer(private_key.encode()), POINT_CONVERSION_UNCOMPRESSED, byref(pubkey_len), pubkey, byref(privkey_len), privkey)
print("private_key:", binascii.b2a_hex(privkey), ", len=", privkey_len.value)
print("public_key:", binascii.b2a_hex(pubkey), ", len=", pubkey_len.value)


privkey_len = c_int32(32)
privkey     = (c_byte * privkey_len.value)()
pubkey_len  = c_int32(65)
pubkey      = (c_byte * pubkey_len.value)()

print("\n######### read X509 public key cert")
ret = lib.read_x509(create_string_buffer(pubkey_cert.encode()), POINT_CONVERSION_UNCOMPRESSED, byref(pubkey_len), pubkey)
assert ret
print("public_key:", binascii.b2a_hex(pubkey), ", len=", pubkey_len.value)

print("\n######### verify X509 public key cert")
ret = lib.verify_x509(create_string_buffer(pubkey_cert.encode()), None)
assert ret == 1
print("verify ok")

print("\n######### verify X509 public key cert and private key")
ret = lib.verify_x509(create_string_buffer(pubkey_cert.encode()),
                      create_string_buffer(private_key.encode()))
assert ret == 1
print("verify ok")

print("\n######### verify X509 public key cert and different private key")
ret = lib.verify_x509(create_string_buffer(pubkey_cert.encode()),
                      create_string_buffer(private_key2.encode()))
assert ret == -4
print("invalid key pair (test ok)")


print("\n######### verify X509 public key cert (expired)")
ret = lib.verify_x509(create_string_buffer(pubkey_cert2.encode()), None)
assert ret == -5
print("expired")
