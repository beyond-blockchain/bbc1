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

with open("private.key", "r") as f:
    private_key = f.read()

with open("self-signed.pem", "r") as f:
    pubkey_cert = f.read()


privkey_len = c_int32(32)
privkey     = (c_byte * privkey_len.value)()
pubkey_len  = c_int32(65)
pubkey      = (c_byte * pubkey_len.value)()

print("######### read private key only")
ret = lib.convert_from_pem(CURVETYPE, create_string_buffer(private_key.encode()), 0, byref(pubkey_len), pubkey, byref(privkey_len), privkey)
print("private_key:", binascii.b2a_hex(privkey), ", len=", privkey_len)
print("public_key:", binascii.b2a_hex(pubkey), ", len=", pubkey_len)


privkey_len = c_int32(32)
privkey     = (c_byte * privkey_len.value)()
pubkey_len  = c_int32(65)
pubkey      = (c_byte * pubkey_len.value)()

print("\n######### read private key and X509 public key cert")
ret = lib.read_x509(CURVETYPE, create_string_buffer(pubkey_cert.encode()),
                    create_string_buffer(private_key.encode()),
                    0, byref(pubkey_len), pubkey, byref(privkey_len), privkey)
if ret == 0:
    print("private_key:", binascii.b2a_hex(privkey), ", len=", privkey_len)
    print("public_key:", binascii.b2a_hex(pubkey), ", len=", pubkey_len)
else:
    print("error code:", ret)