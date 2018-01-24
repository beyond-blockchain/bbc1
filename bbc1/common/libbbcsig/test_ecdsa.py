import binascii
import os
from ctypes import *

if os.name == "nt":
    lib = windll.LoadLibrary("libbbcsig.dll")
else:
    lib = cdll.LoadLibrary("libbbcsig.so")

test_digest = binascii.a2b_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
privkey_len = c_int32(32)
privkey     = (c_byte * privkey_len.value)()
pubkey_len  = c_int32(65)
pubkey      = (c_byte * pubkey_len.value)()

signature = (c_byte * 64)()

print("# -- generate_keypair()")
lib.generate_keypair(0, byref(pubkey_len), pubkey, byref(privkey_len), privkey)
print("private_key:", binascii.b2a_hex(privkey), ", len=", privkey_len)
print("public_key:", binascii.b2a_hex(pubkey), ", len=", pubkey_len)

print("# -- sign()")
print(lib.sign(privkey_len, privkey, privkey_len, test_digest, signature))
print(binascii.b2a_hex(signature))

print("# -- output_der()")
der_data = (c_byte * 512)()     # 256 -> 512
der_len = lib.output_der(privkey_len, privkey, byref(der_data))
print("DER: len=",der_len, "  dat=", binascii.b2a_hex(bytearray(der_data)[:der_len]))

print("# -- clear private key")
privkey = (c_byte * privkey_len.value)()
print("private_key:", binascii.b2a_hex(privkey), ", len=", privkey_len)

print("# -- convert_from_der()")
lib.convert_from_der(der_len, byref(der_data), 0, byref(pubkey_len), pubkey, byref(privkey_len), privkey)
print("private_key:", binascii.b2a_hex(privkey), ", len=", privkey_len)
print("public_key:", binascii.b2a_hex(pubkey), ", len=", pubkey_len)

print("# -- sign()")
print(lib.sign(privkey_len, privkey, privkey_len, test_digest, signature))
print(binascii.b2a_hex(signature))

print("# -- get compressed pubkey")
pubkey = (c_byte * 33)()
lib.get_public_key_compressed(privkey_len, privkey, byref(pubkey_len), pubkey)
print("public_key:", binascii.b2a_hex(pubkey), ", len=", pubkey_len)

print("# -- verify with compressed pubkey")
res = lib.verify(pubkey_len, pubkey, 32, test_digest, 64, signature)
print("result:", res)

print("# -- get uncompressed pubkey")
pubkey = (c_byte * 65)()
lib.get_public_key_uncompressed(privkey_len, privkey, byref(pubkey_len), pubkey)
print("public_key:", binascii.b2a_hex(pubkey), ", len=", pubkey_len)

print("# -- verify with compressed pubkey")
res = lib.verify(pubkey_len, pubkey, 32, test_digest, 64, signature)
print("result:", res)

print("# -- output_pem()")
pem = (c_char * 512)()      # 256 -> 512
length = lib.output_pem(privkey_len, privkey, byref(pem))
print("PEM: len=", length, " dat=", pem.value)
