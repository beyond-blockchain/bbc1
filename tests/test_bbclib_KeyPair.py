import sys
sys.path.append('.')
sys.path.append('..')

import os
import bbc1.core.bbclib as bbclib
import binascii
#import unittest

def _is_windows():
    """
    """
    return os.name == "nt"


in_privkey = b'\xd6Y\xbc#I\xfe\xed\x00\xe1x\xaa\xb4V\xd0\x9c\x01\xe2\x9a\xfd\xd2a\xabf\xcb\x14\xacM\x8e\xca2=\xbb'
in_pubkey = b'\x04\x0fd(\xdd\x8fR\xf7@\x86\xe7\x04\x06\xc3K\xecu\xd9\xfe\xe9de\x95\x8c\x16\x0esJ\xe8\x12Q`\xad).\xbd\xfb\x1c\x80\x96p\x12\xb5o\xfdr;\xd8\xa6`\xec\x85i\xad\x14\xceks8\x17&\x7f\xee\xd0\xc1'

in_der_nt = b'0\x82\x01\x13\x02\x01\x01\x04 \xd6Y\xbc#I\xfe\xed\x00\xe1x\xaa\xb4V\xd0\x9c\x01\xe2\x9a\xfd\xd2a\xabf\xcb\x14\xacM\x8e\xca2=\xbb\xa0\x81\xa50\x81\xa2\x02\x01\x010,\x06\x07*\x86H\xce=\x01\x01\x02!\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xff\xff\xfc/0\x06\x04\x01\x00\x04\x01\x07\x04A\x04y\xbef~\xf9\xdc\xbb\xacU\xa0b\x95\xce\x87\x0b\x07\x02\x9b\xfc\xdb-\xce(\xd9Y\xf2\x81[\x16\xf8\x17\x98H:\xdaw&\xa3\xc4e]\xa4\xfb\xfc\x0e\x11\x08\xa8\xfd\x17\xb4H\xa6\x85T\x19\x9cG\xd0\x8f\xfb\x10\xd4\xb8\x02!\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xba\xae\xdc\xe6\xafH\xa0;\xbf\xd2^\x8c\xd06AA\x02\x01\x01\xa1D\x03B\x00\x04\x0fd(\xdd\x8fR\xf7@\x86\xe7\x04\x06\xc3K\xecu\xd9\xfe\xe9de\x95\x8c\x16\x0esJ\xe8\x12Q`\xad).\xbd\xfb\x1c\x80\x96p\x12\xb5o\xfdr;\xd8\xa6`\xec\x85i\xad\x14\xceks8\x17&\x7f\xee\xd0\xc1'

in_der_posix = b'0t\x02\x01\x01\x04 \xd6Y\xbc#I\xfe\xed\x00\xe1x\xaa\xb4V\xd0\x9c\x01\xe2\x9a\xfd\xd2a\xabf\xcb\x14\xacM\x8e\xca2=\xbb\xa0\x07\x06\x05+\x81\x04\x00\n\xa1D\x03B\x00\x04\x0fd(\xdd\x8fR\xf7@\x86\xe7\x04\x06\xc3K\xecu\xd9\xfe\xe9de\x95\x8c\x16\x0esJ\xe8\x12Q`\xad).\xbd\xfb\x1c\x80\x96p\x12\xb5o\xfdr;\xd8\xa6`\xec\x85i\xad\x14\xceks8\x17&\x7f\xee\xd0\xc1'
if _is_windows():
    in_der = in_der_nt
else:
    in_der = in_der_posix

in_pem_nt = b'-----BEGIN EC PRIVATE KEY-----\nMIIBEwIBAQQg1lm8I0n+7QDheKq0VtCcAeKa/dJhq2bLFKxNjsoyPbuggaUwgaIC\nAQEwLAYHKoZIzj0BAQIhAP////////////////////////////////////7///wv\nMAYEAQAEAQcEQQR5vmZ++dy7rFWgYpXOhwsHApv82y3OKNlZ8oFbFvgXmEg62ncm\no8RlXaT7/A4RCKj9F7RIpoVUGZxH0I/7ENS4AiEA/////////////////////rqu\n3OavSKA7v9JejNA2QUECAQGhRANCAAQPZCjdj1L3QIbnBAbDS+x12f7pZGWVjBYO\nc0roElFgrSkuvfscgJZwErVv/XI72KZg7IVprRTOa3M4FyZ/7tDB\n-----END EC PRIVATE KEY-----\n\x00'

in_pem_posix = b'-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEINZZvCNJ/u0A4XiqtFbQnAHimv3SYatmyxSsTY7KMj27oAcGBSuBBAAK\noUQDQgAED2Qo3Y9S90CG5wQGw0vsddn+6WRllYwWDnNK6BJRYK0pLr37HICWcBK1\nb/1yO9imYOyFaa0UzmtzOBcmf+7QwQ==\n-----END EC PRIVATE KEY-----\n\x00'
if _is_windows():
    in_pem = in_pem_nt
else:
    in_pem = in_pem_posix


def test_keypair_generate():
    """
    """
    keypair = bbclib.KeyPair()
    keypair.generate()
    assert (keypair.private_key_len.value == 32)
    assert (keypair.public_key_len.value == 65)


def test_keypair_pubkey():
    """
    """
    keypair = bbclib.KeyPair(type=bbclib.KeyType.ECDSA_SECP256k1, privkey=in_privkey)
    keypair.mk_keyobj_from_private_key()
    assert (keypair.public_key_len.value == 65)
    assert (bytes(keypair.public_key)[:keypair.public_key_len.value] == in_pubkey)


def test_keypair_der():
    """
    """
    keypair = bbclib.KeyPair(type=bbclib.KeyType.ECDSA_SECP256k1, privkey=in_privkey, pubkey=in_pubkey)

    der = keypair.get_private_key_in_der()
    assert (der == in_der)

    keypair.mk_keyobj_from_private_key_der(der)
    assert (bytes(keypair.private_key)[:keypair.private_key_len.value] == in_privkey)
    assert (bytes(keypair.public_key)[:keypair.public_key_len.value] == in_pubkey)


def test_keypair_pem():
    """
    """
    keypair = bbclib.KeyPair(type=bbclib.KeyType.ECDSA_SECP256k1, privkey=in_privkey, pubkey=in_pubkey)

    pem = keypair.get_private_key_in_pem()
    assert (bytes(pem) == in_pem[:(len(in_pem) - 1)])  # ヌル終端を取り除いて比較する。

    keypair.mk_keyobj_from_private_key_pem(str(pem))   # 文字列化する。
    assert (bytes(keypair.private_key)[:keypair.private_key_len.value] == in_privkey)
    assert (bytes(keypair.public_key)[:keypair.public_key_len.value] == in_pubkey)


def test_keypair_sign_and_verify():
    """
    """
    digest = binascii.a2b_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

    keypair = bbclib.KeyPair(type=bbclib.KeyType.ECDSA_SECP256k1, privkey=in_privkey, pubkey=in_pubkey)
    signature = keypair.sign(digest)
    print("signature = {}".format(signature))

    ret = keypair.verify(digest, signature)
    # print("ret = {}".format(ret))
    assert (ret == 1)

    not_digest = binascii.a2b_hex("bbbbbb")

    ret = keypair.verify(not_digest, signature)
    # print("ret = {}".format(ret))
    assert (ret == 0)
