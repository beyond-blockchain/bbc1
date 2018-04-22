import os
#import unittest
import pybbcsig
import binascii


def _is_windows():
    """
    """
    return os.name == "nt"


sig = pybbcsig.PyBBcSigSecp256k1()

in_privkey = b'\xd6Y\xbc#I\xfe\xed\x00\xe1x\xaa\xb4V\xd0\x9c\x01\xe2\x9a\xfd\xd2a\xabf\xcb\x14\xacM\x8e\xca2=\xbb'
in_pubkey = b'\x04\x0fd(\xdd\x8fR\xf7@\x86\xe7\x04\x06\xc3K\xecu\xd9\xfe\xe9de\x95\x8c\x16\x0esJ\xe8\x12Q`\xad).\xbd\xfb\x1c\x80\x96p\x12\xb5o\xfdr;\xd8\xa6`\xec\x85i\xad\x14\xceks8\x17&\x7f\xee\xd0\xc1'
in_pubkey_compressed = b'\x03\x0fd(\xdd\x8fR\xf7@\x86\xe7\x04\x06\xc3K\xecu\xd9\xfe\xe9de\x95\x8c\x16\x0esJ\xe8\x12Q`\xad'

in_test_digest = binascii.a2b_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

in_signature_nt = b'Dz\xe5\x84$\xf5_\x19\x9d\xda\x83\x00(O\x91\xec\x18MP\xbd\xef\xa2\x9b\x96\xb3\x9d\xea\xb5\xf9\x93;\xa4\xafB\xe9:\x9e\xa5G\xc79\xe1\xb7\xfaS)\xfd\x82\x0e\xa7\x13|\xe6\xc8\xebX\x91[\x8a$\xe3\xf0\xf4\r'

in_signature_posix = b'B)\n@\xe666\xb310z5\x8c\x99\x06u\xe7\xa9}\\\xdc\xa5\x93\x8a\xc6\xb2by\xe1`L\xe8\x95\x18\xd3?\x1f\x1d\x81\x96\xd6\x01\x96\xe2\x80y\x0fz3\xde\xd8\x18\xbd\xbc\xce\xc2\xf6\xdf\xde\x8c\xdd\xb8\xb0\xd5'
if _is_windows():
    in_signature = in_signature_nt
else:
    in_signature = in_signature_posix

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


def test_keypair():
    """
    """
    pubkey, privkey = sig.generate_keypair(0)
    # print("pubkey = {}".format(pubkey))
    # print("privkey = {}".format(privkey))
    assert (len(privkey) == 32)
    assert (len(pubkey) == 65)


def test_sign():
    """
    """
    assert (len(in_privkey) == 32)

    signature = sig.sign(in_privkey, in_test_digest)     # 毎回変わる
    # print("signature = {}".format(signature))
    assert (len(signature) == 64)


def test_der():
    """
    """
    assert (len(in_privkey) == 32)

    der = sig.output_der(in_privkey)
    # print("der = {}".format(der))
    # print("len(der) = {}".format(len(der)))
    if _is_windows():
        assert (len(der) == 279)
    else:
        assert (len(der) == 118)
    assert (der == in_der)


def test_from_der():
    """
    """
    pubkey, privkey = sig.convert_from_der(in_der, 0)
    # print("pubkey = {}".format(pubkey))
    # print("privkey = {}".format(privkey))
    assert (len(privkey) == 32)
    assert (len(pubkey) == 65)
    assert (privkey == in_privkey)
    assert (pubkey == in_pubkey)


def test_from_der2():
    """
    """
    if _is_windows():
        der = in_der_posix
    else:
        der = in_der_nt

    pubkey, privkey = sig.convert_from_der(der, 0)
    # print("pubkey = {}".format(pubkey))
    # print("privkey = {}".format(privkey))
    assert (len(privkey) == 32)
    assert (len(pubkey) == 65)
    assert (privkey == in_privkey)
    assert (pubkey == in_pubkey)


def test_pubkey_compressed():
    """
    """
    assert (len(in_privkey) == 32)

    pubkey = sig.get_public_key_compressed(in_privkey)
    # print("pubkey = {}".format(pubkey))
    # print("len(pubkey) = {}".format(len(pubkey)))
    assert (len(pubkey) == 33)
    assert (pubkey == in_pubkey_compressed)

def test_pubkey_uncompressed():
    """
    """
    assert (len(in_privkey) == 32)

    pubkey = sig.get_public_key_uncompressed(in_privkey)
    # print("pubkey = {}".format(pubkey))
    # print("len(pubkey) = {}".format(len(pubkey)))
    assert (len(pubkey) == 65)
    assert (pubkey == in_pubkey)


def test_verify():
    """
    """
    # print("len(in_signature) = {}".format(len(in_signature)))
    assert (len(in_signature) == 64)

    ret = sig.verify(in_pubkey, in_test_digest, in_signature)
    # print("ret = {}".format(ret))
    assert (ret > 0)
    assert (ret == 1)


def test_verify2():
    """
    """
    if _is_windows():
        signature = in_signature_posix
    else:
        signature = in_signature_nt

    # print("len(signature) = {}".format(len(signature)))
    assert (len(signature) == 64)

    ret = sig.verify(in_pubkey, in_test_digest, signature)
    # print("ret = {}".format(ret))
    assert (ret > 0)
    assert (ret == 1)


def test_pem():
    """
    """
    assert (len(in_privkey) == 32)

    pem = sig.output_pem(in_privkey)
    # print("pem = {}".format(pem))
    # print("len(pem) = {}".format(len(pem)))
    if _is_windows():
        assert (len(pem) == (438 + 1))
    else:
        assert(len(pem) == (223 + 1))
    assert (pem == in_pem)


def test_from_pem():
    """
    """
    pubkey, privkey = sig.convert_from_pem(in_pem, 0)
    # print("pubkey = {}".format(pubkey))
    # print("privkey = {}".format(privkey))
    assert (len(privkey) == 32)
    assert (len(pubkey) == 65)
    assert (privkey == in_privkey)
    assert(pubkey == in_pubkey)


def test_from_pem2():
    """
    """
    if _is_windows():
        pem = in_pem_posix
    else:
        pem = in_pem_nt

    pubkey, privkey = sig.convert_from_pem(pem, 0)
    # print("pubkey = {}".format(pubkey))
    # print("privkey = {}".format(privkey))
    assert (len(privkey) == 32)
    assert (len(pubkey) == 65)
    assert (privkey == in_privkey)
    assert (pubkey == in_pubkey)
