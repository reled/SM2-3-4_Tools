from gmssl import sm4
from gmssl.sm4 import SM4_ENCRYPT, SM4_DECRYPT

def key_fill(key):
    if len(key)==16:
        return key
    elif len(key) > 16:
        return key[0:16]
    else:
        return key.ljust(16,'0')

def SM4_encrypt_ecb(key,plaintext):
    key=key_fill(key)
    sm4_crypt=sm4.CryptSM4()
    sm4_crypt.set_key(key.encode(),SM4_ENCRYPT)
    plainstr=str(plaintext)
    res=sm4_crypt.crypt_ecb(plainstr.encode())
    res_hex=res.hex()
    return res_hex

def SM4_decrypt_ecb(key,ciphertext):
    key = key_fill(key)
    sm4_crypt = sm4.CryptSM4()
    sm4_crypt.set_key(key.encode(), SM4_DECRYPT)
    res=sm4_crypt.crypt_ecb(bytes.fromhex(ciphertext))
    res_str=res.decode()
    return res_str