from gmssl import sm2,func

def file_read(path):
    with open(path,'r',encoding='utf-8') as rf:
        data=rf.read()
    return data

def file_write(path,data):
    with open(path,'w',encoding='utf-8') as wf:
        wf.write(data)

def SM2_en(private_key,public_key,data):
    sm2_encrypt=sm2.CryptSM2(private_key,public_key)
    data=data.encode('utf-8')
    cipher=sm2_encrypt.encrypt(data)
    return cipher.hex()

def SM2_de(private_key,public_key,data):
    sm2_decrypt = sm2.CryptSM2(private_key, public_key)
    data=bytes.fromhex(data)
    plain=sm2_decrypt.decrypt(data)
    return plain.decode('utf-8')

def SM2_sign(private_key,public_key,data):
    sm2_sign=sm2.CryptSM2(private_key,public_key)
    random_hex_str=func.random_hex(sm2_sign.para_len)
    data = data.encode('utf-8')
    sign=sm2_sign.sign_with_sm3(data,random_hex_str)
    return sign,random_hex_str

def SM2_verify(private_key,public_key,sign,data):
    sm2_ver = sm2.CryptSM2(private_key, public_key)
    data = data.encode('utf-8')
    assert sm2_ver.verify_with_sm3(sign,data)