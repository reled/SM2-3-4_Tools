from gmssl import sm2,func

class key_gen(sm2.CryptSM2):
    def __init__(self,private_key=None,public_key="",ecc_table=sm2.default_ecc_table,mode=0):
        super().__init__(private_key,public_key,ecc_table,mode)

    def private_key_gen(self):
        if self.private_key is None:
            self.private_key=func.random_hex(self.para_len) # d∈[1,n-2]
        return self.private_key

    def public_key_gen(self):
        if self.public_key == "":
            self.public_key=self._kg(int(self.private_key_gen(),16),self.ecc_table['g']) # P=[d]G
        return self.public_key

def file_write(path,data):
    with open(path,'w',encoding='utf-8') as wf:
        wf.write(data)

def key_write(priv_path,pub_path):
    sm2_key=key_gen()
    private_key=sm2_key.private_key_gen()
    public_key=sm2_key.public_key_gen()
    file_write(priv_path,private_key)
    file_write(pub_path,public_key)