from gmssl import sm3

def do_hash(data):
    data=bytes(data.encode())
    data_list=[i for i in data]
    hash_hex=sm3.sm3_hash(data_list)
    return hash_hex

def verify(data,hash_value):
    return do_hash(data)==hash_value