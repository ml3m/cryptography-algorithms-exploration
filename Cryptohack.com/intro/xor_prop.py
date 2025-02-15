from binascii import unhexlify

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

KEY1 = unhexlify("a6c8b6733c9b22de7bc0253266a3867df55acde8635e19c73313")
KEY2 = xor_bytes(KEY1, unhexlify("37dcb292030faa90d07eec17e3b1c6d8daf94c35d4c9191a5e1e"))
KEY3 = xor_bytes(KEY2, unhexlify("c1545756687e7573db23aa1c3452a098b71a7fbf0fddddde5fc1"))
FLAG_XOR = unhexlify("04ee9855208a2cd59091d04767ae47963170d1660df7f56f5faf")

FLAG = xor_bytes(FLAG_XOR, xor_bytes(xor_bytes(KEY1, KEY2), KEY3))
print(FLAG.decode())
