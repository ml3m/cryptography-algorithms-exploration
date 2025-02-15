from binascii import unhexlify

def xor_single_byte(data, key):
    return bytes(b ^ key for b in data)

ciphertext = unhexlify("73626960647f6b206821204f21254f7d694f7624662065622127234f726927756d")

for key in range(256):
    decrypted = xor_single_byte(ciphertext, key)
    try:
        text = decrypted.decode()
        if text.isprintable():  # Check if the output is readable
            if "crypto" in text:
                print(f"{text}")
    except UnicodeDecodeError:
        continue
