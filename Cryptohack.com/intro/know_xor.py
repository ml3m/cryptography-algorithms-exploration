from pwn import xor
flag = bytes.fromhex('0e0b213f26041e480b26217f27342e175d0e070a3c5b103e2526217f27342e175d0e077e263451150104')
print(xor(flag, 'crypto{'.encode()))
# This gives us the key
print(xor(flag, 'myXORkey'.encode()))
# using the output of key, and gussing the 'y' we get the key.

# encoding to bytes using `.encode`, it only changes `data type`, not the data

# Credit: oushanmu
