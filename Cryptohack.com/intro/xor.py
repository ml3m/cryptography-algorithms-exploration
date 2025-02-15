from pwn import *

given = "label"

heh = ""
for char in given:
    heh += xor(char, 13).decode("utf-8")

print("crypto{" + heh + "}")
