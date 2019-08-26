# interesting 2

今天做了靶场里面的一道密码学的题目，名字叫 `interesting`。可见把这道题目搬上来的人认为这道题目非常地有趣，但是我并不这么觉得。

懒得写解答了直接上 `exp.py`：

```python
#!/usr/bin/env python
import hashlib
import random
from Crypto.Cipher import AES
from Crypto.Util.number import *


def gen_iv(seed):
    s=random.Random()
    s.seed(seed)
    while True:
        iv=long_to_bytes(s.randint(0xfffffffffffffffffffffffffffffff,0xffffffffffffffffffffffffffffffff))
        if hashlib.sha256(iv).hexdigest()[0:4]==hashlib.sha256(long_to_bytes(seed)).hexdigest()[0:4]:
            return iv

def gen_password(seed):
    s=random.Random()
    s.seed(seed)
    while True:
        password=long_to_bytes(s.randint(0xfffffffffffffffffffffffffffffff,0xffffffffffffffffffffffffffffffff))
        if hashlib.sha256(password).hexdigest()[4:8]==hashlib.sha256(long_to_bytes(seed)).hexdigest()[4:8]:
            return password

def str_diff(str1, str2):
    assert len(str1) == len(str2)
    counter = 0
    for ind, c1 in enumerate(str1):
        if c1 != str2[ind]:
            counter += 1
    return counter

def basedecode(enc, book):
    elen = len(book).bit_length() - 1
    binary_stream = ""
    for c in enc:
        if c == "=":
            binary_stream += "0" * elen
            continue
        binary_stream += bin(book.index(c))[2:].rjust(elen, "0")
    dec = int(binary_stream, 2)
    return long_to_bytes(dec)

class Crack:
    m1 = "token=5t43g5g2j1;admin=0;group=0"
    c1 = "bMPWOsg+YH0eSwchPY6HTEvf3ESETSrEQ3/M1d0lUm0=".decode("base64")

    def __init__(self):
        self.m2, self.c2 = "*"*32, "*"*32
        self.seed = 0
        self.c = open("heheda.txt", "r").read().decode("hex")
        pass

    def situation1(self):
        m2_chunk2 = self.m1[16:].replace("0", "1")
        c2_chunk1 = ''.join([chr(
            ord(self.m1[16 + i]) ^ ord(m2_chunk2[i]) ^ ord(self.c1[i])
        ) for i in range(16)])
        c2_chunk2 = self.c1[16:]
        self.c2 = c2_chunk1 + c2_chunk2
        self.seed = int(hashlib.sha256(self.c2).hexdigest(), 16)
        assert str_diff(self.c2, self.c1) == 2

    def decrypt(self):
        passwd = gen_password(self.seed)
        iv = gen_iv(self.seed)
        aeser = AES.new(passwd, AES.MODE_CBC, iv)
        m = aeser.decrypt(self.c).rstrip("A")
        self.encflag = hex(long(m)).lstrip("0x").rstrip("L").decode("hex")

    def decode(self):
        print "encflag0: %s" % self.encflag

        encflag1 = self.encflag
        import base64
        while True:
            if any([c in encflag1 for c in "ghijklmnopqrstuvwxyz"]):
                encflag1 = base64.b64decode(encflag1)
            elif any([c in encflag1 for c in "GHIJKLMNOPQRSTUVWXYZ"]):
                encflag1 = base64.b32decode(encflag1)
            else: break
        print "encflag1: %s" % encflag1

        encflag2 = encflag1
        encflag2 = [int(encflag2[i:i + 2], 16) for i in range(0, len(encflag2), 2)]
        encflag2 = ''.join([chr(c) for c in encflag2])
        encflag2 = encflag2.decode("hex")
        print "encflag2: %s" % encflag2

        encflag3 = encflag2
        while True:
            if "{" in encflag3 and "}" in encflag3:
                break
            elif any([c in encflag3 for c in "ghijklmnopqrstuvwxyz"]):
                encflag3 = base64.b64decode(encflag3)
            else:
                encflag3 = base64.b32decode(encflag3)
        print "encflag3: %s" % encflag3


if __name__ == "__main__":
    CR = Crack()
    CR.situation1()
    CR.decrypt()
    CR.decode()
    pass
```

