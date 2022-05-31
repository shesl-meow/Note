---
title: "baby lfsr"
date: 2019-07-30T11:01:03+08:00
tags: [""]
categories: ["工具使用接口", "CTF-WriteUp"]
---


在比赛的时候一直在想怎么用 `berlekamp_massey` 算法求解（用矩阵求解，写代码更快，512 比特没必要用 BM 算法），并且把判断条件抄成了 `1124` ....

## 脚本

破解 LFSR：指定一个比特序列，返回一个转移矩阵（实现方式详见 <https://github.com/shesl-meow/shesl-crypto>）。

最终的破解脚本：

```python
#!/usr/bin/env python2
# coding=utf-8
import hashlib
from sage.all import *
from itertools import product

from sheslcrypto.LFSR import CrackLfsr

if __name__=="__main__":
    with open("output", "r") as f:
        raw = [int(b) for b in f.read().strip()]

    for num in product([0, 1], repeat=8):
        CL = CrackLfsr(raw + list(num), period=256)
        try:
            T = CL.crack_by_matrix()
        except AssertionError:
            continue
        Tn = T ** 256
        initial = Tn.solve_left(vector(raw[:256]))
        key = ZZ(list(initial)[::-1], base=2)
        flag = hashlib.sha256(key.hex().rstrip('L')).hexdigest()
        print flag
        if flag[:4] == "1224": break
```


