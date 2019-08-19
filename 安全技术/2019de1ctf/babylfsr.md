# baby lfsr

在比赛的时候一直在想怎么用 `berlekamp_massey` 算法求解（用矩阵求解，写代码更快，512 比特没必要用 BM 算法），并且把判断条件抄成了 `1124` ....

## 脚本

### 破解 LFSR

指定一个比特序列，返回一个转移矩阵。

```python
#!/usr/bin/env python2
from sage.all import *

class CrackLfsr:
    """
    :return A state trans matrix
    """
    def __init__(self, seq, period=None):
        self.period = period
        self.gf2 = GF(2)
        assert (len(seq) & 1)==0
        self.seq = [self.gf2(c) for c in seq]

    def crack_by_matrix(self):
        maxp = len(self.seq) / 2
        S0 = Matrix([self.seq[i:i+maxp] for i in range(maxp)])
        S1 = Matrix([self.seq[i:i+maxp] for i in range(maxp+1)[1:]])
        rs0, rs1 = S0.rank(), S1.rank()
        assert (rs0 == rs1) and (self.period is None or self.period==rs0)
        self.period = rs0

        if self.period != maxp:
            S0 = Matrix([self.seq[i:i+self.period] for i in range(self.period)])
            S1 = Matrix([self.seq[i:i+self.period] for i in range(self.period+1)[1:]])
            assert S0.rank() == S1.rank()
        return S0.solve_right(S1)

if __name__ == "__main__":
    CL = CrackLfsr([1,0,1,0,0,0,1,0])
    print CL.crack_by_matrix()
```

## 破解

最终的破解脚本：

```python
#!/usr/bin/env python2
# coding=utf-8
import hashlib
from sage.all import *
from itertools import product

from CrackLfsr import CrackLfsr

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

