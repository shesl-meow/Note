# Chapter2

## 第六题

话不多说直接上脚本：

```python
#!/usr/bin/env python2
# coding=utf-8
from sage.all import *


class Crack:
    cipher = "1010110110"
    plain = "0100010001"
    order = 3
    def __init__(self):
        mapper = lambda (a,b):GF(2)(int(a)^int(b))
        self.stream = map(mapper, [(self.cipher[i], self.plain[i]) for i in range(10)])

    def crack_by_matrix(self):
        """
        时间复杂度 O(n^3)
        :return: 返回一个状态转移矩阵
        """
        S0 = Matrix([self.stream[i  :i+5] for i in range(5)])
        S1 = Matrix([self.stream[i+1:i+6] for i in range(5)])
        rank1, rank2 = S0.rank(), S1.rank()
        assert (rank1 == rank2) and (self.order == rank1)

        S0 = Matrix([self.stream[i  :i+3] for i in range(3)])
        S1 = Matrix([self.stream[i+1:i+4] for i in range(3)])
        return S0.solve_right(S1)

    def crack_by_bm(self):
        """
        时间复杂度 O(n^2)
        :return: 返回一个 lfsr 的特征多项式
        """
        # todo: 这里直接调用了 sagemath 的系统 api
        #       这个 API 好像有一些问题，后来被放弃了，但是这个题目是正常的
        from sage.matrix.berlekamp_massey import berlekamp_massey
        return berlekamp_massey(self.stream)


if __name__ == "__main__":
    c = Crack()
    print "转移矩阵：\n", c.crack_by_matrix()
    print "\n特征多项式：\n", c.crack_by_bm()
```

用 `sage` 版本的 `python2` 运行这个脚本，可以得到：

```bash
$ python2 crack-6.py 
转移矩阵：
[0 0 1]
[1 0 0]
[0 1 1]

特征多项式：
x^3 + x^2 + 1
```

