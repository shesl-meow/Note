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

## 第八题

我觉得这个题目的 bk 序列是有问题的：

```python
sage: berlekamp_massey([GF(2)(int(c)) for c in "001011011011000001011011011000"])
x^15 + 1
```

这也就是说能够构造 bk 的最小多项式是 $$x^{15} + 1$$，这很显然不是一个四级序列：

- 虽然 bk 的周期等同于一个 4 级 m-sequence 的周期，
- 它并不是 m-sequence，它的特征多项式也非常奇怪。

- 这意味着我们只能用穷举法求他的周期，**使用公式 $$(2^n - 1)(2^m - 1)$$ 是错误的**。

话不多说上代码（第六题中的技巧已经被封装：[shesl-crypto](https://github.com/shesl-meow/shesl-crypto/blob/master/sheslcrypto/LFSR/MatrixCrackLfsr.py)）：

```python
#!/usr/bin/env python2
from sage.all import *
from sheslcrypto.LFSR import MatrixCrackLfsr

class Crack:
    ak = [GF(2)(c) for c in "11101001110100"]
    bk = [GF(2)(c) for c in "001011011011000001011011011000"]
    def __init__(self):
        crackak = MatrixCrackLfsr(self.ak)
        self.Ma = crackak.crack_by_matrix()
        crackbk = MatrixCrackLfsr(self.bk)
        self.Mb = crackbk.crack_by_matrix()
        self.ck = []
    
    def JK_calculate_nextc(self):
        index = len(self.ck)
        if index == len(self.ak):
            next_a = vector(self.ak[-self.Ma.rank():]) * self.Ma
            self.ak.append( GF(2)(next_a[-1]) )
        if index == len(self.bk):
            next_b = vector(self.bk[-self.Mb.rank():]) * self.Mb
            self.bk.append( GF(2)(next_b[-1]) )
        a,b = self.ak[index], self.bk[index]
        self.ck.append(
            a if (index == 0) else ( GF(2)((a + b + 1) * self.ck[index - 1] + a) )
        )
    
    def reach_period(self):
        l = len(self.ck)
        return False if (l & 1 == 1) else (self.ck[:l/2] == self.ck[l/2:])
    
    def crack_JK_c(self):
        for _ in range( max(self.Ma.rank(), self.Mb.rank()) ):
            self.JK_calculate_nextc()

        from sage.matrix.berlekamp_massey import berlekamp_massey
        while True:
            self.JK_calculate_nextc()
            if self.reach_period():
                break
            if len(self.ck) % 2 == 0:
                bm = berlekamp_massey(self.ck)
        return self.ck, len(self.ck)/2
        
        
if __name__ == "__main__":
    c = Crack()
    print c.crack_JK_c()
```

结果如下：

```bash
$ python crack-8.py 
([1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1], 105)
```

周期是 105，虽然和公式结果一样，但是我们并不能使用公式。