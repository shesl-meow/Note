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
    
    def calculate_nexta(self):
        vector_a = vector(self.ak[-self.Ma.rank():])
        next_a = vector_a * self.Ma
        self.ak.append( GF(2)(next_a[-1]) )

    def calculate_nextb(self):
        vector_b = vector(self.bk[-self.Mb.rank():])
        next_b = vector_b * self.Mb
        self.bk.append( GF(2)(next_b[-1]) )

    def JK_calculate_nextc(self):
        index = len(self.ck)
        if index == len(self.ak): self.calculate_nexta()
        if index == len(self.bk): self.calculate_nextb()
        a,b = self.ak[index], self.bk[index]
        self.ck.append(
            a if (index == 0) else ( GF(2)((a + b + 1) * self.ck[index - 1] + a) )
        )
    
    def reach_period(self):
        l = len(self.ck)
        return self.ck[:l/2] == self.ck[l/2:]
    
    def crack_JK_c(self):
        for _ in range( max(self.Ma.rank(), self.Mb.rank()) ):
            self.JK_calculate_nextc()

        while True:
            self.JK_calculate_nextc()
            if self.reach_period():
                break
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

## 例 2-8

> 定理 2-7: GF(2) 上的 n 长 m-sequence {ai}  应该满足下面的三个条件：
>
> 1. 在一个周期内，0、1 出现的次数分别是 $$2^{n-1} - 1$$ 和 $$2^{n - 1}$$；
> 2. 在一个周期内，总游程数为 $$2^{n-1}$$；对长为 $$i (1 \le i \le n-1)$$ 的游程有 $$2^{n-1-i}$$ 个，0、1 各半；
> 3. $$\{a_i\}$$ 的自相关函数为 $$\displaystyle R(\tau) = \begin{cases} 1, & \tau = 0 \\\displaystyle -\frac{1}{2^n - 1}, & 0 < \tau \le 2^n - 2 \end{cases}$$

对于例 2-8，其等价于 $$f_1 = 1 + x +x^3, f_2 = 1 + x^2 + x^3$$ 这样两个多项式，构成一个钟控序列生成器，现在我们通过上面的定理 2-7 证明它是不是一个 m 序列。他们的转移矩阵是很显然的。

话不多说，直接上代码：

```python
#!/usr/bin/env python2
from sage.all import *

class ClockSequence:
    Ta = Matrix(GF(2),[ [0, 0, 1], 
                        [1, 0, 1], 
                        [0, 1, 0]])
    Tb = Matrix(GF(2),[ [0, 0, 1],
                        [1, 0, 0],
                        [0, 1, 1]])

    def __init__(self):
        self.a = vector(GF(2), [1, 1, 1])
        self.b = vector(GF(2), [1, 1, 1])

    def __iter__(self):
        return self
    
    def next(self):
        c = self.b[0]
        if self.a[0] == 1:
            self.b = self.b * self.Tb
        self.a = self.a * self.Ta
        return c


if __name__ == "__main__":
    cs = ClockSequence()
    cs_iter = iter(cs)
    lst = [next(cs_iter) for _ in range(49)]
    print(lst.count(1), lst.count(0))
```

运行它就可以发现：

```bash
(sage-sh) $ python test-2-8.py 
(28, 21)
```

他们的 0、1 数量差了很多。