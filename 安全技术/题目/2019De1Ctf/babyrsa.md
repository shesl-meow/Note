# baby rsa

这题涉及了大量的 `RSA` 相关的破解知识。

## 题目

阅读题目之后实际上就是解数个方程，在没有 `hint` 的情况下，方程如下：

- $$\begin{cases} p^4 \equiv C_{1} \pmod{N_{1}} \\ p^4 \equiv C_{2} \pmod{N_{2}} \\ p^4 \equiv C_{3} \pmod{N_{3}} \\ p^4 \equiv C_{4} \pmod{N_{4}}\end{cases}$$
- $$\begin{cases} (e_1)^{42} &\equiv C_{e1} \pmod{N_e} \\ (e_2 + T)^3 &\equiv C_{e2} \pmod{N_e}\end{cases}$$
- $$q_1 * x = N_q \text{ where } q_1 < x$$

- $$\begin{cases} flag^{e_1} \equiv C_{f1} \pmod{p * q_1} \\ flag^{e_2} \equiv C_{f2} \pmod{p * q_2}\end{cases}$$

上面所有方程的大写字母均为已知数字。

## 脚本

### 分解大小相近的素数积

```python
#!/usr/bin/env python2
from sage.all import *
from gmpy2 import iroot

class CrackNearPQ:
    def __init__(self, n):
        self.n, self.p, self.q = n, 0, 0

    def crack_delta(self):
        k = -1
        while True:
            k += 1
            delta = k ** 2 + 4 * self.n
            res, check = iroot(delta, 2)
            if check: break
        self.p, self.q = (res - k) / 2, (res + k) / 2
        assert is_prime(self.p) and is_prime(self.q)

    def crack(self):
        self.crack_delta()
        return self.p, self.q

if __name__ == "__main__":
    n = 15
    cnpq = CrackNearPQ(n)
    print(cnpq.crack())
```

### 小指数得到明文

下面用 [信安数基](../../../学校课程/信息安全数学基础/7.二次剩余.md) 中的定理检测了是否为高次剩余：

```python
#!/usr/bin/env python2
from sage.all import *


class CrackSmallE:
    def __init__(self, c, e, n, phi=None):
        self.c, self.e, self.n, self.phi = c, e, n, phi

    def check_remainder(self):
        if self.phi is None: return
        d = gcd(self.e, self.phi)
        assert power_mod(self.c, (self.phi / d), self.n) == 1

    def crack_times(self):
        k = -1
        while True:
            k += 1
            try:
                real_val = Integer(k * self.n + self.c)
                res = real_val.nth_root(self.e)
                break
            except ValueError: pass
        self.m = res

    def crack(self):
        self.check_remainder()
        self.crack_times()
        return self.m

if __name__ == "__main__":
    c, e, n = 13, 3, 15
    cse = CrackSmallE(c, e, n)
    print(cse.crack())
```

### 指数与欧拉函数不互素求解

因为在最后一步需要解下面的方程（其中只有 `flag` 一个未知数）：

- $$flag^{e_1} \equiv C_{f1} \pmod{p * q_1}$$

因为上面的 `e1` 与 `phi(p*q1)` 不是互素的，不能用常规的方程求解。

上面的方程显然可以被我们分解成两个独立的方程，然后我们单独研究后者（因为指数 e 与后者的欧拉函数，最小公倍数更小，我们更容易直接开方）：

- 设：$$phi = q_1 -1, g = gcd(phi, e_1)$$
- 我们考虑 $$flag^{g}$$ 作为这个加密体系的明文，可以根据常规的 `RSA` 解出：
  - $$\displaystyle e_g = \frac{e_1}{g}, d_g \equiv (e_g)^{-1} \pmod{phi}$$
  - $$flag^g \equiv (C_{f1})^{d_g} \pmod{q_1}$$
- 因为这个时候的 g，已经非常小了可以直接按小指数得到明文

```python
#!/usr/bin/env python2
from sage.all import *
from CrackSmallE import CrackSmallE


class CrackEPhiNotMutual:
    def __init__(self, c, e, p, q):
        assert is_prime(p) and is_prime(q)
        self.c, self.e, self.p, self.q = c, e, p, q

    def crack_by_p(self):
        g = gcd(self.p - 1, self.e)
        d = inverse_mod(Integer(self.e / g), self.p - 1)
        mg = power_mod(self.c % self.p, d, self.p)
        CRSE = CrackSmallE(mg, g, self.p, self.p-1)
        return mg if g==1 else CRSE.crack()
    
    def crack_by_q(self):
        g = gcd(self.q - 1, self.e)
        d = inverse_mod(Integer(self.e / g), self.q - 1)
        mg = power_mod(self.c % self.q, d, self.q)
        CRSE = CrackSmallE(mg, g, self.q, self.q - 1)
        return mg if g == 1 else CRSE.crack()

    def crack_by_pq(self):
        mp, mq = self.crack_by_p(), self.crack_by_q()
        return crt([mp, mq], self.p, self.q)
```

## 破解

完整的脚本如下：

```python
#!/usr/bin/env python2
from sage.all import *
from binascii import a2b_hex

from CrackNearPQ import CrackNearPQ
from CrackSmallE import CrackSmallE
from CrackEPhiNotMutual import CrackEPhiNotMutual
from const import *

if __name__ == "__main__":
    p4 = crt([C1, C2, C3, C4], [N1, N2, N3, N4])
    CRSE = CrackSmallE(p4, 4, N1 * N2 * N3 * N4)
    p = CRSE.crack()
    assert is_prime(p)
    print "p: %d" % p

    CRSE = CrackSmallE(Ce1, 42, Ne)
    e1 = CRSE.crack()
    print "e1: %d" % e1
    CRSE = CrackSmallE(Ce2, 3, Ne)
    e2 = (CRSE.crack() - T) % Ne
    print "e2: %d" % e2

    CNPQ = CrackNearPQ(Nq)
    q1,_ = CNPQ.crack()
    print "q1: %d" % q1

    CEPM = CrackEPhiNotMutual(Cf1, e1, p, q1)
    flag = CEPM.crack_by_q()
    print "flag: %s" % a2b_hex(flag.hex())

```