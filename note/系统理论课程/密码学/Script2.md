---
title: "第二次作业"
date: 2019-10-14T22:00:15+08:00
tags: [""]
categories: ["系统理论课程", "密码学"]
---


## 第一题

> 在 $$GF(2^8)$$ 中，取模多项式 $$m(x) = x^8 + x^4 + x^3 + x + 1$$，计算下面的积：
>
> 1. 0xB7 * 0x3F
> 2. 0x11 * 0xFF

```python
#!/usr/bin/env python2
from sage.all import *

class Solve:
    def __init__(self):
        x = var('x')
        self.FF = GF(2 ** 8, name='x', modulus=x**8 + x**4 + x**3 + x + 1)
        self.l1, self.r1 = self.FF.fetch_int(0xb7), self.FF.fetch_int(0x3f)
        self.l2, self.r2 = self.FF.fetch_int(0x11), self.FF.fetch_int(0xff)

    def solve1(self):
        res = self.l1 * self.r1
        print "\t%d = %s" % (self.l1.integer_representation(), self.l1)
        print "*\t%d = %s" % (self.r1.integer_representation(), self.r1)
        print "=\t%d = %s" % (res.integer_representation(), res)
        print "mod\t%s\n" % self.FF.modulus()

    def solve2(self):
        res = self.l2 * self.r2
        print "\t%d = %s" % (self.l2.integer_representation(), self.l2)
        print "*\t%d = %s" % (self.r2.integer_representation(), self.r2)
        print "=\t%d = %s" % (res.integer_representation(), res)
        print "mod\t%s\n" % self.FF.modulus()


if __name__ == "__main__":
    s = Solve()
    s.solve1()
    s.solve2()
```

运行结果：

```bash
$ python solve-1.py
	183 = x^7 + x^5 + x^4 + x^2 + x + 1
*	63 = x^5 + x^4 + x^3 + x^2 + x + 1
=	115 = x^6 + x^5 + x^4 + x + 1
mod	x^8 + x^4 + x^3 + x + 1

	17 = x^4 + 1
*	255 = x^7 + x^6 + x^5 + x^4 + x^3 + x^2 + x + 1
=	150 = x^7 + x^4 + x^2 + x
mod	x^8 + x^4 + x^3 + x + 1
```

## 第二题

> 设 $$a(x) = 0x1B*x^3 + 0x03*x^2 + 0xDD*x + 0xA1$$，与 $$b(x) = 0xAC * x^3 + 0xF0 * x + 0x2D$$，为系数在 $$GF(2^8)$$ 上的两个多项式，计算 $$a(x) \otimes b(x) \pmod{x^4 + 1}$$

```python
#!/usr/bin/env python2
from sage.all import *

class Solve:
    def __init__(self):
        c = PolynomialRing(GF(2), names='c').gen()
        self.xPR = PolynomialRing(ZZ, names='x')
        self.cFF = GF(2**8, names="c", modulus=c**8 + c**4 + c**3 + c + 1)
        self.yPR = PolynomialRing(self.cFF, names='y')
        x, y = self.xPR.gen(), self.yPR.gen()
        
        self.f1_x, self.f2_x = 0x1B * x**3 + 0x03 * x**2 + 0xDD*x + 0xA1, 0xAC * x**3 + 0xF0 * x + 0x2D
        self.f1_y, self.f2_y = self.x2y(self.f1_x), self.x2y(self.f2_x)
        self.base_poly = self.x2y(x**4 + 1)

    def x2y(self, x_poly):
        return self.yPR([self.cFF.fetch_int(c) for c in x_poly.list()])

    def y2x(self, y_poly):
        return self.xPR([c.integer_representation() for c in y_poly.list()])

    def display_x(self, x):
        Fstring = "\\begin{bmatrix} %s \end{bmatrix}"
        fstring = "%x &* x^{%d}"
        return Fstring % '\\\\'.join([
            fstring % (coff, ind) for ind,coff in enumerate(x.list())
        ][::-1])

    def display_y(self, y):
        Fstring = "\\begin{bmatrix} %s \end{bmatrix}"
        fstring = "(%s) &* x^{%d}"
        return Fstring % '\\\\'.join([
            fstring % (coff, ind) for ind, coff in enumerate(y.list())
        ][::-1])
        
    def solve(self):
        res_y = self.f1_y * self.f2_y % self.base_poly
        res_x = self.y2x(res_y)
        print "\t%s\n\t%s\n" %( self.display_x(self.f1_x), self.display_y(self.f1_y) )
        print "\odot\t%s\n\t%s\n" % ( self.display_x(self.f2_x), self.display_y(self.f2_y) )
        print "=\t%s\n\t%s\n" % ( self.display_x(res_x), self.display_y(res_y) )
        print "mod\t%s" % self.y2x(self.base_poly)

if __name__ == "__main__":
    s = Solve()
    s.solve()
```

运行结果：

```bash
$ python solve-2.py
	\begin{bmatrix} 1b &* x^{3}\\3 &* x^{2}\\dd &* x^{1}\\a1 &* x^{0} \end{bmatrix}
	\begin{bmatrix} (c^4 + c^3 + c + 1) &* x^{3}\\(c + 1) &* x^{2}\\(c^7 + c^6 + c^4 + c^3 + c^2 + 1) &* x^{1}\\(c^7 + c^5 + 1) &* x^{0} \end{bmatrix}

\odot	\begin{bmatrix} ac &* x^{3}\\0 &* x^{2}\\f0 &* x^{1}\\2d &* x^{0} \end{bmatrix}
	\begin{bmatrix} (c^7 + c^5 + c^3 + c^2) &* x^{3}\\(0) &* x^{2}\\(c^7 + c^6 + c^5 + c^4) &* x^{1}\\(c^5 + c^3 + c^2 + 1) &* x^{0} \end{bmatrix}

=	\begin{bmatrix} 72 &* x^{3}\\12 &* x^{2}\\5a &* x^{1}\\18 &* x^{0} \end{bmatrix}
	\begin{bmatrix} (c^6 + c^5 + c^4 + c) &* x^{3}\\(c^4 + c) &* x^{2}\\(c^6 + c^4 + c^3 + c) &* x^{1}\\(c^4 + c^3) &* x^{0} \end{bmatrix}

mod	x^4 + 1
```


