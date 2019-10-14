# 第二次作业

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
        self.xPR = PolynomialRing(ZZ, names='x')
        self.cFF = GF(2**8, names="c")
        self.yPR = PolynomialRing(self.cFF, names='y')
        x, y = self.xPR.gen(), self.yPR.gen()
        
        self.f1_x, self.f2_x = 0x1B * x**3 + 0x03 * x**2 + 0xDD*x + 0xA1, 0xAC * x**3 + 0xF0 * x + 0x2D
        self.f1_y, self.f2_y = self.x2y(self.f1_x), self.x2y(self.f2_x)
        self.base_poly = self.x2y(x**4 + 1)

    def x2y(self, x_poly):
        return self.yPR([self.cFF.fetch_int(c) for c in x_poly.list()])

    def y2x(self, y_poly):
        return self.xPR([c.integer_representation() for c in y_poly.list()])
        
    def solve(self):
        res_y = self.f1_y * self.f2_y % self.base_poly
        res_x = self.y2x(res_y)
        print "\t%s" % self.f1_x
        print "\odot\t%s" % self.f2_x
        print "=\t%s" % res_x
        print "mod\t%s" % self.y2x(self.base_poly)


if __name__ == "__main__":
    s = Solve()
    s.solve()
```

运行结果：

```bash
$ python solve-2.py
	27*x^3 + 3*x^2 + 221*x + 161
\odot	172*x^3 + 240*x + 45
=	253*x^3 + 157*x^2 + 73*x + 103
mod	x^4 + 1
```

