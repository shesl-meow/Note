# SM 2

## 有限域

本条给出有限域 $$F_q$$ 的描述及其元素的表示，q 是一个奇素数或者是 2 的方幂。

1. 当 q 是奇素数 p 时，要求 p > $$2^{191}$$；
2. 当 q 是 2 的方幂 $$2^m$$ 时，要求 m > 192 且为素数。

### 素域

如果是第一种情况，q 是奇素数 p 时，素域 $$F_p$$ 中的元素用 $$\{0, 1, \cdots, p-1\}$$ 表示。

这个域有以下的特点：

1. 加法单位元是整数 0；
2. 乘法单位元是整数 1；
3. 域元素加法是整数模 p 加法：$$a, b \in F_p$$，则 $$a + b \rightarrow (a+b) \pmod{p}$$

4. 域元素乘法是整数模 p 乘法：$$a, b \in F_p$$，则 $$ab \rightarrow ab \pmod{p}$$

### 二元扩域

当 q 是 2 的方幂 $$2^m$$ 时，二元扩域 $$F_{2^m}$$ 可以看成 $$F_2$$ 上的 m 维向量空间，其元素可用长度为 m 的比特串表示。m 上的元素主要有多项式基（PB）与正规基（NB）两种表示方法。下面以前者为例：

多项式基：

- 设 $$F_2$$ 上的 m 次不可约多项式 $$f(x) = x^m + f_{m-1} x^{m-1} + \cdots + f_1 x + f_0, \text{where }f_i \in F_2$$，则 $$F_{2^m}$$ 由 $$F_2$$ 上所有次数低于 m 的多项式构成。
- 多项式集合 $$\{x_{m−1};x_{m−2}; \cdots ;x;1\}$$是 $$F_{2^m}$$ 在 $$F_2$$上的一组基，称为**多项式基**。
- $$F_{2^m}$$ 中的任意一个元素 $$a(x) = a_{m−1}x_{m−1} +a_{m−2}x_{m−2} + \cdots +a_1x+a_0$$ 在 $$F_2$$ 上的系数恰好构成了长度为 m 的比特串，用 $$a = (a_{m−1};a_{m−2}; \cdots ;a_1;a_0)$$ 表示。

这个域有以下的特点：

1. 加法单位元是 $$(\underbrace{0, \cdots, 0, 0}_{m})$$；
2. 乘法单位元是 $$\displaystyle (\underbrace{0, \cdots, 0}_{m-1}, 1)$$；
3. 域元素的加法运算：$$(a_{m−1};\cdots ; a_0) + (b_{m−1}; \cdots ;b_0) = (a_{m−1} \oplus b_{m-1}; \cdots ;a_0 \oplus b_0)$$

4. 域元素的乘法运算：$$a(x) \cdot b(x) \rightarrow a(x) \cdot b(x) \pmod{f(x)}$$

## 椭圆曲线

有限域 $$F_q$$ 上的椭圆曲线是由点组成的集合。

在仿射坐标系下，椭圆曲线上点 P（非无穷远点）的坐标表示为 $$P = (x_P;y_P)$$，其中 $$x_P, y_P$$ 为满足一定方程的域元素，分别称为点 P 的 x 坐标和 y 坐标。在本文本中，称 $$F_q$$为基域。

### 素域上的椭圆曲线

定义在 $$F_p$$ 上的椭圆方程为：

- $$E: y^2 = x^3 + ax + b \text{ where } a,b \in F_p, 4a^3 +27b^2 \not\equiv 0 \pmod{p}$$

椭圆曲线 $$E(F_p)$$ 定义为：

- $$E(F_p) = \{(x, y) | x,y \in F_p, (x,y) \in E\} \cup\{O\}$$，其中 O 是无穷远点。

椭圆曲线上的点的数目记作椭圆曲线的**阶**。

### 素域上的椭圆曲线群

椭圆曲线 $$E(F_p)$$ 上的点，按照下面的运算规则，构成一个交换群：

1. $$\forall P = (x,y) \in E(F_p)$$，P 的逆元 $$-P = (x, -y)$$，$$P + (-P) = O$$

2. 两个非逆不相同点相加的规则：

   - 设 $$P_1, P_2 = (x_1, y_1), (x_2, y_2) \in E(F_p) \backslash \{O\}, \text{where } x_1 \not= x_2$$

   - 设 $$P_3 = P_1 + P_2 = (x_3, y_3)$$，则：$$\displaystyle \begin{cases}x_3 = \lambda^2 - x_1 - x_2 \\ y_3 = \lambda (x_1 - x_3) - y_1\end{cases}$$，其中 $$\displaystyle \lambda = \frac{y_2 - y_1}{x_2 - x_1}$$

3. 倍加规则：

   - 设 $$P_0 = (x_0, y_0) \in E(F_p) \backslash \{O\}, \text{where } y_0 \not= 0$$
   - 设 $$P_1 = P_0 +P_0 = (x_1, y_1)$$，则：$$\displaystyle \begin{cases}x_1 = \lambda^2 - 2x_0 \\ y_1 = \lambda(x_0 - x_1) - y_0\end{cases}$$，其中 $$\displaystyle \lambda = \frac{3 x_0^2 + a}{2y_0}$$

### 二元扩域上的椭圆曲线

定义在 $$F_{2^m}$$ 上的椭圆方程为：

- $$E: y^2 + xy = x^3 + ax^2 + b \text{ where } a,b \in F_{2^m}, b \not= 0$$

椭圆曲线 $$E(F_{2^m})$$ 定义为：

- $$E(F_{2^m}) = \{(x,y) | x,y \in F_{2^m}, (x,y) \in E\} \cup \{O\}$$，其中 O 是无穷远点。

椭圆曲线上的点的数目记作椭圆曲线的**阶**。

### 二元扩域上的椭圆曲线群

椭圆曲线 $$E(F_{2^m})$$ 上的点，按照下面的运算规则，构成一个交换群：

1. $$\forall P = (x,y) \in E(F_p)$$，P 的逆元 $$-P = (x, x+y)$$，$$P + (-P) = O$$

2. 两个非逆不相同点相加的规则：
   - 设 $$P_1, P_2 = (x_1, y_1), (x_2, y_2) \in E(F_{2^m}) \backslash \{O\}, \text{where } x_1 \not= x_2$$
   - 设 $$P_3 = P_1 + P_2 = (x_3, y_3)$$，则：$$\displaystyle \begin{cases} x_3 = \lambda^2 + \lambda + x_1 + x_2 + a \\ y_3 = \lambda (x_1 + x_3) + x_3 + y_1 \end{cases}$$，其中 $$\displaystyle \lambda = \frac{y_1 + y_2}{x_1 + x_2}$$
3. 倍加规则：
   - 设 $$P_0 = (x_0, y_0) \in E(F_{2^m}) \backslash \{O\}, \text{where } y_0 \not= 0$$
   - 设 $$P_1 = P_0 +P_0 = (x_1, y_1)$$，则：$$\displaystyle \begin{cases}x_1 = \lambda^2 + \lambda + a \\ y_1 = x_0^2 + (\lambda + 1)x_0\end{cases}$$，其中：$$\displaystyle \lambda = x_1 + \frac{y_1}{x_1}$$

## 数据类型及转换

### 数据类型

下面列举算法中会用到的所有数据类型：

1. 比特串：有序的 0 和 1 的序列。
2. 字节串：有序的字节序列，其中 8 比特为 1 个字节。
3. 域元素：有限域 $$F_q$$ 中的元素。

4. 椭圆曲线上的点