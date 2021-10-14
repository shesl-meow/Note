# EllipticCurve

## Elliptic Curve

### 系统参数

如何确定一个 ECC：

1. 选择一个素数 p 和一个整数 n。从有限域 $$\mathbb{F}_p$$ 中选择一个次数为 n 不可约多项式 f(x)，并且用这个不可约多项式得到一个有限域 $$\mathbb{F}_{p^n}$$，设 f(x) 在该有限域下的根为 $$\alpha$$；
2. 在有限域 $$\mathbb{F}_{p^n}$$ 中生成一个非超奇异（non-supersingular）曲线 E；
3. 在 E 上选择一个阶为素数的点 $$P=(x,y)$$，设其阶为 q；
4.  定义一个转化函数 $$c(x): \mathbb{F}_{p^n} \rightarrow \Z_{p^n}$$。具体的定义为：

    $$\displaystyle c(x) = \sum_{i=0}^{n-1} c_i p^i \in \Z_{p^n}, \text{for } x= \sum_{i=0}^{n-1}c_i \alpha^i \in \mathbb{F}_{p^n}, 0 \le c_i < p$$

### 域上的运算

## DSA 签名算法

### 系统参数

系统需要初始化以下信息供所有系统的使用者共享：

1. 选择一个椭圆曲线 EC：
2. 选择一个安全的哈希函数 h(x)；

### 密钥生成

签名者使用这个系统需要通过以下方式生成一个密钥：

1. 随机选择一个整数 d 满足 $$0 < d < q$$
2. 在椭圆曲线 E 上计算 $$Q = dP = (x_d, y_d)$$
3. 封装公钥 $$(x_d, y_d)$$，封装私钥 $$(d)$$

### 签名过程

签名者通过以下的方式进行签名：

1. 随机选取一个整数 k 满足 $$0 < k < q$$，并计算 $$R = kP = (x_k, y_k)$$
2. 通过系统中的函数 c(x) 计算 r，即：$$r = c(x_k)$$
3. 计算满足以下方程的 s：$$h(m) \equiv dr + ks \pmod{q}$$
4. 封装信息 m 的签名 $$(r, s)$$。

### 验证签名

验证签名的流程如下：

1. 计算以下的三个数字：$$\begin{cases} t = s^{-1} \pmod{q}\\ u = h(m) \cdot t \pmod{q}\\ v = -t \cdot r \pmod{q} \end{cases}$$
2. 在椭圆曲线中计算下面的点 $$uP + vQ = u(x,y) + v(x_d,y_d)=(x_k, y_k)$$
3. 判断以下等式是否成立，成立则接受这个签名 $$r = c(x_k) \pmod{q}$$
