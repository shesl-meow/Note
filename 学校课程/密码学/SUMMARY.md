# 密码学期末复习

## 随机数发生器

重点：线性反馈移位寄存器、转移矩阵、特征多项式、m-序列、Golomb 伪随机性

Golomb 随机性公设：

-  GF(2) 上的 n 长 m-sequence {ai}  应该满足下面的三个条件：
	1. 在一个周期内，0、1 出现的次数分别是 $$2^{n-1} - 1$$ 和 $$2^{n - 1}$$；
	2. 在一个周期内，总游程数为 $$2^{n-1}$$；对长为 $$i (1 \le i \le n-1)$$ 的游程有 $$2^{n-1-i}$$ 个，0、1 各半；
	3. $$\{a_i\}$$ 的自相关函数为 $$\displaystyle R(\tau) = \begin{cases} 1, & \tau = 0 \\\displaystyle -\frac{1}{2^n - 1}, & 0 < \tau \le 2^n - 2 \end{cases}$$

自相关函数：

- GF(2) 上周期为 T 的序列 $$\{a_i\}$$ 的自相关函数定义为：
- $$\displaystyle R(\tau) = \frac{1}{T} \sum_{k = 1}^{T} (-1)^{a_k} (-1)^{a_{k+\tau}}$$

## 流密码

流密码的加密原理：将明文比特流 m 与随机比特流 k 按位异或得到加密比特流 c；

随机比特流通常是由多个 LFSR，通过一些方式组合而成：

- Geffe 序列生成器、JK 触发器、Pless 触发器、钟控序列生成器

一些常见的流密码：

- 手机通信的加密方式 `A5/1`、蓝牙的加密方式 `E0`、WiFi-WEP 的加密方式 `RC4`；

## 分组密码

分组密码常用的方法：

- 代换：一个离散可逆函数；
- 扩散和混淆：香农提出的密码设计两个基本方法。扩散破坏明文和密文的统计关系，混淆破坏密钥和密文的统计关系；
- Feistel 加密结构：
  - 将明文分为 L、R 左右两个部分，进行多轮迭代计算。每轮计算通过下面的方式：
  - $$L_i = R_{i-1}$$、$$R_i = L_{i-1} \oplus F(R_{i-1}, K_i)$$

分组密码的运行模式：

- ECB(Electronic Code Book)：电子密码本模式；
- CBC(Cipher Block Chaining)：密码分组链接模式；
- CFB(Cipher FeedBack)：密码反馈模式；
- OFB(Ouput FeedBack)：输出反馈模式；

一些常见的分组密码：

- **DES**(Data Encryption Standard)：由 IBM 公司研制，最初是 **Luciffer** 密码的发展和修改；
- **IDEA**(International Data Encryption Algorithm)：由 X.J.Lai 与 J.L.Massey 提出，当时被称为 **PES**(Proposed Encryption Standard)；在差分密码分析提出之后又改进为 **IPES**，最后更名为 IDEA；
- **AES**(Advanced Encryption Standard)：多个机构提出、攻击、选举的结果，最初名为 **Rijndael**；
- **祖冲之密码**（ZUC）：国家信息安全重点实验室研制，2011 年 9 月成为 LTE 4G 国际标准；
- **SM4**：中国商用密码算法，用于 WEPI 的分组密码算法；

## 公钥密码

常见的公钥密码：

- RSA 算法、背包密码体制、Robin 密码体制、ElGamal 椭圆曲线密码体制、SM2 椭圆曲线加密算法；

椭圆曲线上的加法和倍乘运算：

- 对于椭圆曲线  $$E_p(a, b): y^2 \equiv x^3 +ax +b \pmod{p}$$。设 $$P_1 = (x_1, y_1), P_2 = (x_2, y_2)$$ 是上异于无穷远点 O 的两个点。则：

  负元公式：$$-P_1 = (x_1, y_1)$$

  加法公式：考虑 $$P_3 = (x_3, y_3) = P_1 + P_2$$：

  - 可得 $$\begin{cases} x_3 = k^2 -x_1 - x_2 \\ y_3 = k(x_1 - x_3) - y_1\end{cases}$$，其中 $$k = \begin{cases}\displaystyle \frac{y_2 - y_1}{x_2 - x_1} & x_1 \not= x_2 \\ \displaystyle \frac{3x_1^2 + a}{2y_1} & x_1 = x_2\end{cases}$$


## 密码分配

公钥的分配方式有以下几种：

- 公开发布、公用目录表、公钥管理机构、公钥证书；

秘密分割：

- Shamir 门限方案、基于中国剩余定理的门限方案；