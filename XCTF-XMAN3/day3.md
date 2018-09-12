# 密码学Day1

## 密码学简介

- 一般来说，密码学的设计者根本目标是保障信息以及信息系统的以下几个方面的特性：
  - 机密性（Confidentiality）、完整性（Integrity）、可用性（Availability）、认证性（Authentication）、不可否认性（Non-repudiation）
  - 前三者又被称为信息安全的**CIA三要素**
- 一般来说，我们都会假设攻击者已知待破解的密码体制，而攻击类型通常分为以下四种：
  1. **唯密文攻击**：只拥有密文
  2. **已知明文攻击**：拥有密文与对应的明文
  3. **选择明文攻击**：拥有加密权限，能够对明文加密后获得相应密文
  4. **选择密文攻击**：拥有解密权限，能够对密文解密后获得响应明文

## 古典密码

### 单表代换加密

- 一般有以下两种方式来进行破解：
  1. 在密钥空间较小的情况下，采用暴力破解的方式。
  2. 在密文长度足够长的时候使用[词频分析](http://quipqiup.com/)。
- 分类：凯撒密码、移位密码、AtbashCipher、简单替换密码、仿射密码。下面关于仿射密码：

#### 仿射密码

- 仿射密码的加密函数是：$ E(x) = (ax+b) \mod m $。其中：
  - x 表示明文按照某种编码得到的数字 。
  - a与m互质。
  - m是编码系统中字母的数目。 
- 仿射密码的解密函数是：$ D(x) = a^{-1}*(x-b) \mod m $。其中：
  - $a^{-1}$ 是 a 在群 $\mathbb{Z}_{m}$ 的乘法逆元。

### 多表代换加密

- Polybius（棋盘密码） &rarr; 将给定的明文加密为两两组合的数字。

- Vigenere（维吉尼亚密码） &rarr; [维吉尼亚密码的破解](http://www.practicalcryptography.com/cryptanalysis/stochastic-searching/cryptanalysis-vigenere-cipher/)
- Hill（希尔密码） &rarr; 将给定的明文编码转化为n维向量，跟一个 n × n 的矩阵相乘，再将得出的结果对字符集大小N取模。
  - *Notice*：用作加密的矩阵（密匙）在 $\mathbb{Z}_{26}^{n}$  必须是可逆的，也就是说矩阵的行列式与N互质。
- AutokeyCipher（自动密钥密码） &rarr; 与维吉尼亚密码类似，但使用不同的方法生成密钥。

### 其他古典加密

- 培根密码 &rarr; 使用两种不同的字体，代表 0 和 1，结合加密表进行加解密。
- 栅栏密码（分组重组）、曲路密码、列移位密码、01248密码（云影密码）、JSFuck、猪圈密码、舞动的小人密码（出自福尔摩斯探案集）、键盘密码

- PostScript：自己总结，**在分析时略去字符到数字的编码过程，直接使用数字进行分析，能简化大量思考**

### 练习题目

- 2017 SECCON Vigenere3d

- 关于此题的分析：

  1. 考虑到在程序正常运行下，数组访问不会越界，我们在讨论时做以下约定：$ arr[index] \Leftrightarrow arr[index \% len(arr)] $

  2. 关于python程序中定义的 `_l` 函数，发现以下等价关系：$ \_l(offset, arr)[index] \Leftrightarrow arr[index + offset] $
  3. 关于python的main函数中三维矩阵t的定义，发现以下等价关系：$ t[a][b][c] \Leftrightarrow \_l(a+b, s)[c] $
  4. 综合第2第3点的观察，有如下等价关系：$ t[a][b][c] \Leftrightarrow s[a+b+c] $
  5. 我们将s视为一种编码格式，即：编码过程s.find(x)，解码过程s[x]。并直接使用其编码结果的数字替代其所代指的字符串，那么加密过程可以用以下公式表示：
     - $ e = f +  k1 +k2 $
     - 其中，e是密文，f是明文，k1与k2是通过复制方法得到、与f长度一样的密钥，**加法是向量加**。

- 所以我们只需要通过计算 `k1+k2` ，模拟密钥，即可解密。关于此题的解密python脚本：

  ```python
  enc_str = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz_{}'
  dec_dic = {k:v for v,k in enumerate(enc_str)}
  encrypt = 'POR4dnyTLHBfwbxAAZhe}}ocZR3Cxcftw9'
  flag_bg = 'SECCON{**************************}'
  
  sim_key = [dec_dic[encrypt[i]]-dec_dic[flag_bg[i]] for i in range(7)] # 破解模拟密钥
  sim_key = sim_key + sim_key[::-1]
  
  flag_ed = [dec_dic[v]-sim_key[k%14] for k,v in enumerate(encrypt)] # 模拟密钥解密
  flag_ed = ''.join([enc_str[i%len(enc_str)] for i in flag_ed]) # 解码
  print(flag_ed)
  ```

## 流密码

- 逐字节或者逐比特处理信息。一般来说：
  - 流密码密钥长度与明文长度相同。
  - 流密码派生自一个较短的密钥，派生算法通常为一个伪随机数生成算法。

- 流密码的关键在于设计好的伪随机数生成器。一般来说，伪随机数生成器的基本构造模块为反馈移位寄存器。伪随机数生成器（PRNG），依赖于初始值（也称种子）
  - 分类：线性同余生成器（LCG）、线性回归生成器...

### 伪随机数生成器

- 伪随机数生成器（pseudorandom number generator，PRNG），又称为确定性随机位生成器（deterministic random bit generator，DRBG），是用来生成**接近于绝对随机数序列的数字序列**的算法。
- 随机性的严格性：
  1. 随机性：随机数应该不存在统计学偏差，是完全杂乱的数列。&rarr; 弱伪随机数。
  2. 不可预测性：不能从过去的序列推测出下一个要出现的数字。&rarr; 强伪随机数。
  3. 不可重现性：除非数列保存下来，否则不能出现相同的数列。&rarr; 真随机数。

- PRNG的**周期**：对于一个PRNG的所有可能起始状态，不重复序列的最长长度。
- 目前通用的伪随机数生成器主要有：线性同余生成器（LCG）、线性回归发生器、MersenneTwister、XorshiftGenerator、WELL family of generators、线性反馈移位寄存器（LFSR）
- **密码学安全伪随机数生成器**（cryptographically secure pseudo-random number generator, CSPRNG）或密码学伪随机数生成器（CPRNG），是一种特殊的伪随机数生成器。
  - 关于 CPRNG 的需求：
    1. 通过统计随机性测试。通过 [next-bit test](https://en.wikipedia.org/wiki/Next-bit_test) ，也就是说知道了一个序列的前 k 个比特，攻击者不可能在多项式时间内以大于50%的概率预测出来下一个比特位。
    2. 必须能够足够强的攻击。比如当生成器的部分初始状态或者运行时的状态被攻击者获知时，攻击者仍然不能够获取泄露状态之前生成的随机数。
  - 分类：基于密码学算法、基于数学难题、某些特殊目的的设计。

### 线性同余发生器

**线性同余发生器**（linear congruential generator, LCG）是一种通过不连续线性函数生成伪随机数列的算法。生成器通过以下迭代关系定义：$ X_{n+1} = (aX_n+c) \mod m $，其中：

- m > 0, the "modulus"
- 0 < a < m, the "multiplier"
- 0 &le; c < m, the "increment"
- 0 &le; X<sub>0</sub> < m, the "seed" or "start value"

当 c=0 时，发生器又称作**乘法同余发生器**（multiplicative congruential generator, MCG）或 Lehmer RNG。

当 c&ne;0 时，发生器又称作*混合同余发生器*（mixed congruential generator）

### 反馈移位寄存器

一般情况下，其生成关系可以用以下公式表示：$ a_{i+n} = F(a_i, a_{i+1}, ..., a_{i+n-1}) $，其中：

- $ a_0, a_1, ..., a_{n-1} $ 为初态
- F 称为反馈函数或反馈逻辑。如果 F 为线性函数，那么我们称其为线性反馈移位寄存器（linear-feedback shift register, **LFSR**）。

#### 线性反馈移位寄存器 LFSR

反馈函数一般如下：$ a_{i+n} = \sum\limits_{j=1}^{n}c_j a_{i+n-j} $，其中 $c_j$ 均在某个有限域 $F_q$ 中。

该线性变化对应的矩阵为：$ \left[ \begin{matrix} 0 & 0 & \cdots & 0 & c_n \\ 1 & 0 & \cdots & 0 & c_{n-1}  \\ 0   & 1 & \cdots & 0 & c_{n-2} \\ \vdots & \vdots & \ddots & \vdots & \vdots \\ 0 & 0 & \cdots & 1 & c_1 \\ \end{matrix} \right] $

即：$ \left[ \begin{matrix} a_{i+1} & a_{i+2} & a_{i+3} & \cdots & a_{i+n} \end{matrix}\right] = \left[ \begin{matrix} a_{i} & a_{i+1} & a_{i+2} & \cdots & a_{i+n-1} \end{matrix}\right] \left[ \begin{matrix} 0 & 0 & \cdots & 0 & c_n \\ 1 & 0 & \cdots & 0 & c_{n-1}  \\ 0   & 1 & \cdots & 0 & c_{n-2} \\ \vdots & \vdots & \ddots & \vdots & \vdots \\ 0 & 0 & \cdots & 1 & c_1 \\ \end{matrix} \right] $

我们可以求得其特征多项式：（我们一般讨论 $ \mathbb{Z}_2 $ 上的多项式）$ f(x)=x^n-\sum\limits_{i=1}^{n}c_ix^{n-i} $

同时我们定义其互反多项式：$ \overline f(x) = x^n f(\frac{1}{x}) = 1-\sum\limits_{i=1}^{n} c_i x^i $，也称为LFSR的联结多项式。

- 该序列对应的生成函数为：$ A(x) = \frac{p(x)}{\overline f(x)} $，其中：$ p(x) = \sum\limits_{i=1}^{n} (c_{n-i} x^{n-i} \sum\limits_{j=1}^{i} a_j x^{j-1}) $
- 该序列对应的周期或阶为：使 $ A(x) | (x^T - 1) $ 的最小 T

n 次本原多项式：阶为 $ 2^n - 1 $ 的 n 次不可约多项式。

m 序列：达到最长周期的序列。

- 序列是 m 序列 $ \Leftrightarrow $ 序列的极小多项式是 n 次本原多项式。

#### 非线性反馈移位寄存器 NLFSR

- 非线性组合生成器，对多个 LFSR 的输出使用一个非线性组合函数
- 非线性滤波生成器，对一个 LFSR 的内容使用一个非线性组合函数
- 钟控生成器，使用一个（或多个）LFSR 的输出来控制另一个（或多个）LFSR 的时钟。

### 特殊流密码 RC4

## 块加密

块加密即每次加密一块明文，常见的加密算法有：IDEA、DES、AES 等，块加密也是对称加密。

Shannon 提出的两大设计分组密码的策略：混淆与扩散。

- 混淆 Confusion，将明文与密钥之间的统计关系变得尽可能复杂。常见的方法：S 盒、乘法。
- 扩散 Diffusion，使明文中的每一位影响密文中的许多位。常见的方法：线性变换、置换、（循环）移位。

轮函数（round function）：被块加密重复使用的可逆变换函数。目前主要有以下设计方法：

- Feistel Network，由 Horst Feistel 发明 &rarr; DES
- Substitution-Permutation Network (SPN) &rarr; AES

### ARX - Add-Rotate-Xor

### DES - Data Encryption Standard

下图为一个简单的 DES 流程图：

![DES](/day3/des.jpg)

每一轮的加密过程大致如下：

- $ L_{i+1} = R_i $

- $ R_{i+1} = L_i \oplus F(R_i, K_i) $

因此每一轮的解密过程亦可推出：

- $ L_i = R_{i+i} \oplus F(L_{i+1}, K_i) $

- $ R_i = L_{i+1} $

### IDEA - International Data Encryption Algorithm

### AES - Advanced Encryption Standard

### Simon & Speck

