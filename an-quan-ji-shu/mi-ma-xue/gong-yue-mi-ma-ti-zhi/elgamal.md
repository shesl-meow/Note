# ElGamal

> 参考：
>
> * [https://resources.saylor.org/wwwresources/archived/site/wp-content/uploads/2011/03/ElGamal-signature-scheme.pdf](https://resources.saylor.org/wwwresources/archived/site/wp-content/uploads/2011/03/ElGamal-signature-scheme.pdf)

## ElGamal signature scheme

### 算法的流程

#### 系统参数

系统需要一下在各个使用这个系统的使用者之间共享三个信息：

1. H 是一个抗碰撞的哈希函数；
2. p 是一个大素数，解决 p 的离散对数问题是困难的。
3. g 是在乘法群 $$\Z^*_p$$ 中随机选取的生成元。

#### 密钥生成

签名者需要通过这个系统对一个消息进行签名，需要生成以下的信息：

1. 随机选取的整数 x 满足 $$1 < x < p-1$$
2. 计算以下信息：$$y \equiv g^x \pmod{p}$$
3. 封装公钥：$$(y)$$；封装私钥 $$(x)$$

#### 签名过程

签名者通过以下的方式对消息进行签名：

1. 随机选取一个整数 k 满足 $$0 < k < p-1 \and gcd(k, p-1) = 1$$
2. 计算 $$r = g^k \pmod{p}$$
3. 计算 $$s = (H(m) - xr)k^{-1} \pmod{p-1}$$（即 s 满足 $$H(m) = xr + ks \pmod{p-1}$$）
4. 如果计算得到 s=0，则重新选取随机数 k。
5. 封装 $$(r, s)$$ 即是拥有私钥 x 的签名者对信息 m 的签名。

#### 验证签名

验证一个签名的流程如下：

1. 首先需要不等式恒成立 $$0 < r < p \and 0 < s < p - 1$$
2. 如果等式 $$g^{H(m)} \equiv y^r r^s \pmod{p}$$ 成立，则接受这个签名。

### 安全性的说明

#### 正确性

验证签名的办法是正确的。

通过签名的生成方式我们知道以下的结论：$$H(m) = xr + ks \pmod{p-1}$$

通过费马小定理我们可以得到：

* $$g^{H(m)} \equiv g^{xr}g^{ks} \equiv y^r r^s \pmod{p}$$

#### 不可否认性
