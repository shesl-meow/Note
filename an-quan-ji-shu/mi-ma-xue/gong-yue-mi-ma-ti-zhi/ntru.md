# NTRU

> 参考：
>
> * [http://people.scs.carleton.ca/\~maheshwa/courses/4109/Seminar11/NTRU_presentation.pdf](http://people.scs.carleton.ca/\~maheshwa/courses/4109/Seminar11/NTRU_presentation.pdf)

## NTRU Cryptosystem

`NTRU`: Nth degree Truncated polynomial Ring Units. Or $$\displaystyle R = \frac{Z[X]}{X^{N-1}}$$

### 算法的流程

#### 系统参数

系统需要一下在各个使用这个系统的使用者之间共享三个信息：

* `N&R`：N 是一个整数、R 是一个环，在环 R 上的多项式次数均为 `N-1`；
* `p`：一个小整数。多项式对 p 系数取模得到一个模环；
* `q`：一个与 p 互素的大整数。多项式对 q 系数取模得到一个模环；

#### 密钥生成

使用这个系统的用户需要通过一下的方式生成公钥与私钥：

1. 从 R 中随机选取两个可逆多项式 f, g；
2. 计算 f 关于 p,q 的逆：$$f \cdot f_p \equiv 1 \pmod{p}, f \cdot f_q \equiv 1 \pmod{q}$$
3. 计算下面的多项式积：$$h = p \cdot f_q \cdot g \pmod{q}$$
4. 封装私钥 $$(f, f_p)$$，封装公钥 $$(h)$$

#### 加密流程

一个用户 A 得到了 B 的公钥，想向 B 发送一条信息，通过下面的方式：

1. 将明文 m 表示为模 p 环多项式的形式，多项式的系数选在区间 $$\displaystyle (-\frac{p}{2}, \frac{p}{2})$$ 之中；
2. 随机选取一个多项式 r；
3. 用以下的方式计算密文：$$e = r \cdot h + m \pmod{q}$$；

#### 解密流程

B 收到了来自 A 的加密信息将通过以下的方式解密：

1. B 私钥中有一个私有的多项式 f，通过以下方式计算多项式 a：$$a \equiv f \cdot e \pmod{q}$$，其中多项式的系数选在区间 $$\displaystyle (-\frac{q}{2}, \frac{q}{2})$$ 之中；
2. 在通过小素数 p 计算：$$b \equiv a \pmod{p}$$
3. 最后使用私钥中的多项式 $$f_p$$ 即可得到明文：$$c \equiv f_p \cdot b \pmod{p}$$
