# baby rsa

这题涉及了大量的 `RSA` 相关的破解知识。

## 题目

阅读题目之后实际上就是解数个方程，在没有 `hint` 的情况下，方程如下：

- $$\begin{cases} p^4 \equiv C_{1} \pmod{N_{1}} \\ p^4 \equiv C_{2} \pmod{N_{2}} \\ p^4 \equiv C_{3} \pmod{N_{3}} \\ p^4 \equiv C_{4} \pmod{N_{4}}\end{cases}$$
- $$\begin{cases} (e_1)^{42} &\equiv C_{e1} \pmod{N_e} \\ (e_2 + T)^3 &\equiv C_{e2} \pmod{N_e}\end{cases}$$
- $$q_2 * (q_2 + k) = N_q$$

- $$\begin{cases} flag^{e_1} \equiv C_{f1} \pmod{p * q_1} \\ flag^{e_2} \equiv C_{f2} \pmod{p * q_2}\end{cases}$$

上面所有方程的大写字母均为已知数字。

## 破解

