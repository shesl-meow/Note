---
bookCollapseSection: true
title: "公钥密码体制"
---

# 公钥密码体制总结

| 密码体制                             | 安全性基于的难题         |
| ------------------------------------ | ------------------------ |
| 背包密码体制                         | 背包难题                 |
| RSA                                  | 大整数分解问题           |
| Rabin密码体制（RSA 的一种）          | 大整数分解问题           |
| Williams 密码体制（对 Rabin 的改进） | 大整数分解问题           |
| Diffe-Hellman 密钥交换协议           | 离散对数问题             |
| ElGamal 密码                         | 有限域上离散对数问题     |
| ECC                                  | 椭圆曲线上的离散对数问题 |
| Regev 加密                           | 格困难问题               |
| NTRU                                 | 格中最短向量问题         |
| McEliece 密码                        | 纠错编码理论             |
| Shamir-(t,n) 门限方案                | Lagrange内插多项式       |
| Feistel加密                          | 代换和置换               |
| Asmuth&Bloom-(t,n) 门限              | 中国剩余定理             |
| MI 方案                              | 多变量问题               |