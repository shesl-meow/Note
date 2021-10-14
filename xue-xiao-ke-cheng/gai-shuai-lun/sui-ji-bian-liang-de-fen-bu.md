# 随机变量的分布

常见概率分布总结：

| 分布名称 | 记号                          | 分布律或概率密度函数                                                                                                                              | 数学期望                                | 方差                                    |
| ---- | --------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------- | ------------------------------------- |
| 两点分布 | $$X \sim (0-1)$$            | <p><span class="math">P(X = x) = p^{k}q^{1-k}</span><br><span class="math">x \in \{0,1\}, 0 \lt p \lt 1, q = 1-p</span></p>             | $$p$$                               | $$pq$$                                |
| 二项分布 | $$X \sim B(n, p)$$          | <p><span class="math">P(X = k) = C_n^kp^kq^{n-k}</span><br><span class="math">k \in \{0, 1, ..., n\}, 0 \lt p \lt 1, q = 1-p</span></p> | $$np$$                              | $$npq$$                               |
| 泊松分布 | $$X \sim P(\lambda)$$       | $${\displaystyle P(X = k) = \frac{\lambda^k}{k!}e^{-\lambda}, k \in \{1,2,...\}, \lambda > 0}$$                                         | $$\lambda$$                         | $$\lambda$$                           |
| 均匀分布 | $$X \sim U[a,b]$$           | $$\displaystyle f(x) = \begin{cases}\displaystyle \frac{1}{a-b} &, a \le x \le b \\ 0 &, others \end{cases}$$                           | $$\displaystyle \frac{a+b}{2}$$     | $$\displaystyle \frac{(b-a)^2}{12}$$  |
| 指数分布 | $$X \sim E(\lambda)$$       | $$\displaystyle f(x) = \begin{cases} \lambda e^{-\lambda x} &, x > 0 \\ 0 &, x \le 0 \end{cases}$$                                      | $$\displaystyle \frac{1}{\lambda}$$ | $$\displaystyle \frac{1}{\lambda^2}$$ |
| 正态分布 | $$X \sim N(\mu, \sigma^2)$$ | $$\displaystyle f(x) = \frac{1}{\sqrt{2 \pi} \sigma} e^{-\frac{(x - \mu)^2}{2 \sigma^2}}, \sigma > 0$$                                  | $$\mu$$                             | $$\sigma^2$$                          |
