# 假设检验

## 概念

### 原假设和备选假设

原假设（null hypothesis）：$$H_0$$

1. 原来就有的假设
2. 经过长期证明是对的

对立假设 /备择假设（alternative hypothesis）：$$H_1$$

参数的假设一般具有如下三种形式：

| 原假设 $$H_0$$             | 备选假设 $$H_1$$            | 记作           | 分类   |
| ----------------------- | ----------------------- | ------------ | ---- |
| $$\theta = \theta_0$$   | $$\theta \ne \theta_0$$ | $$H_0(I)$$   | 双侧检验 |
| $$\theta \ge \theta_0$$ | $$\theta \lt \theta_0$$ | $$H_0(II)$$  | 单侧检验 |
| $$\theta \le \theta_0$$ | $$\theta \gt \theta_0$$ | $$H_0(III)$$ | 单侧检验 |

**假设检验**：就是通过样本来回答原假设是正确还是错误。

### 检验统计量

检验统计量的取值范围和变化情况，能包含和反映 $$H_0$$ 与$$H_1$$ 所描述的内容，并且当 $$H_0$$ 成立时，能够确定检验统计量的概率分布。

检验统计量的基本形式例如：$${\displaystyle z = \frac{\overline{x} - \mu_0}{ \sigma/\sqrt{n} }}$$

### 显著性水平

* 原假设 $$H_0$$ 正确，而被我们拒绝，犯这种错误的概率用 $$\alpha$$ 表示。把 $$\alpha$$ 称为假设检验中的显著性水平（Significant level），即决策中的风险。
* 显著性水平就是指当原假设正确时却把它拒绝的概率或风险。
* 通常取 $$\alpha＝0.05$$ 或 $$\alpha =0.01$$ 或 $$\alpha=0.001$$，那么，接受原假设时正确的可能性（概率）为：95%，99%，99.9%。

## 步骤

1. 提出原假设和备择假设
2. 确定适当的检验统计量
3. 规定显著性水平
4. 计算检验统量的值
5. 作出统计决策

## 正态分布总体均值的假设检验

### 1. 单个正态分布总体的均值检验

#### 1.1 方差已知 $$\rightarrow$$ Z 检验法

> 总体 $$X \sim N(\mu , \sigma^2)$$，$$\sigma$$ 已知，假设 $$H_0: \mu = \mu_0; H_1: \mu \ne \mu_0$$

构造 U 统计量 $${\displaystyle Z = \frac{\overline{X} - \mu_0}{\sigma/\sqrt{n}} \sim N(0,1)}$$

由 $${\displaystyle P\Big(\mid \frac{\overline{X} - \mu_0}{\sigma/\sqrt{n}} \mid \ge u_{\alpha/2}\Big) = \alpha}$$，确定拒绝域 $$|Z| \ge u_{\alpha/2}$$

如果统计观察值 $$|Z| \ge u_{\alpha/2}$$，则拒绝原假设；否则接收原假设。

#### 1.2 方差未知 $$\rightarrow$$ T 检验法

> 总体 $$X \sim N(\mu , \sigma^2)$$，$$\sigma$$ 未知，假设 $$H_0: \mu = \mu_0; H_1: \mu \ne \mu_0$$

构造 T 统计量 $${\displaystyle T = \frac{\overline{X} - \mu_0}{S/\sqrt{n}} \sim t(n-1)}$$

由 $${\displaystyle P\Big(\mid \frac{\overline{X} - \mu_0}{S/\sqrt{n}} \mid \ge t_{\alpha/2}(n-1)\Big) = \alpha}$$，确定拒绝域 $$|T| \ge t_{\alpha/2}(n-1)$$

如果统计观察值 $$|T| \ge t_{\alpha/2}$$，则拒绝原假设；否则接收原假设。

### 2. 两个正态分布总体的均值检验

#### 2.1 方差已知，检验均值相等 $$\rightarrow$$ Z 双侧检验法

> 已知 $$X \sim N(\mu_X , \sigma_X^2), Y \sim N(\mu_Y , \sigma_Y^2)$$，已知 $$\sigma_X^2, \sigma_Y^2$$，检验 $$H_0: \mu_X = \mu_Y$$

设 $$X_1, X_2, ..., X_{n_1}$$ 是 X 的一个样本，$$Y_1, Y_2, ..., Y_{n_2}$$ 是 Y 的一个样本，

则当 $$H_0$$ 成立时有：$$\displaystyle Z = \frac{\overline{X} - \overline{Y}}{\sqrt{\sigma_X^2/n_1 + \sigma_Y^2/n_2}} \sim N(0,1)$$，

故对给定的检验水平 $$\alpha$$，得 $$H_0$$ 的拒绝域为：$$\displaystyle \Bigg| \frac{\overline{X} - \overline{Y}}{\sqrt{\sigma_X^2/n_1 + \sigma_Y^2/n_2}} \Bigg| > z_{\alpha/2}$$

#### 2.2 方差未知，但两个总体方差相等，检验均值相等

> 已知 $$X \sim N(\mu_X , \sigma_X^2), Y \sim N(\mu_Y , \sigma_Y^2)$$，$$\sigma_X^2, \sigma_Y^2$$未知，已知 $$\sigma_X^2 = \sigma_Y^2$$，检验 $$H_0: \mu_X = \mu_Y$$

设 $$X_1, X_2, ..., X_{n_1}$$ 是 X 的一个样本，$$Y_1, Y_2, ..., Y_{n_2}$$ 是 Y 的一个样本，

则当 $$H_0$$ 成立时有：$$\displaystyle T = \frac{\overline{X} - \overline{Y} - (\mu_X - \mu_Y)}{\sqrt{\displaystyle \frac{S_X^2(n_1-1) + S_Y^2(n_2 - 1)}{n_1 + n_2 - 2}} \sqrt{\displaystyle \frac{1}{n_1} + \frac{1}{n_2}}} \sim t(n_1 + n_2 -2)$$，

故对给定的检验水平 $$\alpha$$，得 $$H_0$$ 的拒绝域为：$$\displaystyle \Bigg| \frac{\overline{X} - \overline{Y} - (\mu_X - \mu_Y)}{\sqrt{\displaystyle \frac{S_X^2(n_1-1) + S_Y^2(n_2 - 1)}{n_1 + n_2 - 2}} \sqrt{\displaystyle \frac{1}{n_1} + \frac{1}{n_2}}} \Bigg| > t_{\alpha/2}(n_1 + n_2 -2)$$

## 正态分布总体方差的假设检验

### 1. 单个正态分布的方差检验

#### 1.1 均值已知

> 总体 $$X \sim N(\mu , \sigma^2)$$，$$\mu$$ 已知，假设 $$H_0: \sigma^2 = \sigma^2_0; H_1: \sigma^2 \ne \sigma^2_0$$

构造统计量 $$\displaystyle \chi^2 = \frac{\displaystyle \sum_{i=1}^n(X_i - \mu)^2}{\sigma^2_0} \sim \chi^2(n)$$

#### 1.2 均值未知，双边检验

> 总体 $$X \sim N(\mu , \sigma^2)$$，$$\mu$$ 未知，假设 $$H_0: \sigma^2 = \sigma^2_0; H_1: \sigma^2 \ne \sigma^2_0$$

构造统计量 $$\displaystyle \chi^2 = \frac{(n-1)S^2}{\sigma^2_0} \sim \chi^2(n-1)$$

由 $$\displaystyle P(\chi^2 \le \chi^2_{1 - \frac{\alpha}{2}}(n-1)) = \frac{\alpha}{2}, \displaystyle P(\chi^2 \le \chi^2_{\frac{\alpha}{2}}(n-1)) = \frac{\alpha}{2}$$ 确定拒绝域 $$[0, \chi^2_{1 - \frac{\alpha}{2}}(n-1)] \cap [\chi^2_{\frac{\alpha}{2}}(n-1), +\infty]$$

进行统计决策。

#### 1.3 均值未知，单边检验

> 总体 $$X \sim N(\mu , \sigma^2)$$，$$\mu$$ 未知，假设 $$H_0: \sigma^2 \le \sigma^2_0; H_1: \sigma^2 \gt \sigma^2_0$$

构造统计量 $$\displaystyle \chi^2 = \frac{(n-1)S^2}{\sigma^2_0} \sim \chi^2(n-1)$$

通过 $$P(\chi^2 \ge \chi^2_{\alpha}) = \alpha$$ 确定拒绝域 $$[\chi^2_{\alpha}, +\infty)$$

### 2. 两个正态分布的方差检验

#### 2.1 均值未知，双边检验

> 已知 $$X \sim N(\mu_X , \sigma_X^2), Y \sim N(\mu_Y , \sigma_Y^2)$$，$$\mu_X, \mu_Y$$未知，检验 $$H_0: \sigma^2_X = \sigma^2_Y$$

若当 $$H_0$$ 成立时，则有 $$\displaystyle F = \frac{S_X^2}{S_Y^2} \sim F(n_1 - 1, n_2 - 1)$$

对于给定的检验水平 $$\alpha$$，存在临界值 $$C_1$$ 和 $$C_2$$，使得：$$P(F \le C_2 \cup F \ge C_1) = \alpha$$，为了方便计算取：$$\displaystyle P(F \ge C_1) = P(F \le C_2) = \frac{\alpha}{2}$$，

于是可以确定拒绝域 $$\displaystyle F < F_{1 - \frac{\alpha}{2}}(n_1 - 1, n_2 - 1) \or F > F_{\frac{\alpha}{2}}(n_1 - 1, n_2 - 1)$$

#### 2.2 均值未知，方差单边检测

> 已知 $$X \sim N(\mu_X , \sigma_X^2), Y \sim N(\mu_Y , \sigma_Y^2)$$，$$\mu_X, \mu_Y$$未知，检验 $$H_0: \sigma^2_X \le \sigma^2_Y$$

若当 $$H_0$$ 成立时，则有 $$\displaystyle F = \frac{S_X^2}{S_Y^2} \sim F(n_1 - 1, n_2 - 1)$$

拒绝域 $$F > F_{\alpha}(n_1 -1, n_2 - 1)$$

## 总结

|        | 参数 | 均值检测                                                                                                                                                                                                                                                                                                                                                      | 方差检验                                                                                                      |
| ------ | -- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| 单个正态分布 | 已知 | Z-检验：$$\displaystyle \frac{\overline{X} - \mu_0}{\sigma/\sqrt{n}} \sim N(0,1)$$                                                                                                                                                                                                                                                                           | $$\chi^2$$-检验：$$\displaystyle \frac{\displaystyle \sum_{i=1}^n(X_i - \mu)^2}{\sigma^2_0} \sim \chi^2(n)$$ |
|        | 未知 | T-检验：$${\displaystyle \frac{\overline{X} - \mu_0}{S/\sqrt{n}} \sim t(n-1)}$$                                                                                                                                                                                                                                                                              | $$\chi^2$$-检验：$$\displaystyle \frac{(n-1)S^2}{\sigma^2_0} \sim \chi^2(n-1)$$                              |
| 两个正态分布 | 已知 | Z-检验：$$\displaystyle \frac{\overline{X} - \overline{Y}}{\sqrt{\sigma_X^2/n_1 + \sigma_Y^2/n_2}} \sim N(0,1)$$                                                                                                                                                                                                                                             | 经过变换可以等价于未知且相等                                                                                            |
|        | 未知 | <p>T-检验：<span class="math">\displaystyle \frac{U_w}{S_w} \sim t(n_1 + n_2 -2)</span><br><span class="math">\displaystyle U_w = \frac{\overline{X} - \overline{Y} - (\mu_X - \mu_Y)}{\sqrt{\displaystyle \frac{1}{n_1} + \frac{1}{n_2}}}</span><br><span class="math">\displaystyle S_w^2 = \frac{S_X^2(n_1-1) + S_Y^2(n_2 - 1)}{n_1 + n_2 - 2}</span></p> | F-检验：$$\displaystyle \frac{S_X^2}{S_Y^2} \sim F(n_1 - 1, n_2 - 1)$$                                       |
