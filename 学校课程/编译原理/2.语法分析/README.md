> 学习地址：
>
> [国防科技大学MOOC]()

# 简述概念

上下文无关文法：

- 定义：一个上下文无关文法 G 是一个四元式 $$G= (V_T, V_N, S, P)$$，其中：
  - $$V_T$$：终结符号集合（非空）；
  - $$V_N$$：非终结符集合（非空），且 $$V_T \cap V_N = \varnothing$$
  - $$S$$：文法的开始符号，$$S \in V_N$$
  - $$P$$：产生式集合（有限），每个产生式形式为：
    - $$P \rightarrow \alpha, P \in V_N, \alpha \in (V_T \cup V_N)*$$

直接推出：

- 定义：称 $$\alpha A \beta$$ 直接推出 $$\alpha \gamma \beta$$，即：$$\alpha A \beta \Rightarrow \alpha \gamma \beta$$。仅当 $$A \rightarrow \gamma $$ 是一个产生式，且 $$\alpha, \beta \in (V_T \cup V_N)*$$

推导：

- 如果 $$\alpha_1 \Rightarrow \alpha_2 \Rightarrow ... \Rightarrow \alpha_n$$，则我们称这个序列是从 $$\alpha_1$$ 到 $$\alpha_n$$ 的一个推导。若存在一个从 $$\alpha_1$$ 到 $$\alpha_n$$ 的推导，则称 $$\alpha_1$$ 可以推导出 $$\alpha_n$$。

句型：

- 定义：假定 G 是一个文法，S 是它的开始符号。如果 $$S \Rightarrow \alpha$$，则 $$\alpha$$ 称时一个句型。
- 由文法的开始符号能够推导出的任意串，都是该文法的一个句型。

句子：仅含终结符号的句型。

语言：

- 文法所产生的句子的全体是一个语言，将它记作 $$L(G)$$。
  - $$L(G) = \{\alpha | S \Rightarrow \alpha, \alpha \in V_T^*\}$$



语法分析任务：分析一个文法的句子的结构

语法分析器的功能：按照文法的产生式（语言的语法规则），识别输入符号串是否为一个句子（合式程序）
