# SageMath 快速使用手册

基于 python2 的数学教学工具 sage-math。

Quick Manual:

1. 比特流转换为整数：

   ```python
   ZZ([1,1,0,1],base=2)
   ```

   这种方式与 `int('1101',2)` 转换的结果相反，它等价于 `int('1011', 2)`

2. 整数转化为比特流：

   ```python
   Integer(15).binary()
   ```

3. 在 sage 中，通过多项式建立一个有限域：

   ```python
   sage: FF = GF(2**8, name='x', modulus=x^8 + x^4 + x^3 + x + 1)
   ```

   在这个有限域中，整数与多项式相互转化：

   ```python
   # 整数转化为多项式
   sage: FF.fetch_int(5)
   x^2 + 1
   
   # 多项式转化为整数
   sage: FF(x^2 + 1).integer_representation()
   5
   ```
