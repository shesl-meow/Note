# 字典

## ADT 抽象数据类型

```pseudocode
ADT dictionary
{
	DATA:
		data_pair key_value[];
		
    METHOD:
    	empty(): 	return true if key_value is empty.
    	size(): 	return size of key_value.
    	find(k): 	return pointer in key_value whose key is k.
    	insert(p): 	insert data_pair p into key_value.
    	erase(k): 	erase data_pair from key_value where its key is k.
}
```

## 线性表表示

两个类 `sortedArrayList` 和 `sortedChain` 分别存储键和值。

## 跳表表示

跳跃表（[skiplist](http://en.wikipedia.org/wiki/Skip_list)）是一种随机化的数据， 由 William Pugh 在论文[《Skip lists: a probabilistic alternative to balanced trees》](http://www.cl.cam.ac.uk/teaching/0506/Algorithms/skiplists.pdf)中提出， 跳跃表以有序的方式在层次化的链表中保存元素， 效率和平衡树媲美 —— 查找、删除、添加等操作都可以在对数期望时间下完成， 并且比起平衡树来说， 跳跃表的实现要简单直观得多。

## 散列表示

散列函数为 `f`，数对 p 的关键字如果是 k，那么它在散列表中的位置就是 `f(k)`。

性能分析：设 b 为散列表的桶数，n 为散列表中的记录个数，令 $$U_n$$ 和 $$S_n$$ 分别表示在一个成功搜索和不成功搜索中平均搜索的桶数，则：

- $${\displaystyle U_n = \frac{1}{2} (1 + \frac{1}{(1 - \alpha)^2})}$$
- $$\displaystyle S_n = \frac{1}{2} (1 + \frac{1}{(1 - \alpha)})$$

其中 $$\displaystyle \alpha = \frac{n}{b}$$ 称为负载因子 (loading factor)。

## LZW 压缩法

（懒得写了）

