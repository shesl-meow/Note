# 优先级队列

## ADT 抽象数据类型

```pseudocode
ADT maxPriorityQueue
{
    DATA:
    	element ele_queue[];
    	
	METHOD:
		empty():	return true if ele_queue is empty.
		size():		return size of ele_queue.
		top(): 		return the element with max priority.
		pop():		delete the element with max priority.
		push(x):	push element "x".
}
```

## 堆

概念：大根堆，小根堆。

## 左高树

概念：

- 外部结点（external node）：加入在树中所有空子树的结点。

- 内部结点（internal node）：原本就存在的结点。
- 扩充二叉树（extended binary tree）：增加了外部节点的二叉树。



令 s(x) 是从结点 x 到其子树的外部节点的所有路径中最短的一条，则：

- 高度优先左高树（height-based leftist tree, HBLT）：其内部结点的左孩子的 s 值都大于或等于右孩子的 s 值。

- 最大 HBLT：同时为大根树和 HBLT 的二叉树。



令 w(x) 是以结点 x 为根的子树的内部结点数目：

- 重量优先左高树（weight-biased leftist tree, WBLT）：其内部结点的左孩子的 w 值都大于或等于右孩子的 w 值。
- 最大 WBLT：同时为大根树和 WBLT 的二叉树。

## C++

C++ 的 STL 库中由 `prioryty_queue` 这个类可以实现优先级队列。

