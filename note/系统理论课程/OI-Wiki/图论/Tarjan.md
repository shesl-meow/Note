# 图论

## Tarjan

### 实现

[Tarjan's algorithm](https://en.wikipedia.org/wiki/Tarjan%27s_strongly_connected_components_algorithm) 是一个用于求解无向图割点与桥的算法。直接上代码：

```c
void tarjan(int u, int v)
{
  /* compute dfn and low while performing a dfs search
	- beginning at vertex u, v is the parent of u (if any) */
	nodePointer ptr;
	int w;
	dfn[u] = low[u] = num++;
	for (ptr = graph[u]; ptr; ptr = ptr->link) {
		w = ptr->vertex;
    if (dfn[w] < 0) { /* w is an unvisited vertex */
			tarjan(w,u);
			low[u] = min(low[u],low[w]);
    } else if (w != v) {
			low[u] = min(low[u],dfn[w])
  	}
  }
}
```

### 概念

下面先看一些概念：

割点：

- 若从图中删除节点 x 以及所有与 x 关联的边之后，图将被分成两个或两个以上的不相连的子图，那么称 x 为图的**割点**。

桥：

- 若从图中删除边 e 之后，图将分裂成两个不相连的子图，那么称 e 为图的**桥**或**割边**。

搜索树：

- 在无向图中，我们以某一个节点 x 出发进行深度优先搜索，所有被访问过的节点与边构成一棵树，我们可以称之为“无向连通图的搜索树”。

强连通图（Strongly Connected Graph）：

- 如果一个有向图中，对于任意两点x、y，均存在 x 到 y 和 y 到 x 的路径，则称这个图为强连通图。

强连通分量：

- 对于一个普通的有向图，它的最大强连通子图为其强联通分量。

追溯值：

- 追溯值是一个为了求解强连通图而提出的概念，图中的每个节点都被赋予了一个“追溯值”（代码中用 `low[]` 表示），相同“追溯值”节点构成的子图就是强连通图；
- 公式化表示：$low (u) = \min\{ dfn(u), min \{low (w)| \text{where w is a child of u}\}, min \{ dfn(w)| \text{(u, w) is a back edge} \} \}$
- 每个节点的追溯值通过以下思想求解：
  1. 构建原图的搜索树，记录每个点被访问的次序，用 `dfn[]` 表示（`depth first number`：深度序）；
  2. 遍历图中的所有节点 x，从 x 出发可以到达的所有节点中，`dfn[]` 最小的即为 x 的追溯值，用 `low[]` 表示；

双联通（Bi-Connection Component）：

- 边双联通性：对于联通无向图中的两个点 u/v，删除图中任意**一条边**，u/v 间都存在路径，那么称它们是**边双联通**的；
- 点双联通性：对于联通无向图中的两个点 u/v，删除图中任意**一个点**，u/v 间都存在路径，那么称它们是**点双联通**的；
- 边双联通图（e-bcc）：去掉任何一条边都不会改变图的联通性 $\Leftrightarrow$ 图中不存在“桥” $\Leftrightarrow$ 图中任意两个点都是边双联通的；
- 点双联通图（v-bcc）：去掉任何一个点都不会改变图的联通性 $\Leftrightarrow$ 图中不存在“割点” $\Leftrightarrow$ 图中任意两个点都是点双联通的；

### Tarjan 中割点和桥的判断条件

桥：

- 对于一个搜索树树干（可以证明非搜索树边一定不是桥）`parent -> child`，如果满足 `low[child] > dfs[parent]`，则该边是一个桥；
- 即子节点无法通过非搜索树的方式回到搜索树中位置更高的节点；

割点：

- 对于根节点，子树数量大于 1，则该节点是一个割点；
- 对于一个非根节点 `parent`，如果存在任意一条边达到的节点 `child`，如果满足 `low[child] >= dfn[parent]`，则该点 `parent` 是一个割点；
- 即存在一个子节点 `child` 要到达根节点，必须通过 `parent`。

### Tarjan 的结果不是并查集

一个看似合理的结论是：

- Tarjan 的 `low` 数组存储的是，一个节点能够通过非 `dfs` 路径找到的最高搜索树父节点。在并查集的概念中，它用最高搜索树父节点的遍历序 `dfn` 来作为“代表元”表示所有节点。
- 在这个理解下：
  - 桥的计算方式即判断：每条关联的两个节点的代表元（`low`）是否相等；
  - 所有代表元（`low`）相等的点构成的集合即为一个双联通分量。

这个结论在 `low` 的理念前提下是正确的，但是在 `dfs` 实现的代码中是错误的。看下面的例子：

![tarjan_isnot_ufds](../tarjan_isnot_ufds.svg)

左边的图按照给定的边序会生成右边的图，在遍历到 `F`/`E` 时虽然能够回到一个父节点，但是这并不是它们通过非回溯路径能够到达最高的节点，所以 `low` 数组的最终结果会是：

```
[0, 0, 0, 0, 1, 1]
```

