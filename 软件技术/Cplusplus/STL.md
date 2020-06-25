> 参考：
>
> - https://stackoverflow.com/questions/6292332/what-really-is-a-deque-in-stl

# STL

## Deque

`Deque` 的全称是 double ended queue，两端结束队列；

它是 `stack` 与 `queque` 的底层存储结构，它的实现基于 `vector` 的实现，它结构大致如下：

![DequeStructure](./DequeStructure.png)

可以看到这样存储的优点是：

1. 仍然可以通过接近与 O(1) 常数级别的时间复杂度进行访问；
2. 在两端的插入删除复杂度仍然为 O(1)；

对于 `stack` 与 `queue` 这样的仅仅在双端有插入删除访问操作的数据结构，是一个合适的基类；