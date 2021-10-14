# B-Tree

> 学习链接：
>
> * [https://www.geeksforgeeks.org/b-tree-set-1-introduction-2/](https://www.geeksforgeeks.org/b-tree-set-1-introduction-2/)
> * [https://www.geeksforgeeks.org/b-tree-set-1-insert-2/](https://www.geeksforgeeks.org/b-tree-set-1-insert-2/)

## B-Tree

### Introduction

Defination:

> B-Tree is a self-balancing search tree. In most of the other self-balancing search trees (like [AVL](https://www.geeksforgeeks.org/avl-tree-set-1-insertion/) and Red-Black Trees), it is assumed that everything is in main memory.

Usage:

> Disk access time is very high compared to main memory access time. The main idea of using B-Trees is to reduce the number of disk accesses.

Analysis:

> Most of the tree operations (search, insert, delete, max, min, ..etc ) require O(h) disk accesses where h is the height of the tree.
>
> Generally, a B-Tree node size is kept equal to the disk block size.

Properties:

1. All leaves are at same level.
2. A B-Tree is defined by the term _minimum degree_ ‘t’. The value of t depends upon disk block size.
3. Every node except root must contain at least `t-1` keys. Root may contain minimum 1 key.
4. All nodes (including root) may contain at most `2t – 1` keys.
5. Number of children of a node is equal to the number of keys in it plus 1.
6. All keys of a node are sorted in increasing order. The child between two keys k1 and k2 contains all keys in the range from k1 and k2.
7. B-Tree grows and shrinks from the root which is unlike Binary Search Tree. Binary Search Trees grow downward and also shrink from downward.
8. Like other balanced Binary Search Trees, time complexity to search, insert and delete is O(Logn).

### Method

#### Traverse

```cpp
template<class T>
list<T> BTree<T>::traverse()const{
    // terminated condition: this is a leaf node
    if(this->is_leaf_node()) return this->data;

    auto i = this->data.begin();
    auto j = this->children.begin();
    // traverse the first child tree
    list<T> res = (*j)->traverse();
    // begin with the first data node =>
    // traverse the node and its next node tree in order
    for(++j; i != this->data.end(); ++j, ++i){
        res.push_back(*i);
        auto tr = (*j)->traverse();
        res.insert(res.end(), tr.begin(), tr.end());
    }   
    return res;
}
```

#### Search

```cpp
template<class T>
BTree<T>* BTree<T>::search(const T& val)const{
    auto i = this->data.begin();
    auto j = this->children.begin();
    for(;i != this->data.end(); ++i)
        if(*i < val) ++j; else break;

    if(*i == val) return this;
    if(this->is_leaf_node()) return NULL;

    return (*j)->search(val);
}
```

#### Insert

Unlike BSTs, we have a predefined range on number of keys that a node can contain. So before inserting a key to node, we make sure that the node has extra space.

So Here is a question: _How to make sure that a node has space available for key before the key is inserted?_

* We use an operation called `splitChild()` that is used to split a child of a node.

As discussed above, to insert a new key:

1. Initialize x as root.
2. While x is not leaf, do following
   1. Find the child of x that is going to to be traversed next. Let the child be y.
   2. If y is not full, change x to point to y.
   3. If y is full, split it and change x to point to one of the two parts of y. If k is smaller than mid key in y, then set x as first part of y. Else second part of y. When we split y, we move a key from y to its parent x.
3. The loop in step 2 stops when x is leaf. x must have space for 1 extra key as we have been splitting all nodes in advance. So simply insert k to x.
