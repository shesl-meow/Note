# Boyer–Moore majority vote algorithm

多数投票算法：[Boyer-Moore](https://zh.wikipedia.org/zh-hans/%E5%A4%9A%E6%95%B0%E6%8A%95%E7%A5%A8%E7%AE%97%E6%B3%95#:~:text=%E5%8D%9A%E8%80%B6%2D%E6%91%A9%E5%B0%94%E5%A4%9A%E6%95%B0%E6%8A%95%E7%A5%A8,%E7%9A%84%E4%B8%80%E7%A7%8D%E5%85%B8%E5%9E%8B%E7%AE%97%E6%B3%95%E3%80%82) 是为了解决这样一个问题的算法：

- 用来寻找一组数据中占多数的元素的算法，时间复杂度 O(n)，空间复杂度 O(1)；

Golang 代码实现：

```go
func majorityElement(nums []int) int {
    iter, most := 0, 0
    for _,num := range nums {
        if iter == 0 { most, iter = num, iter+1 } 
      	else if most == num { iter += 1 } 
      	else { iter -= 1 }
    }
    count, sz := 0, len(nums)
    for _,num := range nums {
        if num == most { count += 1 }
        if count * 2 > sz { return most }
    }
    return -1
}
```

