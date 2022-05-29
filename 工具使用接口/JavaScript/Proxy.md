> 参考资料：
>
> - https://zhuanlan.zhihu.com/p/75407419
> - https://zhuanlan.zhihu.com/p/69106037

# Proxy

## 实例

直接看一个例子：

```javascript
let target = { x: 10, y: 20, };
let hanler = { get: (obj, prop) => 42 };
target = new Proxy(target, hanler);

target.x; //42
target.y; //42
```

