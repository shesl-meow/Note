---
title: "Hooks.md"
date: 2021-08-08T17:15:28+08:00
tags: [""]
categories: ["工具使用接口", "Reactjs"]
---

> 参考文档：
>
> - https://zh-hans.reactjs.org/docs/hooks-intro
> - https://www.yuque.com/qianduanyongbuweinu/efahmp/vasyzy#8OGwa

# Hooks

## 例子

与 `Hooks` 相关的 API 都是 `use` 开头的，它返回一个元组。以 `useState` 为例，它返回第一个元素即这个状态，第二个元素是设置这个状态的函数。

先看一个 `useState` 使用的例子：

```react
export const MyComponent: React.FC = () => {
  const [st, setSt] = useState<bool>(false);
  return (
    <div>
      <button onClick={setSt} />
      <span>{st}</span>
    </div>
  )
}

```

另一个常见的 Hooks 函数即 `useEffect`，类似于 OOP 中的 `componentDidMount` 与 `componentDidUpdate`：

```react
export const MyComponent: React.FC = () => {
  const [count, setCount] = useState(0);
  useEffect(() => {
    document.title = `You clicked ${count} times`;
  });
  return (<div></div>)
}
```

## 简介

作为一种改变组件状态、处理组件副作用的方式，[Hooks](https://reactjs.org/docs/hooks-intro.html) 这个概念最早由React提出，而后被推广到其他框架，诸如 [Vue](https://css-tricks.com/what-hooks-mean-for-vue/)、Svelte，甚至出现了[原生JS](https://github.com/getify/TNG-Hooks)库。但是，要熟练使用 Hook s需要对 JS 闭包有比较好的理解。

什么是 js 闭包？

- 当代码已经执行到一个函数词法作用域之外，但是这个函数仍然可以记住并访问他的词法作用域，那么他就形成了闭包。

## 使用规则

在 React 官方文档中，对 Hooks 的使用做出了以下两条规则的限制：

1. **只在控制流的最顶层使用 Hooks**，也就是说不要在循环、条件、嵌套函数中使用 Hooks；
2. **只在 `React.FC` 中使用 Hooks**，不要在普通的 js 函数中使用 Hooks；

这是因为 React Hooks 的底层实现机制导致的，可以回答下面问题就能理解这两条限制。

一个函数组件中会使用多个 `state`，那么 React 怎么知道哪个 `state` 对应哪个 `useState`？

- `effect` 与 `state` 在 React Hook 的底层是用两个数组实现的，React 是通过调用顺序确定它们的映射关系的。

## 自定义 Hooks

React Hooks 是一个非常强大的工具、非常通用的设计模式。

React 同样提供了[自定义 Hooks 的方式](https://reactjs.org/docs/hooks-custom.html)，自定义 Hooks 都以 `use` 开头，有非常繁荣的[第三方生态](https://github.com/streamich/react-use)。


