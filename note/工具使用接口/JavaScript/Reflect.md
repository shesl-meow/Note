---
title: "Reflect.md"
date: 2021-04-26T11:02:26+08:00
tags: [""]
categories: ["工具使用接口", "JavaScript"]
---

> https://es6.ruanyifeng.com/#docs/reflect

# Reflect

## 概述

`Reflect`对象与`Proxy`对象一样，也是 ES6 为了操作对象而提供的新 API。`Reflect`对象的设计目的有这样几个：

- 将 `Object` 对象的一些明显属于语言内部的方法（比如 `Object.defineProperty`），放到 `Reflect` 对象上。现阶段，某些方法同时在 `Object` 和 `Reflect` 对象上部署，未来的新方法将只部署在 `Reflect` 对象上。也就是说，从 `Reflect` 对象上可以拿到语言内部的方法。
- 修改某些 `Object` 方法的返回结果，让其变得更合理。比如，`Object.defineProperty(obj, name, desc)` 在无法定义属性时，会抛出一个错误，而 `Reflect.defineProperty(obj, name, desc)` 则会返回 `false`。
- 让 `Object` 操作都变成函数行为。某些 `Object` 操作是命令式，比如 `name in obj` 和 `delete obj[name]`，而 `Reflect.has(obj, name)` 和 `Reflect.deleteProperty(obj, name)` 让它们变成了函数行为。
- `Reflect` 对象的方法与 `Proxy` 对象的方法一一对应，只要是 `Proxy` 对象的方法，就能在 `Reflect` 对象上找到对应的方法。这就让 `Proxy` 对象可以方便地调用对应的 `Reflect` 方法，完成默认行为，作为修改行为的基础。也就是说，不管 `Proxy` 怎么修改默认行为，你总可以在 `Reflect` 上获取默认行为。

## MetaData

API 详见：https://www.npmjs.com/package/reflect-metadata

用 Decorator 声明式调用：

```javascript
class C {
  @Reflect.metadata(metadataKey, metadataValue)
  method() {
  }
}
```

直接定义式调用：

```javascript
Reflect.defineMetadata(metadataKey, metadataValue, C.prototype, "method");
```

通过 Reflect 获取之前定义的值： 

```javascript
let obj = new C();
let metadataValue = Reflect.getMetadata(metadataKey, obj, "method");
```


