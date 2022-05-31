---
title: "Commonjs vs ES Modules"
date: 2021-06-15T10:21:42+08:00
tags: [""]
categories: ["工具使用接口", "Nodejs"]
---

> 参考：
>
> - https://www.zhihu.com/question/62791509
> - https://redfin.engineering/node-modules-at-war-why-commonjs-and-es-modules-cant-get-along-9617135eeca1


## What’s CJS? What’s ESM?

在 Node 模块的早期，所有的 Node Module 都是用 `Common.js` 编写的。我们可以从 `named export` 与 `default export` 两种方式简单地了解它的使用规则：

1. `named export`：

```javascript
// @filename: util.cjs
module.exports.sum = (x, y) => x + y;

// @filename: main.cjs
const {sum} = require('./util.cjs');
```

2. `default export`：

```javascript
// @filename: util.cjs
module.exports = (x, y) => x + y;

// @filename: main.cjs
const whateverWeWant = require('./util.cjs');
console.log(whateverWeWant(2, 4));
```

在 `ES Module` 中，`import` 和 `export` 关键字则是语言的一部分：

1. `named export`：

```javascript
// @filename: util.mjs
export const sum = (x, y) => x + y;

// @filename: main.mjs
import {sum} from './util.mjs'
console.log(sum(2, 4));
```

2. `default export`：

```javascript
// @filename: util.mjs
export default (x, y) => x + y;

// @filename: main.mjs
import whateverWeWant from './util.mjs'
console.log(whateverWeWant(2, 4));
```

## Loader Machanism

`common.js` 的加载机制相当简单：

- `common.js` 中的关键词 `require` 是同步的，它并不会返回一个 `Promise` 对象或使用 `callback` 作为参数。它简单地从磁盘或网络中获取对应的 `js` 脚本，然后直接运行这个脚本，返回设置在 `module.exports` 上的变量；

`ES Module` 的加载机制则可以分为三个步骤：

1. 加载器简单地分析 `import` 和 `export` 语句分析每个文件的引用和导出关系；
2. 所有的无依赖关系的姊妹文件同步地从磁盘或网络加载；
3. 通过第一步中分析得到的关系，构建出一个依赖关系图，并且自底向上地执行，直到这个找到这个图中的一个节点并没有对其他任何模块有引用关系；

## Inter-Invocation

`common.js` 通常是模块（比如浏览器的 `<script>` 标签）的默认策略：因为 `ES Module` 相对于 `common.js` 改变了许多策略。

将模块从 `ES Module` 迁移到 `common.js` 将会对兼容性造成很大损害（[Deno](https://deno.land/) 就是一个完全使用 `ES Module` 的 `JavaScript` 运行时，与之相应的，它的生态也需要从头开始建立）。

### CJS can't `requre` ESM

因为 ESM 支持顶级 `await` 语句（即在任何一个 `async` 函数之外使用 `await` 语句，这是因为之前提及的 `ES Module` 使用多阶段加载机制），但是 CJS 不支持。

Rich Harris 在[这篇文章](https://gist.github.com/Rich-Harris/0b6f317657f5167663b493c722647221)中提出了一系列的原因以表达不支持 JavaScript 语言不应该支持顶级 `await` 语句：

- 顶级 `await` 会阻碍代码的执行；会阻碍资源的获取；`commonjs` 没有与之对应的操作。

`ES Module` 的第三次提案阐明了这些问题：

- 姊妹模块可以同时执行，并没有阻碍无须等待的代码；资源的获取在第二步，也就是 `await` 操作执行之前；`await` 语句仅仅限于被 `ES Module` 使用，没有必要考虑 `commonjs` 对应的操作；

在 `nodejs/module` 的 `issue` 中现在还活跃着有关是否应该在 `ES Module` 中支持 `require` 的[讨论](https://github.com/nodejs/modules/issues/454)，你会发现顶级 `await` 并不唯一的问题。

### CJS can `import` ESM

`commonjs` 可以通过以下不完美的方式从 `ES Module` 导入对应的函数：

```javascript
module.exports.foo = (async () => {
    const {foo} = await import('./foo.mjs');
    return foo;
})();
```

### ESM can't `import` named CJS

ESM 可以通过以下的方式导入 CJS 中的默认导出（但是无法导入命名导入）：

```javascript
import _ from './lodash.cjs';
```

这是因为之前提到的 CJS 只有在脚本执行后才可以明确它导出的内容，而 ESM 需要在分析阶段。但是我们可以用以下的方式导入：

```javascript
import _ from './lodash.cjs';
const {shuffle} = _;
```

解决这个问题有很多思路，但是都有很强的副作用：

- 忽略顺序，将所有的 CJS 模块在 ESM 前执行，这样我们就能在 ESM 的分析阶段得到 CJS 的导出结果。但是这产生了[新问题](https://github.com/nodejs/modules/issues/81#issuecomment-391348241)，如果模块有明显的先后关系，则这种解决方式将导致令人作呕的 bug（nauseatingly problematic）；

- 我们可以保持顺序，还有另一种解决方案的提案，叫做 "[动态模块](https://github.com/nodejs/dynamic-modules)"。这种解决方案使得 ESM 可以使用如 `export * from './foo.cjs'` 这样的语法进行导出。但是这个提案因为种种原因[被拒绝了](https://github.com/tc39/ecma262/pull/1306#issuecomment-467761625)。

### ESM can `require` CJS

ESM 可以通过以下的方式非常轻松地从 CJS 中 `require`：

```javascript
import { createRequire } from 'module';
const require = createRequire(import.meta.url);

const {foo} = require('./foo.cjs'); 
```

虽然这么做非常完美，但是相对于之前的 `import` 更麻烦，没有必要这么做。

## Awareness In Use

在使用时我们需要注意以下的一些区别：

1. CJS 输出的是一个值的拷贝，ESM 输出的是值的引用。

2. CJS 是运行时加载，ESM 是编译时输出接口；

3. CJS 是单个值导出，ESM 可以导出多个；

4. CJS 是动态语法可以写在判断里，ESM 静态语法只能写在顶层；

5. CJS 的 `this` 指向当前模块，ESM 的 `this` 是 `undefined`；


