# 基础

## 介绍

### 起步 HelloWorld

最简单的方式是可以使用以下的例子：

```markup
<script src="https://unpkg.com/vue"></script>

<div id="app">
  <p>{{ message }}</p>
</div>
```

```javascript
new Vue({
  el: '#app',
  data: {
    message: 'Hello Vue.js!'
  }
})
```

### 声明式渲染

数据和 DOM 建立的连接都是**响应式的** → 打开浏览器的 JavaScript 控制台，修改 `app.message` 的值，DOM 的内容会立即响应。除了绑定文本，我们还可以像如下方式绑定元素特性：

```markup
<div id="app-2">
    <span v-bind:title="message">
        鼠标悬停几秒钟查看此处动态绑定的信息。
    </span>
</div>
```

```javascript
var app2 = new Vue({
    el: "#app-2"
    data: {
        message: "页面加载于" + new Data().toLacaleString()
    }
})
```

在 html 中的 `v-bind` 被称为**指令**，其中 `v-` 表示这是 Vue 提供的特殊特性，`bind` 为绑定属性的意思。在这里，该指令的意思是：将这个元素节点的 `title` 特性和 Vue 实例的 `message` 属性保持一致。

### 条件与循环

使用 `v-if` 指令可以进行条件判断，比如以下的例子：

```markup
<div id="app-3">
    <p v-if="seen">
        现在你看到我了
    </p>
</div>
```

```javascript
var app3 = new Vue({
    el: "#app-3"
    data: {
        seen: true
    }
})
```

使用 `v-for` 指令可以用来绑定数组的数据来渲染一个项目列表：

```markup
<div id="app-4">
    <ol>
        <li v-for="todo in todos">
            {{ todo.text }}
        </li>
    </ol>
</div>
```

```javascript
var app4 = new Vue({
    el: "#app-4",
    data: {
        todos: [
            {text: "学习 JavaScript"}
            {text: "学习 Vue"}
            {text: "学习 html"}
        ]
    }
})
```

### 处理用户输入

可以使用 `v-on` 指令添加一个事件监听器，通过该事件监听器调用在 Vue 实例中定义的方法：

```markup
<div id="app-5">
    <p>
        {{ message }}
    </p>
    <button v-on:click="reverseMessage">
        逆转消息
    </button>
</div>
```

```javascript
var app5 = new Vue({
    el: "#app-5",
    data: {
        message: "Hellow Vue.js!"
    },
    methods: {
        reverseMessage: function(){
            this.message = this.message.split('').reverse().join('')
        }
    }
})
```

Vue 还提供了 `v-model` 指令，它能轻松实现表单输入和应用状态之间的双向绑定，比如以下的例子：

```markup
<div id="app">
  <p>{{ message }}</p>
  <input v-model="message">
</div>
```

```javascript
new Vue({
  el: '#app',
  data: {
    message: 'Hello Vue.js!'
  }
})
```

### 组件化应用架构

在 Vue 里，一个组件本质上是一个拥有**预定义选项**的一个 Vue 实例。比如以下的例子定义了一个 `todo-item` 的组件，允许我们在 html 中使用：

```markup
<script src="https://unpkg.com/vue"></script>

<div id="app-7">
  <ol>
    <todo-item 
      v-for = "item in groceryList" 
      v-bind:todo = "item"
      v-bind:key = "item.id">
    </todo-item>
  </ol>
</div>
```

其中，html 文件中使用了 `todo-item` 这个组件，使用以下的 javascript 文件定义：

```javascript
Vue.component("todo-item", {
    props: ["todo"],
  template: "<li>{{ todo.text }}</li>"
})

var app7 = new Vue({
  el: '#app-7',
  data: {
    groceryList: [
        { id: 0, text: '蔬菜' },
      { id: 1, text: '奶酪' },
      { id: 2, text: '随便其它什么人吃的东西' }
    ]
  }
})
```

_PostScript_：组件与自定义元素的关系：

1. Web 组件规范仍然处于草案阶段，并且未被所有浏览器原生实现。相比之下，Vue 组件不需要任何 polyfill，并且在所有支持的浏览器 (IE9 及更高版本) 之下表现一致。必要时，Vue 组件也可以包装于原生自定义元素之内。
2. Vue 组件提供了纯自定义元素所不具备的一些重要功能，最突出的是跨组件数据流、自定义事件通信以及构建工具集成。

## Vue 实例

每个 Vue 应用都是通过用 `Vue` 函数创建一个新的 **Vue 实例**开始的。Vue 的 [API 文档](https://cn.vuejs.org/v2/api)。

### 数据与方法

当一个 Vue 实例被创建时，它向 Vue 的**响应式系统**中加入了其 `data` 对象中能找到的所有的属性。

当这些数据改变时，视图会进行重渲染 → 值得注意的是只有当实例被创建时 `data` 中存在的属性才是**响应式**的（也就是说，添加一个新的属性，将不会触发任何视图的更新）。

这里唯一的例外是使用 `Object.freeze()`，这会阻止修改现有的属性，也意味着响应系统无法再_追踪_变化。比如以下的例子：

```markup
<script src="https://unpkg.com/vue"></script>

<div id="app-8">
  <p>{{ foo }}</p>
  <button v-on:click="foo = 'text'">Change Text</button>
</div>
```

```javascript
var obj = { foo: "bar" }
Object.freeze(obj)

var app8 = new Vue({
    el: "#app-8",
  data: obj,
})
```

除了数据属性，Vue 实例还暴露了一些有用的实例属性与方法。它们都有前缀 `$`，以便与用户定义的属性区分开来。比如：`vm.$data` $$\Leftrightarrow$$ `data`（其中 vm 是一个 Vue 的实例）

### 实例生命周期钩子

每个 Vue 实例在被创建时都要经过一系列初始化的的过程，在这个过程中会运行一些叫做**生命周期钩子**的函数，这给了用户在不同阶段添加自己的代码的机会。

比如 `create` 钩子可以用来在一个实例被创建后执行代码：

```javascript
new Vue({
  data: {
    a: 1
  },
  created: function () {
    // `this` 指向 vm 实例
    console.log('a is: ' + this.a)
  }
})
```

也有一些其他的钩子，在实例的生命周期不同阶段被调用，比如：`mounted`、`update` 和 `destroyed`。生命周期钩子中的 `this` 指向调用它的 Vue 实例。

**Note**：不要在选项属性或回调上使用 [箭头函数](https://developer.mozilla.org/zh-CN/docs/Web/JavaScript/Reference/Functions/Arrow_functions)，比如：`created: () => console.log(this.a)` 或 `vm.$watch('a', newValue => this.myMethod())`。因为箭头函数是和父级上下文绑定在一起的。

### 生命周期图示

![lifecycle](../../../.gitbook/assets/lifecycle.png)

## 模板语法

### 插值

数据绑定最常见的形式就是使用 “Mustache” 语法 (双大括号) 的文本插值：

```markup
<span>Message: {{ msg }}</span>
```

通过使用 [v-once 指令](https://cn.vuejs.org/v2/api/#v-once)，你也能执行一次性地插值，当数据改变时，插值处的内容不会更新。但请留心这会影响到该节点上的其它数据绑定：

```markup
<span v-once>这个将不会改变: {{ msg }}</span>
```

双大括号会将数据解释为普通文本，而非 HTML 代码。为了输出真正的 HTML，你需要使用 `v-html` 指令：

```markup
<script src="https://unpkg.com/vue"></script>

<div id="app-9">
  <p>{{ RawHtml }}</p>
  <p><span v-html="RawHtml"></span></p>
</div>
```

```javascript
var obj = { RawHtml: "<span style='color:red'>This should be red</span>" }

var app8 = new Vue({
    el: "#app-9",
  data: obj,
})
```

**Note**：注意只对可信内容使用 HTML 插值，绝对不要使用用户提供的内容使用插值，因为它很容易导致 XSS。

Mustache 语法不能作用在 HTML 特性上，遇到这种情况应该使用 [v-bind 指令](https://cn.vuejs.org/v2/api/#v-bind)：

```markup
<div v-bind:id="dynamicId"></div>
```

对于所有的数据绑定，Vue.js 都提供了完全的 JavaScript 表达式支持。不过每个绑定只能包含单个表达式，以下是一些例子：

```markup
{{ number + 1 }} <!--生效-->

{{ ok ? 'YES' : 'NO' }} <!--生效-->

{{ var a = 1 }} <!--无效：这是语句，不是表达式-->
```

_PostScript_：模板表达式都被放在沙盒中，只能访问全局变量的一个白名单，如 `Math` 和 `Date` 。你不应该在模板表达式中试图访问用户定义的全局变量。

### 指令

指令 (Directives)：是带有 `v-` 前缀的特殊特性。指令特性的值预期是**单个 JavaScript 表达式**。指令的职责是，当表达式的值改变时，将其产生的连带影响，响应式地作用于 DOM。

一些指令能够接收一个“参数”，在指令名称之后以冒号表示。例如，`v-bind` 指令可以用于响应式地更新 HTML 特性：

```markup
<a v-bind:href="url">...</a>
```
