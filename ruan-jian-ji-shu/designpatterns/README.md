# DesignPatterns

> 参考资料：
>
> * 来源：《Design Patterns - Elements of Reusable Object-Oriented Software》
> * 菜鸟教程：[https://www.runoob.com/design-pattern/factory-pattern.html](https://www.runoob.com/design-pattern/factory-pattern.html)

## 设计模式

### 类型

根据设计模式的参考书 中所提到的，总共有 23 种设计模式。

这些模式可以分为三大类：创建型模式（Creational Patterns）、结构型模式（Structural Patterns）、行为型模式（Behavioral Patterns）。当然，我们还会讨论另一类设计模式：J2EE 设计模式。

| 模式分类    | 描述                                                                     |
| ------- | ---------------------------------------------------------------------- |
| 创建型模式   | <p>这些设计模式提供了一种在创建对象的同时隐藏创建逻辑的方式。<br>这使得程序在判断针对某个给定实例需要创建哪些对象时更加灵活。</p> |
| 结构型模式   | <p>这些设计模式关注类和对象的组合。<br>继承的概念被用来组合接口和定义组合对象获得新功能的方式。</p>                |
| 行为型模式   | 这些设计模式特别关注对象之间的通信。                                                     |
| J2EE 模式 | 这些设计模式特别关注表示层。这些模式是由 Sun Java Center 鉴定的。                              |

### 原则

设计模式的六大原则：

1. 开闭原则（Open Close Principle）：对扩展开放、对修改关闭。
   * 在程序需要扩展功能时，可以实现 hot-plugins；
   * 程序实现扩展时，不能对既有的代码进行修改；
2. 里氏代换原则（Liskov Substitution Principle）：任何基类可以出现的地方，子类一定可以出现。
3. 依赖倒转原则（Dependence Inversion Principle）：针对接口编程，依赖于抽象而不依赖于具体。
4. 接口隔离原则（Interface Segregation Principle）：使用多个隔离的接口，比使用单个接口好。也可以说是降低类之间的耦合度；
5. 迪米特法则，或最少知道原则（Demeter Principle）：一个实体应当尽量少地于其他实体之间发生相互作用，使得系统功能模块相对独立；
6. 合成复用原则（Composite Reuse Principle）：尽量使用合成的方式而不是继承。
