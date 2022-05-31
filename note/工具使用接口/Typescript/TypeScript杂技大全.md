# TypeScipt 杂技大全


定义 getter setter，在类方法前使用关键字 `get`/`set`；

- https://www.typescriptlang.org/docs/handbook/classes.html#accessors

使用 `@` 符号，引用 Decorator：

- https://www.typescriptlang.org/docs/handbook/decorators.html#property-decorators

使用模版字符串：

- https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Template_literals


## StackOverflow

> 来自 StackOverflow 上的大神教程。

如何得到一个类派生出的所有子类型：https://stackoverflow.com/questions/42414045/how-to-get-child-classes-which-implement-a-certain-base-class-using-reflection-i

```typescript
export default function hierarchyTracked(target: new (...args: any[]) => object) {
  for (const proto of walkPrototypeChain(target)) {
    if (!Object.hasOwnProperty.call(proto, 'extendedBy')) {
      const extendedBy: typeof Function.extendedBy = [];
      Object.defineProperty(proto, 'extendedBy', {
        get: () => extendedBy
      });
    }
    // ! is used to suppress a strictNullChecks error on optional.
    // This is OK since we know it is now defined.
    proto.extendedBy!.push(target);
  }
}

declare global {
  interface Function {
    // Declared as optional because not all classes are extended.
    extendedBy?: Array<new (...args: any[]) => object>;
  }
}

function* walkPrototypeChain(target: new (...args: any[]) => object) {
  let proto = Reflect.getPrototypeOf(target);
  while (proto && proto !== Object) {
    yield proto;
    proto = Reflect.getPrototypeOf(proto);
  }
}
```

## Mixin 

`Mixin` 本身是一种设计模式，它指不通过继承而是通过混入，将一个类的方法添加到另一个类中。这通常用于解决多继承的问题（一个子类不能同时继承两个基类）。

TypeScript 官方文档给出了一个 mixin 的方法：https://www.typescriptlang.org/docs/handbook/mixins.html：

```typescript
// Each mixin is a traditional ES class
class Jumpable {
  jump() {}
}

class Duckable {
  duck() {}
}

// Including the base
class Sprite {
  x = 0;
  y = 0;
}

// Then you create an interface which merges
// the expected mixins with the same name as your base
interface Sprite extends Jumpable, Duckable {}
// Apply the mixins into the base class via
// the JS at runtime
applyMixins(Sprite, [Jumpable, Duckable]);

let player = new Sprite();
player.jump();
console.log(player.x, player.y);

// This can live anywhere in your codebase:
function applyMixins(derivedCtor: any, constructors: any[]) {
  constructors.forEach((baseCtor) => {
    Object.getOwnPropertyNames(baseCtor.prototype).forEach((name) => {
      Object.defineProperty(
        derivedCtor.prototype, name,
        Object.getOwnPropertyDescriptor(baseCtor.prototype, name) ||
          Object.create(null)
      );
    });
  });
}
```

