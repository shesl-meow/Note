# Stack Overflow

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

