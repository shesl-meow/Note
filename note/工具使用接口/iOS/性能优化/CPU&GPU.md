---
title: "CPU&GPU.md"
date: 2020-03-20T22:36:11+08:00
tags: [""]
categories: ["工具使用接口", "iOS"]
---

> 参考：
>
> - https://juejin.im/post/5ace078cf265da23994ee493#heading-2
> - https://www.zhihu.com/question/29163054
> - https://www.jianshu.com/p/f62e81b72bba

# CPU & GPU

## 图形学概念

光栅化（Rasterize / Rasteriztion）：

- 就是把矢量图形转化成像素点儿的过程。

着色器（Shader），通常着色器分两种：

1. 顶点着色器（vertex shader）：这个是告诉电脑如何打线稿的——如何处理顶点、法线等的数据的小程序。
2. 片面着色器（fragment shader）：这个是告诉电脑如何上色的——如何处理光、阴影、遮挡、环境等等对物体表面的影响，最终生成一副图像的小程序。

## 二者功能

CPU 的职能：

- 加载资源，对象创建，对象调整，对象销毁，布局计算，Autolayout，文本计算，文本渲染；
- 图片的解码， 图像的绘制（Core Graphics）都是在`CPU`上面进行的。

GPU 的特点：

- `GPU` 是一个专门为图形高并发计算而量身定做的处理单元，比 `CPU` 使用更少的电来完成工作并且 `GPU` 的浮点计算能力要超出 `CPU` 很多。
- `GPU` 的渲染性能要比 `CPU` 高效很多，同时对系统的负载和消耗也更低一些，所以在开发中，**我们应该尽量让 `CPU` 负责主线程的 `UI` 调动，把图形显示相关的工作交给 `GPU` 来处理**，当涉及到光栅化等一些工作时，`CPU`也会参与进来，这点在后面再详细描述。

GPU 的指责：

- 接收提交的纹理（Texture）和顶点描述（三角形），应用变换（transform）、混合（合成）并渲染，然后输出到屏幕上。通常你所能看到的内容，主要也就是纹理（图片）和形状（三角模拟的矢量图形）两类。

## 离屏渲染

GPU 屏幕渲染有以下两种方式：

- On-Screen Rendering 当前屏幕渲染：指的是 GPU 的渲染操作是在当前用于显示的屏幕缓冲区中进行。

- Off-Screen Rendering 意为离屏渲染：指的是 GPU 在当前屏幕缓冲区以外新开辟一个缓冲区进行渲染操作。

**特殊的离屏渲染：**如果将不在GPU的当前屏幕缓冲区中进行的渲染都称为离屏渲染，那么就还有另一种特殊的“离屏渲染”方式：CPU 渲染。

- 如果我们重写了 `drawRect` 方法，并且使用任何 Core Graphics 的技术进行了绘制操作，就涉及到了CPU渲染。整个渲染过程由 CPU 在 App 内同步地完成，渲染得到的 bitmap 最后再交由 GPU 用于显示。

*PostScript*：Core Graphic 通常是线程安全的，所以可以进行异步绘制，显示的时候再放回主线程，一个简单的异步绘制过程大致如下：

```objective-c
(void)display {
	dispatch_async(backgroundQueue, ^{
    CGContextRef ctx = CGBitmapContextCreate(...); // draw in context... 
    CGImageRef img = CGBitmapContextCreateImage(ctx); 
    CFRelease(ctx); 
    dispatch_async(mainQueue, ^{
      layer.contents = img;
    });
  });
}
```

在 iOS 中，设置了以下的属性，会触发离屏渲染：

- 光栅化：`layer.shouldRasterize = YES`；

- 遮罩：`layer.mask`；

- 不透明：`layer.allowsGroupOpacity = YES` 并且 `layer.opacity < 1.0`；

- 阴影：`layer.shadow...`（所有以 `shadow` 前缀开头的属性），使用 `shadowPath` 代替：

  ```objective-c
  // 使用 shadow 开头的属性进行设置
  {
    CALayer *imgLayer = cell.imageView.layer;
    imgLayer.shadowColor = [UIColor blackColor].CGColor;
    imgLayer.shadowOpacity = 1.0;
    imgLayer.shadowRadius = 2.0;
    imgLayer.shadowOffset = CGSizeMake(1.0, 1.0);
  }
  
  // 使用 shadowPath 进行绘制
  {
    CALayer *imgLayer = cell.imageView.layer;
    imgLayer.shadowPath = CGPathCreateWithRect(imgRect, NULL);
  }
  ```

- `edge antialiasing`（抗锯齿）、`group opacity`（不透明）、复杂形状设置圆角等

为什么会使用离屏渲染？

- 当使用圆角，阴影，遮罩的时候，图层属性的混合体被指定为”在未预合成之前，不能直接在屏幕中绘制“，所以就需要屏幕外渲染被唤起。
- 屏幕外渲染并不意味着软件绘制，但是它意味着图层必须在被显示之前在一个屏幕外上下文中被渲染（不论 CPU 还是 GPU）。
- 所以当使用离屏渲染的时候会很容易造成性能消耗，因为在 OPENGL 里离屏渲染会单独在内存中创建一个屏幕外缓冲区并进行渲染，而屏幕外缓冲区跟当前屏幕缓冲区上下文切换是很耗性能的。
