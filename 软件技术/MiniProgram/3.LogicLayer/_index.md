---
bookCollapseSection: true
title: "3.LogicLayer"
---

# 视图层

逻辑层将数据进行处理后发送给视图层，同时接受视图层的事件反馈。

开发者写的所有代码最终将会打包成一份 `JavaScript` 文件，并在小程序启动的时候运行，直到小程序销毁。这一行为类似 [ServiceWorker](https://developer.mozilla.org/en-US/docs/Web/API/Service_Worker_API)，所以逻辑层也称之为 App Service。

在 `JavaScript` 的基础上，我们增加了一些功能，以方便小程序的开发：

- 增加 [App](https://developers.weixin.qq.com/miniprogram/dev/framework/app-service/app.html) 和 [Page](https://developers.weixin.qq.com/miniprogram/dev/framework/app-service/page.html) 方法，进行程序和页面的注册。
- 增加 `getApp` 和 `getCurrentPages` 方法，分别用来获取 `App` 实例和当前页面栈。
- 提供丰富的 [API](https://developers.weixin.qq.com/miniprogram/dev/framework/app-service/api.html)，如微信用户数据，扫一扫，支付等微信特有能力。
- 每个页面有独立的[作用域](https://developers.weixin.qq.com/miniprogram/dev/framework/app-service/module.html#%E6%96%87%E4%BB%B6%E4%BD%9C%E7%94%A8%E5%9F%9F)，并提供[模块化](https://developers.weixin.qq.com/miniprogram/dev/framework/app-service/module.html#%E6%A8%A1%E5%9D%97%E5%8C%96)能力。

**注意：小程序框架的逻辑层并非运行在浏览器中，因此 JavaScript 在 web 中一些能力都无法使用，如 window，document等。**

