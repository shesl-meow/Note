# day12

## XSS

* XSS自动化挖掘。重点在于输入与输出。

## SQl注入

* Cookie、header、url、请求参数中均有可能触发。
  * _PS_：mysql常见的延时注入的函数：sleep、**benchmark**（重复执行同一个函数）
* sql注入的关键：如何闭合sql语句

## SSRF与URL跳转

* 大部分SSRF、URL跳转漏洞触发在请求参数中。
* redis是支持内网的常见服务，可以利用dict与gopher协议与之通信。
