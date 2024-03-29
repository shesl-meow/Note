---
title: ":nut_and_bolt:MySQL 性能优化"
date: 2018-12-30T00:00:00+08:00
tags: ["持续更新", "MySQL", "数据库"]
---


## 查询优化

查询语句使用原则：

1. **范围查询的列放到索引列的最后面**：MySQL 会一直向右利用索引匹配直到遇到范围查询（>、<、between、like）就停止匹配，所以如果将范围放在前面，后面的索引将无法使用。

   *PS*：这里的范围查询是不包括 in 的，in 是指多个等值条件查询，不对联合索引的匹配造成影响。但是通过 explain 分析执行计划时无法区别范围查询和多个等值查询（统一显示为 range）

2. **= 和 in 可以乱序**：MySQL 的查询优化器会帮你优化成索引可以识别的形式。根据经验是将业务中使用到的查询里最常用的列放在前面，这样可以尽量使用到该索引。

3. **字符串通配符尽量后置**：Like 查询如果使用 `%s%` 这种格式，非最左前缀匹配将无法使用到索引。

