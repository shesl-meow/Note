# TSDB 学习

时序数据的特点：

- 数据按照时间严格单调排序；
- Append Only：只能向后插入数据，不能更新；
- 写数量远大于读数量：大于 90% 的数据从未被读取；
- 数据量级特别大，但是相对比较稳定；
- 随着时间的推移，数据的价值减小，最近数据的价值高于历史数据；
- 通常与 `tag` 聚合在一起，根据时间范围进行查询；

Metrics 是字节跳动实现 tsdb 的解决方案，很多平台的数据源都来自 Metrics：

- `alarm`、`grafana`、`metro-fe`、`argos`；

Metrics 系统架构分为三级：

1. SDK 侧：通过 SDK 将日志信息发送到 `agent`，`agent` 通过 `producer` 发送到消息队列中；
2. 核心逻辑：`consimer`/`preshuffle` 两个消费逻辑链路，分别将数据存储到冷热存储的两个不同数据库中；
3. 数据存储：速度快的“热存储”TSDC、速度较慢的“冷存储”mstore；

Open Source：

- 在业界有很多开源的解决方案：`Influxdb`、`Opentsdb`、`Druid`、`Elasticsearch`、`Beringei` 等；