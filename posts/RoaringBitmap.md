---
title: "Roaring Bitmap 学习"
date: 2022-06-02T12:00:00+08:00
tags: ["Bitmap", "压缩位图索引"]
---

# Roaring Bitmap 学习笔记

## 背景

官网：http://roaringbitmap.org/

开源代码：https://github.com/RoaringBitmap/RoaringBitmap

论文：

- 《Better bitmap performance with Roaring bitmaps》：https://arxiv.org/abs/1402.6407，https://arxiv.org/pdf/1402.6407.pdf
- 《Consistently faster and smaller compressed bitmaps with Roaring》：https://arxiv.org/abs/1603.06549，https://arxiv.org/pdf/1603.06549.pdf

相关文章：https://cloud.tencent.com/developer/article/1136054

## 竞品解决方案

Roaring Bitmap 是对 Bitmap 的优化，是“压缩位图索引”的一种，同样的方案还有：

-  RLE（Run-Length Encoding）；
- WAH (Word Aligned Hybrid Compression Scheme) ；
-  Concise (Compressed ‘n’ Composable Integer Set)

## 空间复杂度

假设我们的系统主线是 64 位，我们需要存储类型为 `uint32_t` 的索引到一个对象地址。

传统的 Bitmap 对应的空间复杂度为：

- $2^{32} * 64 bit = 4G * 8byte = 32 GByte$，是一个不论数据分布如何的常数。

而 Roaring Bitmap 对应的空间复杂度为：

- 一级索引的内容是二级索引的地址指针：$2^{16} * 64bit = 2^{22} = 512KByte$

- 而二级索引是一个随数据分布而变化的量：
  - 空标记位 0Byte，只需要标记存储地址的指针；
  - 在数据稀疏时通过数组存储对应的数据，每个数据需要存储剩余的低 16 位索引以及数据本身，对于一个桶中有 n 个数据：$n * (2^{16} + 2^{64})$
  - 对于稠密的数据，将通过 bitmap 存储该桶中的数据，空间退化为常数 $2^{16} * 2^{64}$，这主要是出于查询时间复杂度的考虑而非空间的考虑。