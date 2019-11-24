# Git Advance

## Git 文件系统

### 概述

我们在一个 `git init` 结果的空仓库中，简述一下各个部分的作用：

```bash
.git
├── HEAD 				// 指示当前被检出的分支
├── branches 		// 废弃
├── config 			// 项目内的配置文件
├── description // 供GitWeb程序使用
├── hooks 			// 存储钩子脚本
│   ├── applypatch-msg.sample
│  ...
├── info 				// 目录包含一个全局性排除(global exclude)文件，
│   └── exclude	// 用以放置那些不希望被记录在 .gitignore 文件中的忽略模式(ignored patterns)
├── objects 		// 存储所有数据内容
│   ├── info 		// 仓库的额外信息
│   └── pack 		// 压缩后的包文件
└── refs // 存储指向分支的提交对象的指针
    ├── heads 	// 分支
    └── tags 		// 标签
```

执行以下命令可以查看 Git 目录结构说明：

```bash
git help gitrepository-layout
```

