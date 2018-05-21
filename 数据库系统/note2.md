# Note2

## 故障恢复 

### 故障恢复

* 数据库破环的原因：事务没有正确执行
* Undo/Redo logging
	- log record `<Ti, X, old, new>` flushed to disk before writing X to disk
	- Flush the log at commit
* 故障恢复：
	- 把事务分成两个集合redo、undo
	- 把完成的事务从做一遍
	- 把未完成的事务恢复 

### Nonquiecent Checkpointing

* Slightly different for various logging policies.
* Rules for undo/rodo logging
	`<START CKPT>`-->`<END CKPT>`

### Disk Crush

* Solution a-- 
	* Mirroring: copies on separate disks
		- Output(X) --> multiple disk
		- Input(X) --> one disk
	* 镜像磁盘故障率估算
		> 丢失数据的可能情况是： 修复第一个磁盘损坏的同时，第二个磁盘也损坏了
* Solution b--
	* RAID4: 仅使用一个冗余盘，冗余盘的第i块由所有数据盘的第i块奇偶校验位组成
	* RAID5: 将冗余位分布到四个盘上，防止冗余盘的经常读取而导致冗余盘最容易crush

### PS

* log --> db dump --> checkpoint -->crush
* 两个原则：
	- 事务记录严格按照时间顺序记录
	- 先写日志文件，后写数据库

## Concurrency Control

### schedule

* Correctness depends on scheduling of transactions
* 若多个事务共同访问共同的元素时，这些元素必须按照一定的访问顺序访问
* **serial schedule**

### action confilct

* swapping them may cahnge the meaning of a schedule.
	- any two actions of a single transaction
	- two actions on acommon DB elemtn A, one of which is WRITE(A)
* a schedule is "bad" if it can't be rearranged into a serial schedule.
	- 加锁机制

### Prof

* Definition:
	- S1, S2 are **conflict equivalent schedules**....
	- A schedule is **coflict serializable** if it is conflict equivalent to some serial schedule.
	- **Precedence graph**, P(S)(S if schedule), 冲突调度的先后顺序
* Lemma:
	- Let S1, S2 be schedules for the same of transaciotns.	
		- S1. S2 conflict equivalent ⇨ P(S1)=P(S2)
		- NOTE: 反之不成立,有环的不一定成立
* Theorem:
	* I: P(S1) acyclic ↔ S1 is a conflict serialization


