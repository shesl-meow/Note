# NOTE

## 期末工程作业：
数据库管理系统（对数据库的功能有要求）

1. 有界面的面向用户界面，开发语言自选
2. 完成四个操作，每种操作举一个例子
3. 提交后在数据库上机时向辅导老师汇报
4. 上机考试十个命令

## **integrity or consistness of data**

1. predicates that the data must satisfy

	* 断言：检查操作是否合法（约束）.数据库的正确性-->检查所有约束是否满足
	* **definition**: consistent state(consistent DB):satisfied all constraints
	* **definition**: Transaction: collection of actions that preserve consistency.
	* 数据库的事务特性：ACID：**原子性Atomaicity**, **一致性Consistency**(事务会使一个数据库从一个正确状态转移到另一个正确状态), **隔离性Isolation**(事务的执行不受其他事务的影响),** 持续性Durability**（事务commit提交后永久执行）
	* 数据库恢复操作：begin transaction-->rollback-->commit

2. big assumption:正确的事务会使一致状态转移到另一个一致状态
	
	* 数据库错误原因
		* Transaciotn bug
		* DBMS bug
		* Handware failure
		* Simultaneous transactions accessing shared data
	* interacting address spaces: storage hierachy
	* 一个数据多次存储做校验，防止数据库被破坏

## Undo logging
1. undo logging:
	* 记录内容：
		* `<Ti, start>`
		* `<Ti, commit>`
		* `<Ti, abort>`
		* `<Ti, X, v>`: update element X, whose old value was v
	* example:`<T1, start>`-->`<T1, A, 8>`（无结束状态标识符，数据库回滚）
	* example:`<T1, start>`-->`<T1, A, 8>`-->`<T1, commit>`
2. one  "complication"
	* log is firt written in memory
	* not written to disk on every action
	* before modifying elment X on disk, any log records for X must be flushed to disk.

3. Undo logging Recovery；
	1. Let S = set of transactions with
		- `<Ti, start>` in log, but no `<Ti, commit>`(or `<Ti, abort>` record in log)
	2. For each `<Ti, X, v>` in log, in reverse order (latest-->earliset) do:
		- if Ti ∈ S --> write(X, v) --> output(X)
	3. For each Ti ∈ S do
		- write `<Ti, abort>`to log

## Redo logging

1. 记录新值，commit之后再写磁盘。恢复时日志时，从前往后扫描把带commit全部再做一遍。

2. Redo log-->Recovery is very **slow**-->CKPT(check point): 检查点，之前的事务已经全部完成
	1. stop accepting new trasactions
	2. Wait all transactions to finish(commit/abort)
	3. flush all log to disk
	4. ...

## Undo/Redo logging

Undo logging *versus* Redo logging

* Update record: `<Ti, X, Old-X-value, New-X-value>`
	1. fulshed to disk before writing X to disk
	2. Flsh the log at commit
		- Element X can be written to disk either before or after commit
* Recovery Policy:
	- redo updates by any committed transactions
	- undo updates by any incomplete transactions 