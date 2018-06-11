# last class

## 概念模型调用关系模型的转化

- 明确了解实体、属性、联系、弱实体集和子类的概念
- 弱实体：特殊的实体-->找不到码的实体集（用双矩形表示）
- 考试形式--填表、write SQL statement
- isa的三种写法--基本掌握ER写法就行，**必考**
- 例题：
	- For the relational tables you generated in question 1),Describe which insert and delete operations in this database must be checked to ensure that referential integrity is not violated for that foreign key. Please staet seoecifically which operations in which relations can cause problems.
	- Refrence Answer: 
		- On insert(SC)-->exits(Students) and exist(Course).
		- On delete(Student)-->delete(SC) or not allowed

## 关系代数和SQL与语言操作

- SQL查询语句一般结构（需要看懂命令、掌握输出结果）
	- Select ... From ... Where ... Group by ... Having ...
- 关系代数：并交叉选择投影自然连接 
- 例题：
	- Please write each result of the following question
	- 根据要求写Relational Algebra and **SQL Queries**语句
	 
## 关系模式设计与Normal Form

- 要求内容：3NF、BCNF，了解4NF（没有多值依赖的集合到了BCNF就到了4NF）
- 掌握：保持无损连接和函数依赖
- 考察方式：（抽象形式考察）
	- What is attribute closure of AD?
	- Of the following FDs, circle the ones that are implied bt the functional depencied given above.
	- Lists all keys for R.(一定是多个码)
	- Write down weo funcitonal dependencies that ensures this relation to violation ?NF
	- We decompose R into R1 and R2. What are the keys of R2? What are the key of R2?
	- ...

## 并发控制

- 若干事务并发运行，能够判断所给的调度是不是可串行化调度。
- 例题：
	- What is the precedence graoh if the schema
- 例题l
	- 清添加和合适的读锁（ls[]）、写锁（lx[]）和解锁（ul[]）命令使事务T1和T2在并发运行时可以满足冲突可串行化调度。（为提高并发度，只涉及读的元素要加读锁）T1加锁
	- 按照上述加锁顺序给出一个序集
- 时间戳不考，有效性验证考一个小题
- Transaction Management

## 简答题若干

- 来源于课件的课后练习题