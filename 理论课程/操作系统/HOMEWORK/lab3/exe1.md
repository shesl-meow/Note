如果ucore的缺页服务例程在执行过程中访问内存,出现了页访问异常,请问硬件要做哪
些事情?

将产生页访问异常的线性地址存入 cr2 寄存器中 并且给出 错误码 error_code 说明是页访问异常的具体原因

`error_code : the error code recorded in trapframe->tf_err which is setted by x86 hardware`

将其 存入 `trapframe` 中 `tf_err` 等到中断服务例程 调用页访问异常处理函数`do_pgfault()` 时
再判断 具体原因 
若不在某个`VMA`的地址范围内 或 不满足正确的读写权限 则是非法访问
若在此范围 且 权限也正确 则 认为是 合法访问 只是没有建立虚实对应关系 应分配一页 并修改页表 完成 虚拟地址到 物理地址的映射 刷新` TLB`.重新执行引发页访问异常的 那条指令.