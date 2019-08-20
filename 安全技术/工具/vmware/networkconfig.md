> 学习地址：
>
> - https://www.vmware.com/support/ws5/doc/ws_net_configurations_common.html
> - <https://www.cnblogs.com/wushuaishuai/p/9258849.html#_label3>

# 关于 `vmware` 虚拟机的虚拟网络编辑器

## 桥接模式 (Bridged Networking)

桥接模式就是  将主机网卡与虚拟机虚拟的网卡  利用虚拟网桥进行通信。

在桥接的作用下，类似于把物理主机  虚拟为一个交换机，所有桥接设置的虚拟机  连接到这个交换机的一个接口上，物理主机也同样  插在这个交换机当中，所以所有 桥接下的网卡与主机网卡 都是交换模式的，相互可以访问而不干扰。

在桥接模式下，虚拟机 `ip` 地址需要与主机在同一个网段，如果需要联网，则网关与 `DNS` 需要与主机网卡一致。

