# netstat

> 学习地址：
>
> * [https://linuxtechlab.com/learn-use-netstat-with-examples/](https://linuxtechlab.com/learn-use-netstat-with-examples/)

learn `netstat` with example.

## `netstat`

`Netstat` is a command line utility that tells us about all the `tcp/udp/unix`socket connections on our system. It provides list of all connections that are currently established or are in waiting state. This tool is extremely useful in identifying the port numbers on which an application is working and we can also make sure if an application is working or not on the port it is supposed to work.

### Example

1.  Checking all connections:

    ```
    $ netstat -a
    ```
2.  Check all `tcp` connections:

    ```
    $ netstat -at
    ```

    Check all `udp` connections:

    ```
    $ netstat -au
    ```

    Checking all `unix` connections:

    ```
    $ nestat -ax
    ```
3.  List process id and name (it can be combination with any other `netstat` option):

    ```
    $ netast -ap
    ```
4.  List all port number without its name (it will perform any reverse lookup & produce output with only numbers.), used to speed up:

    ```
    $ netstat -an
    ```

    port such as `22` will be resolve as `ssh` if `n` option is not specify.
5.  Print only listen port:

    ```
    $ netstat -l
    ```
6.  Print networks stats:

    ```
    $ netstat -s
    ```
7.  Print Interfaces stats:

    ```
    $ netstat -i
    ```
8.  Display multicast group information:

    ```
    $ netstat -g
    ```
9.  Display network routing information:

    ```
    $ netstat -r
    ```
10. To get continuous information:

    ```
    $ netstat -c
    ```
