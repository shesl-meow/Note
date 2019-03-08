> 学习地址：
>
> - https://linuxtechlab.com/learn-use-netstat-with-examples/

learn `netstat` with example.

# `netstat`

`Netstat` is a command line utility that tells us about all the `tcp/udp/unix `socket connections on our system. It provides list of all connections that are currently established or are in waiting state. This tool is extremely useful in identifying the port numbers on which an application is working and we can also make sure if an application is working or not on the port it is supposed to work.

## Example

1. Checking all connections:

   ```shell
   $ netstat -a
   ```

2. Check all `tcp` connections:

   ```shell
   $ netstat -at
   ```

   Check all `udp` connections:

   ```shell
   $ netstat -au
   ```

   Checking all `unix` connections:

   ```shell
   $ nestat -ax
   ```

3. List process id and name (it can be combination with any other `netstat` option):

   ```shell
   $ netast -ap
   ```

4. List all port number without its name (it will perform any reverse lookup & produce output with only numbers.), used to speed up:

   ```shell
   $ netstat -an
   ```

   port such as `22` will be resolve as `ssh` if `n` option is not specify.

5. Print only listen port:

   ```shell
   $ netstat -l
   ```

6. Print networks stats:

   ```shell
   $ netstat -s
   ```

7. Print Interfaces stats:

   ```shell
   $ netstat -i
   ```

8. Display multicast group information:

   ```shell
   $ netstat -g
   ```

9. Display network routing information:

   ```shell
   $ netstat -r
   ```

10. To get continuous information:

    ```shell
    $ netstat -c
    ```


