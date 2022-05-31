# exe0

同 [lab2](../lab2/exe0.md)：

1. 导出 change：

   ```bash
   $ git diff 7ca90137c09c54f5afa9b87a35a68d9f65ecef52 HEAD labcodes/lab2/ | sed 's/lab2/lab3/g' > lab3/exe0.patch
   ```

2. 进行 merge：

   ```bash
   $ git apply lab3/exe0.patch
   ```

