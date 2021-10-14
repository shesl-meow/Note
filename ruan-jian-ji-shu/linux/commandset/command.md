# command

Question: [How to check if a program exists from a Bash script?](https://stackoverflow.com/questions/592620/how-to-check-if-a-program-exists-from-a-bash-script)

Answer: three possible method:

*   POSIX compatible:

    ```bash
    $ command -v <the_command>
    ```
*   For `bash` specific environments:

    ```bash
    $ hash <the_command> # For regular commands. Or...
    ```

    ```bash
    $ type <the_command> # To check built-ins and keywords
    ```

Many operating systems have a `which` that **doesn't even set an exit status**, meaning the `if which foo` won't even work there and will **always** report that `foo` exists, even if it doesn't (note that some POSIX shells appear to do this for `hash` too).

So, don't use `which`. Instead use one of these:

```bash
$ command -v foo >/dev/null 2>&1 || { echo >&2 "I require foo but it's not installed.  Aborting."; exit 1; }

$ type foo >/dev/null 2>&1 || { echo >&2 "I require foo but it's not installed.  Aborting."; exit 1; }

$ hash foo 2>/dev/null || { echo >&2 "I require foo but it's not installed.  Aborting."; exit 1; }
```
