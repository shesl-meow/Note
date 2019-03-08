# `Fold`

`fold`:

- manual:

  > Usage: fold [OPTION]... [FILE]...
  > Wrap input lines in each FILE, writing to standard output.

- example:

  ```bash
  $ echo "Hello" > t1
  
  $ echo "World" > t2
  
  $ fold t1 t2
  Hello
  World
  ```
