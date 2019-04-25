# lab 1-2

## QUESTION 1

> Upload the Lab01-02.exe file to http://www.VirusTotal.com/. Does it match
> any existing antivirus definitions?

文件的 sha256 哈希值：

```bash
$ sha256sum Lab01-02.exe
c876a332d7dd8da331cb8eee7ab7bf32752834d4b2b54eaa362674a2a48f64a6  Lab01-02.exe
```

因此上传的 `url` 为：https://www.virustotal.com/#/file/c876a332d7dd8da331cb8eee7ab7bf32752834d4b2b54eaa362674a2a48f64a6/detection

可以看到这同样是一个木马。

## QUESTION 2

> Are there any indications that this file is packed or obfuscated? If so, what are these indicators? If the file is packed, unpack it if possible.

