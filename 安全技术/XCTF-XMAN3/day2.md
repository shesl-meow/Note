# MISC

## 0x00: Recon 

- 信息搜集 &rarr; 社会工程学

## 0x01: Encode

- What is encoding? ([From Stack-Overflow](https://stackoverflow.com/questions/6224052/what-is-the-difference-between-a-string-and-a-byte-string))
  - The only thing that a computer can store is bytes. 
  - To store anything in a computer, you must first encode it. 
  - **An encoding is a format to represent audio, images, text, etc in bytes.**

### 二进制编码

- Python中与二进制相关的类型转化：

  - 二进制字符串与十进制整型变量的相互转化：

     ```python
      dec_integer = int('110',2) # or '0b110'
      bin_integer = bin(6) # 类似的 hex(6)可以转化为16进制
     ```

  - *PS*：Python3中有Bytes类型的概念，可以用于做不同字符串编码格式的中介，比如：

    ```python
    b'\xe4\xbd\xa0\xe5\xa5\xbd'.decode("utf-8")
    # 通过指定的方式解码二进制bytes类型数据
    
    '你好'.encode("utf-8")
    # 通过指定的方式将字符串编码成二进制bytes类型数据
    
    b'HelloWorld'.decode()
    # UTF-8是默认解码方式
    ```

- CTF中有ASCII码、二维码、字符画等考察形式，也可以用任意两个符号来表示（比如：tab与space、莫斯电码）。

### Base64编码

- What is base64? 
  - [From Wikipedia](https://en.wikipedia.org/wiki/Base64) &rarr; Base64 is a group of similar binary-to-text encoding schemes that represent binary data in an ASCII string format by translating it into a radix-64 representation.
  - 自己总结 &rarr; BASE64是一种**将二进制串编码成可见字符**的一种编码方式。其区别于普通编码方式的最大不同之处是采用6位一组的编码方式 $$2^{6}=64$$ 。
- Base64转码大致流程如下：

```mermaid
graph TB;
	subgraph 原始串=>BASE64串
	Raw[原始字符串,比如HelloWorld]-->|指定编码方式,比如ASCII|Temp(BYTES串,比如0x48656c6c6f576f726c64);
	Temp-->|BASE64编码|Res[BASE64转码字符串,比如SGVsbG9Xb3JsZA==];
	end
	subgraph BASE64编码
	S1[8N长度的BYTES串,比如80]-->|末尾补0Padding,比如补16个|S2[24N'长度的BYTES串,比如96]
	S2-->|6位一组BASE64编码|S3[BASE64编码字符串]
	end
	Temp-->S1;S3-->Res
```

- Base64的编码结果可以用如下正则表达式表示（From [Stack-Overflow](https://stackoverflow.com/questions/475074/regex-to-parse-or-validate-base64-data)）：

  ```regex
  ^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$
  ```

- base64 解码工具：
  - Python中的Base64相关编码库（python3中还有一个叫b85encode，实际为对base64的扩展）

    ```python
    from base64 import b64encode
    b64encode(b"HelloWorld")
    # 将Bytes类型数据通过base64方式编码，返回一个Bytes类型串
    # 返回串通过Python的默认UTF-8方式解码即为base64的编码结果
    
    from base64 import b64decode
    b64decode(b'SGVsbG8gV29ybGQ=')
    # 将一个Bytes类型数据或者一个base64字符串通过base64方式解码，返回一个Bytes类型串
    ```

  - bash中的base64工具与openssl工具，或直接使用命令行中的python命令

    ```bash
    echo HelloWorld | base64
    echo SGVsbG9Xb3JsZAo= | base64 --decode
    # coreutils package 中的 base64 模块接受一个文件作为输入
    # 默认模式为编码，--decode 选项声明或 -d 选项声明后，对base64进行解码
    
    openssl enc -base64 <<< "HelloWorld"
    openssl enc -base64 -d <<< "SGVsbG9Xb3JsZAo="
    # 使用 openssl 程序中的 enc 模块， 指定 base64 进行编码解码。同base64模块，也为文件输入。
    # 默认模式为编码（或-e选项），-d选项声明后为解码。
    
    echo HelloWorld | python -m base64
    echo SGVsbG9Xb3JsZAo= | python -m base64 -d
    # 可以在bash中使用python对程序进行编码解码，-d选项声明后为解码
    ```

- **Base64隐写**

  - 原理：Base64在解码的过程中会首先检测`=`的个数，然后直接忽略默认为0的base64码尾部。

  - 流程：base64 &rarr; 解码 &rarr; 编码 &rarr; 出现不一致信息

    ```python
    b64chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    with open('text.txt', 'rb') as f:
        bin_str = ''
        for line in f.readlines():
            stegb64 = ''.join(line.split())
            rowb64 = ''.join(stegb64.decode('base64').encode('base64').split())
            offset = abs(b64chars.index(stegb64.replace('=','')[-1])-b64chars.index(rowb64.replace('=','')[-1]))
            equalum = stegb64.count('=')
            if equalum:
                bin_str += bin(offset)[2:].zfill(equalum * 2)
            print(''.join([chr(int(bin_str[i:i+8], 2)) for i in xrange(0, len(bin_str), 8)]))
    ```

### 其他编码方式

1. 图形码 &rarr; [在线工具](https://online-barcode-reader.inliteresearch.com/)

2. 二维码：（1）CTF：二维码的修复 &rarr; 黑白取反；（2）二维码结构示意图：

    ![QRCodeStructrue](day2/QR_Code_Structure.svg)

### 攻击实践

- rbash（restricted bash） &rarr; 限制命令使用的bashshell
    - 直接tab &rarr; 显示可用的所有命令
    - 没有回显 &rarr; curl命令把文件post到自己的服务器上


## 0x02: Forensic&Steg 隐写矩阵

### 前置技能

- Python &rarr; 字符串处理、二进制数据处理、文件处理(Zip、Png、PCAP)、网络编程(socket, pwntools)

- What is magic number? ([From Wikipedia](https://en.wikipedia.org/wiki/List_of_file_signatrues))

  - A constant numerical or text value used to identify a file format or protocol.

- Tools

  - File(Linux bash), trid(Windows cmd), 用来鉴定文件类型

    ```bash
    file input_file
    # The file command attempts to classify each filesystem object (i.e., file, directory or link) that is provided to it as an argument (i.e., input)
    ```

  - Strings, 查看文件中的可见字符串

    ```bash
    strings [OPTIONS] FILENAME
    # The Strings command basically prints the strings of printable characters in files.
    ```

  - binwalk, foremost, dd 用于分析文件，自动切割文件

    ```bash
    binwalk image.jpg # 使用 binwalk 分析文件
    
    dd if=in_image.jpg of=out_image.jpg skip=140147 bs=1
    # 使用 dd 命令分离隐藏文件。if 指定输入文件，of 指定输出文件，skip 指定分离头位置，bs 设置每次读写块的大小为 1 个字节
    foremost image.jpg # 使用 foremost 命令直接分离文件
    ```

  - Winhex, 010Editor &rarr; 分析文件的十六进制

  - grep, awk, 关键信息的检索提取

### 图片处理

- MetaData([Wikipedia](https://en.wikipedia.org/wiki/Metadata): Metadata is data that provides infoemation about other data.)
    - **Identifiy**：获取图形文件的格式与特性 &rarr; https://www.imagemagick.org/script/escape.php
    - strings
    - ExifTools

- 处理图片的Python库：
```Python
import PIL from image
```

1. jpg图片
    - 文件格式：
        - 标记码（两个字节构成：第一位0xFF，第二位不同有不同含义）
        - 压缩数据：前两个字节表示包括这两个字节的整个段的长度
    - 利用文件格式隐藏信息
        - 在文件尾部的App1数据区插入，MagicEXIF
        - 每段开始前，COM注释
    - 常用工具：JPHIDE隐写，stegdetect检测隐写
2. **png文件**
    - png文件格式构成

    - 利用文件格式隐藏信息
        - 文件头插入信息 &rarr; 破坏文件头，需要修复以识别为png &rarr; `hexdump -C ctf.png|more`
        - IDAT段有长度上限，超过填入下一段 &rarr; 在文件结束后人为加入IDAT段 &rarr; 不打破原图片的情况下实现数据隐写
        - IEND段
        - **LSB隐写**：最低有效位 &rarr; 在颜色码的最后一位加入信息，肉眼一般无法识别
            - 只适用于png这种无损压缩手段，jpg的压缩方式会损失信息
    - 常用工具：`pngcheck`，`Stegsolve`(图片通道查看器，图片隐写必备)，`010Editor`
3. gif文件
    - gif在线编辑器：http://ezgif.com/split
    - 时间轴：`Identifiy -format "%s %T \n" 100.gif`
    - 分割命令：`convert`
4. 音频类：频谱、波形
5. zip文件
    - zip爆破 &rarr; ARCHPR(windows)，fcrackzip
    - 伪加密 &rarr; 修改加密标志位，`zipCenOp`(检测伪加密jar工具)
    - CRC32碰撞
    - 明文攻击（已知一段加密信息的明文） &rarr; http://www.unix-ag.uni-kl.de/~conrad/krypto/pkcrack.html
6. 流量分析
    - 协议：http、https、dns、ftp
    - 隐藏数据
    - 数据提取 &rarr; 手工提取：Python(pcapy)、Tshark(`-r **.pcap -Y ** -T fields -e **`)
    - usb键鼠数据提取
    - 工具：pcapfix(文件修复)、wireshark(协议分析)、tshark(数据提取)、xxd(把二进制流打包成文件)、egrep
7. 内存文件
    - `Volatility` &rarr; 进程、文件、用户

## 0x03: Take a Look

- About Python &rarr; pyc文件 &rarr; dis模块读取指令
    - Python3.6以上的文件DeadZone无参指令也会占用一个字节的参数空间
    - Sandbox Escape &rarr; pysandbox &rarr; python沙箱的构造

- pdf隐写(wbStego4)、html隐写

- 磁盘文件、系统镜像
    - 取证工具：EasyRecovery、FTK、TSK

- 视频文件，字幕攻击

- 工控：协议

## 0x04: Misc+
