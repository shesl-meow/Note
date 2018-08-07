# MISC

1. Encode
2. Forensic && Steg
3. Take a look (other)
4. Misc+ (+'pwn' +'web')

## 0x00: Recon 信息搜集

- 社会工程学

## 0x01: Encode 编码、解码以及相互间的转化

### 编码形式

- 常见的编码：bin, dec, hex, base64...

1. bin &rarr; ASCII码，二维码，**字符画**。进制转化：
    ```python
    dec_integer = int(b'110',2) # 将二进制转化为十进制
    bin_integer = bin(100) # 将十进制转化为二进制
    ```
    - 二进制转化 &rarr; 可以用任意的两个符号表示（比如：tab与space）

2. Morse，莫斯电码

3. Base64 &rarr; 一种可逆的编码方式，编码结果是一个字符串，包含的字符为：`A...Za...z0...9+/` 与填充字符 `=`
    - 编码方式：
        1. 先将3个8位的ASCII码转化位4个6位的base64对应码
        2. 若因为文件大小，最后的不足4个对应码，用`=`填充
        3. 一个等号对应忽略2bits
    - 解码过程：
        - 在解码的过程中会首先检测`=`的个数，直接忽略默认为0的base64码尾部
    - **Base64隐写**：base64 &rarr; 解码 &rarr; 编码 &rarr; 出现不一致信息
    - b85encode，来自python3，对base64的扩展
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
4. 图形码，https://online-barcode-reader.inliteresearch.com/

5. 二维码的修复：黑白取反、ps
    - *二维码的编码方式*： 定位图形、校正图形、格式信息、版本信息、数据和纠错码...

6. 敲击码：`5*5`方格

7. CTF中的编码：
    - BrainFuck, Jsfuck, Jother
    - 混淆加密: asp, php, css/js, VBScript.Encode

### 常用工具

- tools.ph0en1x.com/hashtool/tools.html#conv/
- JPK
- Shell &rarr; base64, uuencode &rarr; grep、strings、awk、sed、cat
- Python

### 攻击实践

- rbash &rarr; 限制命令使用的bashshell
    - 直接tab &rarr; 显示可用的所有命令
    - 没有回显 &rarr; curl命令把文件post到自己的服务器上

- NTFS

## 0x02: Forensic&Steg 隐写矩阵

- 常见的取证对象：PCAP流量包分析，各种图片文件，*音视频文件*，压缩包，磁盘文件，磁盘文件，内存镜像...

- 目的一般为发现文件中包含的隐藏字符串（代表需要取证的机密信息）

- 前置技能：
    1. Encode
    2. Python &rarr; 字符串处理、二进制数据处理、文件处理(Zip、Png、PCAP)、网络编程(socket, pwntools)
    3. File Format文件格式：*文件头magic number* &rarr; https://en.wikipedia.org/wiki/List_of_file_signatrues
    4. Tools
        - File(Linux bash), trid(Windows cmd), 用来鉴定文件类型
        - Strings, 查看文件中的可见字符串，一般用来找到hint
        - binwalk, foremost, 用于分析文件，自动切割文件
        - Winhex, 010Editor &rarr; 分析文件的十六进制
        - grep, awk, 关键信息的检索提取

### 图片处理

- MetaData
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
