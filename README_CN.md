# ctfbox

**一个用于CTF的函数合集，玩得开心**

当前版本: **1.7.0**

python版本:**3.6+**

- ### Guide

    - [ctfbox](#ctfbox)
        * [Guide](#guide)
    - [Install](#install)
    - [Usage](#usage)
        * [Common](#common)
        * [PWN](#pwn)
    - [Functions](#functions)
        * [utils](#utils)
        * [WEB](#web)
        * [REVERSE](#reverse)
        * [MISC](#misc)
        * [PWN](#pwn-1)
    - [Techniques](#techniques)
    - [Depends](#depends)
    - [Contributors](#contributors)

## Install

```
pip install ctfbox
```

## Usage

### Common

```
from ctfbox import * # 这样不会导入pwn模块，请查看下方pwn的使用方法
# enjoy it
```

### PWN

[PWN Usage](https://pypi.org/project/ctfbox/#pwn-1)

## Functions

请参阅文档了解函数的签名和用法。

### utils

一些函数的名称与PHP类似，这很直观

- url: `url_encode()`, `url_decode()`
- html: `html_encode()`, `html_decode()`
- base16: `base16_encode()`, `base16_decode()`
- base32: `base32_encode()`, `base32_decode()`
- base64: `base64_encode()`, `base64_decode()`
- json: `json_encode()`, `json_decode()`
- hex: `bin2hex()`, `hex2bin()`
- jwt: `jwt_encode()`, `jwt_decode()`
- rot: `rot_encode()`
- hash: `md5()`, `sha1()`, `sha256()`, `sha512()`
- random: `random_int()`, `random_string()`
- 解析od命令数据: `od_parse()`
- 一个可以让它多线程的装饰器: `Threader()`

### WEB

- 生成 flask pin: `get_flask_pin()`
- 生成 flask session: `flask_session_encode()`, `flask_session_decode()` (***⚠️ ctfbox本身不自带flask依赖，这两个函数需要自己安装依赖***)
- 生成php序列化逃逸pyload: `php_serialize_escape`, `php_serialize_escape_s2l()`, `php_serialize_escape_l2s()`
- 构建一个简单的文件服务器: `provide()`
- ctf验证代码的蛮力哈希: `hashAuth()`
- 通过python-requests发送原始请求: `httpraw()`
- 构造gopher请求: `gopherraw()`
- php序列化
  - `serialize()`
  - `unserialize()`
  - `serialize_to_file()`
  - `unserialize_from_file()`
  - ...
  更多信息请查阅文档和 [这里](https://github.com/mitsuhiko/phpserialize)
- 针对ssrf 生成php soapClient class: `soapclient_ssrf()`
- 网络扫描
  - 扫描路径: `scan()`
  - 扫描备份文件: `bak_scan()`
- 生成反向shell命令: `reshell()`
- 用于OOB的函数: `OOB()`
- 为blindXXE构建一个服务器: `blindXXE()`
- 为攻击redis生成gopher payload
  - 写 webshell: `gopherredis_webshell()`
  - 写 crontab: `gopherredis_crontab()`
  - ssh密钥授权: `gopherredis_ssh()`
  - 通过主从复制实现的rce: `gopherredis_msr()`
- 源代码泄露利用, 支持.git .svn .DS_Store: `leakdump()`
- 无需爆破还原mt_rand种子: `reverse_mt_rand()`

### REVERSE

- 以十六进制格式打印数据: `printHex()`
- 按字节打包编号: `p16()`, `p32()`, `p64()`
- 从字节中解包number: `u16()`, `u32()`, `u64()`

### MISC

- 提供常用的文件修复功能
  - 修复文件头: `repair_fileheader()`
- 修复zip假加密: `repair_zip_fake_encrypt()`

### PWN

- 用法

  ```
  # 不支持windows
  from pwn import * # import pwntools
  # 设置必要的pwntool配置...
  # context.os = 'linux'
  # context.log_level = 'debug'
  # context.arch = 'amd64'
  from ctfbox.pwntools.config import Config # import confit for pwn part of ctfbox
  # 设置必要的配置
  """
  Attributes:
  - local(bool) : connect to local binary / remote address, default: True
  - bin(str)    : the binary path, e.g. './pwn'
  - address(str): the remote address, e.g. '127.0.0.1:2333'
  - pie(bool)   : whether the memory address is randomized, default: False
  """
  Config.local = True
  Config.address = "127.0.0.1:2333"
  Config.bin = "./bin"
  # import pwn part
  from ctfbox.pwn import *
  ```

  现在就可以使用下面的属性/函数

  ```
  slog // 空字典，可以设置泄露的地址和对应的名称。例如:slog['libc'] = libc_addr
  elf  // pwntools.ELF(binaray)
  cn   // 连接到本地二进制地址或远程地址
  re   // lambda of cn.recv(m, t)
  recv // lambda of cn.recv()
  ru   // lambda of cn.recvuntil(x)
  rl   // lambda of cn.recvline()
  sd   // lambda of cn.send(x)
  sl   // lambda of cn.sendline(x)
  ia   // lambda of cn.interactive()
  sla  // lambda of cn.sendlineafter(a, b)
  sa   // lambda of cn.sendafter(a, b)
  ft   // ft(arg, f=pwnlib.util.cyclic.de_bruijn(), l=None) lambda of flat(*arg, filler=f, length=l)
  gdba // gdba(bps) debug，参数bps保存断点地址，也可以在开机时自动设置断点，需要pmap命令
  slog_show // 以十六进制格式打印所有设置的日志
  ```

## Techniques

- [pdm](https://github.com/frostming/pdm)
- [version-helper](https://github.com/WAY29/version-helper/)

## Depends

- requests
- PyJWT
- python-socketio[client]==4.6.0
  - python-engineio==3.14.2

## Contributors

Syclover

- [Longlone](https://github.com/way29)
- [F4ded](https://github.com/F4ded)
- [lingze](https://github.com/wlingze)
- [pjx](https://github.com/pjx206)
- [AFKL](https://github.com/AFKL-CUIT)
- [kodosan](https://github.com/kodosan)

Other

- [Morouu](http://github.com/Morouu)