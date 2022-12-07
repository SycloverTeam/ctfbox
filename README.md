## ctfbox 
**A box for CTF challenges with some sugar functions, Just enjoy it**

Current version: **1.12.0**

[中文文档点这里](README_CN.md)

Please use python **3.6+**

### Guide
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
- [Logs](#logs)
## Install
All you need to do is
```sh
pip install ctfbox
```

## Usage

### Common
```python
from ctfbox import * # Will not import the pwn part, please check the PWN Usage section below
# enjoy it
```
### PWN
[PWN Usage](#pwn-1)
## Functions
Please refer to docstring for function's signatures and usages
### utils
Some useful functions, close to intuition
- url: `url_encode()`, `url_decode()`, `force_url_encode()`
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
- prase od command data: `od_parse()`
- A decorator to make it multi-threaded: `Threader()`
- Decrypted in the usual way: `auto_decode()`
  

### WEB
- generate flask pin: `get_flask_pin()`
- generate flask session: `flask_session_encode()`, `flask_session_decode()`
(***⚠️ There is no flask dependency in ctfbox itself, the following two functions need to install the dependency by yourself***)
- build a simple file server: `provide()`
- burte force hash for ctf verification code: `hashAuth()`
- Send raw request by python-requests: `httpraw()`
- generate gopher reuqests: `gopherraw()`
- generate php serialize escape payload: `php_serialize_escape`, `php_serialize_escape_s2l()`, `php_serialize_escape_l2s()`
- change normal stirng to php serialize S string: `php_serialize_S()`
- php serialize
   - `serialize()`
   - `unserialize()`
   - `serialize_to_file()`
   - `unserialize_from_file()`
   - ...

   for more information, please check docstring and [here](https://github.com/mitsuhiko/phpserialize)
- generate php soapClient class payload for ssrf: `soapclient_ssrf()`
- network scan
  - scan network path: `scan()`
  - scan for network backup file: `bak_scan()`
- generate reverse shell command: `reshell()`
- use for out of band: `OOB()`
- build a server for blindXXE: `blindXXE()`
- generate gopher payload for attack redis
  - write webshell: `gopherredis_webshell()`
  - write crontab: `gopherredis_crontab()`
  - ssh authorized keys: `gopherredis_ssh()`
  - rce by master-slave replication: `gopherredis_msr()`
- source code leaks, support .git .svn .DS_Store: `leakdump()`
- reverse mt_rand seed without brute force: `reverse_mt_rand()`

### REVERSE
- print data in hex format: `printHex()`
- pack number into bytes: `p16()`, `p32()`, `p64()`
- unpack number from bytes: `u16()`, `u32()`, `u64()`

### MISC
- provide common file signatures and function to patch a file
  - patch file signature: `repair_fileheader()`
- fix zip fake encrypt: `repair_zip_fake_encrypt()`


### CRYPTO
- srand for multiple platforms: `windows_srand()`, `linux_srand()`, `android_srand()`, 
- get random integer from multiple platforms: `windows_rand()`,  `linux_rand()`, `android_nextInt()`, `android_nextInt_bound()`

### PWN
- Usage
   ```python
   # Doesn't support Windows
   from pwn import * # import pwntools
   # set pwntools config...
   # context.os = 'linux'
   # context.log_level = 'debug'
   # context.arch = 'amd64'
   from ctfbox.pwntools.config import Config # import confit for pwn part of ctfbox
   # set necessary config 
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
   now you can use the attributes/functions below
   ```
   slog // empty dictionary, you can set the leaked address and corresponding name. e.g. slog['libc'] = libc_addr
   elf  // pwntools.ELF(binaray)
   cn   // a connect to local binary or remote address
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
   gdba // gdba(bps) debug, argument bps save the breakpoint address, breakpoint can also be automatically set when pie is turned on, need pmap command
   slog_show // print all set slogs, in hexadecimal format
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

## Logs

### 1.11.0
- update some function:
    - hashAuth: add prefix and suffix arguments
### 1.10.0
- remove dependencies:
    - python-socketio[client]==4.6.0
    - python-engineio==3.14.2
- update some functions:
    - printHex
- rewrite some functions: 
    - OOB
- add some functions:
    - crypto
        - windows_srand
        - windows_rand
        - linux_srand
        - linux_rand
        - android_srand
        - android_nextInt
        - android_nextInt_bound

### 1.9.0
- add some functions:
    - force_url_encode

### 1.8.0
- add some functions:
    - php_serialize_S

### 1.7.0
- update some functions:
    - leakdump
        - update docstring
        - support .DS_Store
        - better error output
        - fix some bugs
- add some functions:
    - reverse_mt_rand
### 1.6.0
- 添加[中文文档](README_CN.md)
- add some functions:
    - leakdump
- update some functions:
    - get_flask_bin
        - update docstring
    - print_hex
        - pretty output
### 1.5.0
- add some functions:
    - scan
    - bak_scan
    - reshell
    - OOB
    - blindXXE
    - php_serialize_escape
    - gopherredis_webshell
    - gopherredis_crontab
    - gopherredis_ssh
    - gopherredis_msr
    - repair_fileheader
    - repair_zip_fake_encrypt
    - base16_encode, base16_decode, base32_encode, base32_decode, html_encode, html_decode

- add dependencies: 
    - python-socketio[client]==4.6.0
    - python-engineio==3.14.2

### 1.4.2
- fix bugs:
    - Threader
        - retry can't work
- update some functions:
    - Threader
        - add docstring
        - add task attributes: traceback
### 1.4.1
- fix bugs:
    - soapclient_ssrf
        - docstring about encode is error
        - encode arugment not work
    - md5
        - **can't import**
    - hashAuth
        - **can't work**
        - return type incorrect
### 1.4.0
- add __all__ for limit export
- add some functions:
    - soapclient_ssrf
    - rot_encode
    - thirdparty: phpserialize([Origin](https://github.com/mitsuhiko/phpserialize))
- add tests:
    - php_serialize_escape_l2s
    - php_serialize_escape_s2l
    - httpraw
- update some functions:
    - httpraw
        - add kwargs: session, send
- fix bugs:
    - php_serialize_escape_l2s
        - con't work correctly
    - httpraw
        - url irregular
        - no headers will be send
        - post data may be incorrect

### 1.3.0
- refactor project structure
- add some functions:
    - flask_session_encode
    - flask_session_decode
    - php_serialize_escape_l2s
    - php_serialize_escape_s2l
    - gopherraw
### 1.2.1
httpraw:
   - fix a bug that httpraw may not be able to send post request correctly
   - fix a bug that could not solve port
   - fix a bug that real_host could not use
   - fix a bug that may cause encoding error
### 1.2.0
- add dev dependencies: icecream
- add some functions:
    - od_parse
    - get_flask_pin
    - httpraw
    - p16 p32 p64 and uXX functions
    - Base32 and Base64 table getter
### v1.1.1
- move project to new directory
- update Readme.md, added missing functions
### v1.1.0
- add pwn part, please see Pwn Usage
- add some functions that may be used in reverse
- update hashAuth functions
  - error if startIndex is less than endIndex
  - if startIndex is zero and length of hash(endIndex - startIndex) is not equal to length of answer, endIndex will be set to length of answer
- update Readme.md, add usage and contributors, Supplementary dependency: PyJWT
### v1.0.2
- update Readme.md
### V1.0.1
- update Readme.md
### V1.0.0
- first commit
