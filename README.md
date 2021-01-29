## ctfbox 
**A box for CTF challenges with some sugar functions, Just enjoy it**

Current version: **1.4.2**

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
### utils
Some functions with names similar to PHP, close to intuition
- url_encode(s: str, encoding: str = 'utf-8') -> str
- url_decode(s: str, encoding: str = 'utf-8') -> str
- base64_decode(s: str, encoding='utf-8') -> str
- base64_encode(s: str, encoding='utf-8') -> str
- bin2hex(s: str) -> str
- hex2bin(s: str) -> str
- json_encode(obj) -> object
- json_decode(data) -> str
- jwt_decode(token: str) -> bytes
- jwt_encode(header: dict, payload: dict, key=None, algorithm=None) -> str
- rot_encode(data: str, n: int) -> str
- sha1(s: str, encoding='utf-8') -> str
- sha256(s: str, encoding='utf-8') -> str
- md5(s: str, encoding='utf-8') -> str
- random_int(minN: int = 0, maxN: int = 1024) -> int
- random_string(n: int = 32, alphabet: str = "") -> str
- od_parse(data: str) -> Dict[str, Union[str, list]]
- Threader(number: int, timeout: int = None, retry: int = 2)
   ```
    A simple decorator function that can decorate the function to make it multi-threaded.
   ```
  

### WEB
- get_flask_pin(username: str,  absRootPath: str, macAddress: str, machineId: str, modName: str = "flask.app", appName: str = "Flask") -> str
- flask_session_helper
(***⚠️ There is no flask dependency in ctfbox itself, the following two functions need to install the dependency by yourself***)
  - flask_session_encode(secret_key: str, payload: dict) -> str
  - flask_session_decode(session_data: str, secret_key: str) -> dict
- php_serialize_escape_helper
  - php_serialize_escape_s2l(src: str, dst: str, payload: str, paddingTrush: bool = False) -> dict
  - php_serialize_escape_l2s(src: str, dst: str, payload: str, paddingTrush: bool = False) -> dict
- provide(host: str = "0.0.0.0", port: int = 2005, isasync: bool = False, files: List[Tuple[Union[filepath, content], routePath, contentType]] = {})
   ```
   A simple and customizable http server.
   ```
- hashAuth(startIndex: int = 0, endIndex: int = 5, answer: str = "", maxRange: int = 1000000, threadNum: int = 25, hashType: HashType = HashType.MD5) -> str
   ```
   A function used to blast the first few bits of the hash, often used to crack the ctf verification code
   ```
- httpraw(raw: Union[bytes, str], **kwargs) -> Union[requests.Response, requests.Request]
   ```
   Send raw request by python-requests
   
   Allow kwargs:
      proxies(dict) : requests proxies. Defaults to None.
      timeout(float): requests timeout. Defaults to 60.
      verify(bool)  : requests verify. Defaults to True.
      real_host(str): use real host instead of Host if set.
      ssl(bool)     : whether https. Defaults to False.
      session(bool) : use this session instead of new session.
      send(bool)    : whether to send the request. Defaults to True.
   ```
- gopherraw(raw: str, host: str = "",  ssrfFlag: bool = False) -> str
   ```
   Generate gopher requests URL form a raw http request
   ```
- phpserialize

   for more information, please check docstring and [here](https://github.com/mitsuhiko/phpserialize)
   - serialize(data, charset='utf-8', errors=default_errors, object_hook=phpobject)
      ```
      The realization of php serialize in python
      ```
   - unserialize(data, charset='utf-8',errors=default_errors,decode_strings=False,object_hook=phpobject,array_hook=None, return_unicode=False)
      ```
      The realization of php unserialize in python
      ```
   - serialize_to_file(...)
   - unserialize_from_file(...)
   - ...
- soapclient_ssrf(url, user_agent: str = "", headers: Dict[str, str] = {}, post_data: str = "") -> Union[str, bytes]


### REVERSE
please refer to source code for function's signatures and usages
- print data in hex format: `printHex()`
- pack number into bytes: `p16()`, `p32()`, `p64()`
- unpack number from bytes: `u16()`, `u32()`, `u64()`

### MISC
- TODO

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

## Contributors
Syclover
   - [Longlone](https://github.com/way29)
   - [F4ded](https://github.com/F4ded)
   - [lingze](https://github.com/wlingze)
   - [pjx](https://github.com/pjx206)
   - [AFKL](https://github.com/AFKL-CUIT)

Other
   - [Morouu](http://github.com/Morouu)

## Logs

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
