## ctfbox 
**A box for CTF challenges with some sugar functions, Just Enjoy it**

Current version: **1.0.1**

Please use python **3.6+**

## Functions

### utils
Some functions with names similar to PHP, close to intuition
- url_encode(s: str, encoding: str = 'utf-8') -> str
- url_decode(s: str, encoding: str = 'utf-8') -> str
- base64_decode(s: str, encoding='utf-8') -> str
- base64_encode(s: str, encoding='utf-8') -> str
- json_encode(obj) -> object
- json_decode(data) -> str
- jwt_decode(token: str) -> bytes
- jwt_encode(header: dict, payload: dict, key=None, algorithm=None) -> str
- bin2hex(s: str) -> str
- hex2bin(s: str) -> str
- sha1(s: str, encoding='utf-8') -> str
- sha256(s: str, encoding='utf-8') -> str
- md5(s: str, encoding='utf-8') -> str
- random_int(minN: int = 0, maxN: int = 1024) -> int
- random_string(n: int = 32, alphabet: str = "") -> str


### core
Some functions Write by ourselves
- Threader(number: int, timeout: int = None, retry: int = 2)
   ```
    A simple decorator function that can decorate the function to make it multi-threaded.
   ```
   Here is a example.
   ```Python
   from ctfbox import Threader, random_string, random_int
   from time import sleep

   @Threader(10)
   def exp(i: int):
       sleep(random_int(1, 5))
       return "%d : %s" % (i, random_string())
    
    tasks = [exp(i) for i in range(100)] # 100 tasks
    for task in tasks: 
        # task.result return when a task completed
        # task is a concurrent.futures.Future with some sugar attributes
        print('result: %s running: %s done: %s exception: %s' % (task.result, task.running, task.done, task.exception))
   ```
- provide(host: str = "0.0.0.0", port: int = 2005, isasync: bool = False, files: List[Tuple[Union[filepath, content], routePath, contentType]] = {})
   ```
   A simple and customizable http server.
   ```
   Here is some examples.
   ```python
   # provide a exist file named index.html
   provide(files=[('index.html',)])
   # Here is a trick if you provide only one file
   provide(files=['index.html'])
   # route /index.html provide content Hello world\n
   provide(files=[(b"Hello world\\n", "/index.html")])
   # provide some files
   provide(files=[("test.txt", ), ("index.html", )])
   ```

## Techniques
- [pdm](https://github.com/frostming/pdm)
- [version-helper](https://github.com/WAY29/version-helper/)

## Depends
- requests

## Logs
### V1.1.0
- update Readme.md
### V1.0.0
- first commit