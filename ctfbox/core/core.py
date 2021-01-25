from concurrent.futures import ThreadPoolExecutor
from functools import partial, wraps
from http.server import HTTPServer
from json import loads
from threading import Thread
from typing import List, Tuple, Union
from urllib.parse import quote

import requests

from .internal.utils import *


def Threader(number: int, timeout: int = None, retry: int = 2):
    """
    A simple decorator function that can decorate the function to make it multi-threaded.
    """
    def decorator(func):
        if isinstance(number, int):
            pool = ThreadPoolExecutor(number)
        else:
            raise TypeError(
                "Invalid type: %s for number"
                % type(number)
            )

        @wraps(func)
        def wrapped(*args, **kwargs):
            return Multier(
                pool.submit(func, *args, **kwargs),
                timeout,
                retry,
                pool,
            )
        return wrapped
    return decorator


def provide(host: str = "0.0.0.0", port: int = 2005, isasync: bool = False,  files: List[Tuple[Union[filepath, content], routePath, contentType]] = {}):
    """
    A simple and customizable http server.
    """
    if isinstance(files, list):
        if not isinstance(files[0], (list, tuple)):
            files = [files]
    else:
        raise ArugmentError("files type must be list")
    handler = partial(ProvideHandler, files)
    server = HTTPServer((host, port), handler)
    print(f"Listen on {host}: {port} ...")
    if isasync:
        t = Thread(target=server.serve_forever)
        t.start()
    else:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print('[#] KeyboardInterrupt')
            server.shutdown()


def hashAuth(startIndex: int = 0, endIndex: int = 5, answer: str = "", maxRange: int = 1000000, threadNum: int = 25, hashType: HashType = HashType.MD5) -> str:
    """
    A function used to blast the first few bits of the hash, often used to crack the ctf verification code
    """
    if hashType not in HASHTYPE_DICT:
        raise ArugmentError("HashType type error")

    hash_len = endIndex - startIndex
    if hash_len <= 0:
        raise ArugmentError("startIndex/endIndex error")

    if hash_len != len(answer):
        if startIndex == 0:
            endIndex = len(answer)
        else:
            raise ArugmentError("Hash length error")
    i = iter(range(maxRange))
    context = Context()
    hashfunc = HASHTYPE_DICT[hashType]
    @Threader(threadNum)
    def run(context):
        while context.value is None:
            try:
                guess = next(i)
            except StopIteration:
                break
            if hashfunc(str(guess).encode()).hexdigest()[startIndex:endIndex] == answer:
                context.value = True
                return guess
        return -1
    tasks = [run(context) for _ in range(threadNum)]

    for task in tasks:
        if task.result == -1:
            continue
        pool = task.pool
        pool.shutdown(wait=False)
        return task.result


def _is_json(data):
    try:
        loads(data)
    except ValueError:
        return False
    return True


def _parse_form_data(body, encoding: str = "utf-8"):
    if not body.startswith(b"-"):
        return {}, body
    parse_dict = {"data": {}, "files": {}}
    lines = body.split(b"\n")
    start, end = 0, 0
    while start < len(lines):
        boundary = lines[start]
        if boundary == b"":
            start += 1
            continue
        end = start + lines[start:].index(boundary + b"--")
        file_lines = lines[start:end]
        split_index = file_lines.index(b'')
        file_headers = file_lines[1:split_index]
        file_bodys = file_lines[split_index+1:end]
        header = file_headers[0]
        content_type = ""

        # ? header
        if not header.lower().startswith(b"content-disposition: "):
            start = end + 1
            continue
        other_headers = header[header.index(b";"):]
        _dict = dict([l.split(b"=")
                      for l in other_headers.strip().split(b";") if b"=" in l])
        _dict = {k.strip(): v.strip(b'"') for k, v in _dict.items()}
        field = _dict.get(b'name', b"")
        filename = _dict.get(b'filename', b"")

        # ? content_type
        if len(file_headers) > 1:
            content_type_header = file_headers[1]
            if content_type_header.lower().startswith(b"content-type:"):
                content_type = content_type_header.split(b":")[1].strip()
            else:
                content_type = "text/plain"

        body_content = b'\n'.join(file_bodys)
        if filename == b"":
            parse_dict["data"][field] = body_content
        else:
            parse_dict["files"][field] = (
                filename.decode(), body_content, content_type.decode())
        start = end + 1
    return parse_dict


<<<<<<< Updated upstream:ctfbox/core/core.py
=======
def get_flask_pin(username: str, absRootPath: str, macAddress: str, machineId: str, modName: str = "flask.app",
                  appName: str = "Flask") -> str:
    rv, num = None, None
    probably_public_bits = [
        username,
        modName,
        # getattr(app, '__name__', getattr(app.__class__, '__name__'))
        appName,
        # getattr(mod, '__file__', None),
        absRootPath,
    ]

    private_bits = [
        # str(uuid.getnode()),  /sys/class/net/ens33/address
        str(int(macAddress.strip().replace(":", ""), 16)),
        machineId,  # get_machine_id(), /etc/machine-id
    ]

    h = md5()
    for bit in chain(probably_public_bits, private_bits):
        if not bit:
            continue
        if isinstance(bit, str):
            bit = bit.encode('utf-8')
        h.update(bit)
    h.update(b'cookiesalt')

    h.update(b'pinsalt')
    num = ('%09d' % int(h.hexdigest(), 16))[:9]

    for group_size in 5, 4, 3:
        if len(num) % group_size == 0:
            rv = '-'.join(num[x:x + group_size].rjust(group_size, '0')
                          for x in range(0, len(num), group_size))
            break
    else:
        rv = num
    return rv


class App:
    def __init__(self, secret_key: str):
        self.secret_key = secret_key


def flask_session_encode(secret_key: str, payload: dict) -> str:
    """encode flask session

    Args:
        secret_key: secret_key
        payload: The data you want to encode

    Returns:
        str: session data

    Example:
        sc = '123'
        pl = {
        'user': 'admin',
        'info': 'test'
        }

        print(flask_session_encode(sc, pl))

        # Output
        eyJpbmZvIjoidGVzdCIsInVzZXIiOiJhZG1pbiJ9.YA2XHw.PSPjYFyj3hxsTNx-d2vjncAMJW4
    """
    if not _check_flask_import():
        raise ImportError(
            "Please install moudle flask. e.g. python3 -m pip install flask")
    from flask.sessions import SecureCookieSessionInterface
    try:
        app = App(secret_key)
        scsi = SecureCookieSessionInterface()
        s = scsi.get_signing_serializer(app)
        return s.dumps(payload)
    except Exception as e:
        raise FlaskSessionHelperError("Encode error") from e


def flask_session_decode(session_data: str, secret_key: str) -> dict:
    """decode flask session

    Args:
        session_data: The session you want to decode
        secret_key: secret_key

    Returns:
        dict: session data information

    Example:
        ss = 'eyJpbmZvIjoidGVzdCIsInVzZXIiOiJhZG1pbiJ9.YA2WEA.phDDlkaEQOaXthwvpENxAeiHfiE'
        print(flask_session_decode(ss, '123'))
        print(flask_session_decode(ss, '12345'))

        # Output
        {'info': 'test', 'user': 'admin'}
        # raise a FlaskSessionHelperError
    """
    if not _check_flask_import():
        raise ImportError(
            "Please install moudle flask. e.g. python3 -m pip install flask")
    from flask.sessions import SecureCookieSessionInterface
    try:
        app = App(secret_key)
        scsi = SecureCookieSessionInterface()
        s = scsi.get_signing_serializer(app)
        return s.loads(session_data)
    except Exception as e:
        raise FlaskSessionHelperError("Deocde error") from e


def provide(host: str = "0.0.0.0", port: int = 2005, isasync: bool = False,  files: List[Tuple[Union[filepath, content], routePath, contentType]] = {}):
    """A simple and customizable http server.

    Args:
        host (str, optional): listen host. Defaults to "0.0.0.0".
        port (int, optional): listen port Defaults to 2005.
        isasync (bool, optional): Whether is async. Defaults to False.
        files (List[Tuple[Union[filepath, content], routePath, contentType]], optional): provide files. Defaults to {}.

    Raises:
        ProvideArgumentError

    Example:
        # provide a exist file named index.html
        provide(files=[('index.html',)])
        # Here is a trick if you provide only one file
        provide(files=['index.html'])
        # route /index.html provide content Hello world\n
        provide(files=[(b"Hello world\\n", "/index.html")])
        # provide some files
        provide(files=[("test.txt", ), ("index.html", )])
    """

    if isinstance(files, list):
        if not isinstance(files[0], (list, tuple)):
            files = [files]
    else:
        raise ProvideArgumentError("files type must be list")
    handler = partial(ProvideHandler, files)
    server = HTTPServer((host, port), handler)
    print(f"Listen on {host}: {port} ...")
    if isasync:
        t = Thread(target=server.serve_forever)
        t.start()
    else:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print('[#] KeyboardInterrupt')
            server.shutdown()


def hashAuth(startIndex: int = 0, endIndex: int = 5, answer: str = "", maxRange: int = 1000000, threadNum: int = 25, hashType: HashType = HashType.MD5) -> str:
    """A function used to blast the first few bits of the hash, often used to crack the ctf verification code.

    Args:
        startIndex (int, optional): argument answer start index. Defaults to 0.
        endIndex (int, optional): argument answer end index. Defaults to 5.
        answer (str, optional): Part of the result hash. Defaults to "".
        maxRange (int, optional): burte force number max range. Defaults to 1000000.
        threadNum (int, optional): thread number. Defaults to 25.
        hashType (HashType, optional): burte force hash type. Defaults to HashType.MD5.

    Raises:
        HashAuthArgumentError

    Returns:
        str: the original value that its hash satisfies the answer

    Example:
        ### HashType optional value: HashType.MD5, HashType.SHA1, HashType.SHA256, HashType.SHA512
        ### Crack the first five number MD5 type ctf verification codes
        print(hashAuth(answer="02fcf"))
        ### Crack the first five number SHA1 type ctf verification codes
        print(hashAuth(answer="d13ce", hashType=HashType.SHA1))
        #### Crack more quickly!!
        print(hashAuth(answer="c907773", endIndex=7, threadNum=50))
        ### Make the range bigger!!
        print(hashAuth(answer="59e711d", endIndex=7, maxRange=2000000))
    """
    if hashType not in HASHTYPE_DICT:
        raise HashAuthArgumentError("HashType type error")

    hash_len = endIndex - startIndex
    if hash_len <= 0:
        raise HashAuthArgumentError("startIndex/endIndex error")

    if hash_len != len(answer):
        if startIndex == 0:
            endIndex = len(answer)
        else:
            raise HashAuthArgumentError("Hash length error")
    i = iter(range(maxRange))
    context = Context()
    hashfunc = HASHTYPE_DICT[hashType]
    @Threader(threadNum)
    def run(context):
        while context.value is None:
            try:
                guess = next(i)
            except StopIteration:
                break
            if hashfunc(str(guess).encode()).hexdigest()[startIndex:endIndex] == answer:
                context.value = True
                return guess
        return -1
    tasks = [run(context) for _ in range(threadNum)]

    for task in tasks:
        if task.result == -1:
            continue
        pool = task.pool
        pool.shutdown(wait=False)
        return task.result


>>>>>>> Stashed changes:ctfbox/web/web.py
def httpraw(raw: Union[bytes, str], **kwargs) -> requests.Response:
    """Send raw request by python-requests

   Args:
    raw(bytes/str): raw http request
    kwargs:
        proxies(dict) : requests proxies
        timeout(float): requests timeout
        verify(bool)  : requests verify
        real_host(str): use real host instead of Host if set
        ssl(bool)     : whether https

    Returns:
        requests.Response: the requests response
    """
    if isinstance(raw, str):
        raw = raw.encode()
    # ? Origin: https://github.com/boy-hack/hack-requests
    raw = raw.strip()
    proxies = kwargs.get("proxy", None)
    timeout = kwargs.get("timeout", 60.0)
    verify = kwargs.get("verify", True)
    real_host = kwargs.get("real_host", None)
    ssl = kwargs.get("ssl", False)

    if real_host:
        real_host = real_host.encode()
    # ? Judgment scheme
    scheme = 'http'
    port = b"80"
    if ssl:
        scheme = 'https'
        port = b"443"

    try:
        index = raw.index(b'\n')
    except ValueError:
        raise Exception("ValueError")
    # ? get method, path and protocol
    try:
        method, path, protocol = raw[:index].split(b" ")
    except Exception:
        raise Exception("Protocol format error")
    raw = raw[index + 1:]

    # ? get host
    try:
        host_start = raw.index(b"Host: ")
        host_end = raw.index(b'\n', host_start)

    except ValueError:
        raise ValueError("Host headers not found")

    if real_host:
        host = real_host
        if b":" in real_host:
            host, port = real_host.split(b":")
    else:
        host = raw[host_start + len("Host: "):host_end]
        if b":" in host:
            host, port = host.split(b":")
    raws = raw.splitlines()
    headers = {}
    index = 0
    # ? get headers
    for r in raws:
        if r == b"":
            break
        try:
            k, v = r.split(b": ")
        except Exception:
            k = r
            v = ""
        headers[k.decode()] = v.decode()
        index += 1
    headers["Connection"] = "close"
    # ? get body
    if len(raws) < index + 1:
        body = b''
    else:
        body = b'\n'.join(raws[index + 1:]).lstrip()

    # ? get url
    url = f"{scheme}://{host.decode()}:{port.decode()}/{path.decode()}"
    # ? get content-length
    if body and "Content-Length" not in headers and "Transfer-Encoding" not in headers:
        headers["Content-Length"] = str(len(body))
    # ? deal with chunked
    if body and headers.get("Transfer-Encoding", '').lower() == "chunked":
        body = body.replace('\r\n', '\n')
        body = body.replace('\n', '\r\n')
        body = body + "\r\n" * 2
    # ? deal with Content-Type

    # ? deal with body
    parse_dict = {"files": {}, "data": {}}
    if "Content-Type" not in headers:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif _is_json(body) and headers["Content-Type"] not in ["application/json", "multipart/form-data"]:
        headers["Content-Type"] = "application/json"
    if headers["Content-Type"] == "application/x-www-form-urlencoded":
        body = dict([l.split(b"=")
                     for l in body.strip().split(b"&") if b"=" in l])
        body = {k.strip().decode(): v.strip().decode()
                for k, v in body.items()}
    elif headers["Content-Type"] == "multipart/form-data":
        parse_dict = _parse_form_data(body)
        body = parse_dict["data"]

    # ? prepare request
    s = requests.Session()
    req = requests.Request(method, url, data=body, files=parse_dict["files"])
    prepped = req.prepare()
    return s.send(prepped,
                  proxies=proxies,
                  timeout=timeout,
                  verify=verify,
                  )


def gopherraw(raw: str, host: str = "",  ssrfFlag: bool = True) -> str:
    """Generate gopher requests URL form a raw http request

    Args:
        raw (str): raw http request
        host (str, optional): use this as the real host if this value is set. Defaults to "".
        ssrfFlag (bool, optional): The entire URL will be encoded again if this value is set True. Defaults to True.

    Returns:
        str: gopher requests URL
    """
    data = ""
    for row in raw.split("\n"):
        if len(row) > 0 and row[-1] == "\r":
            data += quote(row + "\n")
        else:
            data += quote("\r\n" + row)

        header = row.lower().strip()
        if header.startswith("host:"):
            if host == "":
                host = header[5:].strip()
                if ":" not in host:
                    host += ":80"

    header = "gopher://" + host + "/_"

    if ssrfFlag:
        return quote(header + data)
    return header + data
