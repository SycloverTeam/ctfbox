from concurrent.futures import ThreadPoolExecutor
from functools import partial, wraps
from http.server import HTTPServer
from threading import Thread
from typing import List, Tuple, Union
from json import loads

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
        body_string = body_content.decode(encoding=encoding)
        if filename == b"":
            parse_dict["data"][field] = body_string
        else:
            parse_dict["files"][field] = (
                filename.decode(), body_content, content_type.decode())
        start = end + 1
    return parse_dict


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
        bytes: The packed bytes
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

    # ? Judgment scheme
    scheme = 'http'
    port = 80
    if ssl:
        scheme = 'https'
        port = 443

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
    url = f"{scheme}://{host.decode()}:{port}/{path.decode()}"
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
                     for l in body.strip().split(b";") if b"=" in l])
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
