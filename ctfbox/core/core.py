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


def parse_form_data(body, encoding: str = "utf-8"):
    if not body.startswith("-"):
        return {}, body
    parse_dict = {"data": {}, "files": {}}
    lines = body.split("\n")
    start, end = 0, 0
    while start < len(lines):
        boundary = lines[start]
        if boundary == "":
            start += 1
            continue
        end = start + lines[start:].index(boundary + "--")
        file_lines = lines[start:end]
        split_index = file_lines.index('')
        file_headers = file_lines[1:split_index]
        file_bodys = file_lines[split_index+1:end]
        header = file_headers[0]
        content_type = ""

        # ? header
        if not header.lower().startswith("content-disposition: "):
            start = end + 1
            continue
        other_headers = header[header.index(";"):]
        _dict = dict([l.split("=")
                      for l in other_headers.strip().split(";") if "=" in l])
        _dict = {k.strip(): v.strip('"') for k, v in _dict.items()}
        field = _dict.get('name', "")
        filename = _dict.get('filename', "")

        # ? content_type
        if len(file_headers) > 1:
            content_type_header = file_headers[1]
            if content_type_header.lower().startswith("content-type:"):
                content_type = content_type_header.split(":")[1].strip()
            else:
                content_type = "text/plain"

        body_string = '\n'.join(file_bodys)
        body_content = body_string.encode(encoding=encoding)
        if filename == "":
            parse_dict["data"][field] = body_string
        else:
            parse_dict["files"][field] = (filename, body_content, content_type)
        start = end + 1
    return parse_dict


def httpraw(raw: str, **kwargs) -> requests.Response:
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
        index = raw.index('\n')
    except ValueError:
        raise Exception("ValueError")
    # ? get method, path and protocol
    try:
        method, path, protocol = raw[:index].split(" ")
    except Exception:
        raise Exception("Protocol format error")
    raw = raw[index + 1:]

    # ? get host
    try:
        host_start = raw.index("Host: ")
        host_end = raw.index('\n', host_start)

    except ValueError:
        raise ValueError("Host headers not found")

    if real_host:
        host = real_host
        if ":" in real_host:
            host, port = real_host.split(":")
    else:
        host = raw[host_start + len("Host: "):host_end]
        if ":" in host:
            host, port = host.split(":")
    raws = raw.splitlines()
    headers = {}
    index = 0
    # ? get headers
    for r in raws:
        if r == "":
            break
        try:
            k, v = r.split(": ")
        except Exception:
            k = r
            v = ""
        headers[k] = v
        index += 1
    headers["Connection"] = "close"
    # ? get body
    if len(raws) < index + 1:
        body = ''
    else:
        body = '\n'.join(raws[index + 1:]).lstrip()

    # ? get url
    url = f"{scheme}://{host}:{port}/{path}"
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
        body = dict([l.split("=")
                     for l in body.strip().split(";") if "=" in l])
    elif headers["Content-Type"] == "multipart/form-data":
        parse_dict = parse_form_data(body)
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
