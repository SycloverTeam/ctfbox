from concurrent.futures import ThreadPoolExecutor
from functools import partial, wraps
from http.server import HTTPServer
from threading import Thread
from typing import List, Tuple, Union

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
