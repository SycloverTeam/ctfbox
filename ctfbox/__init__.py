# import sys
# from os import path
# sys.path.insert(0, path.split(path.realpath(__file__))[0])
from ctfbox.utils.utils import *
from ctfbox.core.core import *
# for dev
try:
    from icecream import ic as _ic
    import builtins
    builtins.ic = _ic
except Exception:
    pass
