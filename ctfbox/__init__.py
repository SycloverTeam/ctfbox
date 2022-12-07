""" A toolbox for CTF challenges with some sugary functions, Just enjoy it
"""
from types import FunctionType as _FunctionType
from ctfbox.utils import *
from ctfbox.web import *
from ctfbox.reverse import *
from ctfbox.misc import *
from ctfbox.crypto import *
from ctfbox.thirdparty.phpserialize import *
# for dev
try:
    from icecream import ic as _ic
    import builtins
    builtins.ic = _ic
except Exception:
    pass


def analysis(global_dict: dict, allowed_modules: list) -> list:
    if "__main__" not in allowed_modules:
        allowed_modules.append("__main__")
    result = []
    for attrname, v in global_dict.items():
        if isinstance(attrname, _FunctionType) or isinstance(attrname, object):
            if attrname.startswith('_') or (hasattr(v, '__module__') and v.__module__ not in allowed_modules):
                attrname = ""
        else:
            if not attrname.isupper() and attrname.startswith('_'):
                attrname = ""
        if attrname:
            result.append(attrname)
    return result


__all__ = analysis(globals(), ["ctfbox.utils.utils",
                               "ctfbox.web.web",
                               "ctfbox.web.fpm",
                               "ctfbox.reverse.reverse",
                               "ctfbox.misc.misc",
                               "ctfbox.crypto.crypto",
                               "ctfbox.thirdparty.phpserialize"])

del analysis
