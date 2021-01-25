from ctfbox.utils import *
from ctfbox.web import *
from ctfbox.reverse import *
from ctfbox.misc import *
from ctfbox.crypto import *
# for dev
try:
    from icecream import ic as _ic
    import builtins
    builtins.ic = _ic
except Exception:
    pass
