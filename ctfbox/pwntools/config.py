
class _config:
    """
    Necessary attribute: address bin
    Allow attribute: local address bin pie

    Attributes:
    - local(bool) : connect to local binary / remote address, default: True
    - bin(str)    : the binary path, e.g. './pwn'
    - address(str): the remote address, e.g. '127.0.0.1:2333'
    - pie(bool)   : whether the memory address is randomized, default: False
    """
    necessary_attribute = ["address", "bin"]
    allow_attribuce = ["address", "bin", "local", "pie"]

    def __setattribute__(self, name, value):
        if not name.startswith("_") and name not in _config.allow_attribuce:
            raise KeyError(f"Access {name} is not allowed")
        else:
            return super().__setattribute__(name, value)

    def __getattribute__(self, name):
        if not name.startswith("_") and name not in _config.allow_attribuce:
            raise KeyError(f"Access {name} is not allowed")
        else:
            return super().__getattribute__(name)
    pass

    def __init__(self):
        self.pie = False
        self.local = True


Config = _config()
