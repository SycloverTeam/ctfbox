from sys import modules, platform
from os import popen


class ConfigError(Exception):
    pass


# ? check

if platform == "win32":
    raise ImportError("This package not support windows")

if "pwn" not in modules and "pwnlib" not in modules:
    raise ImportError("Please import pwn(pwntools) before import this package")

if "ctfbox.pwntools.config" not in modules:
    raise ImportError(
        "Please import ctfbox.pwntools.config and set necessary attribute before import this package")
else:
    m = modules["ctfbox.pwntools.config"]
    Config = m.Config
    for attr in m._config.necessary_attribute:
        if not hasattr(Config, attr):
            raise ImportError(
                f"Please set Config {attr} for config.Config before import this package")

slog = {}
# ? set sugar functions
m = modules["pwn"]
mm = modules["pwnlib"]

if Config.local is True:
    cn = m.process(Config.bin)
else:
    if ":" not in Config.address:
        raise ConfigError("address") from None
    args = Config.address.split(":")
    try:
        args[1] = int(args[1])
    except ValueError:
        raise ConfigError("address") from None
    Config._host = args[0]
    Config._port = args[1]
    cn = m.remote(args[0], args[1])

elf = m.ELF(Config.bin)

re  = lambda m, t : cn.recv(numb=m, timeout=t)
recv= lambda      : cn.recv()
ru  = lambda x    : cn.recvuntil(x)
rl  = lambda      : cn.recvline()
sd  = lambda x    : cn.send(x)
sl  = lambda x    : cn.sendline(x)
ia  = lambda      : cn.interactive()
sla = lambda a, b : cn.sendlineafter(a, b)
sa  = lambda a, b : cn.sendafter(a, b)
ft  = lambda arg, f=mm.util.cyclic.de_bruijn(), l=None: m.flat(*arg, filler=f, length=l)


def gdba(bps: list = []):
    if Config.local is False:
        return
    cmd = 'set follow-fork-mode parent\n'
    if Config.pie:
        binary = Config.bin.split('/')[-1]
        base = int(popen("pmap {}| grep {} | awk '{{print $1}}'".format(cn.pid, binary)).readlines()[1], 16)
        cmd += ''.join(['b *{:#x}\n'.format(b+base) for b in bps])
        cmd += 'set $base={:#x}\n'.format(base)
        slog["base"] = base
    else:
        cmd += ''.join(['b *{:#x}\n'.format(b) for b in bps])
    m.gdb.attach(cn, cmd)


def slog_show():
    for i in slog:
        m.success(i + ' ==> ' + hex(slog[i]))
