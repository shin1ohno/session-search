"""Isolated test launcher: bind(2) returns EADDRINUSE; all other calls pass.

The filter follows exec, so the same fault reaches Python and native ccs.
It applies only to this disposable process and its children, never the parent
test server. No privileges, environment secrets or product hooks are used.
"""
import ctypes
import errno
import os
import platform
import sys
import subprocess
import tempfile
from pathlib import Path


def main():
    if sys.platform == "darwin":
        directory = Path(tempfile.mkdtemp(prefix="ccs-deny-bind-", dir=os.environ["TMPDIR"]))
        source = directory / "deny.c"
        library = directory / "deny.dylib"
        source.write_text(r"""
#include <sys/socket.h>
#include <errno.h>
#include <dlfcn.h>
static int denied_bind(int fd, const struct sockaddr *address, socklen_t length) {
    if (address && address->sa_family == AF_UNIX) { errno = EADDRINUSE; return -1; }
    int (*original)(int, const struct sockaddr *, socklen_t) = dlsym(RTLD_NEXT, "bind");
    return original(fd, address, length);
}
__attribute__((used)) static struct { const void *replacement; const void *original; }
interpose_bind __attribute__((section("__DATA,__interpose"))) = { (const void *)denied_bind, (const void *)bind };
""")
        subprocess.run(["/usr/bin/clang", "-dynamiclib", str(source), "-o", str(library)], check=True)
        os.environ["DYLD_INSERT_LIBRARIES"] = str(library)
        os.execvpe(sys.argv[1], sys.argv[1:], os.environ)
    numbers = {"x86_64": 49, "aarch64": 200}
    number = numbers[platform.machine()]
    class Filter(ctypes.Structure):
        _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte),
                    ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint)]
    class Program(ctypes.Structure):
        _fields_ = [("length", ctypes.c_ushort), ("filters", ctypes.POINTER(Filter))]
    instructions = (Filter * 4)(Filter(0x20, 0, 0, 0), Filter(0x15, 0, 1, number),
                                Filter(0x06, 0, 0, 0x50000 | errno.EADDRINUSE),
                                Filter(0x06, 0, 0, 0x7fff0000))
    program = Program(4, instructions)
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0) or libc.prctl(22, 2, ctypes.byref(program), 0, 0):
        raise OSError(ctypes.get_errno(), "cannot install test bind filter")
    os.execvpe(sys.argv[1], sys.argv[1:], os.environ)


if __name__ == "__main__":
    main()
