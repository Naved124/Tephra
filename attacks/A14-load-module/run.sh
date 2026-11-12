#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Lab use only. Runs inside the scenario's target pod.
python3 - <<'PY'
import ctypes, glob, os
libc = ctypes.CDLL(None, use_errno=True)
SYS_init_module, SYS_delete_module, SYS_finit_module = 175, 176, 313
MODULE_INIT_COMPRESSED_FILE = 4
# "dummy" is a network driver that does nothing until an interface of its
# type is created, and none is.
libc.syscall(SYS_delete_module, b"dummy", 0)
paths = glob.glob(f"/lib/modules/{os.uname().release}/kernel/drivers/net/dummy.ko*")
if not paths:
    raise SystemExit("no dummy module for this kernel")
path = paths[0]
fd = os.open(path, os.O_RDONLY)
flags = 0 if path.endswith(".ko") else MODULE_INIT_COMPRESSED_FILE
if libc.syscall(SYS_finit_module, fd, b"", flags) != 0:
    err = ctypes.get_errno()
    # Kernel without in-kernel decompression: decompress here.
    if path.endswith(".zst"):
        from compression import zstd
        image = zstd.decompress(open(path, "rb").read())
        if libc.syscall(SYS_init_module, image, len(image), b"") != 0:
            raise OSError(ctypes.get_errno(), "init_module")
    else:
        raise OSError(err, "finit_module")
print("dummy loaded")
PY
