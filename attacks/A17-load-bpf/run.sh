#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Lab use only. Runs inside the scenario's target pod.
python3 - <<'PY'
import ctypes, struct
libc = ctypes.CDLL(None, use_errno=True)
SYS_bpf, BPF_PROG_LOAD, BPF_PROG_TYPE_SOCKET_FILTER = 321, 5, 1
# mov r0, 0; exit -- a socket filter that drops everything, attached to nothing.
insns = ctypes.create_string_buffer(struct.pack("<BBhi", 0xb7, 0, 0, 0) + struct.pack("<BBhi", 0x95, 0, 0, 0))
license = ctypes.create_string_buffer(b"GPL")
attr = ctypes.create_string_buffer(struct.pack("<IIQQ", BPF_PROG_TYPE_SOCKET_FILTER, 2, ctypes.addressof(insns), ctypes.addressof(license)).ljust(128, b"\0"))
fd = libc.syscall(SYS_bpf, BPF_PROG_LOAD, attr, len(attr))
if fd < 0:
    raise OSError(ctypes.get_errno(), "bpf(BPF_PROG_LOAD)")
print("program loaded, fd", fd)
PY
